package manager

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/auth"
	"github.com/grafana/grafana/pkg/plugins/config"
	"github.com/grafana/grafana/pkg/plugins/log"
	"github.com/grafana/grafana/pkg/plugins/manager/loader"
	"github.com/grafana/grafana/pkg/plugins/manager/registry"
	"github.com/grafana/grafana/pkg/plugins/manager/sources"
	"github.com/grafana/grafana/pkg/plugins/repo"
	"github.com/grafana/grafana/pkg/plugins/storage"
)

var _ plugins.Installer = (*PluginInstaller)(nil)

type PluginInstaller struct {
	pluginRepo           repo.Service
	pluginStorage        storage.ZipExtractor
	pluginStorageDirFunc storage.DirNameGeneratorFunc
	pluginRegistry       registry.Service
	pluginLoader         loader.Service
	cfg                  *config.PluginManagementCfg

	installing      sync.Map
	log             log.Logger
	serviceRegistry auth.ExternalServiceRegistry
	rbacCleaner     auth.RBACCleaner
}

func ProvideInstaller(cfg *config.PluginManagementCfg, pluginRegistry registry.Service, pluginLoader loader.Service,
	pluginRepo repo.Service, serviceRegistry auth.ExternalServiceRegistry, rbacCleaner auth.RBACCleaner) *PluginInstaller {
	return New(cfg, pluginRegistry, pluginLoader, pluginRepo,
		storage.FileSystem(log.NewPrettyLogger("installer.fs"), cfg.PluginsPaths[0]), storage.SimpleDirNameGeneratorFunc, serviceRegistry, rbacCleaner)
}

func New(cfg *config.PluginManagementCfg, pluginRegistry registry.Service, pluginLoader loader.Service,
	pluginRepo repo.Service, pluginStorage storage.ZipExtractor, pluginStorageDirFunc storage.DirNameGeneratorFunc,
	serviceRegistry auth.ExternalServiceRegistry, rbacCleaner auth.RBACCleaner) *PluginInstaller {
	return &PluginInstaller{
		pluginLoader:         pluginLoader,
		pluginRegistry:       pluginRegistry,
		pluginRepo:           pluginRepo,
		pluginStorage:        pluginStorage,
		pluginStorageDirFunc: pluginStorageDirFunc,
		cfg:                  cfg,
		installing:           sync.Map{},
		log:                  log.New("plugin.installer"),
		serviceRegistry:      serviceRegistry,
		rbacCleaner:          rbacCleaner,
	}
}

func (m *PluginInstaller) Add(ctx context.Context, pluginID, version string, opts plugins.AddOpts) error {
	if ok, _ := m.installing.Load(pluginID); ok != nil {
		return nil
	}
	m.installing.Store(pluginID, true)
	defer func() {
		m.installing.Delete(pluginID)
	}()

	pending, err := m.fetch(ctx, pluginID, version, opts)
	if err != nil {
		return err
	}

	// Dependencies are installed before this plugin's archive is extracted or any existing version
	// is removed, so a dependency that is refused leaves this plugin as it was.
	for _, dep := range pending.manifest.Dependencies {
		m.log.Info(fmt.Sprintf("Fetching %s dependency %s...", pluginID, dep.ID))

		depOpts := plugins.NewAddOpts(opts.GrafanaVersion(), opts.OS(), opts.Arch(), "").
			WithPermissionsAuthorizer(opts.PermissionsAuthorizer())
		err = m.Add(ctx, dep.ID, "", depOpts)
		if err != nil {
			if _, ok := errors.AsType[plugins.DuplicateError](err); ok {
				m.log.Info("Dependency already installed", "pluginId", dep.ID)
				continue
			}
			pending.close(m.log)
			return fmt.Errorf("%v: %w", fmt.Sprintf("failed to download plugin %s from repository", dep.ID), err)
		}
	}

	archive, err := m.install(ctx, pluginID, version, pending)
	if err != nil {
		return err
	}

	_, err = m.pluginLoader.Load(ctx, sources.NewLocalSource(plugins.ClassExternal, []string{archive.Path}))
	if err != nil {
		m.log.Error("Could not load plugins", "path", archive.Path, "error", err)
		return err
	}

	return nil
}

// pendingInstall is a downloaded archive that has been authorized but not yet written to disk.
type pendingInstall struct {
	archive  *repo.PluginArchive
	manifest *storage.ArchiveManifest
	// existing is the installed version this archive replaces, if any.
	existing *plugins.Plugin
}

func (p *pendingInstall) close(logger log.Logger) {
	if err := p.archive.File.Close(); err != nil {
		logger.Warn("Failed to close plugin archive", "error", err)
	}
}

// fetch downloads the archive for pluginID and authorizes the permissions it requests. It changes
// nothing on disk and leaves any installed version in place.
func (m *PluginInstaller) fetch(ctx context.Context, pluginID, version string, opts plugins.AddOpts) (*pendingInstall, error) {
	var pluginArchive *repo.PluginArchive
	compatOpts, err := RepoCompatOpts(opts)
	if err != nil {
		return nil, err
	}
	plugin, exists := m.plugin(ctx, pluginID, version)
	if exists {
		if plugin.IsCorePlugin() {
			return nil, plugins.ErrInstallCorePlugin
		}

		if plugin.Info.Version == version {
			return nil, plugins.DuplicateError{
				PluginID: plugin.ID,
			}
		}
		if opts.URL() != "" {
			pluginArchive, err = m.updateFromURL(ctx, plugin, opts.URL(), compatOpts)
		} else {
			pluginArchive, err = m.updateFromCatalog(ctx, plugin, version, compatOpts)
		}
		if err != nil {
			return nil, err
		}
	} else {
		if opts.URL() != "" {
			pluginArchive, err = m.pluginRepo.GetPluginArchiveByURL(ctx, opts.URL(), compatOpts)
		} else {
			pluginArchive, err = m.pluginRepo.GetPluginArchive(ctx, pluginID, version, compatOpts)
		}
		if err != nil {
			return nil, err
		}
	}

	pending := &pendingInstall{archive: pluginArchive, existing: plugin}

	// The manifest is read from the same open archive that install extracts, so what is
	// authorized here is exactly what reaches the plugins directory.
	pending.manifest, err = storage.ReadArchiveManifest(pluginID, m.pluginStorageDirFunc, pluginArchive.File)
	if err != nil {
		pending.close(m.log)
		return nil, err
	}

	if authorize := opts.PermissionsAuthorizer(); authorize != nil {
		if err := authorize(ctx, pluginID, pending.manifest.Permissions); err != nil {
			pending.close(m.log)
			return nil, err
		}
	}

	return pending, nil
}

// install replaces any existing version of the plugin with the pending archive.
func (m *PluginInstaller) install(ctx context.Context, pluginID, version string, pending *pendingInstall) (*storage.ExtractedPluginArchive, error) {
	if pending.existing != nil {
		// remove existing installation of plugin
		if err := m.Remove(ctx, pending.existing.ID, pending.existing.Info.Version); err != nil {
			pending.close(m.log)
			return nil, err
		}
	} else {
		m.log.Info("Installing plugin", "pluginId", pluginID, "version", version)
	}

	extractedArchive, err := m.pluginStorage.Extract(ctx, pluginID, m.pluginStorageDirFunc, pending.archive.File)
	if err != nil {
		return nil, err
	}

	// Check that the extracted plugin archive has the expected ID and version
	// but avoid a hard error for backwards compatibility with older plugins
	// and because in the case of an update, the previous version has been already uninstalled
	if extractedArchive.ID != pluginID {
		m.log.Error("Installed plugin ID mismatch", "expected", pluginID, "got", extractedArchive.ID)
	}
	if version != "" && extractedArchive.Version != version {
		m.log.Error("Installed plugin version mismatch", "expected", version, "got", extractedArchive.Version)
	}

	return extractedArchive, nil
}

func (m *PluginInstaller) updateFromURL(ctx context.Context, plugin *plugins.Plugin, url string, compatOpts repo.CompatOpts) (*repo.PluginArchive, error) {
	m.log.Info("Updating plugin", "pluginId", plugin.ID, "from", plugin.Info.Version, "url", url)

	return m.pluginRepo.GetPluginArchiveByURL(ctx, url, compatOpts)
}

func (m *PluginInstaller) updateFromCatalog(ctx context.Context, plugin *plugins.Plugin, version string, compatOpts repo.CompatOpts) (*repo.PluginArchive, error) {
	// get plugin update information to confirm if target update is possible
	pluginArchiveInfo, err := m.pluginRepo.GetPluginArchiveInfo(ctx, plugin.ID, version, compatOpts)
	if err != nil {
		return nil, err
	}

	m.log.Info("Updating plugin", "pluginId", plugin.ID, "from", plugin.Info.Version, "to", pluginArchiveInfo.Version)

	// if existing plugin version is the same as the target update version
	if pluginArchiveInfo.Version == plugin.Info.Version {
		return nil, plugins.DuplicateError{
			PluginID: plugin.ID,
		}
	}

	if pluginArchiveInfo.URL == "" && pluginArchiveInfo.Version == "" {
		return nil, fmt.Errorf("could not determine update options for %s", plugin.ID)
	}

	if pluginArchiveInfo.URL != "" {
		return m.pluginRepo.GetPluginArchiveByURL(ctx, pluginArchiveInfo.URL, compatOpts)
	} else {
		return m.pluginRepo.GetPluginArchive(ctx, plugin.ID, pluginArchiveInfo.Version, compatOpts)
	}
}

func (m *PluginInstaller) Remove(ctx context.Context, pluginID, version string) error {
	plugin, exists := m.plugin(ctx, pluginID, version)
	if !exists {
		return plugins.ErrPluginNotInstalled
	}

	if plugin.IsCorePlugin() {
		return plugins.ErrUninstallCorePlugin
	}

	p, err := m.pluginLoader.Unload(ctx, plugin)
	if err != nil {
		return err
	}

	if remover, ok := p.FS.(plugins.FSRemover); ok {
		if err = remover.Remove(); err != nil {
			return err
		}
	}

	if err := m.rbacCleaner.CleanupPluginRBAC(ctx, pluginID); err != nil {
		m.log.Error("Failed to cleanup plugin RBAC. Stale RBAC data can be cleaned up on next startup by setting the cfg.RBAC.PluginsCleanup config option", "pluginId", pluginID, "error", err)
	}

	has, err := m.serviceRegistry.HasExternalService(ctx, pluginID)
	if err == nil && has {
		return m.serviceRegistry.RemoveExternalService(ctx, pluginID)
	}
	return err
}

// plugin finds a plugin with `pluginID` from the store
func (m *PluginInstaller) plugin(ctx context.Context, pluginID, pluginVersion string) (*plugins.Plugin, bool) {
	p, exists := m.pluginRegistry.Plugin(ctx, pluginID, pluginVersion)
	if !exists {
		return nil, false
	}

	return p, true
}

func RepoCompatOpts(opts plugins.AddOpts) (repo.CompatOpts, error) {
	os := opts.OS()
	arch := opts.Arch()
	if len(os) == 0 || len(arch) == 0 {
		return repo.CompatOpts{}, errors.New("invalid system compatibility options provided")
	}

	grafanaVersion := opts.GrafanaVersion()
	if len(grafanaVersion) == 0 {
		return repo.NewSystemCompatOpts(os, arch), nil
	}

	return repo.NewCompatOpts(grafanaVersion, os, arch), nil
}
