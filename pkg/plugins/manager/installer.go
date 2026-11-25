package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
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

	archive, err := m.install(ctx, pluginID, version, opts)
	if err != nil {
		return err
	}

	for _, dep := range archive.Dependencies {
		m.log.Info(fmt.Sprintf("Fetching %s dependency %s...", pluginID, dep.ID))

		err = m.Add(ctx, dep.ID, "", plugins.NewAddOpts(opts.GrafanaVersion(), opts.OS(), opts.Arch(), ""))
		if err != nil {
			if _, ok := errors.AsType[plugins.DuplicateError](err); ok {
				m.log.Info("Dependency already installed", "pluginId", dep.ID)
				continue
			}
			return fmt.Errorf("%v: %w", fmt.Sprintf("failed to download plugin %s from repository", dep.ID), err)
		}
	}

	_, err = m.pluginLoader.Load(ctx, sources.NewLocalSource(plugins.ClassExternal, []string{archive.Path}))
	if err != nil {
		m.log.Error("Could not load plugins", "path", archive.Path, "error", err)
		return err
	}

	return nil
}

func (m *PluginInstaller) install(ctx context.Context, pluginID, version string, opts plugins.AddOpts) (*storage.ExtractedPluginArchive, error) {
	compatOpts, err := RepoCompatOpts(opts)
	if err != nil {
		return nil, err
	}

	installed, exists := m.plugin(ctx, pluginID, version)
	if exists {
		if installed.IsCorePlugin() {
			return nil, plugins.ErrInstallCorePlugin
		}

		if installed.Info.Version == version {
			return nil, plugins.DuplicateError{
				PluginID: installed.ID,
			}
		}
	}

	var pluginArchive *repo.PluginArchive
	fromCatalog := opts.URL() == ""
	catalogVersion := ""
	if fromCatalog {
		pluginArchive, catalogVersion, err = m.catalogArchive(ctx, pluginID, version, installed, compatOpts)
	} else {
		if exists {
			m.log.Info("Updating plugin", "pluginId", installed.ID, "from", installed.Info.Version, "url", opts.URL())
		}
		pluginArchive, err = m.pluginRepo.GetPluginArchiveByURL(ctx, opts.URL(), compatOpts)
	}
	if err != nil {
		return nil, err
	}

	if exists {
		// The installed plugin is only removed once the replacement is known to be the one requested,
		// so a rejected archive leaves it in place.
		if fromCatalog {
			pluginJSON, err := storage.ArchivePluginJSON(pluginArchive.File, pluginID, m.pluginStorageDirFunc)
			if err == nil {
				err = checkCatalogArchive(pluginID, catalogVersion, pluginJSON.ID, pluginJSON.Info.Version)
			}
			if err != nil {
				closeArchive(pluginArchive)
				return nil, err
			}
		}

		if err = m.Remove(ctx, installed.ID, installed.Info.Version); err != nil {
			closeArchive(pluginArchive)
			return nil, err
		}
	} else {
		m.log.Info("Installing plugin", "pluginId", pluginID, "version", version)
	}

	extractedArchive, err := m.pluginStorage.Extract(ctx, pluginID, m.pluginStorageDirFunc, pluginArchive.File)
	if err != nil {
		return nil, err
	}

	if fromCatalog {
		// Extract reads the manifest back from disk, which is what the loader will see.
		if err = checkCatalogArchive(pluginID, catalogVersion, extractedArchive.ID, extractedArchive.Version); err != nil {
			if rmErr := os.RemoveAll(extractedArchive.Path); rmErr != nil {
				m.log.Error("Failed to remove rejected plugin archive", "path", extractedArchive.Path, "error", rmErr)
			}
			return nil, err
		}
		return extractedArchive, nil
	}

	// An archive from an admin-supplied URL has no catalog record to hold it to, so a mismatch is
	// only logged for backwards compatibility with older plugins.
	if extractedArchive.ID != pluginID {
		m.log.Error("Installed plugin ID mismatch", "expected", pluginID, "got", extractedArchive.ID)
	}
	if version != "" && extractedArchive.Version != version {
		m.log.Error("Installed plugin version mismatch", "expected", version, "got", extractedArchive.Version)
	}

	return extractedArchive, nil
}

// catalogArchive downloads the archive named by the catalog record for pluginID and verifies it against
// that same record's checksum. It returns the archive along with the version the record names.
func (m *PluginInstaller) catalogArchive(ctx context.Context, pluginID, version string, installed *plugins.Plugin, compatOpts repo.CompatOpts) (*repo.PluginArchive, string, error) {
	info, err := m.pluginRepo.GetPluginArchiveInfo(ctx, pluginID, version, compatOpts)
	if err != nil {
		return nil, "", err
	}

	if installed != nil {
		m.log.Info("Updating plugin", "pluginId", installed.ID, "from", installed.Info.Version, "to", info.Version)

		if info.Version == installed.Info.Version {
			return nil, "", plugins.DuplicateError{
				PluginID: installed.ID,
			}
		}

		if info.URL == "" && info.Version == "" {
			return nil, "", fmt.Errorf("could not determine update options for %s", installed.ID)
		}
	}

	archive, err := m.pluginRepo.GetPluginArchiveByInfo(ctx, pluginID, info, compatOpts)
	if err != nil {
		return nil, "", err
	}

	return archive, info.Version, nil
}

func checkCatalogArchive(pluginID, catalogVersion, archiveID, archiveVersion string) error {
	if archiveID != pluginID {
		return fmt.Errorf("plugin archive for %s contains plugin %q", pluginID, archiveID)
	}
	if archiveVersion != catalogVersion {
		return fmt.Errorf("plugin archive for %s v%s contains version %q", pluginID, catalogVersion, archiveVersion)
	}
	return nil
}

func closeArchive(archive *repo.PluginArchive) {
	if archive != nil && archive.File != nil {
		_ = archive.File.Close()
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
