package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/auth"
	"github.com/grafana/grafana/pkg/plugins/backendplugin"
	"github.com/grafana/grafana/pkg/plugins/config"
	pluginslog "github.com/grafana/grafana/pkg/plugins/log"
	"github.com/grafana/grafana/pkg/plugins/manager"
	"github.com/grafana/grafana/pkg/plugins/manager/loader/angular/angularinspector"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/plugins/manager/process"
	"github.com/grafana/grafana/pkg/plugins/manager/registry"
	"github.com/grafana/grafana/pkg/plugins/manager/signature"
	"github.com/grafana/grafana/pkg/plugins/pluginassets"
	"github.com/grafana/grafana/pkg/plugins/pluginerrs"
	"github.com/grafana/grafana/pkg/plugins/pluginscdn"
	"github.com/grafana/grafana/pkg/plugins/repo"
	"github.com/grafana/grafana/pkg/plugins/storage"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/extsvcauth"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	loader "github.com/grafana/grafana/pkg/services/pluginsintegration/loader"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pipeline"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginchecker"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsso"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/provisionedplugins"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/serviceregistration"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

const (
	unheldUserAction       = accesscontrol.ActionUsersCreate
	unheldDataSourceAction = datasources.ActionCreate
)

// TestInstallPluginDoesNotGrantUnheldServiceAccountPermissions installs a catalog
// plugin whose plugin.json requests actions the installer does not hold. The
// catalog version document has no permission list; the list is in the archive.
func TestInstallPluginDoesNotGrantUnheldServiceAccountPermissions(t *testing.T) {
	t.Run("datasource in a multi-organization instance", func(t *testing.T) {
		assertInstallRejectsUnheldPermissions(t, installCase{
			pluginID:   "escalation-datasource",
			pluginType: string(plugins.TypeDataSource),
		})
	})

	t.Run("datasource in a single-organization instance", func(t *testing.T) {
		assertInstallRejectsUnheldPermissions(t, installCase{
			pluginID:   "escalation-datasource-single-org",
			pluginType: string(plugins.TypeDataSource),
			singleOrg:  true,
		})
	})

	t.Run("enabled app plugin", func(t *testing.T) {
		enabled := true
		assertInstallRejectsUnheldPermissions(t, installCase{
			pluginID:   "escalation-app",
			pluginType: string(plugins.TypeApp),
			appEnabled: &enabled,
		})
	})

	t.Run("app plugin that has no saved settings", func(t *testing.T) {
		assertInstallRejectsUnheldPermissions(t, installCase{
			pluginID:   "escalation-app-disabled",
			pluginType: string(plugins.TypeApp),
		})
	})
}

// TestInstallPluginUpdateDoesNotReplaceAPluginWithUnheldPermissions updates an
// already installed plugin to a version whose permission list adds actions the
// installer does not hold. The installed copy must stay on the original version.
func TestInstallPluginUpdateDoesNotReplaceAPluginWithUnheldPermissions(t *testing.T) {
	const pluginID = "escalation-datasource-update"
	env := newPluginInstallEnv(t, []string{pluginID}, nil)
	installer := installerPermissions(false)

	first := env.install(t, pluginID, "1.0.0", installer, false)
	require.Equalf(t, http.StatusOK, first.Status(), "installing a plugin that requests no extra actions failed: %s", first.Body())
	require.Empty(t, env.grants.actions())
	require.Empty(t, env.creds.pluginIDs())

	sawArchivePermissions := watchPluginJSON(t, env.pluginsDir, unheldUserAction)
	second := env.install(t, pluginID, "2.0.0", installer, false)
	fileContainedUnheldAction := sawArchivePermissions()

	require.GreaterOrEqualf(t, second.Status(), 400,
		"update status=%d grants=%v credentialed=%v archiveActionWritten=%v",
		second.Status(), env.grants.actions(), env.creds.pluginIDs(), fileContainedUnheldAction)
	require.NotContains(t, env.grants.actions(), unheldUserAction)
	require.NotContains(t, env.grants.actions(), unheldDataSourceAction)
	require.Empty(t, env.creds.pluginIDs())
	require.False(t, fileContainedUnheldAction, "plugin.json containing the unheld action was written before the update was refused")

	stored, exists := env.registry.Plugin(context.Background(), pluginID, "")
	require.True(t, exists, "the previously installed plugin was removed before the update was refused")
	require.Equal(t, "1.0.0", stored.Info.Version)
	require.Nil(t, stored.IAM)
}

// TestInstallPluginDependencyPermissionsAreAuthorizedSeparately installs a plugin
// that requests no actions and depends on a second plugin that requests actions
// the installer does not hold. Authorizing the parent must not grant the dependency.
func TestInstallPluginDependencyPermissionsAreAuthorizedSeparately(t *testing.T) {
	const (
		parentID = "escalation-parent"
		childID  = "escalation-child"
	)
	env := newPluginInstallEnv(t, []string{parentID, childID}, map[string][]string{
		parentID: {childID},
	})

	sawArchivePermissions := watchPluginJSON(t, env.pluginsDir, unheldUserAction)
	resp := env.install(t, parentID, "1.0.0", installerPermissions(false), false)
	fileContainedUnheldAction := sawArchivePermissions()

	require.GreaterOrEqualf(t, resp.Status(), 400,
		"install status=%d grants=%v credentialed=%v archiveActionWritten=%v",
		resp.Status(), env.grants.actions(), env.creds.pluginIDs(), fileContainedUnheldAction)
	require.NotContains(t, env.grants.actions(), unheldUserAction)
	require.NotContains(t, env.grants.actions(), unheldDataSourceAction)
	require.Empty(t, env.creds.pluginIDs())
	require.False(t, fileContainedUnheldAction, "plugin.json containing the unheld action was written before the install was refused")
	for _, id := range []string{parentID, childID} {
		_, err := os.Stat(filepath.Join(env.pluginsDir, id))
		require.ErrorIs(t, err, os.ErrNotExist, "plugin %s was left on disk", id)
		_, exists := env.registry.Plugin(context.Background(), id, "")
		require.Falsef(t, exists, "plugin %s stayed registered", id)
	}
}

type installCase struct {
	pluginID   string
	pluginType string
	singleOrg  bool
	appEnabled *bool
}

func assertInstallRejectsUnheldPermissions(t *testing.T, tc installCase) {
	t.Helper()

	var settings map[string]bool
	if tc.appEnabled != nil {
		settings = map[string]bool{tc.pluginID: *tc.appEnabled}
	}
	env := newPluginInstallEnv(t, []string{tc.pluginID}, nil)
	if len(settings) > 0 {
		env.enableApps(settings)
	}

	sawArchivePermissions := watchPluginJSON(t, env.pluginsDir, unheldUserAction)
	resp := env.install(t, tc.pluginID, "1.0.0", installerPermissions(tc.singleOrg), tc.singleOrg)
	fileContainedUnheldAction := sawArchivePermissions()

	_, registered := env.registry.Plugin(context.Background(), tc.pluginID, "")
	require.GreaterOrEqualf(t, resp.Status(), 400,
		"install status=%d grants=%v credentialed=%v archiveActionWritten=%v registered=%v",
		resp.Status(), env.grants.actions(), env.creds.pluginIDs(), fileContainedUnheldAction, registered)
	require.NotContains(t, env.grants.actions(), unheldUserAction)
	require.NotContains(t, env.grants.actions(), unheldDataSourceAction)
	require.Empty(t, env.creds.pluginIDs())
	require.False(t, fileContainedUnheldAction, "plugin.json containing the unheld action was written before the install was refused")
	require.False(t, registered, "plugin stayed registered after the install was refused")
	_, err := os.Stat(filepath.Join(env.pluginsDir, tc.pluginID))
	require.ErrorIs(t, err, os.ErrNotExist)
}

// installerPermissions is the plugins:install permission plus an unrelated
// users:read grant. It does not include the actions the plugin archive requests.
func installerPermissions(singleOrg bool) map[int64]map[string][]string {
	orgID := int64(accesscontrol.GlobalOrgID)
	if singleOrg {
		orgID = 1
	}
	return map[int64]map[string][]string{
		orgID: {
			"plugins:install":             {},
			accesscontrol.ActionUsersRead: {accesscontrol.ScopeUsersAll},
		},
	}
}

type pluginInstallEnv struct {
	t          *testing.T
	hs         *HTTPServer
	registry   registry.Service
	grants     *recordingExternalServiceRegistry
	creds      *pluginCredentialCapture
	pluginsDir string
	settings   *pluginsettings.FakePluginSettings
}

func newPluginInstallEnv(t *testing.T, pluginIDs []string, dependencies map[string][]string) *pluginInstallEnv {
	t.Helper()

	pluginsDir := t.TempDir()
	versions := archivesFor(t, pluginIDs, dependencies)

	catalog := httptest.NewServer(catalogHandler(versions))
	t.Cleanup(catalog.Close)

	features := featuremgmt.WithFeatures(featuremgmt.FlagExternalServiceAccounts)
	cfg := setting.NewCfg()
	cfg.ManagedServiceAccountsEnabled = true
	cfg.PluginAdminEnabled = true
	cfg.BuildVersion = "11.0.0"

	pCfg := &config.PluginManagementCfg{
		PluginsAllowUnsigned: pluginIDs,
		GrafanaComAPIURL:     catalog.URL,
		GrafanaAppURL:        "http://127.0.0.1:3000/",
		PluginsPaths:         []string{pluginsDir},
	}
	reg := registry.NewInMemory()
	grants := &recordingExternalServiceRegistry{}
	settings := &pluginsettings.FakePluginSettings{Plugins: map[string]*pluginsettings.DTO{}}
	svcReg := serviceregistration.ProvideService(cfg, features, grants, settings)
	creds := &pluginCredentialCapture{}
	proc := process.ProvideService()
	envVars := pluginconfig.NewEnvVarsProvider(&pluginconfig.PluginInstanceCfg{GrafanaAppURL: pCfg.GrafanaAppURL}, nil, stubSSOSettings{}, nil)

	initializer := pipeline.ProvideInitializationStage(
		pCfg,
		reg,
		creds,
		proc,
		svcReg,
		pluginfakes.NewFakeRoleRegistry(),
		pluginfakes.NewFakeActionSetRegistry(),
		envVars,
		tracing.InitializeTracerForTest(),
		provisionedplugins.NewNoop(),
	)
	termination, err := pipeline.ProvideTerminationStage(pCfg, reg, proc)
	require.NoError(t, err)
	pluginLoader := loader.ProvideService(
		pCfg,
		pipeline.ProvideDiscoveryStage(pCfg, reg),
		pipeline.ProvideBootstrapStage(pCfg, signature.DefaultCalculator(pCfg), pluginassets.NewLocalProvider(), pluginscdn.ProvideService(pCfg)),
		pipeline.ProvideValidationStage(pCfg, signature.NewValidator(signature.NewUnsignedAuthorizer(pCfg)), angularinspector.NewStaticInspector()),
		initializer,
		termination,
		pluginerrs.ProvideErrorTracker(),
	)
	pluginRepo, err := repo.ProvideService(pCfg)
	require.NoError(t, err)
	installer := manager.New(
		pCfg,
		reg,
		pluginLoader,
		pluginRepo,
		storage.FileSystem(pluginslog.NewPrettyLogger("test.installer"), pluginsDir),
		storage.SimpleDirNameGeneratorFunc,
		svcReg,
		&pluginfakes.FakeRBACCleaner{},
	)
	store, err := pluginstore.NewPluginStoreForTest(reg, pluginLoader, &pluginfakes.FakeSourceRegistry{})
	require.NoError(t, err)

	hs := &HTTPServer{
		Cfg:              cfg,
		Features:         features,
		log:              log.New("test.plugins"),
		pluginInstaller:  installer,
		pluginStore:      store,
		pluginPreinstall: pluginchecker.ProvidePreinstall(cfg),
		AccessControl:    acimpl.ProvideAccessControl(features),
		authnService:     &authntest.FakeService{},
	}

	return &pluginInstallEnv{
		t:          t,
		hs:         hs,
		registry:   reg,
		grants:     grants,
		creds:      creds,
		pluginsDir: pluginsDir,
		settings:   settings,
	}
}

func (e *pluginInstallEnv) enableApps(enabled map[string]bool) {
	for id, on := range enabled {
		e.settings.Plugins[id] = &pluginsettings.DTO{PluginID: id, Enabled: on, OrgID: 1}
	}
}

func (e *pluginInstallEnv) install(t *testing.T, pluginID, version string, permissions map[int64]map[string][]string, singleOrg bool) *responseStatus {
	t.Helper()
	e.hs.Cfg.RBAC.SingleOrganization = singleOrg
	e.hs.authnService = &authntest.FakeService{
		ExpectedIdentity: &authn.Identity{ID: "user:1", Permissions: permissions},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/"+pluginID+"/install", strings.NewReader(`{"version":"`+version+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req = web.SetURLParams(req, map[string]string{":pluginId": pluginID})
	resp := e.hs.InstallPlugin(&contextmodel.ReqContext{
		Context:      &web.Context{Req: req},
		SignedInUser: &user.SignedInUser{UserID: 1, OrgID: orgIDFrom(permissions), Permissions: permissions},
		Logger:       log.New("test.request"),
	})
	return &responseStatus{status: resp.Status(), body: resp.Body()}
}

type responseStatus struct {
	status int
	body   []byte
}

func (r *responseStatus) Status() int  { return r.status }
func (r *responseStatus) Body() []byte { return r.body }

func orgIDFrom(permissions map[int64]map[string][]string) int64 {
	for orgID := range permissions {
		return orgID
	}
	return 0
}

func archivesFor(t *testing.T, pluginIDs []string, dependencies map[string][]string) map[string]map[string][]byte {
	t.Helper()
	out := make(map[string]map[string][]byte, len(pluginIDs))
	for _, id := range pluginIDs {
		out[id] = map[string][]byte{}
		switch {
		case strings.Contains(id, "update"):
			out[id]["1.0.0"] = pluginArchive(t, id, "1.0.0", string(plugins.TypeDataSource), nil, nil)
			out[id]["2.0.0"] = pluginArchive(t, id, "2.0.0", string(plugins.TypeDataSource), unheldPermissions(), nil)
		case len(dependencies[id]) > 0:
			out[id]["1.0.0"] = pluginArchive(t, id, "1.0.0", string(plugins.TypeDataSource), nil, dependencies[id])
		default:
			out[id]["1.0.0"] = pluginArchive(t, id, "1.0.0", pluginTypeFor(id), unheldPermissions(), nil)
		}
	}
	return out
}

func pluginTypeFor(id string) string {
	if strings.Contains(id, "app") {
		return string(plugins.TypeApp)
	}
	return string(plugins.TypeDataSource)
}

func unheldPermissions() []auth.Permission {
	return []auth.Permission{
		{Action: unheldUserAction},
		{Action: unheldDataSourceAction},
	}
}

func pluginArchive(t *testing.T, id, version, pluginType string, perms []auth.Permission, dependencyIDs []string) []byte {
	t.Helper()
	manifest := map[string]any{
		"id":      id,
		"type":    pluginType,
		"name":    id,
		"backend": true,
		"info": map[string]any{
			"version": version,
		},
	}
	if len(dependencyIDs) > 0 {
		deps := make([]map[string]string, 0, len(dependencyIDs))
		for _, dep := range dependencyIDs {
			deps = append(deps, map[string]string{"id": dep, "type": string(plugins.TypeDataSource), "name": dep})
		}
		manifest["dependencies"] = map[string]any{"plugins": deps}
	}
	if len(perms) > 0 {
		encoded := make([]map[string]string, 0, len(perms))
		for _, perm := range perms {
			encoded = append(encoded, map[string]string{"action": perm.Action, "scope": perm.Scope})
		}
		manifest["iam"] = map[string]any{"permissions": encoded}
	}
	raw, err := json.Marshal(manifest)
	require.NoError(t, err)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	writeZipFile(t, zw, id+"/plugin.json", raw)
	writeZipFile(t, zw, id+"/module.js", []byte("export const plugin = {};\n"))
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func writeZipFile(t *testing.T, zw *zip.Writer, name string, content []byte) {
	t.Helper()
	w, err := zw.Create(name)
	require.NoError(t, err)
	_, err = w.Write(content)
	require.NoError(t, err)
}

func catalogHandler(versions map[string]map[string][]byte) http.Handler {
	arch := runtime.GOOS + "-" + runtime.GOARCH
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		// /plugins/{id}/versions[/{version}[/download]]
		if len(parts) < 3 || parts[0] != "plugins" || parts[2] != "versions" {
			http.NotFound(w, r)
			return
		}
		id := parts[1]
		pluginVersions, ok := versions[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if len(parts) == 3 {
			items := make([]map[string]any, 0, len(pluginVersions))
			for version, archive := range pluginVersions {
				items = append(items, versionDocument(version, arch, archive))
			}
			writeJSON(w, map[string]any{"items": items})
			return
		}
		version := parts[3]
		archive, ok := pluginVersions[version]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if len(parts) == 5 && parts[4] == "download" {
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(archive)
			return
		}
		writeJSON(w, versionDocument(version, arch, archive))
	})
}

func versionDocument(version, arch string, archive []byte) map[string]any {
	sum := sha256.Sum256(archive)
	return map[string]any{
		"version":      version,
		"status":       "active",
		"isCompatible": true,
		"packages": map[string]any{
			arch: map[string]string{"sha256": hex.EncodeToString(sum[:])},
		},
	}
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// recordingExternalServiceRegistry records the permission actions SaveExternalService
// is asked to persist. SaveExternalService stores those actions on a service account
// and returns a credential; this recorder keeps the actions and returns a placeholder
// credential without storing one.
type recordingExternalServiceRegistry struct {
	mu      sync.Mutex
	history []recordedGrant
}

type recordedGrant struct {
	name    string
	actions []string
}

func (r *recordingExternalServiceRegistry) HasExternalService(_ context.Context, name string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, grant := range r.history {
		if grant.name == name {
			return true, nil
		}
	}
	return false, nil
}

func (r *recordingExternalServiceRegistry) GetExternalServiceNames(_ context.Context) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.history))
	for _, grant := range r.history {
		names = append(names, grant.name)
	}
	return names, nil
}

func (r *recordingExternalServiceRegistry) RemoveExternalService(context.Context, string) error {
	// Grants stay in history so a registration that is rolled back after the fact still fails the test.
	return nil
}

func (r *recordingExternalServiceRegistry) SaveExternalService(_ context.Context, cmd *extsvcauth.ExternalServiceRegistration) (*extsvcauth.ExternalService, error) {
	if cmd == nil || len(cmd.Self.Permissions) == 0 {
		return nil, nil
	}
	actions := make([]string, 0, len(cmd.Self.Permissions))
	for _, perm := range cmd.Self.Permissions {
		actions = append(actions, perm.Action)
	}
	r.mu.Lock()
	r.history = append(r.history, recordedGrant{name: cmd.Name, actions: actions})
	r.mu.Unlock()
	return &extsvcauth.ExternalService{
		Name:   cmd.Name,
		ID:     cmd.Name,
		Secret: "placeholder-not-a-credential",
	}, nil
}

func (r *recordingExternalServiceRegistry) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var actions []string
	for _, grant := range r.history {
		actions = append(actions, grant.actions...)
	}
	return actions
}

// pluginCredentialCapture records whether the backend process environment contained
// a plugin service-account credential. The credential value is not retained.
type pluginCredentialCapture struct {
	mu      sync.Mutex
	seen    map[string]bool
	clients map[string]*recordingBackend
}

func (c *pluginCredentialCapture) BackendFactory(_ context.Context, p *plugins.Plugin) backendplugin.PluginFactoryFunc {
	return func(pluginID string, logger pluginslog.Logger, _ trace.Tracer, env func() []string) (backendplugin.Plugin, error) {
		client := &recordingBackend{
			FakePluginClient: pluginfakes.FakePluginClient{ID: pluginID, Managed: true, Log: logger},
			onStart: func() {
				if envContainsCredential(env()) {
					c.mu.Lock()
					if c.seen == nil {
						c.seen = map[string]bool{}
					}
					c.seen[pluginID] = true
					c.mu.Unlock()
				}
			},
		}
		c.mu.Lock()
		if c.clients == nil {
			c.clients = map[string]*recordingBackend{}
		}
		c.clients[pluginID] = client
		c.mu.Unlock()
		return client, nil
	}
}

func (c *pluginCredentialCapture) pluginIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := make([]string, 0, len(c.seen))
	for id := range c.seen {
		ids = append(ids, id)
	}
	return ids
}

func envContainsCredential(env []string) bool {
	const key = "GF_PLUGIN_APP_CLIENT_SECRET"
	for _, entry := range env {
		name, value, ok := strings.Cut(entry, "=")
		if ok && name == key && value != "" {
			return true
		}
	}
	return false
}

type recordingBackend struct {
	pluginfakes.FakePluginClient
	onStart func()
}

func (b *recordingBackend) Start(ctx context.Context) error {
	if b.onStart != nil {
		b.onStart()
	}
	return b.FakePluginClient.Start(ctx)
}

type stubSSOSettings struct{}

func (stubSSOSettings) GetForProvider(context.Context, string) (*pluginsso.Settings, error) {
	return &pluginsso.Settings{Values: map[string]any{}}, nil
}

func watchPluginJSON(t *testing.T, dir, action string) func() bool {
	t.Helper()
	needle := []byte(`"` + action + `"`)
	var seen syncBool
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			time.Sleep(time.Millisecond)
			_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() || d.Name() != "plugin.json" {
					return nil
				}
				contents, readErr := os.ReadFile(path)
				if readErr == nil && bytes.Contains(contents, needle) {
					seen.store(true)
				}
				return nil
			})
		}
	}()
	return func() bool {
		close(stop)
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || d.Name() != "plugin.json" {
				return nil
			}
			contents, readErr := os.ReadFile(path)
			if readErr == nil && bytes.Contains(contents, needle) {
				seen.store(true)
			}
			return nil
		})
		return seen.load()
	}
}

type syncBool struct {
	mu    sync.Mutex
	value bool
}

func (b *syncBool) store(v bool) {
	b.mu.Lock()
	b.value = v
	b.mu.Unlock()
}

func (b *syncBool) load() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.value
}
