package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	preferences "github.com/grafana/grafana/apps/preferences/pkg/apis/preferences/v1"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/socialtest"
	"github.com/grafana/grafana/pkg/middleware"
	accesscontrolmock "github.com/grafana/grafana/pkg/services/accesscontrol/mock"
	"github.com/grafana/grafana/pkg/services/apiserver/endpoints/request"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/dashboards"
	datafakes "github.com/grafana/grafana/pkg/services/datasources/fakes"
	"github.com/grafana/grafana/pkg/services/datasources/guardian"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/hooks"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/managedplugins"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/preference/prefapi"
	"github.com/grafana/grafana/pkg/services/publicdashboards"
	"github.com/grafana/grafana/pkg/services/rendering"
	"github.com/grafana/grafana/pkg/services/updatemanager"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// Placeholder download URLs. The userinfo is not a real credential.
const (
	preinstallAsyncID      = "preinstall-async-plugin"
	preinstallAsyncVersion = "9.8.7-preinstall"
	preinstallAsyncURL     = "https://placeholder-user:placeholder-secret@preinstall-registry.example/from-preinstall.zip"

	preinstallSyncID      = "preinstall-sync-plugin"
	preinstallSyncVersion = "9.8.7-sync"
	preinstallSyncURL     = "https://placeholder-user:placeholder-secret@preinstall-registry.example/from-preinstall-sync.zip"

	installPluginsID      = "install-plugins-plugin"
	installPluginsVersion = "9.8.7-legacy"
	installPluginsURL     = "https://placeholder-user:placeholder-secret@preinstall-registry.example/from-install-plugins.zip"
)

// TestPreinstalledPluginDownloadURLIsOmittedFromPublicBootData loads the three
// documented preinstall inputs and requests the unauthenticated pages that embed
// frontend settings. The download URL must stay on the server. The browser only
// needs the plugin id and version.
func TestPreinstalledPluginDownloadURLIsOmittedFromPublicBootData(t *testing.T) {
	cfg := loadCfgWithPreinstallDownloadURLs(t)
	requireServerKeepsDownloadURLs(t, cfg)

	hs := newPublicBootDataServer(t, cfg)
	viewsPath, err := filepath.Abs("../../public/views")
	require.NoError(t, err)

	mux := web.New()
	mux.Use(getContextHandler(t, cfg).Middleware)
	mux.UseMiddleware(web.Renderer(viewsPath, "[[", "]]"))
	// Same registration as pkg/api/api.go: login and several other HTML pages have
	// no auth middleware, /bootdata uses NoAuth, and /api/frontend/settings has none.
	mux.Get("/login", hs.LoginView)
	mux.Get("/signup", hs.Index)
	mux.Get("/bootdata", middleware.NoAuth(), hs.GetBootdata)
	mux.Get("/api/frontend/settings/", hs.GetFrontendSettings)

	cases := []struct {
		name string
		path string
	}{
		{name: "login page", path: "/login"},
		{name: "signup page", path: "/signup"},
		{name: "bootdata", path: "/bootdata"},
		{name: "frontend settings", path: "/api/frontend/settings/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			body := rec.Body.String()
			require.Equalf(t, http.StatusOK, rec.Code, "unauthenticated %s body: %s", tc.path, body)
			// /api/frontend/settings returns the settings object alone, with no user.
			// The HTML pages and /bootdata include the anonymous user.
			if tc.path != "/api/frontend/settings/" {
				require.Truef(t, strings.Contains(body, `"isSignedIn":false`) || strings.Contains(body, `"isSignedIn": false`),
					"response must be for an anonymous visitor, body: %s", body)
			}
			assertPublicBodyOmitsDownloadURLs(t, body)
		})
	}
}

func loadCfgWithPreinstallDownloadURLs(t *testing.T) *setting.Cfg {
	t.Helper()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "custom.ini")
	config := "" +
		"[plugins]\n" +
		"preinstall = " + preinstallAsyncID + "@" + preinstallAsyncVersion + "@" + preinstallAsyncURL + "\n" +
		"preinstall_sync = " + preinstallSyncID + "@" + preinstallSyncVersion + "@" + preinstallSyncURL + "\n"
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))

	// Legacy installer env. Read directly by readPluginSettings, not as GF_PLUGINS_*.
	t.Setenv("GF_INSTALL_PLUGINS", installPluginsURL+";"+installPluginsID+" "+installPluginsVersion)

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: filepath.Join("..", ".."),
		Config:   configPath,
	}))
	// Dev skips the webassets cache so this test reads the fixture manifest.
	cfg.Env = setting.Dev
	cfg.StaticRootPath = filepath.Join("webassets", "testdata")
	return cfg
}

func requireServerKeepsDownloadURLs(t *testing.T, cfg *setting.Cfg) {
	t.Helper()

	found := map[string]setting.InstallPlugin{}
	for _, plugin := range append(cfg.PreinstallPluginsAsync, cfg.PreinstallPluginsSync...) {
		found[plugin.ID] = plugin
	}
	require.Equal(t, preinstallAsyncURL, found[preinstallAsyncID].URL)
	require.Equal(t, preinstallAsyncVersion, found[preinstallAsyncID].Version)
	require.Equal(t, preinstallSyncURL, found[preinstallSyncID].URL)
	require.Equal(t, preinstallSyncVersion, found[preinstallSyncID].Version)
	require.Equal(t, installPluginsURL, found[installPluginsID].URL)
	require.Equal(t, installPluginsVersion, found[installPluginsID].Version)
}

func newPublicBootDataServer(t *testing.T, cfg *setting.Cfg) *HTTPServer {
	t.Helper()

	features := featuremgmt.WithFeatures()
	cfg.IsFeatureToggleEnabled = features.IsEnabledGlobally

	prefClient := prefapi.NewMockK8sClient(t)
	prefClient.EXPECT().GetMerged(mock.Anything).Return(&preferences.PreferencesSpec{}, nil).Maybe()

	_, htmlHandlerRequestsDuration := setupHTMLHandlerMetrics()

	return &HTTPServer{
		log:                     log.New("preinstall-url-test"),
		Cfg:                     cfg,
		Features:                features,
		License:                 &licensing.OSSLicensingService{Cfg: cfg},
		RenderService:           &rendering.RenderingService{Cfg: cfg},
		pluginStore:             &pluginstore.FakePluginStore{},
		PluginSettings:          &pluginsettings.FakePluginSettings{},
		managedPluginsService:   managedplugins.NewNoop(),
		tracer:                  tracing.InitializeTracerForTest(),
		DataSourcesService:      &datafakes.FakeDataSourceService{},
		dsGuardian:              guardian.ProvideGuardian(),
		publicDashboardsService: &publicdashboards.FakePublicDashboardService{},
		grafanaUpdateChecker:    &updatemanager.GrafanaService{},
		AccessControl:           accesscontrolmock.New(),
		accesscontrolService:    accesscontrolmock.New(),
		authnService:            &authntest.FakeService{EnabledClients: []string{}},
		SocialService: &socialtest.FakeSocialService{
			GetOAuthInfoProvidersFunc: func(context.Context) (map[string]*social.OAuthInfo, error) {
				return map[string]*social.OAuthInfo{}, nil
			},
		},
		namespacer:                  request.GetNamespaceMapper(cfg),
		navTreeService:              &fakeNavTreeService{},
		preferenceK8sHandler:        prefapi.NewK8sHandler(prefClient, dashboards.NewFakeDashboardService(t), preferences.PreferencesSpec{}),
		HooksService:                hooks.ProvideService(),
		htmlHandlerRequestsDuration: htmlHandlerRequestsDuration,
	}
}

func assertPublicBodyOmitsDownloadURLs(t *testing.T, body string) {
	t.Helper()

	plugins := preinstalledPluginsFromBody(t, body)
	require.NotEmpty(t, plugins)
	byID := map[string]setting.InstallPlugin{}
	for _, plugin := range plugins {
		byID[plugin.ID] = plugin
	}
	for _, plugin := range []setting.InstallPlugin{
		{ID: preinstallAsyncID, Version: preinstallAsyncVersion},
		{ID: preinstallSyncID, Version: preinstallSyncVersion},
		{ID: installPluginsID, Version: installPluginsVersion},
	} {
		got, ok := byID[plugin.ID]
		require.Truef(t, ok, "missing %s in pluginCatalogPreinstalledPlugins", plugin.ID)
		require.Equal(t, plugin.Version, got.Version)
		require.Emptyf(t, got.URL, "download URL for %s was sent to the browser", plugin.ID)
	}

	require.NotContains(t, body, "placeholder-secret")
	require.NotContains(t, body, "preinstall-registry.example")
	require.NotContains(t, body, "from-preinstall.zip")
	require.NotContains(t, body, "from-preinstall-sync.zip")
	require.NotContains(t, body, "from-install-plugins.zip")
}

func preinstalledPluginsFromBody(t *testing.T, body string) []setting.InstallPlugin {
	t.Helper()

	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") {
		var payload struct {
			Settings struct {
				PluginCatalogPreinstalledPlugins []setting.InstallPlugin `json:"pluginCatalogPreinstalledPlugins"`
			} `json:"settings"`
			PluginCatalogPreinstalledPlugins []setting.InstallPlugin `json:"pluginCatalogPreinstalledPlugins"`
		}
		require.NoError(t, json.Unmarshal([]byte(trimmed), &payload))
		if payload.Settings.PluginCatalogPreinstalledPlugins != nil {
			return payload.Settings.PluginCatalogPreinstalledPlugins
		}
		return payload.PluginCatalogPreinstalledPlugins
	}

	// index.html assigns boot data with unquoted keys. The settings value itself is JSON.
	boot := strings.Index(body, "window.grafanaBootData")
	require.NotEqualf(t, -1, boot, "login HTML did not embed boot data")
	const marker = "settings: "
	rel := strings.Index(body[boot:], marker)
	require.NotEqualf(t, -1, rel, "boot data did not include settings")
	var settings struct {
		PluginCatalogPreinstalledPlugins []setting.InstallPlugin `json:"pluginCatalogPreinstalledPlugins"`
	}
	require.NoError(t, json.NewDecoder(strings.NewReader(body[boot+rel+len(marker):])).Decode(&settings))
	return settings.PluginCatalogPreinstalledPlugins
}
