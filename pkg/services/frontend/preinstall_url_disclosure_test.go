package frontend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/hooks"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// Same placeholder download URLs as the API boot-data test. The userinfo is not a real credential.
const (
	frontendPreinstallID      = "preinstall-async-plugin"
	frontendPreinstallVersion = "9.8.7-preinstall"
	frontendPreinstallURL     = "https://placeholder-user:placeholder-secret@preinstall-registry.example/from-preinstall.zip"
)

// TestFrontendServiceOmitsPreinstallDownloadURL covers the frontend-service index
// page. With frontendService.reducedBootDataAPI enabled, that page embeds the
// same base frontend settings the API serves. The flag defaults to off; when it
// is off this page does not include pluginCatalogPreinstalledPlugins and the
// browser loads them from the API /bootdata route instead.
func TestFrontendServiceOmitsPreinstallDownloadURL(t *testing.T) {
	enableReducedBootDataToggle(t)

	publicDir := setupTestWebAssets(t)
	cfg := loadFrontendCfgWithPreinstallURL(t, publicDir)

	var promRegister prometheus.Registerer = prometheus.NewRegistry()
	service, err := ProvideFrontendService(
		cfg,
		featuremgmt.WithFeatures(),
		promRegister.(*prometheus.Registry),
		promRegister,
		&licensing.OSSLicensingService{Cfg: cfg},
		hooks.ProvideService(),
	)
	require.NoError(t, err)

	mux := web.New()
	service.addMiddlewares(mux)
	service.registerRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	body := rec.Body.String()
	require.Equal(t, http.StatusOK, rec.Code, body)

	boot := strings.Index(body, "window.grafanaBootData")
	require.NotEqual(t, -1, boot, body)
	const marker = "settings: "
	rel := strings.Index(body[boot:], marker)
	require.NotEqual(t, -1, rel, body)
	var settings struct {
		PluginCatalogPreinstalledPlugins []setting.InstallPlugin `json:"pluginCatalogPreinstalledPlugins"`
	}
	require.NoError(t, json.NewDecoder(strings.NewReader(body[boot+rel+len(marker):])).Decode(&settings))

	var matched *setting.InstallPlugin
	for i := range settings.PluginCatalogPreinstalledPlugins {
		plugin := &settings.PluginCatalogPreinstalledPlugins[i]
		if plugin.ID == frontendPreinstallID {
			matched = plugin
			break
		}
	}
	require.NotNil(t, matched, "preinstalled plugin id must still be sent to the browser")
	require.Equal(t, frontendPreinstallVersion, matched.Version)
	require.Empty(t, matched.URL)
	require.NotContains(t, body, "placeholder-secret")
	require.NotContains(t, body, "preinstall-registry.example")
}

func loadFrontendCfgWithPreinstallURL(t *testing.T, staticRoot string) *setting.Cfg {
	t.Helper()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "custom.ini")
	config := "" +
		"[plugins]\n" +
		"preinstall = " + frontendPreinstallID + "@" + frontendPreinstallVersion + "@" + frontendPreinstallURL + "\n"
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: filepath.Join("..", "..", ".."),
		Config:   configPath,
	}))
	cfg.Env = setting.Dev
	cfg.StaticRootPath = staticRoot
	cfg.HTTPPort = "3000"

	var stored string
	for _, plugin := range cfg.PreinstallPluginsAsync {
		if plugin.ID == frontendPreinstallID {
			stored = plugin.URL
		}
	}
	require.Equal(t, frontendPreinstallURL, stored, "server-side install config must keep the download URL")
	return cfg
}
