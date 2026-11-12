package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/metrics"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// Placeholders for the metrics basic-auth settings under test. They are not
// credentials from any deployment.
const (
	metricsAuthUserPlaceholder = "metrics-user"
	metricsAuthPassPlaceholder = "metrics-password"
)

const (
	metricsCanaryName     = "metrics_endpoint_authz_canary_total"
	pluginMetricsCanary   = "plugin_backend_scrape_canary"
	pluginMetricsCanaryID = "canary-plugin"
	metricsBuildInfoName  = "grafana_build_info"
	metricsUsersName      = "grafana_stat_total_users"
	metricsDashboardsName = "grafana_stat_totals_dashboard"
	metricsAlertRulesName = "grafana_stat_totals_alert_rules"
	metricsActiveAlerts   = "grafana_alerting_active_alerts"
)

// TestMetricsEndpointsRequireAuthentication locks the behavior of the metrics
// scrape routes. With the shipped [metrics] settings, or with the endpoint
// enabled while either basic-auth setting is empty, an unauthenticated GET must
// not receive gatherer or plugin metric text, and the plugin client must not be
// called. These assertions fail until that refusal is implemented.
func TestMetricsEndpointsRequireAuthentication(t *testing.T) {
	scrapes := []string{"/metrics", "/metrics?name=extra"}
	pluginScrapes := []string{
		"/metrics/plugins/" + pluginMetricsCanaryID,
		"/metrics/plugins/" + pluginMetricsCanaryID + "?extra=1",
	}

	t.Run("shipped defaults.ini", func(t *testing.T) {
		cfg := loadShippedConfig(t)
		t.Logf("shipped metrics enabled=%v basic_auth_username_set=%v basic_auth_password_set=%v",
			cfg.MetricsEndpointEnabled,
			cfg.MetricsEndpointBasicAuthUsername != "",
			cfg.MetricsEndpointBasicAuthPassword != "",
		)
		assertScrapesClosed(t, cfg, append(append([]string{}, scrapes...), pluginScrapes...))
	})

	t.Run("enabled and both basic-auth settings empty", func(t *testing.T) {
		assertScrapesClosed(t, metricsCfg(true, "", ""), append(append([]string{}, scrapes...), pluginScrapes...))
	})

	t.Run("enabled and only username set", func(t *testing.T) {
		cfg := metricsCfg(true, metricsAuthUserPlaceholder, "")
		assertScrapesClosed(t, cfg, append(append([]string{}, scrapes...), pluginScrapes...))
		assertScrapesClosedWithHeaders(t, cfg, pluginScrapes, basicAuthHeader(metricsAuthUserPlaceholder, metricsAuthPassPlaceholder))
	})

	t.Run("enabled and only password set", func(t *testing.T) {
		cfg := metricsCfg(true, "", metricsAuthPassPlaceholder)
		assertScrapesClosed(t, cfg, append(append([]string{}, scrapes...), pluginScrapes...))
		assertScrapesClosedWithHeaders(t, cfg, scrapes, basicAuthHeader(metricsAuthUserPlaceholder, metricsAuthPassPlaceholder))
	})

	t.Run("subpath trims to the same routes", func(t *testing.T) {
		cfg := metricsCfg(true, "", "")
		cfg.ServeFromSubPath = true
		cfg.AppSubURL = "/grafana"
		assertScrapesClosed(t, cfg, []string{
			"/grafana/metrics",
			"/grafana/metrics/plugins/" + pluginMetricsCanaryID,
		})
	})

	t.Run("unrelated authorization header is not accepted", func(t *testing.T) {
		cfg := metricsCfg(true, "", "")
		header := http.Header{}
		header.Set("Authorization", "Bearer placeholder-token")
		header.Add("Cookie", "grafana_session=placeholder-session")
		assertScrapesClosedWithHeaders(t, cfg, append(append([]string{}, scrapes...), pluginScrapes...), header)
	})

	t.Run("disabled endpoint stays closed", func(t *testing.T) {
		assertScrapesClosed(t, metricsCfg(false, "", ""), append(append([]string{}, scrapes...), pluginScrapes...))
	})

	t.Run("both basic-auth settings set", func(t *testing.T) {
		cfg := metricsCfg(true, metricsAuthUserPlaceholder, metricsAuthPassPlaceholder)
		assertScrapesClosed(t, cfg, append(append([]string{}, scrapes...), pluginScrapes...))
		assertScrapesClosedWithHeaders(t, cfg, append(append([]string{}, scrapes...), pluginScrapes...), basicAuthHeader(metricsAuthUserPlaceholder, "wrong-password"))

		status, body, calls := scrape(t, cfg, "/metrics", basicAuthHeader(metricsAuthUserPlaceholder, metricsAuthPassPlaceholder))
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, metricsCanaryName)
		require.Contains(t, body, metricsBuildInfoName)
		require.Empty(t, calls)

		status, body, calls = scrape(t, cfg, "/metrics/plugins/"+pluginMetricsCanaryID, basicAuthHeader(metricsAuthUserPlaceholder, metricsAuthPassPlaceholder))
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, pluginMetricsCanary)
		require.Contains(t, body, pluginMetricsCanaryID)
		require.Equal(t, []string{pluginMetricsCanaryID}, calls)
	})
}

func loadShippedConfig(t *testing.T) *setting.Cfg {
	t.Helper()
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "GF_METRICS") {
			t.Setenv(name, "")
		}
	}
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	cfg, err := setting.NewCfgFromArgs(setting.CommandLineArgs{HomePath: root})
	require.NoError(t, err)
	return cfg
}

func metricsCfg(enabled bool, username, password string) *setting.Cfg {
	return &setting.Cfg{
		MetricsEndpointEnabled:           enabled,
		MetricsEndpointBasicAuthUsername: username,
		MetricsEndpointBasicAuthPassword: password,
	}
}

func basicAuthHeader(username, password string) http.Header {
	req, err := http.NewRequest(http.MethodGet, "http://metrics.invalid/", nil)
	if err != nil {
		panic(err)
	}
	req.SetBasicAuth(username, password)
	header := http.Header{}
	header.Set("Authorization", req.Header.Get("Authorization"))
	return header
}

func assertScrapesClosed(t *testing.T, cfg *setting.Cfg, paths []string) {
	t.Helper()
	assertScrapesClosedWithHeaders(t, cfg, paths, nil)
}

func assertScrapesClosedWithHeaders(t *testing.T, cfg *setting.Cfg, paths []string, header http.Header) {
	t.Helper()
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			status, body, calls := scrape(t, cfg, path, header)
			for _, marker := range []string{
				metricsCanaryName,
				metricsBuildInfoName,
				metricsUsersName,
				metricsDashboardsName,
				metricsAlertRulesName,
				metricsActiveAlerts,
				pluginMetricsCanary,
			} {
				if strings.Contains(body, marker) {
					t.Fatalf("GET %s status %d leaked %q\n%s", path, status, marker, body)
				}
			}
			if status == http.StatusOK {
				t.Fatalf("GET %s returned 200 without refusing the scrape\n%s", path, body)
			}
			require.Empty(t, calls, "plugin metrics were collected before the request was refused")
		})
	}
}

func scrape(t *testing.T, cfg *setting.Cfg, path string, header http.Header) (int, string, []string) {
	t.Helper()
	reg := prometheus.NewRegistry()
	metrics.SetBuildInformation(reg, "test-version", "test-revision", "test-branch", 1)
	for _, opts := range []prometheus.GaugeOpts{
		{Namespace: metrics.ExporterName, Name: "stat_total_users", Help: "total amount of users"},
		{Namespace: metrics.ExporterName, Name: "stat_totals_dashboard", Help: "total amount of dashboards"},
		{Namespace: metrics.ExporterName, Name: "stat_totals_alert_rules", Help: "total amount of alert rules"},
		{Namespace: metrics.ExporterName, Name: "alerting_active_alerts", Help: "amount of active alerts"},
	} {
		gauge := prometheus.NewGauge(opts)
		reg.MustRegister(gauge)
		gauge.Set(1)
	}
	canary := prometheus.NewCounter(prometheus.CounterOpts{
		Name: metricsCanaryName,
		Help: "scrape canary",
	})
	reg.MustRegister(canary)
	canary.Inc()

	pluginClient := &recordingPluginMetrics{
		body: []byte(pluginMetricsCanary + "{plugin_id=\"" + pluginMetricsCanaryID + "\"} 1\n"),
	}
	hs := &HTTPServer{
		Cfg:          cfg,
		promGatherer: reg,
		pluginClient: pluginClient,
		log:          log.New("metrics-authz-test"),
	}
	mux := web.New()
	if cfg.ServeFromSubPath && cfg.AppSubURL != "" {
		mux.SetURLPrefix(cfg.AppSubURL)
	}
	// addMiddlewaresAndStaticRoutes registers these handlers before the
	// signed-in not-found gate. A handler that writes the scrape ends the chain.
	mux.Use(hs.metricsEndpoint)
	mux.Use(hs.pluginMetricsEndpoint)
	mux.NotFound(func(ctx *web.Context) {
		if !ctx.Resp.Written() {
			ctx.Resp.WriteHeader(http.StatusUnauthorized)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client.Transport = &http.Transport{DisableCompression: true}

	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "identity")
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body), append([]string(nil), pluginClient.calls...)
}

type recordingPluginMetrics struct {
	plugins.Client
	body  []byte
	calls []string
}

func (c *recordingPluginMetrics) CollectMetrics(_ context.Context, req *backend.CollectMetricsRequest) (*backend.CollectMetricsResult, error) {
	c.calls = append(c.calls, req.PluginContext.PluginID)
	return &backend.CollectMetricsResult{PrometheusMetrics: append([]byte(nil), c.body...)}, nil
}
