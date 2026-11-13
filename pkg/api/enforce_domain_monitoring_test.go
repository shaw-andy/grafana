package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"

	"github.com/grafana/grafana/pkg/infra/db/dbtest"
	"github.com/grafana/grafana/pkg/infra/localcache"
	infraLog "github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/middleware/loggermw"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

const (
	enforceDomainName       = "grafana.example"
	enforceDomainAppURL     = "http://grafana.example:3000/"
	enforceDomainForgedHost = "attacker.example"
	enforceDomainVersion    = "9.9.9-rebind"
	enforceDomainCommit     = "rebindcommit"
	enforceDomainProbe      = "rebind_probe_total"
	enforceDomainPluginBody = "plugin_rebind_probe 1\n"
	// dbHealthyCacheKey is the cache written by databaseHealthy before /api/health responds.
	dbHealthyCacheKey = "db-healthy"

	// Placeholders so metrics basic auth is enabled. These are not real credentials.
	metricsAuthUserPlaceholder = "placeholder-metrics-user"
	metricsAuthPassPlaceholder = "placeholder-metrics-password"
)

// enforceDomainHarness serves through the same mux registration as HTTPServer.Run:
// addMiddlewaresAndStaticRoutes, then the Macaron handler installed on http.Server.
// Static files registered in that function can also finish a response before the host
// check. They are not covered here because they serve the public frontend.
type enforceDomainHarness struct {
	hs             *HTTPServer
	pluginCollects atomic.Int32
}

func newEnforceDomainHarness(t *testing.T, mutate func(*setting.Cfg)) *enforceDomainHarness {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.Domain = enforceDomainName
	cfg.AppURL = enforceDomainAppURL
	cfg.EnforceDomain = true
	cfg.MetricsEndpointEnabled = true
	cfg.EnableGzip = true
	cfg.BuildVersion = enforceDomainVersion
	cfg.BuildCommit = enforceDomainCommit
	cfg.LoginCookieName = "grafana_session"
	cfg.StaticRootPath = t.TempDir()
	cfg.Env = setting.Prod
	if mutate != nil {
		mutate(cfg)
	}

	features := featuremgmt.WithFeatures()
	registry := prometheus.NewRegistry()
	probe := prometheus.NewCounter(prometheus.CounterOpts{
		Name: enforceDomainProbe,
		Help: "Present only so a served /metrics body can be recognized.",
	})
	registry.MustRegister(probe)
	probe.Inc()

	h := &enforceDomainHarness{}
	h.hs = &HTTPServer{
		log:              infraLog.New("enforce-domain-test"),
		web:              web.New(),
		Cfg:              cfg,
		Features:         features,
		promRegister:     registry,
		promGatherer:     registry,
		LoggerMiddleware: loggermw.Provide(cfg, features),
		License:          &licensing.OSSLicensingService{},
		Csrf:             csrf.ProvideCSRFFilter(cfg),
		ContextHandler: contexthandler.ProvideService(cfg, &authntest.FakeService{
			ExpectedErr: errors.New("unauthenticated"),
		}, features),
		tracer:       tracing.NewNoopTracerService(),
		CacheService: localcache.New(time.Minute, time.Minute),
		SQLStore:     dbtest.NewFakeDB(),
		pluginClient: &countingPluginClient{collects: &h.pluginCollects},
	}
	h.hs.addMiddlewaresAndStaticRoutes()
	return h
}

// countingPluginClient records CollectMetrics and returns a fixed payload.
// Other Client methods are unused on this path. The HTTP handler under test
// writes PrometheusMetrics itself.
type countingPluginClient struct {
	plugins.Client
	collects *atomic.Int32
}

func (c *countingPluginClient) CollectMetrics(context.Context, *backend.CollectMetricsRequest) (*backend.CollectMetricsResult, error) {
	c.collects.Add(1)
	return &backend.CollectMetricsResult{PrometheusMetrics: []byte(enforceDomainPluginBody)}, nil
}

func (h *enforceDomainHarness) perform(method, target, host string, body io.Reader, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	req.Host = host
	for key, values := range header {
		req.Header[key] = append([]string(nil), values...)
	}
	rec := httptest.NewRecorder()
	h.hs.web.ServeHTTP(rec, req)
	return rec
}

func assertRedirectedToConfiguredDomain(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	require.Equalf(t, http.StatusMovedPermanently, rec.Code, "body: %q", rec.Body.String())
	location := rec.Header().Get("Location")
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	require.Equal(t, enforceDomainName, parsed.Hostname())
	require.Equal(t, "http", parsed.Scheme)

	body := rec.Body.String()
	require.NotContains(t, body, enforceDomainProbe)
	require.NotContains(t, body, "plugin_rebind_probe")
	require.NotContains(t, body, enforceDomainVersion)
	require.NotContains(t, body, `"database"`)
	require.NotEqual(t, "Ok", strings.TrimSpace(body))
	require.NotEqual(t, "OK", strings.TrimSpace(body))
	require.Empty(t, rec.Header().Get("WWW-Authenticate"))
}

func TestEnforceDomainRejectsForgedHostOnMonitoringHandlers(t *testing.T) {
	forgedHosts := []string{
		enforceDomainForgedHost,
		enforceDomainForgedHost + ":3000",
		"grafana.example.attacker.example",
		"notgrafana.example",
		"grafana.example.",
	}

	t.Run("metrics", func(t *testing.T) {
		for _, host := range forgedHosts {
			t.Run(host, func(t *testing.T) {
				h := newEnforceDomainHarness(t, nil)
				rec := h.perform(http.MethodGet, "/metrics?extra=1", host, nil, nil)
				assertRedirectedToConfiguredDomain(t, rec)
				require.Zero(t, h.pluginCollects.Load())
			})
		}
	})

	t.Run("metrics basic auth challenge is not written first", func(t *testing.T) {
		h := newEnforceDomainHarness(t, func(cfg *setting.Cfg) {
			cfg.MetricsEndpointBasicAuthUsername = metricsAuthUserPlaceholder
			cfg.MetricsEndpointBasicAuthPassword = metricsAuthPassPlaceholder
		})
		rec := h.perform(http.MethodGet, "/metrics", enforceDomainForgedHost, nil, nil)
		assertRedirectedToConfiguredDomain(t, rec)
	})

	t.Run("plugin metrics", func(t *testing.T) {
		h := newEnforceDomainHarness(t, nil)
		rec := h.perform(http.MethodGet, "/metrics/plugins/sample-plugin", enforceDomainForgedHost, nil, nil)
		assertRedirectedToConfiguredDomain(t, rec)
		require.Zero(t, h.pluginCollects.Load(), "plugin metrics were collected before the host was refused")
		_, found := h.hs.CacheService.Get(dbHealthyCacheKey)
		require.False(t, found)
	})

	t.Run("healthz", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(method, func(t *testing.T) {
				h := newEnforceDomainHarness(t, nil)
				rec := h.perform(method, "/healthz", enforceDomainForgedHost, nil, nil)
				assertRedirectedToConfiguredDomain(t, rec)
			})
		}
	})

	t.Run("api health", func(t *testing.T) {
		for _, hideVersion := range []bool{false, true} {
			t.Run(map[bool]string{false: "version visible", true: "version hidden"}[hideVersion], func(t *testing.T) {
				for _, method := range []string{http.MethodGet, http.MethodHead} {
					t.Run(method, func(t *testing.T) {
						h := newEnforceDomainHarness(t, func(cfg *setting.Cfg) {
							cfg.Anonymous.HideVersion = hideVersion
						})
						rec := h.perform(method, "/api/health", enforceDomainForgedHost, nil, nil)
						assertRedirectedToConfiguredDomain(t, rec)
						_, found := h.hs.CacheService.Get(dbHealthyCacheKey)
						require.False(t, found, "database health was checked before the host was refused")
					})
				}
			})
		}
	})

	t.Run("frontend log endpoint while agent is disabled", func(t *testing.T) {
		h := newEnforceDomainHarness(t, nil)
		rec := h.perform(http.MethodPost, grafanaJavascriptAgentEndpointPath, enforceDomainForgedHost, strings.NewReader("{}"), nil)
		assertRedirectedToConfiguredDomain(t, rec)
	})

	t.Run("frontend log endpoint while agent is enabled", func(t *testing.T) {
		var logged atomic.Int32
		orig := frontendLogger.GetLogger()
		frontendLogger.Swap(level.NewFilter(log.LoggerFunc(func(keyvals ...any) error {
			logged.Add(1)
			return nil
		}), level.AllowAll()))
		t.Cleanup(func() {
			frontendLogger.Swap(orig)
		})

		h := newEnforceDomainHarness(t, func(cfg *setting.Cfg) {
			cfg.GrafanaJavascriptAgent.Enabled = true
			cfg.GrafanaJavascriptAgent.EndpointRPS = 100
			cfg.GrafanaJavascriptAgent.EndpointBurst = 100
		})
		body := strings.NewReader(`{"logs":[{"message":"rebind-probe-log","level":"info","timestamp":"2020-01-01T00:00:00Z"}]}`)
		header := http.Header{"Content-Type": []string{"application/json"}}
		rec := h.perform(http.MethodPost, grafanaJavascriptAgentEndpointPath, enforceDomainForgedHost, body, header)
		assertRedirectedToConfiguredDomain(t, rec)
		require.Zero(t, logged.Load(), "frontend log was recorded before the host was refused")
	})

	t.Run("subpath", func(t *testing.T) {
		h := newEnforceDomainHarness(t, func(cfg *setting.Cfg) {
			cfg.ServeFromSubPath = true
			cfg.AppSubURL = "/grafana"
			cfg.AppURL = "http://grafana.example:3000/grafana/"
		})
		for _, target := range []string{"/grafana/metrics", "/grafana/healthz", "/grafana/api/health", "/grafana/metrics/plugins/sample-plugin"} {
			t.Run(target, func(t *testing.T) {
				rec := h.perform(http.MethodGet, target, enforceDomainForgedHost, nil, nil)
				assertRedirectedToConfiguredDomain(t, rec)
			})
		}
		require.Zero(t, h.pluginCollects.Load())
		_, found := h.hs.CacheService.Get(dbHealthyCacheKey)
		require.False(t, found)
	})
}

func TestEnforceDomainAllowsConfiguredHostOnMonitoringHandlers(t *testing.T) {
	allowedHosts := []string{
		enforceDomainName,
		"Grafana.Example",
		enforceDomainName + ":3000",
	}
	for _, host := range allowedHosts {
		t.Run(host, func(t *testing.T) {
			h := newEnforceDomainHarness(t, nil)

			metrics := h.perform(http.MethodGet, "/metrics", host, nil, nil)
			require.Equal(t, http.StatusOK, metrics.Code)
			require.Contains(t, metrics.Body.String(), enforceDomainProbe)

			healthz := h.perform(http.MethodGet, "/healthz", host, nil, nil)
			require.Equal(t, http.StatusOK, healthz.Code)
			require.Equal(t, "Ok", healthz.Body.String())

			apiHealth := h.perform(http.MethodGet, "/api/health", host, nil, nil)
			require.Equal(t, http.StatusOK, apiHealth.Code)
			require.Contains(t, apiHealth.Body.String(), enforceDomainVersion)
			require.Contains(t, apiHealth.Body.String(), `"database": "ok"`)
			cached, found := h.hs.CacheService.Get(dbHealthyCacheKey)
			require.True(t, found)
			require.Equal(t, true, cached)

			plugins := h.perform(http.MethodGet, "/metrics/plugins/sample-plugin", host, nil, nil)
			require.Equal(t, http.StatusOK, plugins.Code)
			require.Equal(t, enforceDomainPluginBody, plugins.Body.String())
			require.Equal(t, int32(1), h.pluginCollects.Load())
		})
	}
}

func TestEnforceDomainRedirectsWhenMonitoringHandlerDoesNotWrite(t *testing.T) {
	h := newEnforceDomainHarness(t, func(cfg *setting.Cfg) {
		cfg.MetricsEndpointEnabled = false
	})

	metrics := h.perform(http.MethodGet, "/metrics", enforceDomainForgedHost, nil, nil)
	assertRedirectedToConfiguredDomain(t, metrics)

	pluginMetrics := h.perform(http.MethodGet, "/metrics/plugins/sample-plugin", enforceDomainForgedHost, nil, nil)
	assertRedirectedToConfiguredDomain(t, pluginMetrics)
	require.Zero(t, h.pluginCollects.Load())

	// The metrics handler only claims GET. Other methods fall through to the host check.
	head := h.perform(http.MethodHead, "/metrics", enforceDomainForgedHost, nil, nil)
	assertRedirectedToConfiguredDomain(t, head)

	frontendGet := h.perform(http.MethodGet, grafanaJavascriptAgentEndpointPath, enforceDomainForgedHost, nil, nil)
	assertRedirectedToConfiguredDomain(t, frontendGet)

	other := h.perform(http.MethodGet, "/login", enforceDomainForgedHost, nil, nil)
	assertRedirectedToConfiguredDomain(t, other)
}

func TestEnforceDomainDisabledLeavesMonitoringHandlersOpen(t *testing.T) {
	h := newEnforceDomainHarness(t, func(cfg *setting.Cfg) {
		cfg.EnforceDomain = false
	})
	rec := h.perform(http.MethodGet, "/metrics", enforceDomainForgedHost, nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), enforceDomainProbe)

	health := h.perform(http.MethodGet, "/api/health", enforceDomainForgedHost, nil, nil)
	require.Equal(t, http.StatusOK, health.Code)
	require.Contains(t, health.Body.String(), enforceDomainVersion)
}
