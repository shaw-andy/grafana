package api

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/metrics"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// Bounds a fixed handler must enforce. The frontend posts one sample per boot
// metric, so a small batch and a body far below the global JSON bind cap is
// enough for legitimate reports. Values above this ceiling, non-finite values,
// and negative values are not boot or preload timings.
const (
	maxFrontendMetricEvents     = 32
	maxFrontendMetricValue      = 1e7
	maxFrontendMetricsBodyBytes = 64 << 10
)

// Names registered by initFrontendMetrics. One handler records every name.
var frontendMetricNames = []string{
	"frontend_boot_load_time_seconds",
	"frontend_boot_first_paint_time_seconds",
	"frontend_boot_first_contentful_paint_time_seconds",
	"frontend_boot_js_done_time_seconds",
	"frontend_boot_css_time_seconds",
	"frontend_plugins_preload_ms",
}

func TestFrontendMetricsRejectsPoisoning(t *testing.T) {
	for _, name := range frontendMetricNames {
		t.Run(name+"/max_float", func(t *testing.T) {
			postAndRequireUnchanged(t, viewerIdentity(), eventsBody(name, "1.7976931348623157e+308"))
		})
		t.Run(name+"/above_ceiling", func(t *testing.T) {
			postAndRequireUnchanged(t, viewerIdentity(), eventsBody(name, "1e16"))
		})
		t.Run(name+"/negative", func(t *testing.T) {
			postAndRequireUnchanged(t, viewerIdentity(), eventsBody(name, "-1.7976931348623157e+308"))
		})
	}

	t.Run("anonymous identity", func(t *testing.T) {
		postAndRequireUnchanged(t, anonymousIdentity(), eventsBody(frontendMetricNames[0], "1.7976931348623157e+308"))
	})

	t.Run("api key identity", func(t *testing.T) {
		postAndRequireUnchanged(t, apiKeyIdentity(), eventsBody(frontendMetricNames[0], "1e16"))
	})

	t.Run("invalid event discards the whole batch", func(t *testing.T) {
		body := fmt.Sprintf(
			`{"events":[{"name":%q,"value":1.25},{"name":%q,"value":1e308}]}`,
			frontendMetricNames[0], frontendMetricNames[0],
		)
		postAndRequireUnchanged(t, viewerIdentity(), body)
	})

	t.Run("too many events", func(t *testing.T) {
		postAndRequireUnchanged(t, viewerIdentity(), repeatedEvents(frontendMetricNames[0], 1, maxFrontendMetricEvents+1))
	})

	t.Run("body above endpoint limit", func(t *testing.T) {
		// One in-range sample plus ignored padding. The event count stays under
		// the cap, so only a body limit smaller than the global bind cap can
		// refuse this without recording the sample.
		sample := eventsBody(frontendMetricNames[0], "1.25")
		pad := strings.Repeat("a", maxFrontendMetricsBodyBytes)
		body := fmt.Sprintf(`{"events":%s,"pad":"%s"}`, sample[len(`{"events":`):len(sample)-1], pad)
		if len(body) <= maxFrontendMetricsBodyBytes {
			t.Fatalf("constructed body is %d bytes, want more than %d", len(body), maxFrontendMetricsBodyBytes)
		}
		if len(body) >= 100<<20 {
			t.Fatalf("constructed body is %d bytes, which trips the global bind cap", len(body))
		}
		postAndRequireUnchanged(t, viewerIdentity(), body)
	})
}

func TestFrontendMetricsAcceptsBoundedReport(t *testing.T) {
	srv, gatherer := newFrontendMetricsServer(t, viewerIdentity(), nil)
	body := fmt.Sprintf(
		`{"events":[{"name":%q,"value":1.25},{"name":%q,"value":2.5}]}`,
		frontendMetricNames[0], frontendMetricNames[1],
	)
	before0, sum0 := histogramSample(t, gatherer, frontendMetricNames[0])
	before1, sum1 := histogramSample(t, gatherer, frontendMetricNames[1])

	rec := postFrontendMetrics(t, srv, body, true)
	require.Equal(t, http.StatusOK, rec.Code)

	count0, gotSum0 := histogramSample(t, gatherer, frontendMetricNames[0])
	count1, gotSum1 := histogramSample(t, gatherer, frontendMetricNames[1])
	require.Equal(t, before0+1, count0)
	require.InDelta(t, sum0+1.25, gotSum0, 1e-9)
	require.Equal(t, before1+1, count1)
	require.InDelta(t, sum1+2.5, gotSum1, 1e-9)
}

func TestFrontendMetricsAcceptsBatchAtCap(t *testing.T) {
	srv, gatherer := newFrontendMetricsServer(t, viewerIdentity(), nil)
	body := repeatedEvents(frontendMetricNames[0], 0.5, maxFrontendMetricEvents)
	require.LessOrEqual(t, len(body), maxFrontendMetricsBodyBytes)

	before, sumBefore := histogramSample(t, gatherer, frontendMetricNames[0])
	rec := postFrontendMetrics(t, srv, body, true)
	require.Equal(t, http.StatusOK, rec.Code)

	count, sum := histogramSample(t, gatherer, frontendMetricNames[0])
	require.Equal(t, before+uint64(maxFrontendMetricEvents), count)
	require.InDelta(t, sumBefore+0.5*float64(maxFrontendMetricEvents), sum, 1e-6)
}

func TestFrontendMetricsRequiresAuthentication(t *testing.T) {
	srv, gatherer := newFrontendMetricsServer(t, nil, fmt.Errorf("no auth"))
	before, sumBefore := histogramSample(t, gatherer, frontendMetricNames[0])

	rec := postFrontendMetrics(t, srv, eventsBody(frontendMetricNames[0], "1.7976931348623157e+308"), false)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	count, sum := histogramSample(t, gatherer, frontendMetricNames[0])
	require.Equal(t, before, count)
	require.Equal(t, sumBefore, sum)
}

func postAndRequireUnchanged(t *testing.T, identity *authn.Identity, body string) {
	t.Helper()
	srv, gatherer := newFrontendMetricsServer(t, identity, nil)

	before := map[string][2]float64{}
	for _, name := range frontendMetricNames {
		count, sum := histogramSample(t, gatherer, name)
		before[name] = [2]float64{float64(count), sum}
	}

	rec := postFrontendMetrics(t, srv, body, identity == nil || !identity.IsIdentityType(claims.TypeAnonymous))

	var changed []string
	for _, name := range frontendMetricNames {
		count, sum := histogramSample(t, gatherer, name)
		if count != uint64(before[name][0]) || sum != before[name][1] {
			changed = append(changed, fmt.Sprintf("%s count %v -> %d, sum %v -> %v", name, before[name][0], count, before[name][1], sum))
		}
	}
	if rec.Code < 400 || rec.Code >= 500 || len(changed) > 0 {
		t.Fatalf("status = %d, want a 4xx refusal that records nothing; histogram changes: %v", rec.Code, changed)
	}
}

func newFrontendMetricsServer(t *testing.T, identity *authn.Identity, authErr error) (http.Handler, prometheus.Gatherer) {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.LoginCookieName = "grafana_session"
	_, err := cfg.Raw.NewSection("metrics")
	require.NoError(t, err)
	security, err := cfg.Raw.NewSection("security")
	require.NoError(t, err)
	_, err = security.NewKey("csrf_always_check", "false")
	require.NoError(t, err)

	reg := prometheus.NewRegistry()
	_, err = metrics.ProvideService(cfg, reg, reg)
	require.NoError(t, err)

	hs := &HTTPServer{}
	rr := routing.NewRouteRegister(middleware.ProvideRouteOperationName)
	rr.Group("/api", func(apiRoute routing.RouteRegister) {
		apiRoute.Post("/frontend-metrics", routing.Wrap(hs.PostFrontendMetrics))
	}, middleware.ReqSignedIn)

	m := web.New()
	// Same order as HTTPServer.addMiddlewaresAndStaticRoutes: CSRF, then the
	// context handler, then org redirect and action-url checks, then the route.
	m.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	m.UseMiddleware(contexthandler.ProvideService(cfg, &authntest.FakeService{
		ExpectedIdentity: identity,
		ExpectedErr:      authErr,
	}, featuremgmt.WithFeatures()).Middleware)
	var userSvc user.Service
	m.Use(middleware.OrgRedirect(cfg, userSvc))
	m.UseMiddleware(middleware.ValidateActionUrl(cfg, log.New("frontend-metrics-test")))
	rr.Register(m)

	return m, reg
}

func postFrontendMetrics(t *testing.T, handler http.Handler, body string, withSessionCookie bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/frontend-metrics", strings.NewReader(body))
	req.Host = "grafana.example"
	req.Header.Set("Content-Type", "application/json")
	// A signed-in browser sends the session cookie and a same-origin Origin.
	// With csrf_always_check off, that pair passes the CSRF check and reaches
	// the handler. Anonymous calls have no cookie, which also skips the check.
	if withSessionCookie {
		req.AddCookie(&http.Cookie{Name: "grafana_session", Value: "placeholder"})
		req.Header.Set("Origin", "http://grafana.example")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func viewerIdentity() *authn.Identity {
	return &authn.Identity{
		ID:       "1",
		Type:     claims.TypeUser,
		OrgID:    1,
		OrgRoles: map[int64]org.RoleType{1: org.RoleViewer},
	}
}

func anonymousIdentity() *authn.Identity {
	return &authn.Identity{
		ID:       "0",
		Type:     claims.TypeAnonymous,
		OrgID:    1,
		OrgRoles: map[int64]org.RoleType{1: org.RoleViewer},
	}
}

func apiKeyIdentity() *authn.Identity {
	return &authn.Identity{
		ID:       "7",
		Type:     claims.TypeAPIKey,
		OrgID:    1,
		OrgRoles: map[int64]org.RoleType{1: org.RoleViewer},
	}
}

func eventsBody(name, value string) string {
	return fmt.Sprintf(`{"events":[{"name":%q,"value":%s}]}`, name, value)
}

func repeatedEvents(name string, value float64, n int) string {
	var b strings.Builder
	b.WriteString(`{"events":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"name":%q,"value":%g}`, name, value)
	}
	b.WriteString(`]}`)
	return b.String()
}

func histogramSample(t *testing.T, g prometheus.Gatherer, name string) (uint64, float64) {
	t.Helper()
	full := "grafana_" + name
	families, err := g.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != full || family.GetType() != dto.MetricType_HISTOGRAM {
			continue
		}
		require.NotEmpty(t, family.Metric)
		h := family.Metric[0].GetHistogram()
		require.NotNil(t, h)
		sum := h.GetSampleSum()
		require.False(t, math.IsNaN(sum), "histogram %s sum is NaN", full)
		return h.GetSampleCount(), sum
	}
	t.Fatalf("histogram %s is not registered", full)
	return 0, 0
}
