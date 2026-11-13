package pluginproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web"
)

// dashboardPageReferer is the address of the dashboard the browser loaded.
// Its query string is not part of the query Grafana sends to the datasource or plugin.
const dashboardPageReferer = "https://grafana.example/d/abc/overview?orgId=1&var-region=page-query-value"

const pageQueryValue = "page-query-value"

func TestDataSourceProxyDoesNotForwardDashboardPageQuery(t *testing.T) {
	var got *http.Request
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(backend.Close)

	req := httptest.NewRequest(http.MethodGet, "http://grafana.example/api/datasources/proxy/1/render?expr=up", nil)
	req.Header.Set("Referer", dashboardPageReferer)
	req.RemoteAddr = "192.0.2.10:1234"
	ctx := &contextmodel.ReqContext{
		SignedInUser: &user.SignedInUser{},
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(http.MethodGet, httptest.NewRecorder()),
		},
	}
	ds := &datasources.DataSource{URL: backend.URL, Type: datasources.DS_GRAPHITE}
	proxy, err := setupDSProxyTest(t, ctx, ds, nil, "/render")
	require.NoError(t, err)

	proxy.HandleRequest()

	require.NotNil(t, got)
	require.Equal(t, "expr=up", got.URL.RawQuery)
	requirePageQueryNotForwarded(t, got.Header, got.URL)
}

func TestDataSourceProxyRouteDoesNotForwardDashboardPageQuery(t *testing.T) {
	var got *http.Request
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	req := httptest.NewRequest(http.MethodGet, "http://grafana.example/api/datasources/proxy/1/api/v1/labels?match=up", nil)
	req.Header.Set("Referer", dashboardPageReferer)
	req.RemoteAddr = "192.0.2.10:1234"
	ctx := &contextmodel.ReqContext{
		SignedInUser: &user.SignedInUser{},
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(http.MethodGet, httptest.NewRecorder()),
		},
	}
	ds := &datasources.DataSource{URL: backend.URL, Type: datasources.DS_PROMETHEUS}
	routes := []*plugins.Route{{
		Path: "api/v1/labels",
		URL:  backend.URL,
	}}
	proxy, err := setupDSProxyTest(t, ctx, ds, routes, "api/v1/labels")
	require.NoError(t, err)

	proxy.HandleRequest()

	require.NotNil(t, got)
	require.Equal(t, "match=up", got.URL.RawQuery)
	requirePageQueryNotForwarded(t, got.Header, got.URL)
}

func TestPluginProxyDoesNotForwardDashboardPageQuery(t *testing.T) {
	var got *http.Request
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(backend.Close)

	req := httptest.NewRequest(http.MethodGet, "http://grafana.example/api/plugin-proxy/example-app/items?limit=1", nil)
	req.Header.Set("Referer", dashboardPageReferer)
	req.RemoteAddr = "192.0.2.10:1234"
	responseWriter := web.NewResponseWriter(http.MethodGet, httptest.NewRecorder())
	routes := []*plugins.Route{{
		Path: "/",
		URL:  backend.URL,
	}}
	proxy, err := NewPluginProxy(
		&pluginsettings.DTO{SecureJSONData: map[string][]byte{}},
		routes,
		req,
		responseWriter,
		&user.SignedInUser{},
		"",
		false,
		false,
		nil,
		tracing.InitializeTracerForTest(),
		&http.Transport{},
		acimpl.ProvideAccessControl(featuremgmt.WithFeatures()),
		featuremgmt.WithFeatures(),
	)
	require.NoError(t, err)

	proxy.HandleRequest()

	require.NotNil(t, got)
	require.Equal(t, "limit=1", got.URL.RawQuery)
	requirePageQueryNotForwarded(t, got.Header, got.URL)
}

// requirePageQueryNotForwarded fails while the proxy copies the browser Referer,
// query string included, into the request it sends upstream.
// Omitting X-Grafana-Referer, or sending only the dashboard path, both pass.
func requirePageQueryNotForwarded(t *testing.T, headers http.Header, upstream *url.URL) {
	t.Helper()

	for name, values := range headers {
		for _, value := range values {
			if strings.Contains(value, pageQueryValue) {
				t.Fatalf("upstream header %s contains the dashboard page query", name)
			}
		}
	}
	if upstream != nil {
		combined := upstream.String()
		require.NotContains(t, combined, pageQueryValue)
	}

	forwarded := headers.Get("X-Grafana-Referer")
	if forwarded == "" {
		return
	}
	parsed, err := url.Parse(forwarded)
	require.NoError(t, err)
	require.Empty(t, parsed.RawQuery)
	require.NotContains(t, forwarded, "?")
	require.NotContains(t, forwarded, pageQueryValue)
}
