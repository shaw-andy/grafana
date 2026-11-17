package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/pluginproxy"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web"
)

const (
	routeCredentialHeader = "X-Plugin-Route-Credential"
	// Obvious placeholder. The route template reads it from secure settings.
	routeCredentialValue = "placeholder-not-a-secret"
	proxyCallerLogin     = "caller"
)

// TestAppPluginProxyWildcardStaysUnderRouteURL drives the app plugin proxy the
// way a signed-in caller does: the macaron route /api/plugin-proxy/:pluginId/*,
// then extractProxyPath, then PluginProxy.HandleRequest. The upstream must not
// observe a path outside the route URL, a path that still has dot segments, or
// the route credential on such a path.
func TestAppPluginProxyWildcardStaysUnderRouteURL(t *testing.T) {
	t.Run("path under the prefix keeps the route credential and caller identity", func(t *testing.T) {
		hits, status, body := proxyAppPlugin(t, "/api/v1/", "/api/plugin-proxy/demo-app/some-api/health")
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		require.Len(t, hits, 1)
		require.Equal(t, "/api/v1/health", requestPath(hits[0].requestURI))
		require.Equal(t, routeCredentialValue, hits[0].credential)
		require.Equal(t, proxyCallerLogin, hits[0].user)
		require.Contains(t, hits[0].grafanaContext, `"Login":"`+proxyCallerLogin+`"`)
		require.Equal(t, hits[0].host, hits[0].wantHost)
	})

	escapeCases := []struct {
		name string
		url  string
		in   string
	}{
		{
			name: "percent-encoded parent segments",
			url:  "/api/v1/",
			in:   "/api/plugin-proxy/demo-app/some-api/%2e%2e/%2e%2e/admin",
		},
		{
			name: "uppercase percent-encoded parent segments",
			url:  "/api/v1/",
			in:   "/api/plugin-proxy/demo-app/some-api/%2E%2E/%2E%2E/admin",
		},
		{
			name: "literal parent segments",
			url:  "/api/v1/",
			in:   "/api/plugin-proxy/demo-app/some-api/../../admin",
		},
		{
			name: "percent-encoded slash and parent segments",
			url:  "/api/v1/",
			in:   "/api/plugin-proxy/demo-app/some-api/%2e%2e%2f%2e%2e%2fadmin",
		},
		{
			name: "parent segments after an extra directory",
			url:  "/api/v1/",
			in:   "/api/plugin-proxy/demo-app/some-api/foo/%2e%2e/%2e%2e/secret",
		},
		{
			name: "single parent segment leaves the prefix",
			url:  "/api/v1/",
			in:   "/api/plugin-proxy/demo-app/some-api/../admin",
		},
		{
			name: "route url without trailing slash",
			url:  "/api/v1",
			in:   "/api/plugin-proxy/demo-app/some-api/%2e%2e/%2e%2e/admin",
		},
	}
	for _, tc := range escapeCases {
		t.Run(tc.name, func(t *testing.T) {
			hits, status, body := proxyAppPlugin(t, tc.url, tc.in)
			assertNoEscape(t, hits, tc.url, status, body)
		})
	}

	t.Run("dot segments that normalize inside the prefix are not forwarded", func(t *testing.T) {
		const routeURLPath = "/api/v1/"
		hits, status, body := proxyAppPlugin(t, routeURLPath, "/api/plugin-proxy/demo-app/some-api/child/../kept")
		if len(hits) == 0 {
			require.GreaterOrEqual(t, status, 400, "body: %s", body)
			return
		}
		require.Len(t, hits, 1, "body: %s", body)
		got := requestPath(hits[0].requestURI)
		require.False(t, hasDotSegment(got), "forwarded path %q still has a dot segment", got)
		require.True(t, pathUnderPrefix(got, routeURLPath), "forwarded path %q is outside %q", got, routeURLPath)
		require.Equal(t, hits[0].wantHost, hits[0].host)
	})
}

// TestGcomProxyWildcardStaysUnderAPIPrefix covers the grafana.com proxy, which
// joins the same kind of decoded catch-all onto a configured URL prefix.
func TestGcomProxyWildcardStaysUnderAPIPrefix(t *testing.T) {
	const prefix = "/api"

	t.Run("listed path stays under the api prefix", func(t *testing.T) {
		hits, status, body := proxyGcom(t, "/api/gnet/plugins/demo")
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		require.Len(t, hits, 1)
		require.Equal(t, "/api/plugins/demo", requestPath(hits[0].requestURI))
		require.True(t, pathUnderPrefix(hits[0].requestURI, prefix))
	})

	for _, tc := range []struct {
		name string
		in   string
	}{
		{name: "percent-encoded parent segment", in: "/api/gnet/%2e%2e/admin"},
		{name: "literal parent segment", in: "/api/gnet/../admin"},
		{name: "parent segments through a listed path shape", in: "/api/gnet/plugins/../admin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits, status, body := proxyGcom(t, tc.in)
			assertNoEscape(t, hits, prefix, status, body)
		})
	}
}

type upstreamHit struct {
	requestURI     string
	host           string
	wantHost       string
	credential     string
	user           string
	grafanaContext string
}

func proxyAppPlugin(t *testing.T, routeURLPath, incomingPath string) ([]upstreamHit, int, string) {
	t.Helper()

	hits := make(chan upstreamHit, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- upstreamHit{
			requestURI:     r.RequestURI,
			host:           r.Host,
			wantHost:       r.Host,
			credential:     r.Header.Get(routeCredentialHeader),
			user:           r.Header.Get("X-Grafana-User"),
			grafanaContext: r.Header.Get("X-Grafana-Context"),
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream"))
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	routes := []*plugins.Route{{
		Path:   "some-api/*",
		Method: http.MethodGet,
		URL:    upstream.URL + routeURLPath,
		Headers: []plugins.Header{{
			Name:    routeCredentialHeader,
			Content: "{{.SecureJsonData.token}}",
		}},
	}}
	ps := &pluginsettings.DTO{PluginID: "demo-app", Enabled: true}
	secure := func(context.Context) (map[string]string, error) {
		return map[string]string{"token": routeCredentialValue}, nil
	}
	caller := &user.SignedInUser{UserID: 1, Login: proxyCallerLogin, OrgID: 1}
	features := featuremgmt.WithFeatures()

	m := web.New()
	rr := routing.NewRouteRegister()
	rr.Group("/api", func(apiRoute routing.RouteRegister) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxy, err := pluginproxy.NewPluginProxy(
				ps,
				routes,
				r,
				w,
				caller,
				extractProxyPath(r.URL.EscapedPath()),
				false,
				true,
				secure,
				tracing.InitializeTracerForTest(),
				&http.Transport{},
				acimpl.ProvideAccessControl(features),
				features,
			)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			proxy.HandleRequest()
		})
		apiRoute.Any("/plugin-proxy/:pluginId/*", handler)
		apiRoute.Any("/plugin-proxy/:pluginId", handler)
	})
	rr.Register(m)

	grafana := httptest.NewServer(m)
	t.Cleanup(grafana.Close)

	status, body := doGet(t, grafana.URL+incomingPath)
	got := drainHits(hits)
	for i := range got {
		got[i].wantHost = upstreamURL.Host
	}
	return got, status, body
}

func proxyGcom(t *testing.T, incomingPath string) ([]upstreamHit, int, string) {
	t.Helper()

	hits := make(chan upstreamHit, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- upstreamHit{requestURI: r.RequestURI, host: r.Host}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream"))
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	logger := log.New("gcom-proxy-test")
	m := web.New()
	rr := routing.NewRouteRegister()
	rr.Any("/api/gnet/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyPath := web.Params(r)["*"]
		proxy := ReverseProxyGnetReq(logger, proxyPath, "test", upstream.URL+"/api", routeCredentialValue)
		proxy.Transport = &http.Transport{}
		proxy.ServeHTTP(w, r)
	}))
	rr.Register(m)

	grafana := httptest.NewServer(m)
	t.Cleanup(grafana.Close)

	status, body := doGet(t, grafana.URL+incomingPath)
	got := drainHits(hits)
	for i := range got {
		got[i].wantHost = upstreamURL.Host
	}
	return got, status, body
}

func doGet(t *testing.T, rawURL string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	client := &http.Client{
		Transport: &http.Transport{},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(buf)
}

func drainHits(ch <-chan upstreamHit) []upstreamHit {
	var hits []upstreamHit
	for {
		select {
		case hit := <-ch:
			hits = append(hits, hit)
		default:
			return hits
		}
	}
}

func assertNoEscape(t *testing.T, hits []upstreamHit, prefix string, status int, body string) {
	t.Helper()
	for _, hit := range hits {
		got := requestPath(hit.requestURI)
		require.False(t, hasDotSegment(got), "upstream received %q with a dot segment on host %s; route credential header set: %v", got, hit.host, hit.credential != "")
		require.True(t, pathUnderPrefix(got, prefix), "upstream received %q, outside prefix %q, on host %s; route credential header set: %v", got, prefix, hit.host, hit.credential != "")
		require.Equal(t, hit.wantHost, hit.host)
	}
	if len(hits) == 0 {
		require.GreaterOrEqual(t, status, 400, "caller was told the proxy succeeded without an in-prefix upstream response; body: %s", body)
	}
}

func requestPath(requestURI string) string {
	if i := strings.Index(requestURI, "?"); i >= 0 {
		return requestURI[:i]
	}
	return requestURI
}

func hasDotSegment(raw string) bool {
	decoded, err := url.PathUnescape(requestPath(raw))
	if err != nil {
		decoded = requestPath(raw)
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func pathUnderPrefix(raw, prefix string) bool {
	decoded, err := url.PathUnescape(requestPath(raw))
	if err != nil {
		return false
	}
	cleaned := path.Clean(decoded)
	base := path.Clean(prefix)
	if cleaned == base {
		return true
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return strings.HasPrefix(cleaned, base)
}
