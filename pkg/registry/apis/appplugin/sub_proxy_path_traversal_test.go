package appplugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/pluginproxy"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web"
)

// TestAppPluginConnectProxyStaysUnderRouteURL covers the app-plugin connect
// subresource. proxyRequest takes the decoded request path after
// /app/instance/proxy and PluginProxy appends that wildcard to the route URL.
func TestAppPluginConnectProxyStaysUnderRouteURL(t *testing.T) {
	const prefix = "/api/v1/"

	t.Run("path under the prefix is proxied", func(t *testing.T) {
		hits, status, body := proxyConnect(t, "/apis/demo.grafana.app/v1alpha1/namespaces/default/app/instance/proxy/some-api/health")
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		require.Len(t, hits, 1)
		require.Equal(t, "/api/v1/health", connectRequestPath(hits[0]))
	})

	for _, tc := range []struct {
		name string
		in   string
	}{
		{
			name: "percent-encoded parent segments",
			in:   "/apis/demo.grafana.app/v1alpha1/namespaces/default/app/instance/proxy/some-api/%2e%2e/%2e%2e/admin",
		},
		{
			name: "literal parent segments",
			in:   "/apis/demo.grafana.app/v1alpha1/namespaces/default/app/instance/proxy/some-api/../../admin",
		},
		{
			name: "percent-encoded slash and parent segments",
			in:   "/apis/demo.grafana.app/v1alpha1/namespaces/default/app/instance/proxy/some-api/%2e%2e%2f%2e%2e%2fadmin",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits, status, body := proxyConnect(t, tc.in)
			for _, hit := range hits {
				got := connectRequestPath(hit)
				require.False(t, connectHasDotSegment(got), "upstream received %q", got)
				require.True(t, connectUnderPrefix(got, prefix), "upstream received %q outside %q", got, prefix)
			}
			if len(hits) == 0 {
				require.GreaterOrEqual(t, status, 400, "body: %s", body)
			}
		})
	}
}

func proxyConnect(t *testing.T, incomingPath string) ([]string, int, string) {
	t.Helper()

	hits := make(chan string, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- r.RequestURI
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream"))
	}))
	t.Cleanup(upstream.Close)

	routes := []*plugins.Route{{
		Path:   "some-api/*",
		Method: http.MethodGet,
		URL:    upstream.URL + "/api/v1/",
		Headers: []plugins.Header{{
			Name:    "X-Plugin-Route-Credential",
			Content: "{{.SecureJsonData.token}}",
		}},
	}}
	ps := &pluginsettings.DTO{PluginID: "demo-app", Enabled: true}
	secure := func(context.Context) (map[string]string, error) {
		return map[string]string{"token": "placeholder-not-a-secret"}, nil
	}
	caller := &user.SignedInUser{UserID: 1, Login: "caller", OrgID: 1}
	features := featuremgmt.WithFeatures()

	req := httptest.NewRequest(http.MethodGet, incomingPath, nil)
	proxyReq, proxyPath, err := proxyRequest(req.Context(), req)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	responseWriter := web.NewResponseWriter(http.MethodGet, recorder)
	proxy, err := pluginproxy.NewPluginProxy(
		ps,
		routes,
		proxyReq,
		responseWriter,
		caller,
		proxyPath,
		false,
		true,
		secure,
		tracing.InitializeTracerForTest(),
		&http.Transport{},
		acimpl.ProvideAccessControl(features),
		features,
	)
	require.NoError(t, err)
	proxy.HandleRequest()

	var got []string
	for {
		select {
		case hit := <-hits:
			got = append(got, hit)
		default:
			return got, recorder.Code, recorder.Body.String()
		}
	}
}

func connectRequestPath(requestURI string) string {
	if i := strings.Index(requestURI, "?"); i >= 0 {
		return requestURI[:i]
	}
	return requestURI
}

func connectHasDotSegment(raw string) bool {
	decoded, err := url.PathUnescape(connectRequestPath(raw))
	if err != nil {
		decoded = connectRequestPath(raw)
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func connectUnderPrefix(raw, prefix string) bool {
	decoded, err := url.PathUnescape(connectRequestPath(raw))
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
