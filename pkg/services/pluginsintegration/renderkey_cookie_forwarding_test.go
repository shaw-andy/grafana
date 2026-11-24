package pluginsintegration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/handlertest"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins/manager/registry"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/clientmiddleware"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

// The plugin client middleware installed by CreateMiddlewares is the other caller
// of cookie filtering. Backend datasource queries, resource calls, and health checks
// must withhold the same Grafana authentication cookies as the data proxy.
func TestCreateMiddlewares_doesNotForwardGrafanaAuthCookies(t *testing.T) {
	const benignCookie = "graphite_session"
	const benignValue = "upstream-session-placeholder"

	cases := []struct {
		name            string
		loginCookieName string
		keepCookies     []string
	}{
		{
			name:            "exact keepCookies names",
			loginCookieName: "grafana_session",
			keepCookies:     []string{"renderKey", "grafana_session", "oauth_state", "oauth_code_verifier", benignCookie},
		},
		{
			name:            "prefix keepCookies patterns",
			loginCookieName: "grafana_session",
			keepCookies:     []string{"render[]", "oauth_[]", "grafana_session", benignCookie},
		},
		{
			name:            "match-all keepCookies pattern",
			loginCookieName: "grafana_session",
			keepCookies:     []string{"[]"},
		},
		{
			name:            "configured login cookie name",
			loginCookieName: "tenant_session",
			keepCookies:     []string{"renderKey", "tenant_session", "oauth_state", "oauth_code_verifier", benignCookie},
		},
	}

	operations := []string{"QueryData", "QueryChunkedData", "CallResource", "CheckHealth"}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mw := productionCookiesMiddleware(t, tc.loginCookieName)
			jsonData, err := json.Marshal(map[string]any{"keepCookies": tc.keepCookies})
			require.NoError(t, err)
			pluginCtx := backend.PluginContext{
				DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{JSONData: jsonData},
			}

			for _, op := range operations {
				t.Run(op, func(t *testing.T) {
					req := httptest.NewRequest(http.MethodPost, "http://grafana.example/api/ds/query", nil)
					req.AddCookie(&http.Cookie{Name: "renderKey", Value: "render-key-placeholder"})
					req.AddCookie(&http.Cookie{Name: tc.loginCookieName, Value: "login-cookie-placeholder"})
					req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "oauth-state-placeholder"})
					req.AddCookie(&http.Cookie{Name: "oauth_code_verifier", Value: "pkce-placeholder"})
					req.AddCookie(&http.Cookie{Name: benignCookie, Value: benignValue})

					cdt := handlertest.NewHandlerMiddlewareTest(t,
						clientmiddleware.WithReqContext(req, &user.SignedInUser{}),
						handlertest.WithMiddlewares(mw),
					)

					var header string
					switch op {
					case "QueryData":
						_, err = cdt.MiddlewareHandler.QueryData(req.Context(), &backend.QueryDataRequest{
							PluginContext: pluginCtx,
							Headers:       map[string]string{},
						})
						require.NoError(t, err)
						require.NotNil(t, cdt.QueryDataReq)
						header = cdt.QueryDataReq.Headers["Cookie"]
					case "QueryChunkedData":
						err = cdt.MiddlewareHandler.QueryChunkedData(req.Context(), &backend.QueryChunkedDataRequest{
							PluginContext: pluginCtx,
							Headers:       map[string]string{},
						}, nopChunkedWriter{})
						require.NoError(t, err)
						require.NotNil(t, cdt.QueryChunkedDataReq)
						header = cdt.QueryChunkedDataReq.Headers["Cookie"]
					case "CallResource":
						err = cdt.MiddlewareHandler.CallResource(req.Context(), &backend.CallResourceRequest{
							PluginContext: pluginCtx,
							Headers:       map[string][]string{},
						}, backend.CallResourceResponseSenderFunc(func(*backend.CallResourceResponse) error { return nil }))
						require.NoError(t, err)
						require.NotNil(t, cdt.CallResourceReq)
						if values := cdt.CallResourceReq.Headers["Cookie"]; len(values) > 0 {
							header = values[0]
						}
					case "CheckHealth":
						_, err = cdt.MiddlewareHandler.CheckHealth(req.Context(), &backend.CheckHealthRequest{
							PluginContext: pluginCtx,
							Headers:       map[string]string{},
						})
						require.NoError(t, err)
						require.NotNil(t, cdt.CheckHealthReq)
						header = cdt.CheckHealthReq.Headers["Cookie"]
					default:
						t.Fatalf("unknown operation %s", op)
					}

					forwarded := http.Request{Header: http.Header{"Cookie": {header}}}
					for _, name := range []string{"renderKey", tc.loginCookieName, "oauth_state", "oauth_code_verifier"} {
						_, cookieErr := forwarded.Cookie(name)
						require.ErrorIs(t, cookieErr, http.ErrNoCookie, "plugin request forwarded protected cookie %s: %q", name, header)
					}
					got, cookieErr := forwarded.Cookie(benignCookie)
					require.NoError(t, cookieErr)
					require.Equal(t, benignValue, got.Value)
				})
			}
		})
	}
}

func productionCookiesMiddleware(t *testing.T, loginCookieName string) backend.HandlerMiddleware {
	t.Helper()

	cfg, err := setting.NewCfgFromBytes([]byte("[auth]\nlogin_cookie_name = " + loginCookieName + "\n"))
	require.NoError(t, err)

	middlewares := CreateMiddlewares(
		cfg,
		nil,
		tracing.InitializeTracerForTest(),
		nil,
		featuremgmt.WithFeatures(),
		prometheus.NewRegistry(),
		registry.ProvideService(),
	)

	for _, mw := range middlewares {
		handler := mw.CreateHandlerMiddleware(&backend.BaseHandler{})
		if _, ok := handler.(*clientmiddleware.CookiesMiddleware); ok {
			return mw
		}
	}
	t.Fatal("CreateMiddlewares did not install the cookies middleware")
	return nil
}

type nopChunkedWriter struct{}

func (nopChunkedWriter) WriteFrame(_ context.Context, _ string, _ string, _ *data.Frame) error {
	return nil
}

func (nopChunkedWriter) WriteError(_ context.Context, _ string, _ backend.Status, _ error) error {
	return nil
}
