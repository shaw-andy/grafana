package pluginproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/plugins"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// Grafana authentication cookies must never be forwarded to a datasource, including
// when jsonData.keepCookies names them exactly, by prefix, or with the match-all
// pattern. The image renderer authenticates as the user who requested the render
// with the renderKey cookie, so forwarding it lets the datasource owner replay it.
func TestDataSourceProxy_doesNotForwardGrafanaAuthCookies(t *testing.T) {
	const benignCookie = "graphite_session"
	const benignValue = "upstream-session-placeholder"

	cases := []struct {
		name            string
		loginCookieName string
		keepCookies     []any
	}{
		{
			name:            "exact keepCookies names",
			loginCookieName: "grafana_session",
			keepCookies:     []any{"renderKey", "grafana_session", "oauth_state", "oauth_code_verifier", benignCookie},
		},
		{
			name:            "prefix keepCookies patterns",
			loginCookieName: "grafana_session",
			keepCookies:     []any{"render[]", "oauth_[]", "grafana_session", benignCookie},
		},
		{
			name:            "match-all keepCookies pattern",
			loginCookieName: "grafana_session",
			keepCookies:     []any{"[]"},
		},
		{
			name:            "configured login cookie name",
			loginCookieName: "tenant_session",
			keepCookies:     []any{"renderKey", "tenant_session", "oauth_state", "oauth_code_verifier", benignCookie},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got *http.Request
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Clone(r.Context())
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "ok")
			}))
			t.Cleanup(upstream.Close)

			cfg := cfgWithLoginCookie(t, tc.loginCookieName)
			ds := &datasources.DataSource{
				Type:     datasources.DS_GRAPHITE,
				URL:      upstream.URL,
				JsonData: simplejson.NewFromAny(map[string]any{"keepCookies": tc.keepCookies}),
			}

			// Graphite frontend mode posts the panel query to <proxy>/render.
			req := httptest.NewRequest(http.MethodPost, "http://grafana.example/api/datasources/proxy/uid/graphite/render", nil)
			addAuthAndBenignCookies(req, tc.loginCookieName, benignCookie, benignValue)

			ctx := &contextmodel.ReqContext{
				SignedInUser: &user.SignedInUser{},
				Context: &web.Context{
					Req:  req,
					Resp: web.NewResponseWriter(http.MethodPost, httptest.NewRecorder()),
				},
			}
			proxy, err := setupDSProxyTest(t, ctx, ds, []*plugins.Route{}, "/render", func(p *DataSourceProxy) {
				p.settings = NewDataSourceProxySettings(cfg)
			})
			require.NoError(t, err)

			proxy.HandleRequest()

			require.NotNil(t, got, "graphite POST /render must be proxied")
			assertAuthCookiesWithheld(t, got, tc.loginCookieName)
			require.Equal(t, benignValue, cookieValue(got, benignCookie))
		})
	}
}

func cfgWithLoginCookie(t *testing.T, name string) *setting.Cfg {
	t.Helper()
	cfg, err := setting.NewCfgFromBytes([]byte("[auth]\nlogin_cookie_name = " + name + "\n"))
	require.NoError(t, err)
	require.Equal(t, name, cfg.LoginCookieName)
	return cfg
}

func addAuthAndBenignCookies(req *http.Request, loginCookieName, benignName, benignValue string) {
	req.AddCookie(&http.Cookie{Name: "renderKey", Value: "render-key-placeholder"})
	req.AddCookie(&http.Cookie{Name: loginCookieName, Value: "login-cookie-placeholder"})
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "oauth-state-placeholder"})
	req.AddCookie(&http.Cookie{Name: "oauth_code_verifier", Value: "pkce-placeholder"})
	req.AddCookie(&http.Cookie{Name: benignName, Value: benignValue})
}

func assertAuthCookiesWithheld(t *testing.T, req *http.Request, loginCookieName string) {
	t.Helper()
	for _, name := range []string{"renderKey", loginCookieName, "oauth_state", "oauth_code_verifier"} {
		_, err := req.Cookie(name)
		require.ErrorIs(t, err, http.ErrNoCookie, "datasource upstream received protected cookie %s", name)
	}
}

func cookieValue(req *http.Request, name string) string {
	c, err := req.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
