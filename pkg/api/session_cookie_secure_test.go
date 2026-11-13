package api

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/models/usertoken"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

const placeholderSessionToken = "placeholder-session-token"

func TestSessionCookieSecure_APILoginPathsWithholdSessionFromCleartext(t *testing.T) {
	cfg := loadShippedConfig(t, `
[server]
protocol = http
domain = grafana.example.com
root_url = https://grafana.example.com/
`)
	require.Equal(t, "https://grafana.example.com/", cfg.AppURL)
	page := mustURL(t, cfg.AppURL)
	clear := *page
	clear.Scheme = "http"

	hs := &HTTPServer{
		log:              log.NewNopLogger(),
		Cfg:              cfg,
		Features:         featuremgmt.WithFeatures(),
		SecretsService:   fakes.NewFakeSecretsService(),
		AuthTokenService: &authtest.FakeUserAuthTokenService{},
	}

	t.Run("auth proxy login", func(t *testing.T) {
		hs.AuthTokenService = &authtest.FakeUserAuthTokenService{
			CreateTokenProvider: func(context.Context, *auth.CreateTokenCommand) (*auth.UserToken, error) {
				return placeholderToken(), nil
			},
		}
		req := httptest.NewRequest(http.MethodGet, page.String(), nil)
		req.RemoteAddr = "192.0.2.10:443"
		rec := httptest.NewRecorder()
		ctx := newReqContext(req, rec)
		require.NoError(t, hs.loginUserWithUser(&user.User{ID: 1, Login: "user", Email: "user@example.com"}, ctx))
		assertNamedCookieWithheld(t, page, &clear, rec, cfg.LoginCookieName)
	})

	t.Run("token rotation", func(t *testing.T) {
		hs.AuthTokenService = &authtest.FakeUserAuthTokenService{
			RotateTokenProvider: func(context.Context, auth.RotateCommand) (*auth.UserToken, error) {
				return placeholderToken(), nil
			},
		}
		req := httptest.NewRequest(http.MethodPost, page.String()+"api/user/using/1", nil)
		req.RemoteAddr = "192.0.2.10:443"
		req.AddCookie(&http.Cookie{Name: cfg.LoginCookieName, Value: "placeholder-old-session"})
		rec := httptest.NewRecorder()
		require.NoError(t, hs.rotateToken(newReqContext(req, rec)))
		assertNamedCookieWithheld(t, page, &clear, rec, cfg.LoginCookieName)
	})

	t.Run("oauth callback", func(t *testing.T) {
		hs.authnService = &authntest.FakeService{
			ExpectedIdentity: &authn.Identity{SessionToken: &usertoken.UserToken{
				Id:            1,
				UserId:        1,
				UnhashedToken: placeholderSessionToken,
				AuthTokenSeen: true,
				RotatedAt:     time.Now().Unix(),
			}},
		}
		req := httptest.NewRequest(http.MethodGet, page.String()+"login/generic_oauth?code=placeholder-code", nil)
		req = web.SetURLParams(req, map[string]string{":name": "generic_oauth"})
		rec := httptest.NewRecorder()
		hs.OAuthLogin(newReqContext(req, rec))
		assertNamedCookieWithheld(t, page, &clear, rec, cfg.LoginCookieName)
	})

	t.Run("oauth state and pkce", func(t *testing.T) {
		hs.authnService = &authntest.FakeService{
			ExpectedRedirect: &authn.Redirect{
				URL: "https://idp.example.com/authorize",
				Extra: map[string]string{
					authn.KeyOAuthState: "placeholder-oauth-state",
					authn.KeyOAuthPKCE:  "placeholder-pkce",
				},
			},
		}
		req := httptest.NewRequest(http.MethodGet, page.String()+"login/generic_oauth", nil)
		req = web.SetURLParams(req, map[string]string{":name": "generic_oauth"})
		rec := httptest.NewRecorder()
		hs.OAuthLogin(newReqContext(req, rec))
		assertNamedCookieWithheld(t, page, &clear, rec, OauthStateCookieName)
		assertNamedCookieWithheld(t, page, &clear, rec, OauthPKCECookieName)
	})

	t.Run("login error cookie", func(t *testing.T) {
		hs.authnService = &authntest.FakeService{ExpectedErr: authn.ErrClientNotConfigured}
		req := httptest.NewRequest(http.MethodGet, page.String()+"login/generic_oauth", nil)
		req = web.SetURLParams(req, map[string]string{":name": "generic_oauth"})
		rec := httptest.NewRecorder()
		hs.OAuthLogin(newReqContext(req, rec))
		assertNamedCookieWithheld(t, page, &clear, rec, loginErrorCookieName)
	})
}

func placeholderToken() *auth.UserToken {
	return &auth.UserToken{
		Id:            1,
		UserId:        1,
		UnhashedToken: placeholderSessionToken,
		AuthTokenSeen: true,
		RotatedAt:     time.Now().Unix(),
	}
}

func newReqContext(req *http.Request, rec *httptest.ResponseRecorder) *contextmodel.ReqContext {
	return &contextmodel.ReqContext{
		Context: &web.Context{Req: req, Resp: web.NewResponseWriter(req.Method, rec)},
		Logger:  log.NewNopLogger(),
	}
}

func assertNamedCookieWithheld(t *testing.T, page, clear *url.URL, rec *httptest.ResponseRecorder, name string) {
	t.Helper()
	issued := setCookieByName(t, rec, name)
	require.True(t, issued.Secure, "%s Set-Cookie is missing Secure", name)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	jar.SetCookies(page, rec.Result().Cookies())
	for _, c := range jar.Cookies(clear) {
		require.NotEqual(t, name, c.Name, "user agent attached %s to a cleartext request", name)
	}
}

func setCookieByName(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, line := range rec.Header().Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		require.NoError(t, err)
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("Set-Cookie %s was not written", name)
	return nil
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func loadShippedConfig(t *testing.T, extra string) *setting.Cfg {
	t.Helper()
	cookieSecure := setting.CookieSecure
	sameSiteDisabled := setting.CookieSameSiteDisabled
	sameSiteMode := setting.CookieSameSiteMode
	appURL := setting.AppUrl
	appSubURL := setting.AppSubUrl
	t.Cleanup(func() {
		setting.CookieSecure = cookieSecure
		setting.CookieSameSiteDisabled = sameSiteDisabled
		setting.CookieSameSiteMode = sameSiteMode
		setting.AppUrl = appURL
		setting.AppSubUrl = appSubURL
	})

	dir := t.TempDir()
	iniPath := filepath.Join(dir, "custom.ini")
	require.NoError(t, os.WriteFile(iniPath, []byte("[log]\nmode = console\n"+extra), 0o600))

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: repoRoot(t),
		Config:   iniPath,
	}))
	return cfg
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "conf", "defaults.ini")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "conf/defaults.ini not found")
		dir = parent
	}
}
