package authn

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/models/usertoken"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
)

const placeholderSessionToken = "placeholder-session-token"

func TestSessionCookieSecure_LoginHandlersWithholdSessionFromCleartext(t *testing.T) {
	cfg := loadShippedConfig(t, `
[server]
protocol = http
domain = grafana.example.com
root_url = https://grafana.example.com/
`)
	require.Equal(t, "https://grafana.example.com/", cfg.AppURL)

	identity := &Identity{SessionToken: &usertoken.UserToken{
		Id:            1,
		UserId:        1,
		UnhashedToken: placeholderSessionToken,
		AuthTokenSeen: true,
		RotatedAt:     time.Now().Unix(),
	}}
	features := featuremgmt.WithFeatures()
	validator := func(target string) (string, error) { return target, nil }
	page := mustURL(t, cfg.AppURL)
	clear := *page
	clear.Scheme = "http"

	t.Run("form login", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, page.String()+"login", nil)
		rec := httptest.NewRecorder()
		HandleLoginResponse(req, rec, cfg, identity, validator, features)
		assertSessionWithheldFromCleartext(t, page, &clear, rec, cfg.LoginCookieName)
	})

	t.Run("oauth redirect", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, page.String()+"login/generic_oauth", nil)
		rec := httptest.NewRecorder()
		HandleLoginRedirect(req, rec, cfg, identity, validator, features)
		assertSessionWithheldFromCleartext(t, page, &clear, rec, cfg.LoginCookieName)
	})

	t.Run("redirect response", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, page.String()+"login/generic_oauth", nil)
		rec := httptest.NewRecorder()
		HandleLoginRedirectResponse(req, rec, cfg, identity, validator, features, "")
		assertSessionWithheldFromCleartext(t, page, &clear, rec, cfg.LoginCookieName)
	})
}

func assertSessionWithheldFromCleartext(t *testing.T, page, clear *url.URL, rec *httptest.ResponseRecorder, name string) {
	t.Helper()
	issued := setCookieByName(t, rec, name)
	require.True(t, issued.Secure, "grafana_session Set-Cookie is missing Secure")
	require.True(t, issued.HttpOnly)

	expiry := setCookieByName(t, rec, sessionExpiryCookie)
	require.True(t, expiry.Secure, "grafana_session_expiry Set-Cookie is missing Secure")

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	jar.SetCookies(page, rec.Result().Cookies())
	for _, c := range jar.Cookies(clear) {
		require.NotEqual(t, name, c.Name, "user agent attached grafana_session to a cleartext request")
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
