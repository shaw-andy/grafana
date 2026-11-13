package middleware

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

func TestSessionCookieSecure_RedirectCookieWithheldFromCleartext(t *testing.T) {
	cfg := loadShippedConfig(t, `
[server]
protocol = http
domain = grafana.example.com
root_url = https://grafana.example.com/
`)
	require.Equal(t, "https://grafana.example.com/", cfg.AppURL)

	req := httptest.NewRequest(http.MethodGet, cfg.AppURL+"d/abc", nil)
	req.RequestURI = "/d/abc"
	rec := httptest.NewRecorder()
	writeRedirectCookie(&contextmodel.ReqContext{
		Context: &web.Context{Req: req, Resp: web.NewResponseWriter(req.Method, rec)},
		Logger:  log.NewNopLogger(),
	})

	page := mustURL(t, cfg.AppURL)
	clear := *page
	clear.Scheme = "http"
	issued := setCookieByName(t, rec, "redirect_to")
	require.True(t, issued.Secure, "redirect_to Set-Cookie is missing Secure")

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	jar.SetCookies(page, rec.Result().Cookies())
	for _, c := range jar.Cookies(&clear) {
		require.NotEqual(t, "redirect_to", c.Name, "user agent attached redirect_to to a cleartext request")
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
