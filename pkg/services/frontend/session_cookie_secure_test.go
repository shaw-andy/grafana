package frontend

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
	fswebassets "github.com/grafana/grafana/pkg/services/frontend/webassets"
	"github.com/grafana/grafana/pkg/setting"
)

func TestSessionCookieSecure_PreviewCookiesWithheldFromCleartext(t *testing.T) {
	cfg := loadShippedConfig(t, `
[server]
protocol = http
domain = grafana.example.com
root_url = https://grafana.example.com/
`)
	require.Equal(t, "https://grafana.example.com/", cfg.AppURL)

	handler := newPreviewAssetsHandler(cfg, fswebassets.PreviewAssetsConfig{})
	rec := httptest.NewRecorder()
	handler.setCookie(rec, previewAssetsCookieName, "placeholder-folder", int(previewCookieMaxAge.Seconds()))
	handler.renderConfirmationPage(rec, log.NewNopLogger(), "placeholder-folder", "https://grafana.example.com/public/build")

	page := mustURL(t, cfg.AppURL)
	clear := *page
	clear.Scheme = "http"
	// The CSRF cookie is scoped to the preview confirmation path. Ask for that
	// path so a missing Secure flag is what keeps it off the cleartext request.
	clear.Path = previewAssetsPath
	for _, name := range []string{previewAssetsCookieName, previewCSRFCookieName} {
		issued := setCookieByName(t, rec, name)
		require.True(t, issued.Secure, "%s Set-Cookie is missing Secure", name)
	}

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	jar.SetCookies(page, rec.Result().Cookies())
	for _, c := range jar.Cookies(&clear) {
		require.NotEqual(t, previewAssetsCookieName, c.Name, "user agent attached preview cookie to a cleartext request")
		require.NotEqual(t, previewCSRFCookieName, c.Name, "user agent attached preview CSRF cookie to a cleartext request")
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
