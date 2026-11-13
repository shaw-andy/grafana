package clients

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
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/login/authinfotest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

// placeholderSessionToken is an obvious stand-in for the unhashed session token.
// The tests never need a real credential.
const placeholderSessionToken = "placeholder-session-token"

// TestSessionCookieSecure_HTTPSPublicURLWithholdsSessionFromCleartext is the
// shipped-default attack: cookie_secure is left unset, the public URL is HTTPS,
// and a user agent that honors the Secure attribute must not attach
// grafana_session to a later cleartext request for that host. Presenting the
// cookie on an HTTP request still authenticates, which is what a TLS-terminating
// proxy does and what a replay of an already copied cookie does.
func TestSessionCookieSecure_HTTPSPublicURLWithholdsSessionFromCleartext(t *testing.T) {
	cases := []struct {
		name string
		ini  string
		page string
	}{
		{
			name: "reverse proxy public URL",
			ini: `
[server]
protocol = http
domain = grafana.example.com
root_url = https://grafana.example.com/
`,
			page: "https://grafana.example.com/",
		},
		{
			name: "grafana terminates TLS",
			ini: `
[server]
protocol = https
domain = grafana.example.com
http_port = 3000
`,
			page: "https://grafana.example.com:3000/",
		},
		{
			name: "explicit cookie_secure false does not opt out of HTTPS",
			ini: `
[server]
protocol = http
domain = grafana.example.com
root_url = https://grafana.example.com/

[security]
cookie_secure = false
`,
			page: "https://grafana.example.com/",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadShippedConfig(t, tc.ini)
			require.Equal(t, tc.page, cfg.AppURL)

			page := mustURL(t, tc.page)
			clear := *page
			clear.Scheme = "http"

			rec := httptest.NewRecorder()
			authn.WriteSessionCookie(rec, cfg, placeholderToken())

			issued := setCookieByName(t, rec, cfg.LoginCookieName)
			require.True(t, issued.Secure, "grafana_session Set-Cookie is missing Secure")
			require.True(t, issued.HttpOnly)

			expiry := setCookieByName(t, rec, "grafana_session_expiry")
			require.True(t, expiry.Secure, "grafana_session_expiry Set-Cookie is missing Secure")

			client := newSessionClient(t, cfg)
			jarReq := requestWithJar(t, page, rec.Result().Cookies(), &clear)
			_, err := client.Authenticate(context.Background(), &authn.Request{HTTPRequest: jarReq})
			require.Error(t, err, "user agent attached grafana_session to a cleartext request")

			replay := httptest.NewRequest(http.MethodGet, clear.String(), nil)
			replay.AddCookie(issued)
			ident, err := client.Authenticate(context.Background(), &authn.Request{HTTPRequest: replay})
			require.NoError(t, err)
			require.Equal(t, "1", ident.ID)
		})
	}
}

// TestSessionCookieSecure_HTTPOnlyExplicitOptOutStillSendsSession keeps the
// opt-out for installs whose public URL is HTTP and that set cookie_secure = false.
func TestSessionCookieSecure_HTTPOnlyExplicitOptOutStillSendsSession(t *testing.T) {
	cfg := loadShippedConfig(t, `
[server]
protocol = http
domain = grafana.example.com
root_url = http://grafana.example.com/

[security]
cookie_secure = false
`)
	require.Equal(t, "http://grafana.example.com/", cfg.AppURL)
	require.False(t, cfg.CookieSecure)

	page := mustURL(t, cfg.AppURL)
	rec := httptest.NewRecorder()
	authn.WriteSessionCookie(rec, cfg, placeholderToken())

	issued := setCookieByName(t, rec, cfg.LoginCookieName)
	require.False(t, issued.Secure)

	client := newSessionClient(t, cfg)
	jarReq := requestWithJar(t, page, rec.Result().Cookies(), page)
	ident, err := client.Authenticate(context.Background(), &authn.Request{HTTPRequest: jarReq})
	require.NoError(t, err)
	require.Equal(t, "1", ident.ID)
}

// TestSessionCookieSecure_AuthnSettingsHTTPSPublicURLDoesNotUseStaleGlobal covers
// ApplyAuthnSettings, which parses cookie_secure before the public URL and does
// not copy the result onto the process-wide cookie flag. The session cookie is
// still written for that cfg and must not be attached to cleartext.
func TestSessionCookieSecure_AuthnSettingsHTTPSPublicURLDoesNotUseStaleGlobal(t *testing.T) {
	restoreCookieGlobals(t)
	setting.CookieSecure = false

	file := ini.Empty()
	server, err := file.NewSection("server")
	require.NoError(t, err)
	_, err = server.NewKey("root_url", "https://grafana.example.com/")
	require.NoError(t, err)

	cfg := setting.NewCfg()
	require.NoError(t, cfg.ApplyAuthnSettings(file))
	require.Equal(t, "https://grafana.example.com/", cfg.AppURL)
	require.False(t, setting.CookieSecure)

	// Path and SameSite still follow the process-wide values WriteCookie reads
	// when the login path passes a nil options func. Only Secure has to follow
	// this cfg's public URL.
	setting.AppSubUrl = cfg.AppSubURL
	setting.CookieSameSiteDisabled = cfg.CookieSameSiteDisabled
	setting.CookieSameSiteMode = cfg.CookieSameSiteMode

	page := mustURL(t, cfg.AppURL)
	clear := *page
	clear.Scheme = "http"

	rec := httptest.NewRecorder()
	authn.WriteSessionCookie(rec, cfg, placeholderToken())
	issued := setCookieByName(t, rec, cfg.LoginCookieName)
	require.True(t, issued.Secure, "grafana_session Set-Cookie is missing Secure")

	client := newSessionClient(t, cfg)
	jarReq := requestWithJar(t, page, rec.Result().Cookies(), &clear)
	_, err = client.Authenticate(context.Background(), &authn.Request{HTTPRequest: jarReq})
	require.Error(t, err, "user agent attached grafana_session to a cleartext request")
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

func newSessionClient(t *testing.T, cfg *setting.Cfg) *Session {
	t.Helper()
	provider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	return ProvideSession(provider, &authtest.FakeUserAuthTokenService{
		LookupTokenProvider: func(context.Context, string) (*auth.UserToken, error) {
			return &auth.UserToken{
				Id:            1,
				UserId:        1,
				AuthTokenSeen: true,
				RotatedAt:     time.Now().Unix(),
			}, nil
		},
	}, &authinfotest.FakeService{ExpectedError: user.ErrUserNotFound}, tracing.InitializeTracerForTest())
}

func requestWithJar(t *testing.T, page *url.URL, setCookies []*http.Cookie, next *url.URL) *http.Request {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	jar.SetCookies(page, setCookies)

	req := httptest.NewRequest(http.MethodGet, next.String(), nil)
	for _, c := range jar.Cookies(next) {
		req.AddCookie(c)
	}
	return req
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
	restoreCookieGlobals(t)

	dir := t.TempDir()
	iniPath := filepath.Join(dir, "custom.ini")
	body := "[log]\nmode = console\n" + extra
	require.NoError(t, os.WriteFile(iniPath, []byte(body), 0o600))

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: repoRoot(t),
		Config:   iniPath,
	}))
	return cfg
}

func restoreCookieGlobals(t *testing.T) {
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
