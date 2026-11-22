package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	claims "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/models/usertoken"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// sessionTokenPlaceholder is a stand-in for the victim's session cookie value.
const sessionTokenPlaceholder = "session-token-placeholder"

// rotatedTokenPlaceholder is a stand-in for the token issued by rotation.
const rotatedTokenPlaceholder = "rotated-token-placeholder"

// TestTokenRotationGetRedirectDoesNotEndSession is the spec for the session-rotation GET.
// A caller-supplied redirect must not be followed, and following the response must not
// delete the session cookie. Logout targets are rejected by the shared redirect allowlist.
func TestTokenRotationGetRedirectDoesNotEndSession(t *testing.T) {
	cfg := loadDefaultTestCfg(t)
	features, err := featuremgmt.ProvideManagerService(cfg)
	require.NoError(t, err)
	require.True(t, features.IsEnabledGlobally(featuremgmt.FlagUseSessionStorageForRedirection),
		"useSessionStorageForRedirection is on in the default configuration")

	srv := newRotationHTTPServer(t, cfg, features)

	t.Run("cross-site origin is rejected before rotation", func(t *testing.T) {
		status, locations, session := rotateAndFollow(t, srv, cfg, "/logout", nil, "http://attacker.example")
		require.Equal(t, http.StatusForbidden, status)
		assert.Empty(t, locations)
		require.NotNil(t, session)
		assert.Equal(t, sessionTokenPlaceholder, session.Value)
	})

	redirects := []string{
		"/logout",
		"/logout/",
		"/logout?next=/",
		"/logout/saml",
		"/explore",
	}
	for _, redirectTo := range redirects {
		t.Run("query "+redirectTo, func(t *testing.T) {
			status, locations, session := rotateAndFollow(t, srv, cfg, redirectTo, nil, "")
			require.NotEqual(t, http.StatusForbidden, status, "a top-level navigation without Origin must reach the handler")
			assertFixedRotationRedirect(t, cfg, locations)
			require.NotNil(t, session, "session cookie was deleted while following redirects: %v", locations)
			assert.NotEmpty(t, session.Value)
			for _, loc := range locations {
				assert.Falsef(t, isLogoutLocation(loc), "rotation redirected to logout via %s", loc)
			}
		})
	}

	t.Run("cookie redirect when session storage flag is off", func(t *testing.T) {
		off := newRotationHTTPServer(t, cfg, featuremgmt.WithFeatures())
		status, locations, session := rotateAndFollow(t, off, cfg, "", []*http.Cookie{{
			Name:  "redirect_to",
			Value: url.QueryEscape("/logout"),
			Path:  "/",
		}}, "")
		require.NotEqual(t, http.StatusForbidden, status)
		assertFixedRotationRedirect(t, cfg, locations)
		require.NotNil(t, session, "session cookie was deleted while following redirects: %v", locations)
		for _, loc := range locations {
			assert.Falsef(t, isLogoutLocation(loc), "rotation redirected to logout via %s", loc)
		}
	})
}

func TestValidateRedirectToRejectsLogout(t *testing.T) {
	cfg := setting.NewCfg()
	hs := &HTTPServer{Cfg: cfg}

	for _, redirectTo := range []string{
		"/logout",
		"/logout/",
		"/logout?next=/",
		"/logout/saml",
	} {
		t.Run(redirectTo, func(t *testing.T) {
			_, err := hs.ValidateRedirectTo(redirectTo)
			require.Error(t, err)
		})
	}

	t.Run("subpath", func(t *testing.T) {
		hs.Cfg.AppSubURL = "/grafana"
		_, err := hs.ValidateRedirectTo("/grafana/logout")
		require.Error(t, err)
	})
}

func TestOAuthLoginRedirectDoesNotTargetLogout(t *testing.T) {
	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = setting.NewCfg()
		hs.Cfg.LoginCookieName = "grafana_session"
		hs.Cfg.LoginMaxLifetime = 24 * time.Hour
		hs.Features = featuremgmt.WithFeatures(featuremgmt.FlagUseSessionStorageForRedirection)
		hs.log = log.NewNopLogger()
		hs.authnService = &authntest.FakeService{
			ExpectedRedirect: &authn.Redirect{
				URL: "https://oauth-provider.example/authorize",
				Extra: map[string]string{
					authn.KeyOAuthState: "oauth-state-placeholder",
				},
			},
		}
	})
	server.HttpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	res, err := server.Send(server.NewGetRequest("/login/generic_oauth?redirectTo=" + url.QueryEscape("/logout")))
	require.NoError(t, err)
	defer func() { require.NoError(t, res.Body.Close()) }()
	require.Equal(t, http.StatusFound, res.StatusCode)

	var redirectCookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "redirectTo" {
			redirectCookie = c
			break
		}
	}
	require.NotNil(t, redirectCookie)

	req := httptest.NewRequest(http.MethodGet, "http://localhost/login/generic_oauth?code=oauth-code-placeholder", nil)
	req.AddCookie(redirectCookie)
	rr := httptest.NewRecorder()
	identity := &authn.Identity{
		ID:   "1",
		Type: claims.TypeUser,
		SessionToken: &usertoken.UserToken{
			UnhashedToken: rotatedTokenPlaceholder,
		},
	}
	authn.HandleLoginRedirect(req, rr, serverRouteCfg(t), identity, (&HTTPServer{Cfg: setting.NewCfg()}).ValidateRedirectTo, featuremgmt.WithFeatures(featuremgmt.FlagUseSessionStorageForRedirection))

	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	assert.False(t, isLogoutLocation(loc.Path), "post-login redirect Location = %s", rr.Header().Get("Location"))
	assertFixedOrEmpty(t, "", loc.Path)
}

func serverRouteCfg(t *testing.T) *setting.Cfg {
	t.Helper()
	cfg := setting.NewCfg()
	cfg.LoginCookieName = "grafana_session"
	cfg.LoginMaxLifetime = 24 * time.Hour
	return cfg
}

func loadDefaultTestCfg(t *testing.T) *setting.Cfg {
	t.Helper()
	prevMode := setting.CookieSameSiteMode
	prevDisabled := setting.CookieSameSiteDisabled
	prevSecure := setting.CookieSecure
	t.Cleanup(func() {
		setting.CookieSameSiteMode = prevMode
		setting.CookieSameSiteDisabled = prevDisabled
		setting.CookieSecure = prevSecure
	})

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: "../../",
		Config:   "../../conf/defaults.ini",
	}))
	require.Equal(t, http.SameSiteLaxMode, cfg.CookieSameSiteMode)
	require.Equal(t, "grafana_session", cfg.LoginCookieName)
	return cfg
}

func newRotationHTTPServer(t *testing.T, cfg *setting.Cfg, features featuremgmt.FeatureToggles) *httptest.Server {
	t.Helper()

	hs := &HTTPServer{
		Cfg:      cfg,
		Features: features,
		log:      log.New("rotation-redirect-test"),
		AuthTokenService: &authtest.FakeUserAuthTokenService{
			RotateTokenProvider: func(ctx context.Context, cmd auth.RotateCommand) (*auth.UserToken, error) {
				if cmd.UnHashedToken != sessionTokenPlaceholder {
					return nil, auth.ErrInvalidSessionToken
				}
				return &auth.UserToken{UnhashedToken: rotatedTokenPlaceholder}, nil
			},
		},
		authnService: &rotationLogoutService{redirectURL: cfg.AppSubURL + "/login"},
	}

	// Same registration as HTTPServer.registerRoutes: neither route is inside the
	// signed-in group, and both sit behind the global CSRF and context middleware.
	m := web.New()
	m.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	m.UseMiddleware(contexthandler.ProvideService(cfg, hs.authnService, features).Middleware)
	m.Get("/user/auth-tokens/rotate", routing.Wrap(hs.RotateUserAuthTokenRedirect))
	m.Get("/logout", hs.Logout)

	server := httptest.NewServer(m)
	t.Cleanup(server.Close)
	return server
}

// rotationLogoutService returns the same post-logout redirect the authn service returns
// before it revokes a token. Cookie deletion is performed by HTTPServer.Logout.
type rotationLogoutService struct {
	authntest.FakeService
	redirectURL string
}

func (s *rotationLogoutService) Authenticate(context.Context, *authn.Request) (*authn.Identity, error) {
	return nil, errors.New("no signed-in identity")
}

func (s *rotationLogoutService) Logout(context.Context, identity.Requester, *usertoken.UserToken) (*authn.Redirect, error) {
	return &authn.Redirect{URL: s.redirectURL}, nil
}

func rotateAndFollow(t *testing.T, srv *httptest.Server, cfg *setting.Cfg, redirectTo string, extra []*http.Cookie, origin string) (int, []string, *http.Cookie) {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	base, err := url.Parse(srv.URL)
	require.NoError(t, err)
	seed := []*http.Cookie{{
		Name:  cfg.LoginCookieName,
		Value: sessionTokenPlaceholder,
		Path:  "/",
	}}
	seed = append(seed, extra...)
	jar.SetCookies(base, seed)

	var locations []string
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow a logout redirect so the test observes the session cookie being cleared.
			// Stop before any other hop so the login page does not have to render.
			locations = append(locations, req.URL.RequestURI())
			if isLogoutLocation(req.URL.Path) {
				return nil
			}
			return http.ErrUseLastResponse
		},
	}

	target := srv.URL + "/user/auth-tokens/rotate"
	if redirectTo != "" {
		target += "?redirectTo=" + url.QueryEscape(redirectTo)
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}

	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	var session *http.Cookie
	for _, c := range jar.Cookies(base) {
		if c.Name == cfg.LoginCookieName && c.Value != "" {
			session = c
			break
		}
	}
	return resp.StatusCode, locations, session
}

func assertFixedRotationRedirect(t *testing.T, cfg *setting.Cfg, locations []string) {
	t.Helper()
	if len(locations) == 0 {
		return
	}
	u, err := url.Parse(locations[0])
	require.NoError(t, err)
	assert.Truef(t, isFixedAppPath(cfg.AppSubURL, u.Path), "rotation Location path = %q, full hop %q", u.Path, locations[0])
}

func assertFixedOrEmpty(t *testing.T, appSubURL, path string) {
	t.Helper()
	if path == "" {
		return
	}
	assert.Truef(t, isFixedAppPath(appSubURL, path), "redirect path = %q", path)
}

func isFixedAppPath(appSubURL, path string) bool {
	if appSubURL == "" {
		return path == "/" || path == "/login"
	}
	return path == appSubURL+"/" || path == appSubURL+"/login"
}

func isLogoutLocation(path string) bool {
	return path == "/logout" || strings.HasPrefix(path, "/logout/")
}
