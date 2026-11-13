package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/login/authinfotest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

const navigationSessionToken = "session-token-placeholder"

// sessionNavigationFixture serves the same middleware order as the running
// server for the two GET routes a variable-description anchor can navigate to.
type sessionNavigationFixture struct {
	macaron       *web.Macaron
	revoked       bool
	cookieCleared bool
	orgUpdates    []*user.UpdateUserCommand
}

func newSessionNavigationFixture(t *testing.T, appSubURL string) *sessionNavigationFixture {
	t.Helper()

	const viewerID int64 = 42

	cfg := setting.NewCfg()
	cfg.LoginCookieName = "grafana_session"
	cfg.AppSubURL = appSubURL
	cfg.TokenRotationIntervalMinutes = 10

	token := &auth.UserToken{
		Id:            7,
		UserId:        viewerID,
		UnhashedToken: navigationSessionToken,
		AuthTokenSeen: true,
		RotatedAt:     time.Now().Unix(),
	}

	fx := &sessionNavigationFixture{}
	tokenService := &authtest.FakeUserAuthTokenService{
		LookupTokenProvider: func(_ context.Context, raw string) (*auth.UserToken, error) {
			if raw != navigationSessionToken {
				return nil, auth.ErrUserTokenNotFound
			}
			return token, nil
		},
		RevokeTokenProvider: func(_ context.Context, revoked *auth.UserToken, soft bool) error {
			if revoked != nil && !soft {
				fx.revoked = true
			}
			return nil
		},
	}
	authInfo := &authinfotest.FakeService{ExpectedError: user.ErrUserNotFound}
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)

	tracer := tracing.InitializeTracerForTest()
	authnService := authnimpl.ProvideService(cfg, tracer, tokenService, &usagestats.NoopUsageStats{}, nil, authInfo)
	authnService.RegisterClient(clients.ProvideSession(cfgProvider, tokenService, authInfo, tracer))

	userService := usertest.NewUserServiceFake()
	userService.UpdateFn = func(_ context.Context, cmd *user.UpdateUserCommand) error {
		fx.orgUpdates = append(fx.orgUpdates, cmd)
		return nil
	}
	orgService := orgtest.NewOrgServiceFake()
	orgService.ExpectedUserOrgDTO = []*org.UserOrgDTO{{OrgID: 1}, {OrgID: 2}, {OrgID: 15}}

	hs := &HTTPServer{
		Cfg:          cfg,
		log:          log.NewNopLogger(),
		authnService: authnService,
		userService:  userService,
		orgService:   orgService,
	}
	ctxHandler := contexthandler.ProvideService(cfg, authnService, featuremgmt.WithFeatures())

	m := web.New()
	if appSubURL != "" {
		m.SetURLPrefix(appSubURL)
	}
	m.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	m.UseMiddleware(ctxHandler.Middleware)
	m.Get("/logout", hs.Logout)
	m.Get("/profile/switch-org/:id", middleware.ReqSignedInNoAnonymous, hs.ChangeActiveOrgAndRedirectToHome)

	fx.macaron = m
	return fx
}

func (fx *sessionNavigationFixture) navigate(t *testing.T, rawURL, origin string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, rawURL, nil)
	req.AddCookie(&http.Cookie{
		Name:  "grafana_session",
		Value: url.QueryEscape(navigationSessionToken),
	})
	if origin != "" {
		req.Header.Set("Origin", origin)
	}

	rec := httptest.NewRecorder()
	fx.macaron.ServeHTTP(rec, req)
	return rec
}

func (fx *sessionNavigationFixture) sessionUntouched(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "grafana_session" {
			fx.cookieCleared = true
		}
	}
	if len(fx.orgUpdates) > 0 {
		orgID := int64(0)
		if fx.orgUpdates[0].OrgID != nil {
			orgID = *fx.orgUpdates[0].OrgID
		}
		t.Fatalf("GET navigation set active organization to %d for user %d, status %d", orgID, fx.orgUpdates[0].UserID, rec.Code)
	}
	if fx.revoked {
		t.Fatalf("GET navigation revoked the session, status %d", rec.Code)
	}
	if fx.cookieCleared {
		t.Fatalf("GET navigation cleared the session cookie, status %d", rec.Code)
	}
}

func TestVariableDescriptionNavigationDoesNotChangeSession(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		rawURL string
		origin string
		subURL string
	}{
		{name: "logout without an Origin header", rawURL: "http://localhost:3000/logout"},
		{name: "logout with the same host as Origin", rawURL: "http://localhost:3000/logout", origin: "http://localhost:3000"},
		{name: "logout with a query string", rawURL: "http://localhost:3000/logout?continue=1"},
		{name: "percent-encoded logout path", rawURL: "http://localhost:3000/%6Cogout"},
		{name: "logout under the server subpath", rawURL: "http://localhost:3000/grafana/logout", subURL: "/grafana"},
		{name: "organization switch without an Origin header", rawURL: "http://localhost:3000/profile/switch-org/2"},
		{name: "organization switch with the same host as Origin", rawURL: "http://localhost:3000/profile/switch-org/2", origin: "http://localhost:3000"},
		{name: "organization switch under the server subpath", rawURL: "http://localhost:3000/grafana/profile/switch-org/15", subURL: "/grafana"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fx := newSessionNavigationFixture(t, tc.subURL)
			rec := fx.navigate(t, tc.rawURL, tc.origin)
			fx.sessionUntouched(t, rec)
		})
	}
}

func TestCrossSiteGetDoesNotChangeSession(t *testing.T) {
	t.Parallel()

	fx := newSessionNavigationFixture(t, "")
	rec := fx.navigate(t, "http://localhost:3000/logout", "https://evil.example")
	fx.sessionUntouched(t, rec)
	require.Equal(t, http.StatusForbidden, rec.Code)
}
