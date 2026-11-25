package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

const placeholderSessionToken = "placeholder-session-token"

func TestSubresourceGetDoesNotMutateViewerSession(t *testing.T) {
	cases := []struct {
		name string
		dest string
		mode string
	}{
		{name: "image", dest: "image", mode: "no-cors"},
		{name: "audio", dest: "audio", mode: "no-cors"},
		{name: "video", dest: "video", mode: "no-cors"},
		{name: "iframe", dest: "iframe", mode: "navigate"},
	}

	for _, tc := range cases {
		t.Run("logout "+tc.name, func(t *testing.T) {
			h := newSessionHarness(t)
			rec := h.get("/logout", tc.dest, tc.mode)
			require.Falsef(t, h.revoked, "GET /logout as %s revoked the session (status %d)", tc.dest, rec.Code)
			require.Falsef(t, cookieCleared(rec), "GET /logout as %s cleared the session cookie: %v", tc.dest, rec.Header().Values("Set-Cookie"))
		})

		t.Run("switch org "+tc.name, func(t *testing.T) {
			h := newSessionHarness(t)
			rec := h.get("/profile/switch-org/2", tc.dest, tc.mode)
			require.Falsef(t, h.orgUpdated, "GET /profile/switch-org/2 as %s changed the active org (status %d)", tc.dest, rec.Code)
		})
	}
}

func TestDocumentNavigationLogoutStillRevokesSession(t *testing.T) {
	h := newSessionHarness(t)
	rec := h.get("/logout", "document", "navigate")
	require.Truef(t, h.revoked, "a top-level logout navigation must still revoke the session, status %d", rec.Code)
	require.True(t, cookieCleared(rec), "a top-level logout navigation must still clear the session cookie")
}

type sessionHarness struct {
	t          *testing.T
	mux        *web.Mux
	revoked    bool
	orgUpdated bool
	lookedUp   bool
}

func newSessionHarness(t *testing.T) *sessionHarness {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.LoginCookieName = "grafana_session"
	cfg.CookieSameSiteMode = http.SameSiteLaxMode

	h := &sessionHarness{t: t}
	token := &auth.UserToken{
		Id:            11,
		UserId:        7,
		AuthTokenSeen: true,
		RotatedAt:     time.Now().Add(time.Hour).Unix(),
		UnhashedToken: placeholderSessionToken,
	}
	tokens := &authtest.FakeUserAuthTokenService{
		LookupTokenProvider: func(_ context.Context, raw string) (*auth.UserToken, error) {
			h.lookedUp = true
			require.Equal(t, placeholderSessionToken, raw)
			return token, nil
		},
		RevokeTokenProvider: func(_ context.Context, got *auth.UserToken, soft bool) error {
			h.revoked = true
			require.Equal(t, token, got)
			require.False(t, soft)
			return nil
		},
	}
	authInfo := &authinfotest.FakeService{ExpectedError: user.ErrUserNotFound}
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)

	authnService := authnimpl.ProvideService(cfg, tracing.InitializeTracerForTest(), tokens, &usagestats.NoopUsageStats{}, nil, authInfo)
	authnService.RegisterClient(clients.ProvideSession(cfgProvider, tokens, authInfo, tracing.InitializeTracerForTest()))

	targetOrg := int64(2)
	users := &usertest.FakeUserService{
		UpdateFn: func(_ context.Context, cmd *user.UpdateUserCommand) error {
			if cmd.OrgID != nil && *cmd.OrgID == targetOrg {
				h.orgUpdated = true
			}
			return nil
		},
	}
	orgs := &orgtest.FakeOrgService{
		ExpectedUserOrgDTO: []*org.UserOrgDTO{
			{OrgID: 1, Name: "Main", Role: org.RoleViewer},
			{OrgID: targetOrg, Name: "Other", Role: org.RoleViewer},
		},
	}

	hs := &HTTPServer{
		Cfg:          cfg,
		log:          log.New("test"),
		authnService: authnService,
		userService:  users,
		orgService:   orgs,
		Features:     featuremgmt.WithFeatures(),
	}

	mux := web.New()
	mux.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	mux.UseMiddleware(contexthandler.ProvideService(cfg, authnService, featuremgmt.WithFeatures()).Middleware)
	mux.Use(middleware.OrgRedirect(cfg, users))
	mux.Get("/logout", hs.Logout)
	mux.Get("/profile/switch-org/:id", hs.ChangeActiveOrgAndRedirectToHome)
	h.mux = mux
	return h
}

func (h *sessionHarness) get(path, dest, mode string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "grafana.example"
	req.Header.Set("Sec-Fetch-Dest", dest)
	req.Header.Set("Sec-Fetch-Mode", mode)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(&http.Cookie{Name: "grafana_session", Value: placeholderSessionToken})
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	require.Truef(h.t, h.lookedUp, "session cookie was not presented to the session client for %s %s", dest, path)
	return rec
}

func cookieCleared(rec *httptest.ResponseRecorder) bool {
	for _, line := range rec.Header().Values("Set-Cookie") {
		if strings.Contains(line, "grafana_session=") && strings.Contains(line, "Max-Age=0") {
			return true
		}
	}
	return false
}
