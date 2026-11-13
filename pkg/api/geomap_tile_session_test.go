package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/models/usertoken"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/login/authinfotest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// placeholderSession is not a credential. The session client only compares it to the
// value presented in the grafana_session cookie.
const placeholderSession = "placeholder-session"

const tileSessionUserID int64 = 42
const tileSessionTargetOrg int64 = 2

// tileSessionHarness is the production route stack for the two GET handlers a Geomap
// tile image can reach: CSRF, then authentication from the session cookie, then
// GET /logout and GET /profile/switch-org/:id.
type tileSessionHarness struct {
	cfg        *setting.Cfg
	mux        *web.Mux
	revoked    []*usertoken.UserToken
	orgUpdates []*user.UpdateUserCommand
}

func newTileSessionHarness(t *testing.T) *tileSessionHarness {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.LoginCookieName = "grafana_session"
	cfg.TokenRotationIntervalMinutes = 10

	h := &tileSessionHarness{cfg: cfg}
	token := &usertoken.UserToken{
		Id:            7,
		UserId:        tileSessionUserID,
		AuthTokenSeen: true,
		RotatedAt:     time.Now().Unix(),
		UnhashedToken: placeholderSession,
	}
	tokens := authtest.NewFakeUserAuthTokenService()
	tokens.LookupTokenProvider = func(_ context.Context, unhashedToken string) (*usertoken.UserToken, error) {
		if unhashedToken != placeholderSession {
			return nil, user.ErrUserNotFound
		}
		return token, nil
	}
	tokens.RevokeTokenProvider = func(_ context.Context, got *usertoken.UserToken, _ bool) error {
		h.revoked = append(h.revoked, got)
		return nil
	}

	authInfo := &authinfotest.FakeService{ExpectedError: user.ErrUserNotFound}
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)

	authnSvc := authnimpl.ProvideService(cfg, tracing.NewNoopTracerService(), tokens, &usagestats.NoopUsageStats{}, nil, authInfo)
	authnSvc.RegisterClient(clients.ProvideSession(cfgProvider, tokens, authInfo, noop.NewTracerProvider().Tracer("tile-session-test")))

	users := usertest.NewUserServiceFake()
	users.UpdateFn = func(_ context.Context, cmd *user.UpdateUserCommand) error {
		h.orgUpdates = append(h.orgUpdates, cmd)
		return nil
	}
	orgs := &orgtest.FakeOrgService{
		ExpectedUserOrgDTO: []*org.UserOrgDTO{{OrgID: 1}, {OrgID: tileSessionTargetOrg}},
	}

	hs := &HTTPServer{
		Cfg:          cfg,
		log:          log.NewNopLogger(),
		authnService: authnSvc,
		userService:  users,
		orgService:   orgs,
	}

	m := web.New()
	m.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	m.Use(contexthandler.ProvideService(cfg, authnSvc, featuremgmt.WithFeatures()).Middleware)
	m.Get("/logout", func(c *contextmodel.ReqContext) {
		hs.Logout(c)
	})
	m.Get("/profile/switch-org/:id", middleware.ReqSignedInNoAnonymous, func(c *contextmodel.ReqContext) {
		hs.ChangeActiveOrgAndRedirectToHome(c)
	})
	h.mux = m
	return h
}

// imageRequest is the request Chrome makes for a same-origin tile image: a GET that
// carries the session cookie and does not send an Origin header.
func (h *tileSessionHarness) imageRequest(t *testing.T, path string, origin string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(&http.Cookie{Name: h.cfg.LoginCookieName, Value: placeholderSession})
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp := httptest.NewRecorder()
	h.mux.ServeHTTP(resp, req)
	return resp
}

func (h *tileSessionHarness) sessionCookieCleared(t *testing.T, resp *httptest.ResponseRecorder) bool {
	t.Helper()
	for _, cookie := range resp.Result().Cookies() {
		if cookie.Name == h.cfg.LoginCookieName && (cookie.MaxAge < 0 || cookie.Value == "") {
			return true
		}
	}
	return false
}

func TestGeomapTileImageDoesNotLogOut(t *testing.T) {
	h := newTileSessionHarness(t)

	resp := h.imageRequest(t, "http://grafana.example/logout", "")

	require.False(t, h.sessionCookieCleared(t, resp), "GET /logout from a tile image cleared grafana_session")
	require.Empty(t, h.revoked, "GET /logout from a tile image revoked the session")
}

func TestGeomapTileImageDoesNotSwitchOrg(t *testing.T) {
	h := newTileSessionHarness(t)

	resp := h.imageRequest(t, "http://grafana.example/profile/switch-org/2", "")

	require.Empty(t, h.orgUpdates, "GET /profile/switch-org/2 from a tile image changed the active organization")
	require.False(t, h.sessionCookieCleared(t, resp), "organization switch cleared grafana_session")
}

func TestGeomapTileImageWithForeignOriginDoesNotMutate(t *testing.T) {
	h := newTileSessionHarness(t)

	logout := h.imageRequest(t, "http://grafana.example/logout", "http://evil.example")
	require.False(t, h.sessionCookieCleared(t, logout))
	require.Empty(t, h.revoked)

	switched := h.imageRequest(t, "http://grafana.example/profile/switch-org/2", "http://evil.example")
	require.Empty(t, h.orgUpdates)
	require.False(t, h.sessionCookieCleared(t, switched))
}
