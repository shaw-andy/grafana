package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/models/usertoken"
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

// placeholderSession is not a real session secret. The test only checks that the
// value carried by the session cookie is enough for these GETs to run as the viewer.
const placeholderSession = "placeholder-session"

func imageLikeGET(t *testing.T, target string, withOrigin bool) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Cookie", "grafana_session="+placeholderSession)
	req.Header.Set("Sec-Fetch-Dest", "image")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Accept", "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5")
	if withOrigin {
		req.Header.Set("Origin", "http://"+req.Host)
	}
	return req
}

type subresourceHarness struct {
	mux       *web.Mux
	revoked   bool
	rotated   bool
	orgWrites []int64
}

func newSubresourceHarness(t *testing.T) *subresourceHarness {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.LoginCookieName = "grafana_session"
	cfg.TokenRotationIntervalMinutes = 10

	sessionToken := &usertoken.UserToken{
		Id:            1,
		UserId:        1,
		AuthTokenSeen: true,
		RotatedAt:     time.Now().Unix(),
	}

	h := &subresourceHarness{}
	tokens := &authtest.FakeUserAuthTokenService{
		LookupTokenProvider: func(_ context.Context, unhashedToken string) (*auth.UserToken, error) {
			if unhashedToken != placeholderSession {
				return nil, auth.ErrUserTokenNotFound
			}
			return sessionToken, nil
		},
		RevokeTokenProvider: func(_ context.Context, _ *auth.UserToken, _ bool) error {
			h.revoked = true
			return nil
		},
		RotateTokenProvider: func(_ context.Context, _ auth.RotateCommand) (*auth.UserToken, error) {
			h.rotated = true
			return sessionToken, nil
		},
	}

	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	sessionClient := clients.ProvideSession(
		cfgProvider,
		tokens,
		&authinfotest.FakeService{ExpectedError: user.ErrUserNotFound},
		tracing.InitializeTracerForTest(),
	)

	authnService := authnimpl.ProvideService(
		cfg,
		tracing.InitializeTracerForTest(),
		tokens,
		noopUsageStats{},
		nil,
		&authinfotest.FakeService{ExpectedError: user.ErrUserNotFound},
	)
	authnService.RegisterClient(sessionClient)

	users := &usertest.FakeUserService{
		UpdateFn: func(_ context.Context, cmd *user.UpdateUserCommand) error {
			if cmd.OrgID != nil {
				h.orgWrites = append(h.orgWrites, *cmd.OrgID)
			}
			return nil
		},
	}
	orgs := &orgtest.FakeOrgService{
		ExpectedUserOrgDTO: []*org.UserOrgDTO{
			{OrgID: 1, Name: "Main", Role: org.RoleViewer},
			{OrgID: 2, Name: "Other", Role: org.RoleViewer},
		},
	}

	hs := &HTTPServer{
		Cfg:              cfg,
		log:              log.NewNopLogger(),
		authnService:     authnService,
		AuthTokenService: tokens,
		userService:      users,
		orgService:       orgs,
	}

	mux := web.New()
	mux.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	mux.UseMiddleware(contexthandler.ProvideService(cfg, authnService, featuremgmt.WithFeatures()).Middleware)
	mux.Get("/logout", hs.Logout)
	mux.Get("/profile/switch-org/:id", hs.ChangeActiveOrgAndRedirectToHome)
	mux.Get("/user/auth-tokens/rotate", routing.Wrap(hs.RotateUserAuthTokenRedirect))
	h.mux = mux
	return h
}

func (h *subresourceHarness) serve(req *http.Request) *httptest.ResponseRecorder {
	resp := httptest.NewRecorder()
	h.mux.ServeHTTP(resp, req)
	return resp
}

func sessionCookieCleared(resp *httptest.ResponseRecorder) bool {
	for _, cookie := range resp.Result().Cookies() {
		if cookie.Name == "grafana_session" && (cookie.MaxAge < 0 || cookie.Value == "") {
			return true
		}
	}
	return false
}

func TestImageGetDoesNotChangeTheViewerSession(t *testing.T) {
	for _, withOrigin := range []bool{false, true} {
		name := "without origin"
		if withOrigin {
			name = "with same-origin origin"
		}
		t.Run(name, func(t *testing.T) {
			t.Run("logout", func(t *testing.T) {
				h := newSubresourceHarness(t)
				resp := h.serve(imageLikeGET(t, "http://grafana.example/logout", withOrigin))

				require.Falsef(t, h.revoked, "session token was revoked, status %d", resp.Code)
				require.Falsef(t, sessionCookieCleared(resp), "session cookie was cleared, status %d", resp.Code)
			})

			t.Run("switch organization", func(t *testing.T) {
				h := newSubresourceHarness(t)
				resp := h.serve(imageLikeGET(t, "http://grafana.example/profile/switch-org/2", withOrigin))

				require.Emptyf(t, h.orgWrites, "active organization was changed, status %d, orgs %v", resp.Code, h.orgWrites)
			})

			t.Run("rotate token", func(t *testing.T) {
				h := newSubresourceHarness(t)
				resp := h.serve(imageLikeGET(t, "http://grafana.example/user/auth-tokens/rotate", withOrigin))

				require.Falsef(t, h.rotated, "session token was rotated, status %d", resp.Code)
			})
		})
	}
}

type noopUsageStats struct{}

func (noopUsageStats) GetUsageReport(context.Context) (usagestats.Report, error) {
	return usagestats.Report{}, nil
}

func (noopUsageStats) RegisterMetricsFunc(usagestats.MetricsFunc) {}

func (noopUsageStats) RegisterSendReportCallback(usagestats.SendReportCallbackFunc) {}

func (noopUsageStats) SetReadyToReport(context.Context) {}
