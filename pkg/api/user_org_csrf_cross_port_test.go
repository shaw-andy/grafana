package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn"
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

// placeholderSession is not a credential. The test only checks that this
// cookie value is the one mapped to the signed-in user.
const placeholderSession = "placeholder-session"

const signedInUserID int64 = 42
const targetOrgID int64 = 2

func TestCrossPortOriginCannotChangeActiveOrg(t *testing.T) {
	t.Parallel()

	t.Run("post switch org", func(t *testing.T) {
		t.Parallel()
		rr, updates := performOrgChange(t, orgChangeRequest{
			method: http.MethodPost,
			target: "/api/user/using/2",
			host:   "grafana.example.com:3000",
			origin: "http://grafana.example.com:8443",
		})
		require.Equal(t, http.StatusForbidden, rr.Code)
		require.Empty(t, updates, "active organization was changed for a cross-port Origin")
	})

	t.Run("get switch org", func(t *testing.T) {
		t.Parallel()
		rr, updates := performOrgChange(t, orgChangeRequest{
			method: http.MethodGet,
			target: "/profile/switch-org/2",
			host:   "grafana.example.com:3000",
			origin: "http://grafana.example.com:8443",
		})
		require.Equal(t, http.StatusForbidden, rr.Code)
		require.Empty(t, updates, "active organization was changed for a cross-port Origin")
	})

	t.Run("get orgId query redirect", func(t *testing.T) {
		t.Parallel()
		rr, updates := performOrgChange(t, orgChangeRequest{
			method: http.MethodGet,
			target: "/d/abc/my-dashboard?orgId=2",
			host:   "grafana.example.com:3000",
			origin: "http://grafana.example.com:8443",
		})
		require.Equal(t, http.StatusForbidden, rr.Code)
		require.Empty(t, updates, "active organization was changed for a cross-port Origin")
	})

	t.Run("same origin post still changes the signed-in user's org", func(t *testing.T) {
		t.Parallel()
		rr, updates := performOrgChange(t, orgChangeRequest{
			method: http.MethodPost,
			target: "/api/user/using/2",
			host:   "grafana.example.com:3000",
			origin: "http://grafana.example.com:3000",
		})
		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, []orgUpdate{{userID: signedInUserID, orgID: targetOrgID}}, updates)
	})
}

type orgChangeRequest struct {
	method string
	target string
	host   string
	origin string
}

type orgUpdate struct {
	userID int64
	orgID  int64
}

// sessionAuthenticator is the production session client. Test and Authenticate
// are the real cookie read, unescape, and token lookup calls.
type sessionAuthenticator struct {
	client *clients.Session
}

func (s sessionAuthenticator) Authenticate(ctx context.Context, r *authn.Request) (*authn.Identity, error) {
	if !s.client.Test(ctx, r) {
		return nil, auth.ErrUserTokenNotFound
	}
	return s.client.Authenticate(ctx, r)
}

func performOrgChange(t *testing.T, in orgChangeRequest) (*httptest.ResponseRecorder, []orgUpdate) {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.LoginCookieName = "grafana_session"
	cfg.AppURL = "http://grafana.example.com:3000/"
	cfg.TokenRotationIntervalMinutes = 60

	var (
		mu      sync.Mutex
		updates []orgUpdate
	)
	userSvc := &usertest.FakeUserService{
		UpdateFn: func(_ context.Context, cmd *user.UpdateUserCommand) error {
			mu.Lock()
			defer mu.Unlock()
			orgID := int64(0)
			if cmd.OrgID != nil {
				orgID = *cmd.OrgID
			}
			updates = append(updates, orgUpdate{userID: cmd.UserID, orgID: orgID})
			return nil
		},
	}
	orgSvc := &orgtest.FakeOrgService{
		ExpectedUserOrgDTO: []*org.UserOrgDTO{{OrgID: targetOrgID, Name: "Other"}},
	}

	tokens := authtest.NewFakeUserAuthTokenService()
	tokens.LookupTokenProvider = func(_ context.Context, unhashedToken string) (*auth.UserToken, error) {
		// Stand-in for authimpl.UserAuthTokenService.LookupToken: a known session
		// token resolves to its user, and any other value does not.
		if unhashedToken != placeholderSession {
			return nil, auth.ErrUserTokenNotFound
		}
		now := time.Now().Unix()
		return &auth.UserToken{
			UserId:        signedInUserID,
			AuthTokenSeen: true,
			RotatedAt:     now,
			CreatedAt:     now,
		}, nil
	}

	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	sessionClient := clients.ProvideSession(
		cfgProvider,
		tokens,
		&authinfotest.FakeService{ExpectedError: user.ErrUserNotFound},
		tracing.InitializeTracerForTest(),
	)

	hs := &HTTPServer{
		Cfg:         cfg,
		log:         log.New("test"),
		userService: userSvc,
		orgService:  orgSvc,
		Csrf:        csrf.ProvideCSRFFilter(cfg),
	}
	ctxHdlr := contexthandler.ProvideService(
		cfg,
		sessionAuthenticator{client: sessionClient},
		featuremgmt.WithFeatures(),
	)

	// Same order as HTTPServer.addMiddlewaresAndStaticRoutes and registerRoutes:
	// CSRF, then the context handler that authenticates the session cookie,
	// then org redirect, then the signed-in org-switch routes.
	m := web.New()
	m.UseMiddleware(hs.Csrf.Middleware())
	m.UseMiddleware(ctxHdlr.Middleware)
	m.Use(middleware.OrgRedirect(cfg, userSvc))
	m.Post("/api/user/using/:id", middleware.ReqSignedInNoAnonymous, routing.Wrap(hs.UserSetUsingOrg))
	m.Get("/profile/switch-org/:id", middleware.ReqSignedInNoAnonymous, hs.ChangeActiveOrgAndRedirectToHome)
	m.Get("/*", middleware.ReqSignedInNoAnonymous, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(in.method, in.target, nil)
	req.Host = in.host
	req.Header.Set("Origin", in.origin)
	req.AddCookie(&http.Cookie{Name: cfg.LoginCookieName, Value: placeholderSession})

	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	return rr, updates
}
