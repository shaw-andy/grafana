package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/models/usertoken"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
	"github.com/grafana/grafana/pkg/web/webtest"
)

const placeholderSession = "placeholder-session"

// logoutRecorder counts session revocations. The embedded fake panics on Logout.
type logoutRecorder struct {
	*authntest.FakeService
	calls int
}

func (r *logoutRecorder) Logout(context.Context, identity.Requester, *usertoken.UserToken) (*authn.Redirect, error) {
	r.calls++
	return &authn.Redirect{URL: "/login"}, nil
}

func newRetargetServer(t *testing.T, opts ...APITestServerOption) *webtest.Server {
	t.Helper()
	server := SetupAPITestServer(t, opts...)
	server.HttpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return server
}

func signedInMember(userID, activeOrg int64) *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  userID,
		OrgID:   activeOrg,
		OrgRole: org.RoleViewer,
		Login:   "viewer",
		Name:    "Viewer",
	}
}

func sessionCookieCleared(t *testing.T, res *http.Response) bool {
	t.Helper()
	for _, line := range res.Header.Values("Set-Cookie") {
		if strings.HasPrefix(line, "grafana_session=") && strings.Contains(line, "Max-Age=0") {
			return true
		}
	}
	return false
}

func TestGetLogoutDoesNotEndSession(t *testing.T) {
	authnSpy := &logoutRecorder{FakeService: &authntest.FakeService{}}
	server := newRetargetServer(t, func(hs *HTTPServer) {
		cfg := setting.NewCfg()
		cfg.LoginCookieName = "grafana_session"
		hs.Cfg = cfg
		hs.log = log.New("invite-session-retarget-test")
		hs.authnService = authnSpy
	})

	req := server.NewGetRequest("/logout")
	req.AddCookie(&http.Cookie{Name: "grafana_session", Value: placeholderSession, Path: "/"})
	req = webtest.RequestWithSignedInUser(req, signedInMember(42, 1))

	res, err := server.Send(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()

	if authnSpy.calls != 0 || sessionCookieCleared(t, res) {
		t.Fatalf("GET /logout ended the session: revocations=%d cookieCleared=%v setCookie=%q", authnSpy.calls, sessionCookieCleared(t, res), res.Header.Values("Set-Cookie"))
	}
}

func TestGetSwitchOrgDoesNotChangeActiveOrg(t *testing.T) {
	var updated *user.UpdateUserCommand
	users := usertest.NewUserServiceFake()
	users.UpdateFn = func(_ context.Context, cmd *user.UpdateUserCommand) error {
		copied := *cmd
		updated = &copied
		return nil
	}
	orgs := orgtest.NewOrgServiceFake()
	orgs.ExpectedUserOrgDTO = []*org.UserOrgDTO{
		{OrgID: 1, Name: "Home", Role: org.RoleViewer},
		{OrgID: 2, Name: "Other", Role: org.RoleViewer},
	}

	server := newRetargetServer(t, func(hs *HTTPServer) {
		cfg := setting.NewCfg()
		cfg.LoginCookieName = "grafana_session"
		hs.Cfg = cfg
		hs.log = log.New("invite-session-retarget-test")
		hs.userService = users
		hs.orgService = orgs
	})

	req := server.NewGetRequest("/profile/switch-org/2")
	req.AddCookie(&http.Cookie{Name: "grafana_session", Value: placeholderSession, Path: "/"})
	req = webtest.RequestWithSignedInUser(req, signedInMember(42, 1))

	res, err := server.Send(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, res.Body)

	if updated != nil {
		orgID := int64(0)
		if updated.OrgID != nil {
			orgID = *updated.OrgID
		}
		t.Fatalf("GET /profile/switch-org/2 updated user %d active org to %d", updated.UserID, orgID)
	}
}

func TestGetAuthTokenRotateDoesNotRotateSession(t *testing.T) {
	rotated := 0
	server := newRetargetServer(t, func(hs *HTTPServer) {
		cfg := setting.NewCfg()
		cfg.LoginCookieName = "grafana_session"
		hs.Cfg = cfg
		hs.log = log.New("invite-session-retarget-test")
		hs.AuthTokenService = &authtest.FakeUserAuthTokenService{
			RotateTokenProvider: func(context.Context, auth.RotateCommand) (*auth.UserToken, error) {
				rotated++
				return &auth.UserToken{UnhashedToken: placeholderSession}, nil
			},
		}
	})

	req := server.NewGetRequest("/user/auth-tokens/rotate")
	req.AddCookie(&http.Cookie{Name: "grafana_session", Value: placeholderSession, Path: "/"})
	req = webtest.RequestWithSignedInUser(req, signedInMember(42, 1))

	res, err := server.Send(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()

	require.Zero(t, rotated, "GET /user/auth-tokens/rotate rotated the session token")
}

// TestEncodedInvitePathStaysOnInviteRoute checks the router the product uses:
// a single invite segment that contains percent-encoded slashes is the invite
// page, not a rewritten logout request. The client then builds the dangerous
// URL. This test fails if that segment is served by the logout handler.
func TestEncodedInvitePathStaysOnInviteRoute(t *testing.T) {
	hit := ""
	mark := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if code := web.Params(r)[":code"]; code != "" {
				hit = name + ":" + code
			} else if id := web.Params(r)[":id"]; id != "" {
				hit = name + ":" + id
			} else {
				hit = name
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}
	m := web.New()
	m.Get("/logout", mark("logout"))
	m.Get("/invite/:code", mark("invite"))
	m.Get("/profile/switch-org/:id", mark("switch"))
	m.Get("/user/auth-tokens/rotate", mark("rotate"))

	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	targets := map[string]string{
		"/invite/..%2F..%2F..%2F..%2Flogout":                      "invite:../../../../logout",
		"/invite/..%2F..%2F..%2F..%2Fprofile%2Fswitch-org%2F2":    "invite:../../../../profile/switch-org/2",
		"/invite/..%2F..%2F..%2F..%2Fuser%2Fauth-tokens%2Frotate": "invite:../../../../user/auth-tokens/rotate",
	}
	for target, want := range targets {
		hit = ""
		req, err := http.NewRequest(http.MethodGet, srv.URL+target, nil)
		require.NoError(t, err)
		res, err := client.Do(req)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		require.Equalf(t, want, hit, "request URL %s", target)
	}
}
