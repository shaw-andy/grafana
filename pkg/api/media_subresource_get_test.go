package api

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/models/usertoken"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// recordingAuthn counts session revocations performed by GET /logout.
type recordingAuthn struct {
	authntest.FakeService
	loggedOut []*usertoken.UserToken
}

func (r *recordingAuthn) Logout(_ context.Context, _ identity.Requester, token *usertoken.UserToken) (*authn.Redirect, error) {
	r.loggedOut = append(r.loggedOut, token)
	return &authn.Redirect{URL: "/login"}, nil
}

// A cookied GET with no Origin is what an img, audio, or video element sends.
// Logout, organization switch, and session-token rotation must not run for that request.
func TestMediaSubresourceGetDoesNotChangeSession(t *testing.T) {
	authnSvc := &recordingAuthn{}
	var orgUpdates []*user.UpdateUserCommand
	userSvc := &usertest.FakeUserService{
		UpdateFn: func(_ context.Context, cmd *user.UpdateUserCommand) error {
			orgUpdates = append(orgUpdates, cmd)
			return nil
		},
	}
	var rotations []auth.RotateCommand
	tokenSvc := authtest.NewFakeUserAuthTokenService()
	tokenSvc.RotateTokenProvider = func(_ context.Context, cmd auth.RotateCommand) (*auth.UserToken, error) {
		rotations = append(rotations, cmd)
		return &auth.UserToken{UnhashedToken: "rotated-placeholder"}, nil
	}

	cfg := setting.NewCfg()
	cfg.LoginCookieName = "grafana_session"

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.log = log.New("media-subresource-test")
		hs.authnService = authnSvc
		hs.userService = userSvc
		hs.orgService = &orgtest.FakeOrgService{
			ExpectedUserOrgDTO: []*org.UserOrgDTO{{OrgID: 1}, {OrgID: 2}},
		}
		hs.AuthTokenService = tokenSvc
	})
	// The production server runs this filter in front of every route.
	server.Mux.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	server.HttpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	viewer := &contextmodel.ReqContext{
		IsSignedIn: true,
		SignedInUser: &user.SignedInUser{
			UserID: 7,
			OrgID:  1,
			Login:  "viewer",
		},
		UserToken: &usertoken.UserToken{Id: 99, UserId: 7},
	}

	send := func(t *testing.T, path string) *http.Response {
		t.Helper()
		req := server.NewGetRequest(path)
		req.Header.Del("Origin")
		req.AddCookie(&http.Cookie{Name: cfg.LoginCookieName, Value: "placeholder-session", Path: "/"})
		req = webtest.RequestWithWebContext(req, viewer)
		resp, err := server.Send(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp
	}

	clearsSession := func(t *testing.T, resp *http.Response) bool {
		t.Helper()
		for _, cookie := range resp.Cookies() {
			if cookie.Name == cfg.LoginCookieName && cookie.MaxAge < 0 {
				return true
			}
		}
		return false
	}

	t.Run("GET /logout", func(t *testing.T) {
		authnSvc.loggedOut = nil
		resp := send(t, "/logout")
		require.Empty(t, authnSvc.loggedOut)
		require.False(t, clearsSession(t, resp))
	})

	t.Run("GET /%6Cogout", func(t *testing.T) {
		authnSvc.loggedOut = nil
		resp := send(t, "/%6Cogout")
		require.Empty(t, authnSvc.loggedOut)
		require.False(t, clearsSession(t, resp))
	})

	t.Run("GET /profile/switch-org/2", func(t *testing.T) {
		orgUpdates = nil
		_ = send(t, "/profile/switch-org/2")
		require.Empty(t, orgUpdates)
	})

	t.Run("GET /user/auth-tokens/rotate", func(t *testing.T) {
		rotations = nil
		_ = send(t, "/user/auth-tokens/rotate")
		require.Empty(t, rotations)
	})
}
