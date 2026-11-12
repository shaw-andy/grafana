package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

func TestSessionIPUpdatesUseTCPPeerInsteadOfForwardingHeader(t *testing.T) {
	const (
		peerAddr = "203.0.113.10:4242"
		peerIP   = "203.0.113.10"
	)

	newContext := func() *contextmodel.ReqContext {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = peerAddr
		req.Header.Set("X-Real-IP", "198.51.100.9")
		req.Header.Set("X-Forwarded-For", "198.51.100.8, 198.51.100.80")
		req.Header.Set("User-Agent", "lockout-test")
		return &contextmodel.ReqContext{
			Context: &web.Context{
				Req:  req,
				Resp: web.NewResponseWriter(req.Method, httptest.NewRecorder()),
			},
		}
	}

	t.Run("loginUserWithUser", func(t *testing.T) {
		var got net.IP
		hs := &HTTPServer{
			log: log.New("test"),
			Cfg: setting.NewCfg(),
			AuthTokenService: &authtest.FakeUserAuthTokenService{
				CreateTokenProvider: func(_ context.Context, cmd *auth.CreateTokenCommand) (*auth.UserToken, error) {
					got = append(net.IP(nil), cmd.ClientIP...)
					return &auth.UserToken{UserId: cmd.User.ID}, nil
				},
			},
		}

		err := hs.loginUserWithUser(&user.User{ID: 1}, newContext())
		require.NoError(t, err)
		require.True(t, net.ParseIP(peerIP).Equal(got), "session client IP = %v, want the TCP peer %s", got, peerIP)
	})

	t.Run("rotateToken", func(t *testing.T) {
		var got net.IP
		hs := &HTTPServer{
			log: log.New("test"),
			Cfg: setting.NewCfg(),
			AuthTokenService: &authtest.FakeUserAuthTokenService{
				RotateTokenProvider: func(_ context.Context, cmd auth.RotateCommand) (*auth.UserToken, error) {
					got = append(net.IP(nil), cmd.IP...)
					return &auth.UserToken{}, nil
				},
			},
		}

		err := hs.rotateToken(newContext())
		require.NoError(t, err)
		require.True(t, net.ParseIP(peerIP).Equal(got), "rotated session client IP = %v, want the TCP peer %s", got, peerIP)
	})
}
