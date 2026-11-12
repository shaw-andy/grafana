package authnimpl

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	claims "github.com/grafana/authlib/types"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
)

func TestLoginRecordsTCPPeerInsteadOfForwardingHeader(t *testing.T) {
	const (
		peerAddr = "203.0.113.10:4242"
		peerIP   = "203.0.113.10"
	)

	var got net.IP
	svc := setupTests(t, func(svc *Service) {
		svc.RegisterClient(&authntest.FakeClient{
			ExpectedName:     "fake",
			ExpectedIdentity: &authn.Identity{ID: "7", Type: claims.TypeUser},
		})
		svc.sessionService = &authtest.FakeUserAuthTokenService{
			CreateTokenProvider: func(_ context.Context, cmd *auth.CreateTokenCommand) (*auth.UserToken, error) {
				got = append(net.IP(nil), cmd.ClientIP...)
				// CreateToken stores this address as the session client IP and does not read the request again.
				return &auth.UserToken{UserId: cmd.User.ID}, nil
			},
		}
	})

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = peerAddr
	req.Header.Set("X-Real-IP", "198.51.100.9")
	req.Header.Set("X-Forwarded-For", "198.51.100.8, 198.51.100.80")

	identity, err := svc.Login(context.Background(), "fake", &authn.Request{HTTPRequest: req})
	require.NoError(t, err)
	require.NotNil(t, identity)
	require.True(t, net.ParseIP(peerIP).Equal(got), "session client IP = %v, want the TCP peer %s", got, peerIP)
}
