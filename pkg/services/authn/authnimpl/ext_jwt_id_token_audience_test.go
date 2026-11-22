package authnimpl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	authnlib "github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/setting"
)

// Service.Authenticate is the authenticator the HTTP context handler calls.
// With auth.extended_jwt enabled, a grafana-audience access token plus an
// identity token is dispatched to the extended JWT client. The identity token
// must carry the grafana audience; a token for another audience must not
// become the signed-in user.
func TestService_ExtendedJWTIdentityTokenAudience(t *testing.T) {
	const keyID = "test-key"
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &signingKey.PublicKey,
			KeyID:     keyID,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		}}}))
	}))
	t.Cleanup(jwks.Close)

	cfg, err := setting.NewCfgFromBytes([]byte(`
[auth.extended_jwt]
enabled = true
jwks_url = http://127.0.0.1/unused

[auth.anonymous]
org_role = Viewer
`))
	require.NoError(t, err)
	require.True(t, cfg.ExtJWTAuth.Enabled)
	require.Equal(t, []string{"grafana"}, cfg.ExtJWTAuth.Audiences)
	cfg.ExtJWTAuth.JWKSUrl = jwks.URL

	svc := setupTests(t, func(svc *Service) {
		svc.cfg = cfg
		svc.RegisterClient(clients.ProvideExtendedJWT(cfg, tracing.InitializeTracerForTest()))
	})

	delegated := []string{"dashboards:read", "dashboards.grafana.app/dashboards:get"}
	access := signServiceExtJWT(t, signingKey, keyID, authnlib.TokenTypeAccess, serviceAccessClaims("grafana", delegated))

	t.Run("grafana audience signs in as the identity token user", func(t *testing.T) {
		identity, err := svc.Authenticate(context.Background(), serviceExtJWTRequest(t, access, signServiceExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, serviceIDClaims("user:42", []string{"grafana"})), false))
		require.NoError(t, err)
		require.Equal(t, types.TypeUser, identity.Type)
		require.Equal(t, "42", identity.ID)
		require.Equal(t, int64(42), identity.SignedInUser().UserID)
		require.Equal(t, []string{"dashboards:read"}, identity.ClientParams.FetchPermissionsParams.RestrictedActions)
		require.Equal(t, []string{"dashboards.grafana.app/dashboards:get"}, identity.ClientParams.FetchPermissionsParams.K8sRestrictedActions)
		require.True(t, identity.ClientParams.FetchSyncedUser)
	})

	t.Run("foreign audience is not the signed-in user", func(t *testing.T) {
		identity, err := svc.Authenticate(context.Background(), serviceExtJWTRequest(t, access, signServiceExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, serviceIDClaims("user:42", []string{"other-service"})), false))
		requireServiceRejectedAudience(t, identity, err)
	})

	t.Run("missing audience is not the signed-in user", func(t *testing.T) {
		identity, err := svc.Authenticate(context.Background(), serviceExtJWTRequest(t, access, signServiceExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, serviceIDClaims("user:42", nil)), true))
		requireServiceRejectedAudience(t, identity, err)
	})

	t.Run("render identity token with a foreign audience is not org admin", func(t *testing.T) {
		identity, err := svc.Authenticate(context.Background(), serviceExtJWTRequest(t, access, signServiceExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, serviceIDClaims("render:0", []string{"other-service"})), false))
		requireServiceRejectedAudience(t, identity, err)
	})

	t.Run("render identity token with the grafana audience is org admin", func(t *testing.T) {
		identity, err := svc.Authenticate(context.Background(), serviceExtJWTRequest(t, access, signServiceExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, serviceIDClaims("render:0", []string{"grafana"})), false))
		require.NoError(t, err)
		require.Equal(t, types.TypeRenderService, identity.Type)
		require.Equal(t, "0", identity.ID)
		require.Equal(t, org.RoleAdmin, identity.GetOrgRole())
		require.False(t, identity.ClientParams.FetchSyncedUser)
	})
}

func requireServiceRejectedAudience(t *testing.T, identity *authn.Identity, err error) {
	t.Helper()
	if identity != nil {
		t.Fatalf("identity token was accepted as %s id %s org role %s", identity.Type, identity.ID, identity.GetOrgRole())
	}
	require.Error(t, err)
	require.ErrorIs(t, err, authnlib.ErrInvalidAudience)
}

func serviceExtJWTRequest(t *testing.T, accessToken, idToken string, bearer bool) *authn.Request {
	t.Helper()
	if bearer {
		accessToken = "Bearer " + accessToken
		idToken = "Bearer " + idToken
	}
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://grafana.example/api/user", nil)
	require.NoError(t, err)
	httpReq.Header.Set(clients.ExtJWTAuthenticationHeaderName, accessToken)
	httpReq.Header.Set(clients.ExtJWTAuthorizationHeaderName, idToken)
	return &authn.Request{HTTPRequest: httpReq}
}

func serviceAccessClaims(audience string, delegated []string) authnlib.Claims[authnlib.AccessTokenClaims] {
	now := time.Now()
	return authnlib.Claims[authnlib.AccessTokenClaims]{
		Claims: jwt.Claims{
			Subject:  "access-policy:policy-1",
			Audience: jwt.Audience{audience},
			Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(now),
		},
		Rest: authnlib.AccessTokenClaims{
			Namespace:            "default",
			DelegatedPermissions: delegated,
		},
	}
}

func serviceIDClaims(subject string, audience []string) authnlib.Claims[authnlib.IDTokenClaims] {
	now := time.Now()
	claims := authnlib.Claims[authnlib.IDTokenClaims]{
		Claims: jwt.Claims{
			Subject:  subject,
			Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(now),
		},
		Rest: authnlib.IDTokenClaims{Namespace: "default"},
	}
	if audience != nil {
		claims.Audience = append(jwt.Audience(nil), audience...)
	}
	return claims
}

func signServiceExtJWT(t *testing.T, key *ecdsa.PrivateKey, keyID, tokenType string, claims any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType(jose.ContentType(tokenType)).WithHeader("kid", keyID),
	)
	require.NoError(t, err)
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}
