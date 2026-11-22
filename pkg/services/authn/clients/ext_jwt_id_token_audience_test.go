package clients

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	authnlib "github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/setting"
)

// Identity tokens used for extended JWT login are signed by the same keys as
// access tokens. Login must accept an identity token only when its audience
// contains the grafana audience configured for access tokens, and must reject
// a token with a different audience or no audience. Namespace matching does
// not replace that check.
func TestExtendedJWT_IdentityTokenAudience(t *testing.T) {
	const keyID = "test-key"
	const foreignAudience = "other-service"

	signingKey := mustGenerateP256(t)
	otherKey := mustGenerateP256(t)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &signingKey.PublicKey,
			KeyID:     keyID,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		}}}))
	}))
	t.Cleanup(jwks.Close)

	cfg := mustExtendedJWTCfg(t, jwks.URL)
	require.Equal(t, []string{"grafana"}, cfg.ExtJWTAuth.Audiences)
	grafanaAudience := cfg.ExtJWTAuth.Audiences[0]
	delegated := []string{"dashboards:read", "dashboards.grafana.app/dashboards:get"}

	client := ProvideExtendedJWT(cfg, tracing.InitializeTracerForTest())
	require.True(t, client.IsEnabled(context.Background()))

	subjects := []idTokenSubjectCase{
		{
			name:      "user",
			subject:   "user:42",
			wantType:  types.TypeUser,
			wantID:    "42",
			wantRole:  org.RoleNone,
			fetchUser: true,
			userID:    42,
		},
		{
			name:      "service account",
			subject:   "service-account:7",
			wantType:  types.TypeServiceAccount,
			wantID:    "7",
			wantRole:  org.RoleNone,
			fetchUser: true,
			userID:    7,
		},
		{
			name:     "render service",
			subject:  "render:0",
			wantType: types.TypeRenderService,
			wantID:   "0",
			wantRole: org.RoleAdmin,
		},
		{
			name:     "anonymous",
			subject:  "anonymous:0",
			wantType: types.TypeAnonymous,
			wantID:   "0",
			wantRole: org.RoleViewer,
		},
	}

	access := signExtJWT(t, signingKey, keyID, authnlib.TokenTypeAccess, accessTokenClaimsFor(grafanaAudience, "default", delegated))

	for _, subject := range subjects {
		t.Run(subject.name, func(t *testing.T) {
			t.Run("grafana audience", func(t *testing.T) {
				idToken := signExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, idTokenClaimsFor(subject.subject, "default", []string{grafanaAudience}))
				identity, err := presentExtendedJWT(t, client, access, idToken, false)
				requireAcceptedIdentity(t, identity, err, subject, delegated, grafanaAudience)
			})

			t.Run("grafana audience among others", func(t *testing.T) {
				idToken := signExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, idTokenClaimsFor(subject.subject, "default", []string{foreignAudience, grafanaAudience}))
				identity, err := presentExtendedJWT(t, client, access, idToken, false)
				requireAcceptedIdentity(t, identity, err, subject, delegated, grafanaAudience)
			})

			t.Run("bearer prefix", func(t *testing.T) {
				idToken := signExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, idTokenClaimsFor(subject.subject, "default", []string{foreignAudience}))
				identity, err := presentExtendedJWT(t, client, access, idToken, true)
				requireRejectedAudience(t, identity, err)
			})

			for _, audienceCase := range []struct {
				name     string
				audience []string
			}{
				{name: "foreign audience", audience: []string{foreignAudience}},
				{name: "several foreign audiences", audience: []string{foreignAudience, "logs-service"}},
				{name: "audience case mismatch", audience: []string{"Grafana"}},
				{name: "audience prefix", audience: []string{"grafana-extra"}},
				{name: "missing audience", audience: nil},
			} {
				t.Run(audienceCase.name, func(t *testing.T) {
					idToken := signExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, idTokenClaimsFor(subject.subject, "default", audienceCase.audience))
					identity, err := presentExtendedJWT(t, client, access, idToken, false)
					requireRejectedAudience(t, identity, err)
				})
			}
		})
	}

	t.Run("wildcard access token namespace does not replace audience", func(t *testing.T) {
		wildcardAccess := signExtJWT(t, signingKey, keyID, authnlib.TokenTypeAccess, accessTokenClaimsFor(grafanaAudience, "*", delegated))
		t.Run("foreign audience", func(t *testing.T) {
			idToken := signExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, idTokenClaimsFor("user:42", "default", []string{foreignAudience}))
			identity, err := presentExtendedJWT(t, client, wildcardAccess, idToken, false)
			requireRejectedAudience(t, identity, err)
		})
		t.Run("grafana audience", func(t *testing.T) {
			accepted := signExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, idTokenClaimsFor("user:42", "default", []string{grafanaAudience}))
			identity, err := presentExtendedJWT(t, client, wildcardAccess, accepted, false)
			requireAcceptedIdentity(t, identity, err, subjects[0], delegated, grafanaAudience)
		})
	})

	t.Run("stack namespace does not replace audience", func(t *testing.T) {
		stackCfg := mustExtendedJWTCfg(t, jwks.URL)
		stackCfg.StackID = "7"
		stackClient := ProvideExtendedJWT(stackCfg, tracing.InitializeTracerForTest())
		stackAccess := signExtJWT(t, signingKey, keyID, authnlib.TokenTypeAccess, accessTokenClaimsFor(grafanaAudience, "stacks-7", delegated))

		t.Run("foreign audience", func(t *testing.T) {
			foreign := signExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, idTokenClaimsFor("render:0", "stacks-7", []string{foreignAudience}))
			identity, err := presentExtendedJWT(t, stackClient, stackAccess, foreign, false)
			requireRejectedAudience(t, identity, err)
		})
		t.Run("missing audience", func(t *testing.T) {
			missing := signExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, idTokenClaimsFor("user:42", "stacks-7", nil))
			identity, err := presentExtendedJWT(t, stackClient, stackAccess, missing, false)
			requireRejectedAudience(t, identity, err)
		})
		t.Run("grafana audience", func(t *testing.T) {
			accepted := signExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, idTokenClaimsFor("user:42", "stacks-7", []string{grafanaAudience}))
			identity, err := presentExtendedJWT(t, stackClient, stackAccess, accepted, false)
			require.NoError(t, err)
			require.Equal(t, types.TypeUser, identity.Type)
			require.Equal(t, "42", identity.ID)
			require.Equal(t, "stacks-7", identity.Namespace)
		})
	})

	t.Run("access token audience is still enforced", func(t *testing.T) {
		badAccess := signExtJWT(t, signingKey, keyID, authnlib.TokenTypeAccess, accessTokenClaimsFor(foreignAudience, "default", delegated))
		idToken := signExtJWT(t, signingKey, keyID, authnlib.TokenTypeID, idTokenClaimsFor("user:42", "default", []string{grafanaAudience}))
		identity, err := presentExtendedJWT(t, client, badAccess, idToken, false)
		requireRejectedAudience(t, identity, err)
	})

	t.Run("identity token signed by a different key is rejected", func(t *testing.T) {
		idToken := signExtJWT(t, otherKey, keyID, authnlib.TokenTypeID, idTokenClaimsFor("user:42", "default", []string{grafanaAudience}))
		identity, err := presentExtendedJWT(t, client, access, idToken, false)
		require.Nil(t, identity)
		require.Error(t, err)
		require.ErrorIs(t, err, errExtJWTInvalid)
		require.NotErrorIs(t, err, authnlib.ErrInvalidAudience)
	})
}

type idTokenSubjectCase struct {
	name      string
	subject   string
	wantType  types.IdentityType
	wantID    string
	wantRole  org.RoleType
	fetchUser bool
	userID    int64
}

func requireAcceptedIdentity(t *testing.T, identity *authn.Identity, err error, subject idTokenSubjectCase, delegated []string, grafanaAudience string) {
	t.Helper()
	require.NoError(t, err)
	require.NotNil(t, identity)
	require.Equal(t, subject.wantType, identity.Type)
	require.Equal(t, subject.wantID, identity.ID)
	require.Equal(t, subject.wantRole, identity.GetOrgRole())
	require.Equal(t, login.ExtendedJWTModule, identity.AuthenticatedBy)
	require.Equal(t, "access-policy:policy-1", identity.AuthID)
	require.Equal(t, "default", identity.Namespace)
	require.Equal(t, subject.fetchUser, identity.ClientParams.FetchSyncedUser)
	require.True(t, identity.ClientParams.SyncPermissions)
	wantActions, wantK8s := splitDelegated(delegated)
	require.Equal(t, wantActions, identity.ClientParams.FetchPermissionsParams.RestrictedActions)
	require.Equal(t, wantK8s, identity.ClientParams.FetchPermissionsParams.K8sRestrictedActions)
	require.NotNil(t, identity.IDTokenClaims)
	require.Equal(t, subject.subject, identity.IDTokenClaims.Subject)
	require.True(t, identity.IDTokenClaims.Audience.Contains(grafanaAudience))
	require.NotNil(t, identity.AccessTokenClaims)
	require.Equal(t, jwt.Audience{grafanaAudience}, jwt.Audience(identity.AccessTokenClaims.Audience))

	signedIn := identity.SignedInUser()
	require.Equal(t, subject.userID, signedIn.UserID)
	require.Equal(t, subject.wantRole, signedIn.OrgRole)
	if subject.wantType == types.TypeServiceAccount {
		require.True(t, signedIn.IsServiceAccount)
	}
	if subject.wantType == types.TypeAnonymous {
		require.True(t, signedIn.IsAnonymous)
	}
}

func splitDelegated(delegated []string) (actions, k8s []string) {
	actions = []string{}
	k8s = []string{}
	for _, perm := range delegated {
		if strings.Contains(perm, "grafana.app") {
			k8s = append(k8s, perm)
			continue
		}
		actions = append(actions, perm)
	}
	return actions, k8s
}

func requireRejectedAudience(t *testing.T, identity *authn.Identity, err error) {
	t.Helper()
	if identity != nil {
		t.Fatalf("identity token was accepted as %s id %s org role %s", identity.Type, identity.ID, identity.GetOrgRole())
	}
	require.Error(t, err)
	require.ErrorIs(t, err, errExtJWTInvalid)
	require.ErrorIs(t, err, authnlib.ErrInvalidAudience)
}

func presentExtendedJWT(t *testing.T, client *ExtendedJWT, accessToken, idToken string, bearer bool) (*authn.Identity, error) {
	t.Helper()
	req := extendedJWTRequest(t, accessToken, idToken, bearer)
	require.True(t, client.Test(context.Background(), req), "extended jwt client did not claim the access token")
	return client.Authenticate(context.Background(), req)
}

func extendedJWTRequest(t *testing.T, accessToken, idToken string, bearer bool) *authn.Request {
	t.Helper()
	accessHeader := accessToken
	idHeader := idToken
	if bearer {
		accessHeader = "Bearer " + accessToken
		idHeader = "Bearer " + idToken
	}
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://grafana.example/api/user", nil)
	require.NoError(t, err)
	httpReq.Header.Set(ExtJWTAuthenticationHeaderName, accessHeader)
	if idToken != "" {
		httpReq.Header.Set(ExtJWTAuthorizationHeaderName, idHeader)
	}
	return &authn.Request{HTTPRequest: httpReq}
}

func mustExtendedJWTCfg(t *testing.T, jwksURL string) *setting.Cfg {
	t.Helper()
	cfg, err := setting.NewCfgFromBytes([]byte(`
[auth.extended_jwt]
enabled = true
jwks_url = http://127.0.0.1/unused

[auth.anonymous]
org_role = Viewer
`))
	require.NoError(t, err)
	require.True(t, cfg.ExtJWTAuth.Enabled)
	cfg.ExtJWTAuth.JWKSUrl = jwksURL
	return cfg
}

func mustGenerateP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func accessTokenClaimsFor(audience, namespace string, delegated []string) authnlib.Claims[authnlib.AccessTokenClaims] {
	now := time.Now()
	return authnlib.Claims[authnlib.AccessTokenClaims]{
		Claims: jwt.Claims{
			Subject:  "access-policy:policy-1",
			Audience: jwt.Audience{audience},
			Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(now),
		},
		Rest: authnlib.AccessTokenClaims{
			Namespace:            namespace,
			DelegatedPermissions: delegated,
		},
	}
}

func idTokenClaimsFor(subject, namespace string, audience []string) authnlib.Claims[authnlib.IDTokenClaims] {
	now := time.Now()
	claims := authnlib.Claims[authnlib.IDTokenClaims]{
		Claims: jwt.Claims{
			Subject:  subject,
			Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(now),
		},
		Rest: authnlib.IDTokenClaims{Namespace: namespace},
	}
	if audience != nil {
		claims.Audience = append(jwt.Audience(nil), audience...)
	}
	return claims
}

func signExtJWT(t *testing.T, key *ecdsa.PrivateKey, keyID, tokenType string, claims any) string {
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
