package clients

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	authjwt "github.com/grafana/grafana/pkg/services/auth/jwt"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/setting"
)

func TestOrgMappingStrictValidJWTKeepsMappedOrg(t *testing.T) {
	t.Parallel()

	identity, err := authenticateJWT(t, []string{"contractors:5:Viewer"}, []string{"contractors"})
	require.NoError(t, err)
	require.Equal(t, map[int64]org.RoleType{5: org.RoleAdmin}, identity.OrgRoles)
}

func TestOrgMappingStrictInvalidJWT(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		orgMapping   []string
		externalOrgs []string
	}{
		{
			name:         "malformed sibling drops the valid line",
			orgMapping:   []string{"contractors:5:Viewer", "not-a-mapping"},
			externalOrgs: []string{"contractors"},
		},
		{
			name:         "missing role drops the valid line",
			orgMapping:   []string{"contractors:5:Viewer", "staff:5"},
			externalOrgs: []string{"contractors"},
		},
		{
			name:         "invalid role drops the valid line",
			orgMapping:   []string{"contractors:5:Viewer", "staff:5:SuperUser"},
			externalOrgs: []string{"contractors"},
		},
		{
			name:         "unresolved organization drops the valid line",
			orgMapping:   []string{"contractors:5:Viewer", "staff:RenamedOrg:Editor"},
			externalOrgs: []string{"contractors"},
		},
		{
			name:         "unmatched external org still receives the token role after a discarded mapping",
			orgMapping:   []string{"contractors:5:Viewer", "staff:RenamedOrg:Editor"},
			externalOrgs: []string{"intruders"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			identity, err := authenticateJWT(t, tc.orgMapping, tc.externalOrgs)
			requireJWTDiscardedMappingDoesNotGrantDefaultOrg(t, err, identity)
		})
	}
}

func authenticateJWT(t *testing.T, orgMapping []string, externalOrgs []string) (*authn.Identity, error) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustPKIX(t, &privateKey.PublicKey)})

	cfg := setting.NewCfg()
	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgId = 1
	cfg.AutoAssignOrgRole = string(org.RoleViewer)
	cfg.JWTAuth.Enabled = true
	cfg.JWTAuth.HeaderName = "X-Forwarded-User"
	cfg.JWTAuth.EmailClaim = "email"
	cfg.JWTAuth.UsernameClaim = "preferred_username"
	cfg.JWTAuth.ExpectClaims = "{}"
	cfg.JWTAuth.KeyValue = base64.StdEncoding.EncodeToString(publicPEM)
	cfg.JWTAuth.AutoSignUp = true
	cfg.JWTAuth.RoleAttributeStrict = true
	cfg.JWTAuth.RoleAttributePath = "role"
	cfg.JWTAuth.OrgAttributePath = "orgs"
	cfg.JWTAuth.OrgMapping = orgMapping

	verifier, err := authjwt.ProvideService(cfg, nil)
	require.NoError(t, err)

	client := ProvideJWT(verifier, connectors.ProvideOrgRoleMapper(testConfigProvider(t, cfg), &orgtest.FakeOrgService{
		ExpectedOrgs:  []*org.OrgDTO{{ID: 5, Name: "Limited"}},
		ExpectedError: org.ErrOrgNotFound,
	}), cfg, tracing.InitializeTracerForTest())

	token := signClientJWT(t, privateKey, map[string]any{
		"sub":                "user-1",
		"email":              "attacker@example.com",
		"preferred_username": "attacker",
		"role":               "Admin",
		"orgs":               externalOrgs,
	})
	return client.Authenticate(context.Background(), &authn.Request{
		OrgID: 1,
		HTTPRequest: &http.Request{
			Header: http.Header{"X-Forwarded-User": []string{token}},
		},
	})
}

func mustPKIX(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	return encoded
}

func signClientJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	token, err := josejwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

func requireJWTDiscardedMappingDoesNotGrantDefaultOrg(t *testing.T, err error, identity *authn.Identity) {
	t.Helper()
	var roles map[int64]org.RoleType
	if identity != nil {
		roles = identity.OrgRoles
	}
	if role, ok := roles[1]; ok {
		t.Fatalf("granted role %s in the default organization (1): %v", role, roles)
	}
	if err == nil {
		t.Fatalf("JWT login succeeded after an invalid org_mapping with role_attribute_strict enabled; org roles=%v", roles)
	}
}
