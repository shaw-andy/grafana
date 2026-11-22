package clients

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	authjwt "github.com/grafana/grafana/pkg/services/auth/jwt"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/setting"
)

func TestInlineSymmetricKeyCannotAuthenticateAsGrafanaAdmin(t *testing.T) {
	const kid = "placeholder-kid"
	key := placeholderOctetKey(32)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       key,
		KeyID:     kid,
		Algorithm: string(jose.HS256),
		Use:       "sig",
	}}}
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(raw)

	logsDir := t.TempDir()
	dataDir := t.TempDir()
	t.Setenv("GF_PATHS_LOGS", logsDir)
	t.Setenv("GF_PATHS_DATA", dataDir)
	t.Setenv("GF_LOG_MODE", "file")
	t.Setenv("GF_AUTH_JWT_ENABLED", "true")
	t.Setenv("GF_AUTH_JWT_HEADER_NAME", "X-JWT-Assertion")
	t.Setenv("GF_AUTH_JWT_EMAIL_CLAIM", "email")
	t.Setenv("GF_AUTH_JWT_USERNAME_CLAIM", "sub")
	t.Setenv("GF_AUTH_JWT_ROLE_ATTRIBUTE_PATH", "role")
	t.Setenv("GF_AUTH_JWT_ALLOW_ASSIGN_GRAFANA_ADMIN", "true")
	t.Setenv("GF_AUTH_JWT_AUTO_SIGN_UP", "true")
	t.Setenv(setting.EnvKey("auth.jwt", "jwk_set_value"), encoded)

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{HomePath: "../../../../"}))
	t.Cleanup(func() {
		_ = log.Close()
	})
	require.True(t, cfg.JWTAuth.Enabled)
	require.Equal(t, encoded, cfg.JWTAuth.JWKSetValue)

	svc, err := authjwt.ProvideService(cfg, nil)
	if err != nil {
		return
	}

	client := ProvideJWT(svc, connectors.ProvideOrgRoleMapper(testConfigProvider(t, cfg), &orgtest.FakeOrgService{
		ExpectedOrgs: []*org.OrgDTO{{ID: 1, Name: "Main"}},
	}), cfg, tracing.InitializeTracerForTest())

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	require.NoError(t, err)
	token, err := josejwt.Signed(sig).Claims(map[string]any{
		"sub":   "placeholder-user",
		"email": "placeholder-user@example.com",
		"role":  "GrafanaAdmin",
	}).Serialize()
	require.NoError(t, err)

	req := &authn.Request{
		OrgID:       1,
		HTTPRequest: newJWTRequest(cfg.JWTAuth.HeaderName, token),
	}
	if !client.Test(context.Background(), req) {
		return
	}
	id, authErr := client.Authenticate(context.Background(), req)
	if authErr == nil && id.GetIsGrafanaAdmin() {
		t.Fatal("token signed with the inline symmetric key authenticated as Grafana admin")
	}
	if authErr == nil {
		t.Fatal("token signed with the inline symmetric key was accepted")
	}
}

func TestInlinePublicKeyStillAuthenticates(t *testing.T) {
	const kid = "placeholder-kid"
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &priv.PublicKey,
		KeyID:     kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}
	raw, err := json.Marshal(set)
	require.NoError(t, err)

	cfg := setting.NewCfg()
	cfg.JWTAuth = setting.AuthJWTSettings{
		Enabled:                 true,
		HeaderName:              "X-JWT-Assertion",
		EmailClaim:              "email",
		UsernameClaim:           "sub",
		RoleAttributePath:       "role",
		AllowAssignGrafanaAdmin: true,
		AutoSignUp:              true,
		ExpectClaims:            "{}",
		JWKSetValue:             base64.StdEncoding.EncodeToString(raw),
	}
	svc, err := authjwt.ProvideService(cfg, nil)
	require.NoError(t, err)

	client := ProvideJWT(svc, connectors.ProvideOrgRoleMapper(testConfigProvider(t, cfg), &orgtest.FakeOrgService{
		ExpectedOrgs: []*org.OrgDTO{{ID: 1, Name: "Main"}},
	}), cfg, tracing.InitializeTracerForTest())

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: priv}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	require.NoError(t, err)
	token, err := josejwt.Signed(sig).Claims(map[string]any{
		"sub":   "placeholder-user",
		"email": "placeholder-user@example.com",
		"role":  "GrafanaAdmin",
	}).Serialize()
	require.NoError(t, err)

	req := &authn.Request{
		OrgID:       1,
		HTTPRequest: newJWTRequest(cfg.JWTAuth.HeaderName, token),
	}
	require.True(t, client.Test(context.Background(), req))
	id, err := client.Authenticate(context.Background(), req)
	require.NoError(t, err)
	require.True(t, id.GetIsGrafanaAdmin())
	require.Equal(t, org.RoleAdmin, id.OrgRoles[1])
	require.NotNil(t, id.ClientParams.LookUpParams.Login)
	require.Equal(t, "placeholder-user", *id.ClientParams.LookUpParams.Login)
}

func newJWTRequest(headerName, token string) *http.Request {
	req, err := http.NewRequest(http.MethodGet, "http://grafana.local/", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set(headerName, token)
	return req
}

func placeholderOctetKey(n int) []byte {
	const label = "placeholder-not-a-secret"
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, label...)
	}
	return out[:n]
}
