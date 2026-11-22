package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
)

const placeholderKid = "placeholder-kid"

func TestEnvInlineJWKSIsRedactedAndRejected(t *testing.T) {
	key := placeholderOctetKey(minOctetKeySize(jose.HS256))
	encoded := encodeKeySet(t, symmetricKeySet(key, jose.HS256))

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
	t.Setenv(setting.EnvKey("auth.jwt", "jwk_set_value"), encoded)

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{HomePath: "../../../../"}))
	t.Cleanup(func() {
		_ = log.Close()
	})

	logText := readStartupLog(t, cfg)
	if strings.Contains(logText, encoded) {
		t.Error("startup log contains the inline JWT key set")
	}
	if !strings.Contains(logText, setting.EnvKey("auth.jwt", "jwk_set_value")+"=") {
		t.Error("startup log did not record the inline JWT key set override")
	}
	if !strings.Contains(logText, setting.EnvKey("auth.jwt", "jwk_set_value")+"="+setting.RedactedPassword) {
		t.Error("startup log did not redact the inline JWT key set override")
	}

	published := setting.ProvideProvider(cfg).Current()["auth.jwt"]["jwk_set_value"]
	if published == encoded || strings.Contains(published, encoded) {
		t.Error("admin settings document contains the inline JWT key set")
	}
	if published != setting.RedactedPassword {
		t.Error("admin settings document did not redact the inline JWT key set")
	}
	if cfg.JWTAuth.JWKSetValue != encoded {
		t.Error("runtime JWT configuration did not keep the configured inline key set")
	}
	require.True(t, cfg.JWTAuth.Enabled)
	require.Equal(t, "role", cfg.JWTAuth.RoleAttributePath)
	require.True(t, cfg.JWTAuth.AllowAssignGrafanaAdmin)

	svc := newService(cfg, nil)
	err := svc.init()
	token := signSymmetric(t, jose.HS256, key, map[string]any{
		"sub":   "placeholder-user",
		"email": "placeholder-user@example.com",
		"role":  "GrafanaAdmin",
	})
	if svc.keySet != nil {
		claims, verifyErr := svc.Verify(context.Background(), token)
		if verifyErr == nil {
			t.Errorf("Verify accepted a token signed with the inline symmetric key, role claim %v", claims["role"])
		}
	}
	if err == nil {
		t.Error("startup accepted an inline key set that contains a symmetric key")
	}
}

func TestInlineJWKSRejectsSymmetricKeys(t *testing.T) {
	for _, alg := range []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512} {
		t.Run(string(alg), func(t *testing.T) {
			key := placeholderOctetKey(minOctetKeySize(alg))
			encoded := encodeKeySet(t, symmetricKeySet(key, alg))
			svc, err := initAuthService(t, func(t *testing.T, cfg *setting.Cfg) {
				cfg.JWTAuth.JWKSetValue = encoded
			})
			assertSymmetricKeyRejected(t, svc, err, alg, key)
		})
	}
}

func TestJWKSFileRejectsSymmetricKeys(t *testing.T) {
	for _, alg := range []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512} {
		t.Run(string(alg), func(t *testing.T) {
			key := placeholderOctetKey(minOctetKeySize(alg))
			path := writeKeySetFile(t, symmetricKeySet(key, alg))
			svc, err := initAuthService(t, func(t *testing.T, cfg *setting.Cfg) {
				cfg.JWTAuth.JWKSetFile = path
			})
			assertSymmetricKeyRejected(t, svc, err, alg, key)
		})
	}
}

func TestRemoteJWKSRejectsSymmetricKeys(t *testing.T) {
	for _, alg := range []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512} {
		t.Run(string(alg), func(t *testing.T) {
			key := placeholderOctetKey(minOctetKeySize(alg))
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, json.NewEncoder(w).Encode(symmetricKeySet(key, alg)))
			}))
			t.Cleanup(ts.Close)

			svc, err := initAuthService(t, func(t *testing.T, cfg *setting.Cfg) {
				cfg.Env = setting.Dev
				cfg.JWTAuth.JWKSetURL = ts.URL
			})
			require.NoError(t, err)
			token := signSymmetric(t, alg, key, map[string]any{"sub": "placeholder-user"})
			_, verifyErr := svc.Verify(context.Background(), token)
			if verifyErr == nil {
				t.Fatal("Verify accepted a symmetric key fetched for JWT authentication")
			}
			assertRetainedKeysArePublic(t, svc)
		})
	}
}

func TestInlineJWKSRejectsPrivateKeys(t *testing.T) {
	priv := generateTestRSAKey(t)
	encoded := encodeKeySet(t, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privateTestJWK(priv)}})
	svc, err := initAuthService(t, func(t *testing.T, cfg *setting.Cfg) {
		cfg.JWTAuth.JWKSetValue = encoded
	})
	if err == nil {
		t.Error("startup accepted an inline key set that contains a private key")
	}
	assertRetainedKeysArePublic(t, svc)
	if svc.keySet != nil {
		token := sign(t, priv, jwt.Claims{Subject: "placeholder-user"}, (&jose.SignerOptions{}).WithHeader("kid", placeholderKid))
		_, verifyErr := svc.Verify(context.Background(), token)
		if verifyErr == nil {
			t.Error("Verify accepted a token signed with a private key stored in the inline key set")
		}
	}
}

func TestJWKSFileRejectsPrivateKeys(t *testing.T) {
	priv := generateTestRSAKey(t)
	path := writeKeySetFile(t, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privateTestJWK(priv)}})
	svc, err := initAuthService(t, func(t *testing.T, cfg *setting.Cfg) {
		cfg.JWTAuth.JWKSetFile = path
	})
	if err == nil {
		t.Error("startup accepted a key set file that contains a private key")
	}
	assertRetainedKeysArePublic(t, svc)
}

func TestRemoteJWKSRejectsPrivateKeys(t *testing.T) {
	priv := generateTestRSAKey(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privateTestJWK(priv)}}))
	}))
	t.Cleanup(ts.Close)

	svc, err := initAuthService(t, func(t *testing.T, cfg *setting.Cfg) {
		cfg.Env = setting.Dev
		cfg.JWTAuth.JWKSetURL = ts.URL
	})
	require.NoError(t, err)
	token := sign(t, priv, jwt.Claims{Subject: "placeholder-user"}, (&jose.SignerOptions{}).WithHeader("kid", placeholderKid))
	_, verifyErr := svc.Verify(context.Background(), token)
	if verifyErr == nil {
		t.Error("Verify accepted a private key fetched for JWT authentication")
	}
	assertRetainedKeysArePublic(t, svc)
}

func TestInlinePublicJWKSStillVerifies(t *testing.T) {
	priv := generateTestRSAKey(t)
	pub := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: placeholderKid, Use: "sig", Algorithm: string(jose.RS256)}
	encoded := encodeKeySet(t, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	svc, err := initAuthService(t, func(t *testing.T, cfg *setting.Cfg) {
		cfg.JWTAuth.JWKSetValue = encoded
	})
	require.NoError(t, err)
	token := sign(t, priv, jwt.Claims{Subject: "placeholder-user"}, (&jose.SignerOptions{}).WithHeader("kid", placeholderKid))
	claims, err := svc.Verify(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, "placeholder-user", claims["sub"])
}

func assertSymmetricKeyRejected(t *testing.T, svc *AuthService, initErr error, alg jose.SignatureAlgorithm, key []byte) {
	t.Helper()
	token := signSymmetric(t, alg, key, map[string]any{
		"sub":  "placeholder-user",
		"role": "GrafanaAdmin",
	})
	if svc.keySet != nil {
		claims, verifyErr := svc.Verify(context.Background(), token)
		if verifyErr == nil {
			t.Errorf("Verify accepted a %s token signed with a symmetric key, role claim %v", alg, claims["role"])
		}
	}
	if initErr == nil {
		t.Errorf("startup accepted a %s symmetric key", alg)
	}
	assertRetainedKeysArePublic(t, svc)
}

func assertRetainedKeysArePublic(t *testing.T, svc *AuthService) {
	t.Helper()
	if svc == nil || svc.keySet == nil {
		return
	}
	keys, err := svc.keySet.Key(context.Background(), placeholderKid)
	if err != nil {
		return
	}
	for _, key := range keys {
		if !key.IsPublic() {
			t.Error("JWT key set retained a private or symmetric key")
		}
	}
}

func readStartupLog(t *testing.T, cfg *setting.Cfg) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(cfg.LogsPath, "grafana.log"))
	require.NoError(t, err)
	return string(body)
}

func symmetricKeySet(key []byte, alg jose.SignatureAlgorithm) jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       key,
		KeyID:     placeholderKid,
		Algorithm: string(alg),
		Use:       "sig",
	}}}
}

func privateTestJWK(priv *rsa.PrivateKey) jose.JSONWebKey {
	return jose.JSONWebKey{Key: priv, KeyID: placeholderKid, Use: "sig", Algorithm: string(jose.RS256)}
}

func encodeKeySet(t *testing.T, set jose.JSONWebKeySet) string {
	t.Helper()
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw)
}

func writeKeySetFile(t *testing.T, set jose.JSONWebKeySet) string {
	t.Helper()
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "jwks.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

func signSymmetric(t *testing.T, alg jose.SignatureAlgorithm, key []byte, claims any) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", placeholderKid))
	require.NoError(t, err)
	token, err := jwt.Signed(sig).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

func placeholderOctetKey(n int) []byte {
	const label = "placeholder-not-a-secret"
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, label...)
	}
	return out[:n]
}

func minOctetKeySize(alg jose.SignatureAlgorithm) int {
	switch alg {
	case jose.HS256:
		return 32
	case jose.HS384:
		return 48
	default:
		return 64
	}
}

func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return priv
}
