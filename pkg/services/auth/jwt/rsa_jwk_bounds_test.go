package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/setting"
)

// rsaParameterBytes is the byte length of the crafted RSA modulus and prime.
// 3072 bytes is 24576 bits, above the 4096-bit modulus bound added in go-jose
// v4.1.6. On v4.1.5 those values reach crypto/rsa.PrivateKey.Validate, whose
// modular exponentiation takes seconds. A fixed parser rejects them immediately.
const rsaParameterBytes = 3072

const rsaParseLimit = time.Second

func oversizedRSAPrivateJWKToken(t *testing.T) string {
	t.Helper()

	wide := oddBytes(rsaParameterBytes)
	narrow := oddBytes(32)
	jwk := map[string]string{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(wide),
		"e":   "AQAB",
		"d":   base64.RawURLEncoding.EncodeToString(narrow),
		"p":   base64.RawURLEncoding.EncodeToString(wide),
		"q":   base64.RawURLEncoding.EncodeToString(narrow),
	}
	header, err := json.Marshal(map[string]any{"alg": "RS256", "jwk": jwk})
	require.NoError(t, err)

	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte{1})
	return base64.RawURLEncoding.EncodeToString(header) + "." + payload + "." + signature
}

func oddBytes(n int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = 0xff
	}
	buf[0] = 0x80
	return buf
}

func requireFast(t *testing.T, elapsed time.Duration) {
	t.Helper()
	if elapsed >= rsaParseLimit {
		t.Fatalf("parsing oversized RSA parameters took %s, limit is %s", elapsed, rsaParseLimit)
	}
}

func TestHasSubClaimRejectsOversizedRSAParametersQuickly(t *testing.T) {
	token := oversizedRSAPrivateJWKToken(t)

	start := time.Now()
	hasSub := HasSubClaim(token)
	elapsed := time.Since(start)

	require.False(t, hasSub)
	requireFast(t, elapsed)
}

func TestVerifyRejectsOversizedRSAParametersQuickly(t *testing.T) {
	svc := newService(&setting.Cfg{}, nil)
	token := oversizedRSAPrivateJWKToken(t)

	start := time.Now()
	claims, err := svc.Verify(context.Background(), token)
	elapsed := time.Since(start)

	require.Nil(t, claims)
	require.Error(t, err)
	requireFast(t, elapsed)
}

func TestHasSubClaimStillReadsSubjectWithoutEmbeddedJWK(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte{1})
	token := header + "." + payload + "." + signature

	start := time.Now()
	hasSub := HasSubClaim(token)
	requireFast(t, time.Since(start))
	require.True(t, hasSub)
}
