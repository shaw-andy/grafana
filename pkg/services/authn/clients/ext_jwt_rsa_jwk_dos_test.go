package clients

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/grafana/authlib/authn"
)

// rsaJWKParseBudget is far below the time rsa.PrivateKey.Validate spends on
// the fixture below with go-jose v4.1.5, and far above a bounds check.
const rsaJWKParseBudget = 2 * time.Second

// degenerateRSAJWKS is a JWKS whose RSA private key has a 32768-bit odd "p"
// and a tiny modulus. Parsing it reaches crypto/rsa.PrivateKey.Validate only
// when the JWK decoder does not reject the parameters first.
func degenerateRSAJWKS(t *testing.T) []byte {
	t.Helper()

	p := make([]byte, 4096)
	for i := range p {
		p[i] = 0xff
	}
	enc := base64.RawURLEncoding.EncodeToString
	jwk := `{"kty":"RSA","kid":"attacker","n":"` + enc([]byte{0x01, 0x00, 0x01}) +
		`","e":"` + enc([]byte{0x01, 0x00, 0x01}) +
		`","d":"` + enc([]byte{0x01}) +
		`","p":"` + enc(p) +
		`","q":"` + enc([]byte{0x03}) + `"}`
	return []byte(`{"keys":[` + jwk + `]}`)
}

func TestExtendedJWTKeyRetrieverRejectsDegenerateRSAJWKS(t *testing.T) {
	doc := degenerateRSAJWKS(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)

	retriever := authn.NewKeyRetriever(authn.KeyRetrieverConfig{SigningKeysURL: srv.URL}, authn.WithHTTPClientKeyRetrieverOpt(srv.Client()))
	start := time.Now()
	key, err := retriever.Get(context.Background(), "attacker")
	elapsed := time.Since(start)

	var priv *rsa.PrivateKey
	if key != nil {
		priv, _ = key.Key.(*rsa.PrivateKey)
	}
	if priv != nil {
		t.Fatalf("accepted degenerate RSA private key after %s", elapsed)
	}
	if elapsed > rsaJWKParseBudget {
		t.Fatalf("degenerate RSA JWK was not rejected within %s (took %s)", rsaJWKParseBudget, elapsed)
	}
	if err == nil {
		t.Fatal("degenerate RSA JWK was accepted")
	}
}
