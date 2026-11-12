package connectors

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/remotecache"
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

func assertDegenerateRSAJWKSRejected(t *testing.T, elapsed time.Duration, err error, priv *rsa.PrivateKey) {
	t.Helper()
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

func privateKeyFromSet(set *keySetJWKS) *rsa.PrivateKey {
	if set == nil {
		return nil
	}
	for _, key := range set.Keys {
		if priv, ok := key.Key.(*rsa.PrivateKey); ok {
			return priv
		}
	}
	return nil
}

func TestRetrieveJWKSFromURLRejectsDegenerateRSAJWKS(t *testing.T) {
	doc := degenerateRSAJWKS(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)

	social := &SocialBase{log: log.NewNopLogger(), providerName: "generic_oauth"}
	start := time.Now()
	set, _, err := social.retrieveJWKSFromURL(context.Background(), srv.Client(), srv.URL)
	assertDegenerateRSAJWKSRejected(t, time.Since(start), err, privateKeyFromSet(set))
}

func TestRetrieveJWKSFromCacheRejectsDegenerateRSAJWKS(t *testing.T) {
	doc := degenerateRSAJWKS(t)
	cache := remotecache.NewFakeCacheStorage()
	social := &SocialBase{
		log:          log.NewNopLogger(),
		cache:        cache,
		providerName: "generic_oauth",
	}
	cacheKey := social.getJWKSCacheKeyForURL("https://idp.example/jwks")
	if err := cache.Set(context.Background(), cacheKey, doc, time.Hour); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	start := time.Now()
	set, _, err := social.retrieveJWKSFromCache(context.Background(), cacheKey)
	assertDegenerateRSAJWKSRejected(t, time.Since(start), err, privateKeyFromSet(set))
}
