package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/setting"
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

func privateKeyFromKeys(keys []jose.JSONWebKey) *rsa.PrivateKey {
	for _, key := range keys {
		if priv, ok := key.Key.(*rsa.PrivateKey); ok {
			return priv
		}
	}
	return nil
}

func TestInitKeySetFileRejectsDegenerateRSAJWKS(t *testing.T) {
	doc := degenerateRSAJWKS(t)
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatalf("write jwks file: %v", err)
	}

	svc := &AuthService{
		Cfg: &setting.Cfg{JWTAuth: setting.AuthJWTSettings{JWKSetFile: path}},
		log: log.NewNopLogger(),
	}
	start := time.Now()
	err := svc.initKeySet()
	elapsed := time.Since(start)

	var priv *rsa.PrivateKey
	if ks, ok := svc.keySet.(*keySetJWKS); ok {
		priv = privateKeyFromSet(ks)
	}
	assertDegenerateRSAJWKSRejected(t, elapsed, err, priv)
}

func TestInitKeySetValueRejectsDegenerateRSAJWKS(t *testing.T) {
	doc := degenerateRSAJWKS(t)
	svc := &AuthService{
		Cfg: &setting.Cfg{JWTAuth: setting.AuthJWTSettings{
			JWKSetValue: base64.StdEncoding.EncodeToString(doc),
		}},
		log: log.NewNopLogger(),
	}
	start := time.Now()
	err := svc.initKeySet()
	elapsed := time.Since(start)

	var priv *rsa.PrivateKey
	if ks, ok := svc.keySet.(*keySetJWKS); ok {
		priv = privateKeyFromSet(ks)
	}
	assertDegenerateRSAJWKSRejected(t, elapsed, err, priv)
}

func TestHTTPKeySetRejectsDegenerateRSAJWKS(t *testing.T) {
	doc := degenerateRSAJWKS(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)

	ks := &keySetHTTP{
		url:    srv.URL,
		log:    log.NewNopLogger(),
		client: srv.Client(),
	}
	start := time.Now()
	keys, err := ks.Key(context.Background(), "attacker")
	assertDegenerateRSAJWKSRejected(t, time.Since(start), err, privateKeyFromKeys(keys))
}

func TestHTTPKeySetCachedJWKSRejectsDegenerateRSAJWKS(t *testing.T) {
	doc := degenerateRSAJWKS(t)
	// A fast, empty document. The cached copy is what must be rejected; this
	// response only exists so a failed cache decode has somewhere to fall through.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(srv.Close)

	cache := remotecache.NewFakeStore(t)
	ks := &keySetHTTP{
		url:             srv.URL,
		log:             log.NewNopLogger(),
		client:          srv.Client(),
		cache:           cache,
		cacheKey:        "auth-jwt:jwk-" + srv.URL,
		cacheExpiration: time.Hour,
	}
	if err := cache.Set(context.Background(), ks.cacheKey, doc, time.Hour); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	start := time.Now()
	keys, err := ks.Key(context.Background(), "attacker")
	elapsed := time.Since(start)
	priv := privateKeyFromKeys(keys)
	if priv != nil {
		t.Fatalf("accepted degenerate RSA private key from cache after %s", elapsed)
	}
	if elapsed > rsaJWKParseBudget {
		t.Fatalf("cached degenerate RSA JWK was not rejected within %s (took %s)", rsaJWKParseBudget, elapsed)
	}
	// Cache decode failure falls through to the endpoint. Either outcome is a
	// rejection of the cached private key; accepting that key is not.
	if err == nil && len(keys) != 0 {
		t.Fatalf("returned %d keys after reading the cached degenerate RSA JWK", len(keys))
	}
}
