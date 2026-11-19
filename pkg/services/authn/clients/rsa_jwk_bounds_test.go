package clients

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/services/auth/jwt"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/setting"
)

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

func TestJWTClientRejectsOversizedRSAParametersQuickly(t *testing.T) {
	const headerName = "X-JWT-Assertion"
	cfg := &setting.Cfg{
		JWTAuth: setting.AuthJWTSettings{
			Enabled:    true,
			HeaderName: headerName,
		},
	}
	client := ProvideJWT(&jwt.FakeJWTService{},
		connectors.ProvideOrgRoleMapper(testConfigProvider(t, cfg), &orgtest.FakeOrgService{}),
		cfg, tracing.InitializeTracerForTest())

	req := httptest.NewRequest(http.MethodGet, "http://grafana.example/api/user", nil)
	req.Header.Set(headerName, oversizedRSAPrivateJWKToken(t))

	start := time.Now()
	accepted := client.Test(context.Background(), &authn.Request{HTTPRequest: req})
	elapsed := time.Since(start)

	require.False(t, accepted)
	requireFast(t, elapsed)
}

func TestJWTClientURLLoginRejectsOversizedRSAParametersQuickly(t *testing.T) {
	cfg := &setting.Cfg{
		JWTAuth: setting.AuthJWTSettings{
			Enabled:    true,
			HeaderName: "X-JWT-Assertion",
			URLLogin:   true,
		},
	}
	client := ProvideJWT(&jwt.FakeJWTService{},
		connectors.ProvideOrgRoleMapper(testConfigProvider(t, cfg), &orgtest.FakeOrgService{}),
		cfg, tracing.InitializeTracerForTest())

	req := httptest.NewRequest(http.MethodGet, "http://grafana.example/login", nil)
	query := req.URL.Query()
	query.Set(authQueryParamName, oversizedRSAPrivateJWKToken(t))
	req.URL.RawQuery = query.Encode()

	start := time.Now()
	accepted := client.Test(context.Background(), &authn.Request{HTTPRequest: req})
	elapsed := time.Since(start)

	require.False(t, accepted)
	requireFast(t, elapsed)
}

func TestExtendedJWTClientRejectsOversizedRSAParametersQuickly(t *testing.T) {
	cfg := &setting.Cfg{
		ExtJWTAuth: setting.ExtJWTSettings{Enabled: true},
	}
	client := ProvideExtendedJWT(cfg, tracing.InitializeTracerForTest())

	req := httptest.NewRequest(http.MethodGet, "http://grafana.example/api/user", nil)
	req.Header.Set(ExtJWTAuthenticationHeaderName, oversizedRSAPrivateJWKToken(t))

	start := time.Now()
	accepted := client.Test(context.Background(), &authn.Request{HTTPRequest: req})
	elapsed := time.Since(start)

	require.False(t, accepted)
	requireFast(t, elapsed)
}
