package connectors

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/login/social"
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

func TestValidateIDTokenSignatureRejectsOversizedRSAParametersQuickly(t *testing.T) {
	connector := &SocialBase{log: log.New("oauth.test")}
	token := oversizedRSAPrivateJWKToken(t)

	start := time.Now()
	raw, err := connector.validateIDTokenSignature(context.Background(), http.DefaultClient, token, "http://idp.example/jwks")
	elapsed := time.Since(start)

	require.Nil(t, raw)
	require.Error(t, err)
	requireFast(t, elapsed)
}

func TestOktaUserInfoRejectsOversizedRSAParametersQuickly(t *testing.T) {
	connector := &SocialOkta{SocialBase: &SocialBase{
		log:  log.New("oauth.okta"),
		info: &social.OAuthInfo{},
	}}
	token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": oversizedRSAPrivateJWKToken(t)})

	start := time.Now()
	info, err := connector.UserInfo(context.Background(), http.DefaultClient, token)
	elapsed := time.Since(start)

	require.Nil(t, info)
	require.Error(t, err)
	requireFast(t, elapsed)
}

func TestAzureADAccessTokenRejectsOversizedRSAParametersQuickly(t *testing.T) {
	connector := &SocialAzureAD{SocialBase: &SocialBase{log: log.New("oauth.azuread")}}
	accessToken := &oauth2.Token{AccessToken: oversizedRSAPrivateJWKToken(t)}

	start := time.Now()
	endpoint, err := connector.groupsGraphAPIURL(log.New("oauth.azuread"), &azureClaims{}, accessToken)
	elapsed := time.Since(start)

	require.Empty(t, endpoint)
	require.Error(t, err)
	requireFast(t, elapsed)
}
