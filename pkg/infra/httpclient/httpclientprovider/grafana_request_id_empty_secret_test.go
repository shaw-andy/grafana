package httpclientprovider

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	sdkhttpclient "github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/clientmiddleware"
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
)

const allowListedURL = "https://logs.example.test/api/query"

func TestEmptySecretDoesNotInstallOrApplyHTTPRequestIDMiddleware(t *testing.T) {
	cfg := loadIPRangeCfg(t, ""+
		"enabled = true\n"+
		"allow_list = https://logs.example.test\n")
	require.Empty(t, cfg.IPRangeACSecretKey)

	t.Run("round trip does not sign", func(t *testing.T) {
		ctx := &testContext{}
		mw := GrafanaRequestIDHeaderMiddleware(cfg, log.New("test"))
		rt := mw.CreateMiddleware(sdkhttpclient.Options{}, ctx.createRoundTripper("final"))

		for _, remoteAddr := range []string{"", "192.0.2.10:443"} {
			req, err := http.NewRequest(http.MethodGet, allowListedURL, nil)
			require.NoError(t, err)
			req.RemoteAddr = remoteAddr
			res, err := rt.RoundTrip(req)
			require.NoError(t, err)
			require.NoError(t, res.Body.Close())
			requireNoOutboundAccessHeaders(t, req, cfg.IPRangeACSecretKey)
		}
	})

	t.Run("provider does not install middleware", func(t *testing.T) {
		require.NotContains(t, middlewareNames(t, cfg), GrafanaRequestIDHeaderMiddlewareName)
	})
}

func TestConfiguredSecretInstallsHTTPRequestIDMiddleware(t *testing.T) {
	cfg := loadIPRangeCfg(t, ""+
		"enabled = true\n"+
		"secret_key = test-signing-key\n"+
		"allow_list = https://logs.example.test\n")
	require.True(t, cfg.IPRangeACEnabled)
	require.Contains(t, middlewareNames(t, cfg), GrafanaRequestIDHeaderMiddlewareName)

	ctx := &testContext{}
	mw := GrafanaRequestIDHeaderMiddleware(cfg, log.New("test"))
	rt := mw.CreateMiddleware(sdkhttpclient.Options{}, ctx.createRoundTripper("final"))
	req, err := http.NewRequest(http.MethodGet, allowListedURL, nil)
	require.NoError(t, err)
	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	requestID := req.Header.Get(clientmiddleware.GrafanaRequestID)
	signed := req.Header.Get(clientmiddleware.GrafanaSignedRequestID)
	require.NotEmpty(t, requestID)
	require.Equal(t, macHex(cfg.IPRangeACSecretKey, requestID), signed)
	require.NotEqual(t, macHex("", requestID), signed)
	require.Equal(t, "true", req.Header.Get(clientmiddleware.GrafanaInternalRequest))
	require.Empty(t, req.Header.Get(clientmiddleware.XRealIPHeader))
}

func middlewareNames(t *testing.T, cfg *setting.Cfg) []string {
	t.Helper()
	orig := newProviderFunc
	t.Cleanup(func() { newProviderFunc = orig })
	var got []sdkhttpclient.ProviderOptions
	newProviderFunc = func(opts ...sdkhttpclient.ProviderOptions) *sdkhttpclient.Provider {
		got = opts
		return nil
	}
	_ = New(cfg, &validations.OSSDataSourceRequestURLValidator{}, tracing.InitializeTracerForTest())
	require.Len(t, got, 1)
	names := make([]string, 0, len(got[0].Middlewares))
	for _, mw := range got[0].Middlewares {
		named, ok := mw.(sdkhttpclient.MiddlewareName)
		require.True(t, ok)
		names = append(names, named.MiddlewareName())
	}
	return names
}

func requireNoOutboundAccessHeaders(t *testing.T, req *http.Request, secret string) {
	t.Helper()
	requestID := req.Header.Get(clientmiddleware.GrafanaRequestID)
	signed := req.Header.Get(clientmiddleware.GrafanaSignedRequestID)
	internal := req.Header.Get(clientmiddleware.GrafanaInternalRequest)
	realIP := req.Header.Get(clientmiddleware.XRealIPHeader)
	if requestID == "" && signed == "" && internal == "" && realIP == "" {
		return
	}
	t.Errorf("outbound access-control headers attached with empty signing key: id=%q signed=%q emptyKeyMatch=%v internal=%q realIP=%q",
		requestID, signed, signed != "" && signed == macHex(secret, requestID), internal, realIP)
}

func macHex(key, message string) string {
	m := hmac.New(sha256.New, []byte(key))
	_, _ = m.Write([]byte(message))
	return hex.EncodeToString(m.Sum(nil))
}

func loadIPRangeCfg(t *testing.T, body string) *setting.Cfg {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.ini")
	require.NoError(t, os.WriteFile(path, []byte("[datasources.ip_range_security]\n"+body), 0o600))
	cfg := setting.NewCfg()
	err := cfg.Load(setting.CommandLineArgs{
		HomePath: filepath.Join("..", "..", "..", ".."),
		Config:   path,
	})
	require.NoError(t, err)
	return cfg
}
