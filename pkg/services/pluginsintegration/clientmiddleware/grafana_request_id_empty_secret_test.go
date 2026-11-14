package clientmiddleware

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/handlertest"
	"github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

const allowListedDatasourceURL = "https://logs.example.test"

// Signing must not run when the key loaded from configuration is empty.
// These tests fail while the empty key still produces an HMAC and access-control headers.
func TestEmptySecretDoesNotSignPluginRequests(t *testing.T) {
	cfg := loadIPRangeCfg(t, ""+
		"enabled = true\n"+
		"allow_list = https://logs.example.test\n")
	require.Empty(t, cfg.IPRangeACSecretKey)
	requireAllowListed(t, cfg)

	ds := backend.PluginContext{
		DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{URL: allowListedDatasourceURL},
	}

	t.Run("no client address marks nothing internal", func(t *testing.T) {
		assertPluginOperationsUnsigned(t, cfg, context.Background(), ds)
	})

	t.Run("client address is not copied", func(t *testing.T) {
		req := &http.Request{Header: make(http.Header)}
		req.Header.Set("X-Real-IP", "192.0.2.10")
		ctx := context.WithValue(context.Background(), ctxkey.Key{}, &contextmodel.ReqContext{
			Context:      &web.Context{Req: req},
			SignedInUser: &user.SignedInUser{},
		})
		assertPluginOperationsUnsigned(t, cfg, ctx, ds)
	})
}

func TestEmptySecretDoesNotForwardSignedHeadersOnOutboundHTTP(t *testing.T) {
	cfg := loadIPRangeCfg(t, ""+
		"enabled = true\n"+
		"secret_key =\n"+
		"allow_list = https://logs.example.test\n")
	require.Empty(t, cfg.IPRangeACSecretKey)
	requireAllowListed(t, cfg)

	ds := backend.PluginContext{
		DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{URL: allowListedDatasourceURL + "/query"},
	}
	cdt := handlertest.NewHandlerMiddlewareTest(t, handlertest.WithMiddlewares(
		NewHostedGrafanaACHeaderMiddleware(cfg),
		NewHTTPClientMiddleware(),
	))

	capture := func(ctx context.Context) http.Header {
		t.Helper()
		var header http.Header
		next := httpclient.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
			header = r.Header.Clone()
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(nil)),
				Request:    r,
			}, nil
		})
		rt := httpclient.ContextualMiddleware().CreateMiddleware(httpclient.Options{}, next)
		outbound, err := http.NewRequestWithContext(ctx, http.MethodGet, allowListedDatasourceURL+"/query", nil)
		require.NoError(t, err)
		res, err := rt.RoundTrip(outbound)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		return header
	}

	cdt.TestHandler.QueryDataFunc = func(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
		requireNoAccessControlHeaders(t, capture(ctx).Get, cfg.IPRangeACSecretKey)
		return &backend.QueryDataResponse{}, nil
	}
	cdt.TestHandler.QueryChunkedDataFunc = func(ctx context.Context, req *backend.QueryChunkedDataRequest, w backend.ChunkedDataWriter) error {
		requireNoAccessControlHeaders(t, capture(ctx).Get, cfg.IPRangeACSecretKey)
		return nil
	}
	cdt.TestHandler.CallResourceFunc = func(ctx context.Context, req *backend.CallResourceRequest, sender backend.CallResourceResponseSender) error {
		requireNoAccessControlHeaders(t, capture(ctx).Get, cfg.IPRangeACSecretKey)
		return nil
	}
	cdt.TestHandler.CheckHealthFunc = func(ctx context.Context, req *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
		requireNoAccessControlHeaders(t, capture(ctx).Get, cfg.IPRangeACSecretKey)
		return &backend.CheckHealthResult{}, nil
	}

	_, err := cdt.MiddlewareHandler.QueryData(context.Background(), &backend.QueryDataRequest{PluginContext: ds})
	require.NoError(t, err)
	err = cdt.MiddlewareHandler.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{PluginContext: ds}, nopChunkedWriter{})
	require.NoError(t, err)
	err = cdt.MiddlewareHandler.CallResource(context.Background(), &backend.CallResourceRequest{PluginContext: ds}, nopCallResourceSender)
	require.NoError(t, err)
	_, err = cdt.MiddlewareHandler.CheckHealth(context.Background(), &backend.CheckHealthRequest{PluginContext: ds})
	require.NoError(t, err)
}

func TestConfiguredSecretStillSignsPluginQuery(t *testing.T) {
	cfg := loadIPRangeCfg(t, ""+
		"enabled = true\n"+
		"secret_key = test-signing-key\n"+
		"allow_list = https://logs.example.test\n")
	require.True(t, cfg.IPRangeACEnabled)
	requireAllowListed(t, cfg)

	cdt := handlertest.NewHandlerMiddlewareTest(t, handlertest.WithMiddlewares(NewHostedGrafanaACHeaderMiddleware(cfg)))
	_, err := cdt.MiddlewareHandler.QueryData(context.Background(), &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{
			DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{URL: allowListedDatasourceURL},
		},
	})
	require.NoError(t, err)

	requestID := cdt.QueryDataReq.GetHTTPHeader(GrafanaRequestID)
	signed := cdt.QueryDataReq.GetHTTPHeader(GrafanaSignedRequestID)
	require.NotEmpty(t, requestID)
	require.Equal(t, macHex(cfg.IPRangeACSecretKey, requestID), signed)
	require.NotEqual(t, macHex("", requestID), signed)
	require.Equal(t, "true", cdt.QueryDataReq.GetHTTPHeader(GrafanaInternalRequest))
}

func assertPluginOperationsUnsigned(t *testing.T, cfg *setting.Cfg, ctx context.Context, ds backend.PluginContext) {
	t.Helper()
	cdt := handlertest.NewHandlerMiddlewareTest(t, handlertest.WithMiddlewares(NewHostedGrafanaACHeaderMiddleware(cfg)))

	_, err := cdt.MiddlewareHandler.QueryData(ctx, &backend.QueryDataRequest{PluginContext: ds})
	require.NoError(t, err)
	requireNoAccessControlHeaders(t, cdt.QueryDataReq.GetHTTPHeader, cfg.IPRangeACSecretKey)

	err = cdt.MiddlewareHandler.QueryChunkedData(ctx, &backend.QueryChunkedDataRequest{PluginContext: ds}, nopChunkedWriter{})
	require.NoError(t, err)
	requireNoAccessControlHeaders(t, cdt.QueryChunkedDataReq.GetHTTPHeader, cfg.IPRangeACSecretKey)

	err = cdt.MiddlewareHandler.CallResource(ctx, &backend.CallResourceRequest{PluginContext: ds}, nopCallResourceSender)
	require.NoError(t, err)
	requireNoAccessControlHeaders(t, cdt.CallResourceReq.GetHTTPHeader, cfg.IPRangeACSecretKey)

	_, err = cdt.MiddlewareHandler.CheckHealth(ctx, &backend.CheckHealthRequest{PluginContext: ds})
	require.NoError(t, err)
	requireNoAccessControlHeaders(t, cdt.CheckHealthReq.GetHTTPHeader, cfg.IPRangeACSecretKey)

	logger := log.New("test")
	for _, req := range []*http.Request{
		nil,
		{Header: make(http.Header)},
		{Header: make(http.Header), RemoteAddr: "192.0.2.10:443"},
	} {
		headers := GetGrafanaRequestIDHeaders(req, cfg, logger)
		requireNoAccessControlHeaderMap(t, headers, cfg.IPRangeACSecretKey)
	}
}

func requireNoAccessControlHeaderMap(t *testing.T, headers map[string]string, secret string) {
	t.Helper()
	if headers == nil {
		return
	}
	requireNoAccessControlHeaders(t, func(key string) string { return headers[key] }, secret)
}

func requireAllowListed(t *testing.T, cfg *setting.Cfg) {
	t.Helper()
	parsed, err := http.NewRequest(http.MethodGet, allowListedDatasourceURL+"/query", nil)
	require.NoError(t, err)
	require.True(t, IsRequestURLInAllowList(parsed.URL, cfg))
}

func requireNoAccessControlHeaders(t *testing.T, get func(string) string, secret string) {
	t.Helper()
	requestID := get(GrafanaRequestID)
	signed := get(GrafanaSignedRequestID)
	internal := get(GrafanaInternalRequest)
	realIP := get(XRealIPHeader)
	if requestID == "" && signed == "" && internal == "" && realIP == "" {
		return
	}
	t.Errorf("access-control headers attached with empty signing key: id=%q signed=%q emptyKeyMatch=%v internal=%q realIP=%q",
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
