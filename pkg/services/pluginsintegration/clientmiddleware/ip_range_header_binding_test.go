package clientmiddleware_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	sdkhttpclient "github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/grafana/grafana-plugin-sdk-go/data"

	"github.com/grafana/grafana/pkg/infra/httpclient/httpclientprovider"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/clientmiddleware"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tsdb/graphite"
	"github.com/grafana/grafana/pkg/web"
)

// ipRangeTestSecret is an obvious placeholder, not a deployed credential.
const ipRangeTestSecret = "ip-range-test-secret"

// signedIPRangePayload is the HMAC input IP range access control must use.
// It binds the fresh request id to the client address and the internal flag.
// The address is the host of the inbound TCP connection. The internal flag is
// "true" only when the call has no inbound user request.
func signedIPRangePayload(requestID, address, internal string) string {
	return requestID + "\n" + address + "\n" + internal
}

func ipRangeMAC(payload string) string {
	mac := hmac.New(sha256.New, []byte(ipRangeTestSecret))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func assertSignedClient(t *testing.T, header http.Header, tcpHost string, internal bool) {
	t.Helper()

	requestID := header.Get(clientmiddleware.GrafanaRequestID)
	signature := header.Get(clientmiddleware.GrafanaSignedRequestID)
	require.NotEmpty(t, requestID)
	require.NotEmpty(t, signature)

	if internal {
		require.Equal(t, "true", header.Get(clientmiddleware.GrafanaInternalRequest))
		require.Empty(t, header.Get(clientmiddleware.XRealIPHeader))
	} else {
		require.Empty(t, header.Get(clientmiddleware.GrafanaInternalRequest))
		require.Equal(t, tcpHost, header.Get(clientmiddleware.XRealIPHeader))
	}

	idOnly := ipRangeMAC(requestID)
	require.NotEqual(t, idOnly, signature, "signature must cover the client address and internal flag, not only the request id")
	address := tcpHost
	flag := "false"
	if internal {
		address = ""
		flag = "true"
	}
	require.Equal(t, ipRangeMAC(signedIPRangePayload(requestID, address, flag)), signature)
}

type capturedHeader struct {
	mu     sync.Mutex
	header http.Header
}

func (c *capturedHeader) handler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.header = r.Header.Clone()
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	}
}

func (c *capturedHeader) get() http.Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.header == nil {
		return nil
	}
	return c.header.Clone()
}

func (c *capturedHeader) reset() {
	c.mu.Lock()
	c.header = nil
	c.mu.Unlock()
}

func ipRangeCfg(t *testing.T, datasourceURL string) *setting.Cfg {
	t.Helper()
	parsed, err := url.Parse(datasourceURL)
	require.NoError(t, err)
	cfg := setting.NewCfg()
	cfg.IPRangeACEnabled = true
	cfg.IPRangeACSecretKey = ipRangeTestSecret
	cfg.IPRangeACAllowedURLs = []*url.URL{parsed}
	return cfg
}

func ipRangeProvider(t *testing.T, cfg *setting.Cfg) *sdkhttpclient.Provider {
	t.Helper()
	return httpclientprovider.New(cfg, &validations.OSSDataSourceRequestURLValidator{}, tracing.InitializeTracerForTest())
}

func signedInQueryContext(t *testing.T, remoteAddr string, headers map[string]string) context.Context {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/ds/query", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	reqCtx := &contextmodel.ReqContext{
		Context:      &web.Context{Req: req},
		SignedInUser: &user.SignedInUser{UserID: 1, OrgID: 1, Login: "viewer"},
		IsSignedIn:   true,
	}
	ctx := ctxkey.Set(req.Context(), reqCtx)
	reqCtx.Req = req.WithContext(ctx)
	return reqCtx.Req.Context()
}

func pluginContext(datasourceURL string) backend.PluginContext {
	return backend.PluginContext{
		OrgID:    1,
		PluginID: "graphite",
		DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{
			ID:       1,
			UID:      "graphite-uid",
			Name:     "graphite",
			URL:      datasourceURL,
			Type:     "graphite",
			JSONData: []byte(`{}`),
		},
	}
}

func headerMiddlewares(cfg *setting.Cfg, tracer tracing.Tracer) []backend.HandlerMiddleware {
	return []backend.HandlerMiddleware{
		clientmiddleware.NewTracingMiddleware(tracer),
		clientmiddleware.NewContextualLoggerMiddleware(),
		clientmiddleware.NewTracingHeaderMiddleware(),
		clientmiddleware.NewClearAuthHeadersMiddleware(&cfg.JWTAuth, &cfg.AuthProxy),
		clientmiddleware.NewOAuthTokenMiddleware(nil),
		clientmiddleware.NewCookiesMiddleware(nil),
		clientmiddleware.NewForwardIDMiddleware(),
		clientmiddleware.NewUseAlertHeadersMiddleware(),
		clientmiddleware.NewHostedGrafanaACHeaderMiddleware(cfg),
		clientmiddleware.NewHTTPCaptureMiddleware(),
		clientmiddleware.NewHTTPClientMiddleware(),
	}
}

// issuingHandler performs the same outbound call a built-in datasource makes:
// a new http.Request with no TCP peer, sent through Grafana's HTTP client.
type issuingHandler struct {
	client *http.Client
	rawURL string
}

func (h *issuingHandler) do(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.rawURL, nil)
	if err != nil {
		return err
	}
	res, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	return nil
}

func (h *issuingHandler) QueryData(ctx context.Context, _ *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	if err := h.do(ctx); err != nil {
		return nil, err
	}
	return backend.NewQueryDataResponse(), nil
}

func (h *issuingHandler) QueryChunkedData(ctx context.Context, _ *backend.QueryChunkedDataRequest, _ backend.ChunkedDataWriter) error {
	return h.do(ctx)
}

func (h *issuingHandler) CallResource(ctx context.Context, _ *backend.CallResourceRequest, _ backend.CallResourceResponseSender) error {
	return h.do(ctx)
}

func (h *issuingHandler) CheckHealth(ctx context.Context, _ *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	if err := h.do(ctx); err != nil {
		return nil, err
	}
	return &backend.CheckHealthResult{Status: backend.HealthStatusOk}, nil
}

var nopCallResourceSender = backend.CallResourceResponseSenderFunc(func(*backend.CallResourceResponse) error {
	return nil
})

type nopChunkedWriter struct{}

func (nopChunkedWriter) WriteFrame(context.Context, string, string, *data.Frame) error { return nil }

func (nopChunkedWriter) WriteError(context.Context, string, backend.Status, error) error { return nil }

func TestIPRangeGraphiteQueryBindsTCPClient(t *testing.T) {
	var cap capturedHeader
	srv := httptest.NewServer(cap.handler(`[{"target":"metric","datapoints":[]}]`))
	t.Cleanup(srv.Close)

	cfg := ipRangeCfg(t, srv.URL)
	provider := ipRangeProvider(t, cfg)
	tracer := tracing.InitializeTracerForTest()
	svc := graphite.ProvideService(provider, noop.NewTracerProvider().Tracer("graphite"))

	handler, err := backend.HandlerFromMiddlewares(&backend.Handlers{QueryDataHandler: svc}, headerMiddlewares(cfg, tracer)...)
	require.NoError(t, err)

	const tcpAddr = "203.0.113.10:44321"
	ctx := signedInQueryContext(t, tcpAddr, map[string]string{
		"X-Real-IP":       "198.51.100.8",
		"X-Forwarded-For": "198.51.100.9, 203.0.113.10",
	})
	_, err = handler.QueryData(ctx, &backend.QueryDataRequest{
		PluginContext: pluginContext(srv.URL),
		Queries: []backend.DataQuery{{
			RefID:         "A",
			MaxDataPoints: 100,
			TimeRange: backend.TimeRange{
				From: time.Now().Add(-time.Hour),
				To:   time.Now(),
			},
			JSON: []byte(`{"target":"metric"}`),
		}},
	})
	require.NoError(t, err)

	got := cap.get()
	require.NotNil(t, got, "graphite query did not reach the allow-listed datasource")
	require.NotEqual(t, "198.51.100.8", got.Get(clientmiddleware.XRealIPHeader))
	require.NotEqual(t, "198.51.100.9", got.Get(clientmiddleware.XRealIPHeader))
	assertSignedClient(t, got, "203.0.113.10", false)
}

func TestIPRangePluginCallsBindTCPClient(t *testing.T) {
	var cap capturedHeader
	srv := httptest.NewServer(cap.handler(`{}`))
	t.Cleanup(srv.Close)

	cfg := ipRangeCfg(t, srv.URL)
	provider := ipRangeProvider(t, cfg)
	client, err := provider.New()
	require.NoError(t, err)
	tracer := tracing.InitializeTracerForTest()

	final := &issuingHandler{client: client, rawURL: srv.URL + "/query"}
	handler, err := backend.HandlerFromMiddlewares(&backend.Handlers{
		QueryDataHandler:        final,
		QueryChunkedDataHandler: final,
		CallResourceHandler:     final,
		CheckHealthHandler:      final,
	}, headerMiddlewares(cfg, tracer)...)
	require.NoError(t, err)

	pctx := pluginContext(srv.URL)
	const tcpHost = "203.0.113.10"
	cases := []struct {
		name    string
		headers map[string]string
		call    func(ctx context.Context) error
	}{
		{
			name: "QueryData prefers caller X-Real-IP",
			headers: map[string]string{
				"X-Real-IP": "198.51.100.8",
			},
			call: func(ctx context.Context) error {
				_, err := handler.QueryData(ctx, &backend.QueryDataRequest{PluginContext: pctx})
				return err
			},
		},
		{
			name: "CallResource prefers leading X-Forwarded-For",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.9, 203.0.113.50",
			},
			call: func(ctx context.Context) error {
				return handler.CallResource(ctx, &backend.CallResourceRequest{PluginContext: pctx}, nopCallResourceSender)
			},
		},
		{
			name: "CheckHealth prefers caller X-Real-IP",
			headers: map[string]string{
				"X-Real-IP": "198.51.100.8",
			},
			call: func(ctx context.Context) error {
				_, err := handler.CheckHealth(ctx, &backend.CheckHealthRequest{PluginContext: pctx})
				return err
			},
		},
		{
			name: "QueryChunkedData prefers leading X-Forwarded-For",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.9",
			},
			call: func(ctx context.Context) error {
				return handler.QueryChunkedData(ctx, &backend.QueryChunkedDataRequest{PluginContext: pctx}, nopChunkedWriter{})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cap.reset()
			ctx := signedInQueryContext(t, tcpHost+":44321", tc.headers)
			require.NoError(t, tc.call(ctx))
			got := cap.get()
			require.NotNil(t, got)
			assertSignedClient(t, got, tcpHost, false)
		})
	}
}

func TestIPRangeNoInboundRequestIsInternalAndBound(t *testing.T) {
	var cap capturedHeader
	srv := httptest.NewServer(cap.handler(`{}`))
	t.Cleanup(srv.Close)

	cfg := ipRangeCfg(t, srv.URL)
	provider := ipRangeProvider(t, cfg)
	client, err := provider.New()
	require.NoError(t, err)
	tracer := tracing.InitializeTracerForTest()

	final := &issuingHandler{client: client, rawURL: srv.URL + "/query"}
	handler, err := backend.HandlerFromMiddlewares(&backend.Handlers{
		QueryDataHandler: final,
	}, headerMiddlewares(cfg, tracer)...)
	require.NoError(t, err)

	_, err = handler.QueryData(context.Background(), &backend.QueryDataRequest{
		PluginContext: pluginContext(srv.URL),
	})
	require.NoError(t, err)

	got := cap.get()
	require.NotNil(t, got)
	assertSignedClient(t, got, "", true)
}
