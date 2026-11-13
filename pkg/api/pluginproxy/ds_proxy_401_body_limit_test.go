package pluginproxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	gokitlog "github.com/go-kit/log"
	"github.com/stretchr/testify/require"

	sdkhttpclient "github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/infra/httpclient/httpclientprovider"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// maxProxied401BodyBytes is the most of an upstream 401 body the datasource
// proxy may read. The status code is enough to decide that authentication
// failed. The cap applies when dataproxy.response_limit is 0, which is the
// shipped default and which the outgoing client treats as unlimited.
const maxProxied401BodyBytes = 8 * 1024

// upstream401BodyMarker is repeated through the upstream 401 body. It must not
// appear in the proxy log or in the response returned to the caller.
const upstream401BodyMarker = "UNAUTHORIZED-UPSTREAM-BODY"

// TestDataSourceProxy_Upstream401BodyIsCappedAndNotLogged covers the 401
// conversion in DataSourceProxy.HandleRequest. These callers all reach that
// function and have no separate body limit:
//   - HTTPServer.ProxyDataSourceRequestWithUID (/api/datasources/proxy/uid/:uid and /uid/:uid/*)
//   - HTTPServer.ProxyDataSourceRequest (/api/datasources/proxy/:id and /:id/*, legacy id API)
//   - subProxyREST.Connect (datasource apiserver proxy subresource)
func TestDataSourceProxy_Upstream401BodyIsCappedAndNotLogged(t *testing.T) {
	// An empty value is not a positive limit. ResponseLimitMiddleware reads
	// this when the transport is built and ignores it unless it parses as > 0.
	t.Setenv(sdkhttpclientResponseLimitEnv, "")

	cfg := shippedDataProxyConfig(t)
	require.Zero(t, cfg.ResponseLimit, "shipped dataproxy.response_limit must be 0 for this test; the handler has to cap 401 bodies itself")

	prevTimeouts := sdkhttpclient.DefaultTimeoutOptions
	t.Cleanup(func() {
		sdkhttpclient.DefaultTimeoutOptions = prevTimeouts
	})
	provider := httpclientprovider.New(cfg, validations.ProvideURLValidator(), tracing.InitializeTracerForTest())

	const bodySize = 256 * 1024
	payload := bytes.Repeat([]byte(upstream401BodyMarker), (bodySize/len(upstream401BodyMarker))+1)
	payload = payload[:bodySize]

	var upstreamBytes atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write(payload)
		require.NoError(t, err)
	}))
	t.Cleanup(upstream.Close)

	var logBuf bytes.Buffer
	// HandleRequest logs through the package logger. Point that variable at a
	// fresh logger for this test and put the original back afterwards, so the
	// shared data-proxy logger stays attached to the process log config.
	capture := log.New("data-proxy-401-body-test")
	capture.Swap(gokitlog.NewLogfmtLogger(gokitlog.NewSyncWriter(&logBuf)))
	origLogger := logger
	logger = capture
	t.Cleanup(func() { logger = origLogger })

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/render", nil)
	ctx := &contextmodel.ReqContext{
		SignedInUser: &user.SignedInUser{},
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(http.MethodGet, recorder),
		},
	}
	ds := &datasources.DataSource{
		ID:   1,
		UID:  "upstreamuid",
		Name: "upstream",
		Type: datasources.DS_GRAPHITE,
		URL:  upstream.URL,
	}

	proxy, err := setupDSProxyTest(t, ctx, ds, []*plugins.Route{}, "/render")
	require.NoError(t, err)
	proxy.clientProvider = bodyCountingProvider{inner: provider, read: &upstreamBytes}

	proxy.HandleRequest()

	clientBody := recorder.Body.Bytes()
	readN := upstreamBytes.Load()
	loggedBody := bytes.Contains(logBuf.Bytes(), []byte(upstream401BodyMarker))
	if readN > maxProxied401BodyBytes || loggedBody || recorder.Code != http.StatusBadRequest ||
		bytes.Contains(clientBody, []byte(upstream401BodyMarker)) || len(clientBody) > 512 {
		t.Fatalf("upstream 401 body was not capped before the proxy answered: read=%d cap=%d loggedBody=%t status=%d clientBodyLen=%d logLen=%d",
			readN, maxProxied401BodyBytes, loggedBody, recorder.Code, len(clientBody), logBuf.Len())
	}
}

// sdkhttpclientResponseLimitEnv is GF_DATAPROXY_RESPONSE_LIMIT. The SDK reads it
// inside ResponseLimitMiddleware and, when positive, overrides the configured limit.
const sdkhttpclientResponseLimitEnv = "GF_DATAPROXY_RESPONSE_LIMIT"

func shippedDataProxyConfig(t *testing.T) *setting.Cfg {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	defaultsPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "conf", "defaults.ini")
	raw, err := os.ReadFile(defaultsPath)
	require.NoError(t, err)
	cfg, err := setting.NewCfgFromBytes(raw)
	require.NoError(t, err)
	return cfg
}

// bodyCountingProvider wraps the production HTTP client provider and counts
// bytes the proxy reads from the upstream response body. The count sits
// outside ResponseLimitMiddleware, so a limit of 0 is visible as a full read.
type bodyCountingProvider struct {
	inner httpclient.Provider
	read  *atomic.Int64
}

func (p bodyCountingProvider) New(opts ...sdkhttpclient.Options) (*http.Client, error) {
	return p.inner.New(opts...)
}

func (p bodyCountingProvider) GetTLSConfig(opts ...sdkhttpclient.Options) (*tls.Config, error) {
	return p.inner.GetTLSConfig(opts...)
}

func (p bodyCountingProvider) GetTransport(opts ...sdkhttpclient.Options) (http.RoundTripper, error) {
	rt, err := p.inner.GetTransport(opts...)
	if err != nil {
		return nil, err
	}
	return bodyCountRoundTripper{base: rt, read: p.read}, nil
}

type bodyCountRoundTripper struct {
	base http.RoundTripper
	read *atomic.Int64
}

func (b bodyCountRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := b.base.RoundTrip(req)
	if err != nil || resp == nil || resp.Body == nil {
		return resp, err
	}
	resp.Body = &countingReadCloser{ReadCloser: resp.Body, read: b.read}
	return resp, nil
}

type countingReadCloser struct {
	io.ReadCloser
	read *atomic.Int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		c.read.Add(int64(n))
	}
	return n, err
}
