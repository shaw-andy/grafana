package pluginproxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	gokitlog "github.com/go-kit/log"
	"github.com/stretchr/testify/require"

	authlib "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	datasourcesV0 "github.com/grafana/grafana/pkg/apis/datasource/v0alpha1"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/registry/apis/datasource/converter"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/oauthtoken"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/user"
)

// maxLoggedDataProxyBodyBytes is the most request-body bytes dataproxy
// logging may copy into a log record. The read in logRequest must stop at
// this size, the log may contain only that prefix, and the reverse proxy
// must still receive the original body.
const maxLoggedDataProxyBodyBytes = 64 * 1024

// bodyPastCapMarker is written immediately after the logged prefix. A log
// record that contains it copied body bytes past the cap.
const bodyPastCapMarker = "PAST_LOG_CAP"

var dataProxyLogMu sync.Mutex

// TestDataProxyRequestBodyLogging covers DataSourceProxy.logRequest, which
// HandleRequest calls for both proxy entry points:
// ProxyDataSourceRequestWithUID (/api/datasources/proxy/uid/:uid and
// /api/datasources/proxy/uid/:uid/*) and ProxyDataSourceRequest
// (/api/datasources/proxy/:id and /api/datasources/proxy/:id/*).
// Prometheus, Loki, and Elasticsearch reject some methods inside
// validateRequest before logRequest. Every request that passes that check
// uses this read. Graphite POST is one of those requests.
func TestDataProxyRequestBodyLogging(t *testing.T) {
	t.Run("logging enabled", func(t *testing.T) {
		body := oversizedProxyBody()
		var forwarded []byte
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			forwarded, err = io.ReadAll(r.Body)
			require.NoError(t, err)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(upstream.Close)

		counter := &countingReadCloser{Reader: bytes.NewReader(body)}
		transport := &captureTransport{base: http.DefaultTransport, src: counter}
		logs, rec := runDataSourceProxy(t, true, counter, int64(len(body)), upstream, transport)

		require.Equalf(t, http.StatusOK, rec.Code, "proxy response %s\nlog %s", rec.Body.String(), logs.String())
		require.Equal(t, body, forwarded, "reverse proxy must still receive the full request body")
		require.LessOrEqualf(t, transport.readAtRoundTrip.Load(), int64(maxLoggedDataProxyBodyBytes),
			"logRequest read %d body bytes before the reverse proxy; the cap is %d",
			transport.readAtRoundTrip.Load(), maxLoggedDataProxyBodyBytes)
		assertLoggedPrefixOnly(t, logs.String())
	})

	t.Run("logging disabled", func(t *testing.T) {
		body := oversizedProxyBody()
		var forwarded []byte
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			forwarded, err = io.ReadAll(r.Body)
			require.NoError(t, err)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(upstream.Close)

		counter := &countingReadCloser{Reader: bytes.NewReader(body)}
		transport := &captureTransport{base: http.DefaultTransport, src: counter}
		logs, rec := runDataSourceProxy(t, false, counter, int64(len(body)), upstream, transport)

		require.Equalf(t, http.StatusOK, rec.Code, "proxy response %s\nlog %s", rec.Body.String(), logs.String())
		require.Equal(t, body, forwarded)
		require.Zero(t, transport.readAtRoundTrip.Load(), "logging is off, so the body must not be read before the reverse proxy")
		require.NotContains(t, logs.String(), "Proxying incoming request")
		require.NotContains(t, logs.String(), bodyPastCapMarker)
	})
}

// TestPluginProxyRequestBodyLogging covers PluginProxy.logRequest, which
// HandleRequest calls for HTTPServer.ProxyPluginRequest
// (/api/plugin-proxy/:pluginId and /api/plugin-proxy/:pluginId/*) and for
// appplugin subProxyREST.Connect. PluginProxy stores an *http.Transport, so
// the byte-cap check calls logRequest on that proxy and then reads the
// restored body. HandleRequest is still run against a real upstream so the
// log line and the forwarded body are the ones the proxy produces.
func TestPluginProxyRequestBodyLogging(t *testing.T) {
	t.Run("logging enabled caps the read and keeps the body", func(t *testing.T) {
		body := oversizedProxyBody()
		logs := captureDataProxyLog(t)
		counter := &countingReadCloser{Reader: bytes.NewReader(body)}
		proxy := newPluginProxy(t, true, counter, int64(len(body)), "http://127.0.0.1:1")
		proxy.logRequest()

		require.LessOrEqualf(t, counter.n.Load(), int64(maxLoggedDataProxyBodyBytes),
			"logRequest read %d body bytes; the cap is %d", counter.n.Load(), maxLoggedDataProxyBodyBytes)
		restored, err := io.ReadAll(proxy.req.Body)
		require.NoError(t, err)
		require.Equal(t, body, restored, "logRequest must leave the original body for the reverse proxy")
		assertLoggedPrefixOnly(t, logs.String())
	})

	t.Run("logging enabled handle request forwards the full body", func(t *testing.T) {
		body := oversizedProxyBody()
		var forwarded []byte
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			forwarded, err = io.ReadAll(r.Body)
			require.NoError(t, err)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(upstream.Close)

		logs := captureDataProxyLog(t)
		proxy := newPluginProxy(t, true, io.NopCloser(bytes.NewReader(body)), int64(len(body)), upstream.URL)
		proxy.HandleRequest()
		rec := proxy.resp.(*httptest.ResponseRecorder)
		require.Equalf(t, http.StatusOK, rec.Code, "proxy response %s\nlog %s", rec.Body.String(), logs.String())
		require.Equal(t, body, forwarded, "reverse proxy must still receive the full request body")
		assertLoggedPrefixOnly(t, logs.String())
	})

	t.Run("logging disabled", func(t *testing.T) {
		body := oversizedProxyBody()
		logs := captureDataProxyLog(t)
		counter := &countingReadCloser{Reader: bytes.NewReader(body)}
		proxy := newPluginProxy(t, false, counter, int64(len(body)), "http://127.0.0.1:1")
		proxy.logRequest()

		require.Zero(t, counter.n.Load())
		restored, err := io.ReadAll(proxy.req.Body)
		require.NoError(t, err)
		require.Equal(t, body, restored)
		require.NotContains(t, logs.String(), "Proxying incoming request")
		require.NotContains(t, logs.String(), bodyPastCapMarker)
	})
}

func assertLoggedPrefixOnly(t *testing.T, logged string) {
	t.Helper()
	require.Contains(t, logged, "Proxying incoming request")
	require.Contains(t, logged, strings.Repeat("A", maxLoggedDataProxyBodyBytes))
	require.NotContains(t, logged, bodyPastCapMarker)
}

func oversizedProxyBody() []byte {
	body := make([]byte, maxLoggedDataProxyBodyBytes+len(bodyPastCapMarker)+32)
	for i := 0; i < maxLoggedDataProxyBodyBytes; i++ {
		body[i] = 'A'
	}
	copy(body[maxLoggedDataProxyBodyBytes:], bodyPastCapMarker)
	for i := maxLoggedDataProxyBodyBytes + len(bodyPastCapMarker); i < len(body); i++ {
		body[i] = 'B'
	}
	return body
}

func runDataSourceProxy(t *testing.T, logging bool, body io.ReadCloser, contentLength int64, upstream *httptest.Server, transport http.RoundTripper) (*bytes.Buffer, *httptest.ResponseRecorder) {
	t.Helper()
	logs := captureDataProxyLog(t)

	model := &datasources.DataSource{
		UID:      "grafds",
		Name:     "Graphite",
		Type:     datasources.DS_GRAPHITE,
		URL:      upstream.URL,
		OrgID:    1,
		Access:   datasources.DS_ACCESS_PROXY,
		JsonData: simplejson.New(),
	}
	conv := converter.NewConverter(authlib.OrgNamespaceFormatter, model.Type+".datasource.grafana.app", model.Type, nil)
	ds, err := conv.AsDataSource(model)
	require.NoError(t, err)

	viewer := viewerUser()
	req := httptest.NewRequest(http.MethodPost, "http://grafana.example/api/datasources/proxy/uid/grafds/render", http.NoBody)
	req.RequestURI = "/api/datasources/proxy/uid/grafds/render"
	req.Body = body
	req.GetBody = nil
	req.ContentLength = contentLength
	req = req.WithContext(identity.WithRequester(req.Context(), viewer))
	rec := httptest.NewRecorder()

	proxy, err := NewDataSourceProxy(
		staticLoader{plugin: model.Type, ds: ds, rt: transport},
		nil,
		HTTPContext{Req: req, Resp: rec},
		"render",
		&DataSourceProxySettings{DataProxyLogging: logging, DataProxyUserAgent: "grafana-test"},
		httpclient.NewProvider(),
		&oauthtoken.Service{},
		tracing.InitializeTracerForTest(),
		featuremgmt.WithFeatures(),
	)
	require.NoError(t, err)
	proxy.HandleRequest()
	return logs, rec
}

func newPluginProxy(t *testing.T, logging bool, body io.ReadCloser, contentLength int64, upstreamURL string) *PluginProxy {
	t.Helper()
	viewer := viewerUser()
	req := httptest.NewRequest(http.MethodPost, "http://grafana.example/api/plugin-proxy/test-app/render", http.NoBody)
	req.RequestURI = "/api/plugin-proxy/test-app/render"
	req.Body = body
	req.GetBody = nil
	req.ContentLength = contentLength
	req = req.WithContext(identity.WithRequester(req.Context(), viewer))

	proxy, err := NewPluginProxy(
		&pluginsettings.DTO{PluginID: "test-app", OrgID: 1, JSONData: map[string]any{}, Enabled: true},
		[]*plugins.Route{{
			Path:   "render",
			Method: http.MethodPost,
			URL:    upstreamURL,
		}},
		req,
		httptest.NewRecorder(),
		viewer,
		"render",
		logging,
		false,
		func(context.Context) (map[string]string, error) { return map[string]string{}, nil },
		tracing.InitializeTracerForTest(),
		&http.Transport{},
		acimpl.ProvideAccessControl(featuremgmt.WithFeatures()),
		featuremgmt.WithFeatures(),
	)
	require.NoError(t, err)
	return proxy
}

func viewerUser() *user.SignedInUser {
	return &user.SignedInUser{UserID: 7, OrgID: 1, Login: "viewer", OrgRole: org.RoleViewer}
}

type staticLoader struct {
	plugin string
	ds     *datasourcesV0.DataSource
	rt     http.RoundTripper
}

func (s staticLoader) PluginType() string { return s.plugin }

func (s staticLoader) DataSource(context.Context) (*datasourcesV0.DataSource, error) {
	return s.ds, nil
}

func (s staticLoader) GetHTTPTransport(context.Context, httpclient.Provider) (http.RoundTripper, error) {
	return s.rt, nil
}

func (s staticLoader) DecryptedPassword(context.Context) (string, error) { return "", nil }

func (s staticLoader) DecryptedBasicAuthPassword(context.Context) (string, error) {
	return "", nil
}

func (s staticLoader) DecryptedValues(context.Context) (map[string]string, error) {
	return map[string]string{}, nil
}

type countingReadCloser struct {
	io.Reader
	n atomic.Int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	if n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

func (c *countingReadCloser) Close() error { return nil }

type captureTransport struct {
	base            http.RoundTripper
	src             *countingReadCloser
	readAtRoundTrip atomic.Int64
}

func (c *captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.readAtRoundTrip.Store(c.src.n.Load())
	return c.base.RoundTrip(r)
}

func captureDataProxyLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	dataProxyLogMu.Lock()
	t.Cleanup(dataProxyLogMu.Unlock)
	buf := &bytes.Buffer{}
	logger.Swap(gokitlog.NewLogfmtLogger(buf))
	t.Cleanup(func() {
		logger.Swap(gokitlog.NewLogfmtLogger(io.Discard))
	})
	return buf
}
