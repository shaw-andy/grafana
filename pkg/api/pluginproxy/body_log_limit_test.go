package pluginproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	datasourcesV0 "github.com/grafana/grafana/pkg/apis/datasource/v0alpha1"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web"
)

// maxLoggedPluginProxyBody is the most of a caller-supplied request body the
// data-proxy request logger may read or copy into a log record. A short prefix
// is enough to debug a proxied call; the logger must not retain the rest.
// http.MaxBytesReader may consume one extra byte from the underlying reader
// when it checks the limit (net/http maxBytesReader.Read).
const maxLoggedPluginProxyBody = 1024

const pluginProxyBodyTail = "PLUGIN-PROXY-BODY-TAIL"

func TestPluginProxyRequestBodyLoggingIsBounded(t *testing.T) {
	// A viewer is enough: a route with no reqRole and no reqAction is allowed
	// for every signed-in caller that already passed the app-access check.
	viewer := &user.SignedInUser{UserID: 7, OrgID: 1, Login: "viewer", OrgRole: org.RoleViewer}

	t.Run("logging enabled does not read past the prefix before dialing", func(t *testing.T) {
		body := bytes.Repeat([]byte("A"), 256*1024)
		copy(body[len(body)-len(pluginProxyBodyTail):], pluginProxyBodyTail)
		n, bodies := proxyPluginRequest(t, true, viewer, body)

		require.LessOrEqualf(t, n, maxLoggedPluginProxyBody+1,
			"data-proxy logging read %d bytes of a caller-supplied body before dialing the upstream; the logger must read at most a %d byte prefix",
			n, maxLoggedPluginProxyBody)
		for _, logged := range bodies {
			require.LessOrEqual(t, len(logged), maxLoggedPluginProxyBody)
			require.NotContains(t, logged, pluginProxyBodyTail)
		}
	})

	t.Run("logging disabled does not read the body before dialing", func(t *testing.T) {
		body := bytes.Repeat([]byte("B"), 64*1024)
		n, bodies := proxyPluginRequest(t, false, viewer, body)
		require.Zero(t, n)
		require.Empty(t, bodies)
	})

	t.Run("logging enabled still records a body under the prefix", func(t *testing.T) {
		body := []byte("small-plugin-proxy-body")
		n, bodies := proxyPluginRequest(t, true, viewer, body)
		require.Equal(t, len(body), n)
		require.Contains(t, bodies, string(body))
	})
}

func TestDataSourceProxyRequestBodyLoggingIsBounded(t *testing.T) {
	viewer := &user.SignedInUser{UserID: 7, OrgID: 1, Login: "viewer", OrgRole: org.RoleViewer}

	t.Run("logging enabled does not read past the prefix before dialing", func(t *testing.T) {
		body := bytes.Repeat([]byte("C"), 256*1024)
		copy(body[len(body)-len(pluginProxyBodyTail):], pluginProxyBodyTail)
		n, bodies := proxyDataSourceRequest(t, true, viewer, body)

		require.LessOrEqualf(t, n, maxLoggedPluginProxyBody+1,
			"data-source proxy logging read %d bytes of a caller-supplied body before dialing the upstream; the logger must read at most a %d byte prefix",
			n, maxLoggedPluginProxyBody)
		for _, logged := range bodies {
			require.LessOrEqual(t, len(logged), maxLoggedPluginProxyBody)
			require.NotContains(t, logged, pluginProxyBodyTail)
		}
	})

	t.Run("logging disabled does not read the body before dialing", func(t *testing.T) {
		body := bytes.Repeat([]byte("D"), 64*1024)
		n, bodies := proxyDataSourceRequest(t, false, viewer, body)
		require.Zero(t, n)
		require.Empty(t, bodies)
	})
}

func proxyPluginRequest(t *testing.T, logging bool, signedIn *user.SignedInUser, payload []byte) (int, []string) {
	t.Helper()

	reader := &countingReadCloser{data: payload}
	var dialed bool
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("stop before writing the request body")
		},
	}

	req := httptest.NewRequest(http.MethodPost, "http://grafana.example/api/plugin-proxy/test-app/echo", reader)
	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	recorder := httptest.NewRecorder()

	proxy, err := NewPluginProxy(
		&pluginsettings.DTO{PluginID: "test-app", JSONData: map[string]any{}},
		[]*plugins.Route{{
			Path:   "echo",
			Method: http.MethodPost,
			URL:    "http://127.0.0.1:9/upstream",
		}},
		req,
		web.NewResponseWriter(http.MethodPost, recorder),
		signedIn,
		"echo",
		logging,
		false,
		func(context.Context) (map[string]string, error) { return map[string]string{}, nil },
		tracing.InitializeTracerForTest(),
		transport,
		acimpl.ProvideAccessControl(featuremgmt.WithFeatures()),
		featuremgmt.WithFeatures(),
	)
	require.NoError(t, err)

	bodies := captureProxyLogs(t, func() {
		proxy.HandleRequest()
	})
	require.True(t, dialed, "the proxy must attempt to dial the upstream so the test observes only the bytes read before that dial")
	return reader.n, bodies
}

func proxyDataSourceRequest(t *testing.T, logging bool, signedIn *user.SignedInUser, payload []byte) (int, []string) {
	t.Helper()

	reader := &countingReadCloser{data: payload}
	var dialed bool
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("stop before writing the request body")
		},
	}

	ds := &datasourcesV0.DataSource{}
	ds.Spec.SetURL("http://127.0.0.1:9")

	req := httptest.NewRequest(http.MethodPost, "http://grafana.example/api/datasources/proxy/uid/test/query", reader)
	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	req = req.WithContext(identity.WithRequester(req.Context(), signedIn))

	proxy, err := NewDataSourceProxy(
		stubDataSourceLoader{ds: ds, transport: transport},
		nil,
		HTTPContext{
			Req:  req,
			Resp: web.NewResponseWriter(http.MethodPost, httptest.NewRecorder()),
		},
		"query",
		&DataSourceProxySettings{DataProxyLogging: logging},
		nil,
		nil,
		tracing.InitializeTracerForTest(),
		featuremgmt.WithFeatures(),
	)
	require.NoError(t, err)

	bodies := captureProxyLogs(t, func() {
		proxy.HandleRequest()
	})
	require.True(t, dialed, "the proxy must attempt to dial the upstream so the test observes only the bytes read before that dial")
	return reader.n, bodies
}

type stubDataSourceLoader struct {
	ds        *datasourcesV0.DataSource
	transport *http.Transport
}

func (s stubDataSourceLoader) PluginType() string { return "test-datasource" }

func (s stubDataSourceLoader) DataSource(context.Context) (*datasourcesV0.DataSource, error) {
	return s.ds, nil
}

func (s stubDataSourceLoader) GetHTTPTransport(context.Context, httpclient.Provider) (http.RoundTripper, error) {
	return s.transport, nil
}

func (s stubDataSourceLoader) DecryptedPassword(context.Context) (string, error) { return "", nil }

func (s stubDataSourceLoader) DecryptedBasicAuthPassword(context.Context) (string, error) {
	return "", nil
}

func (s stubDataSourceLoader) DecryptedValues(context.Context) (map[string]string, error) {
	return map[string]string{}, nil
}

type countingReadCloser struct {
	data []byte
	off  int
	n    int
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	r.n += n
	return n, nil
}

func (r *countingReadCloser) Close() error { return nil }

type captureKitLogger struct {
	records [][]any
}

func (c *captureKitLogger) Log(keyvals ...any) error {
	c.records = append(c.records, append([]any{}, keyvals...))
	return nil
}

func captureProxyLogs(t *testing.T, fn func()) []string {
	t.Helper()

	orig := logger
	t.Cleanup(func() { logger = orig })
	captured := &captureKitLogger{}
	replacement := log.New("data-proxy-log-test")
	replacement.Swap(captured)
	logger = replacement

	fn()
	return loggedBodyValues(captured.records)
}

func loggedBodyValues(records [][]any) []string {
	var bodies []string
	for _, rec := range records {
		for i := 0; i+1 < len(rec); i += 2 {
			key, ok := rec[i].(string)
			if !ok || key != "body" {
				continue
			}
			switch v := rec[i+1].(type) {
			case string:
				bodies = append(bodies, v)
			default:
				bodies = append(bodies, "")
			}
		}
	}
	return bodies
}
