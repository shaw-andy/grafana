package pluginproxy_test

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

	"github.com/stretchr/testify/require"

	sdkhttpclient "github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"

	"github.com/grafana/grafana/pkg/api/pluginproxy"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	datasourcesV0 "github.com/grafana/grafana/pkg/apis/datasource/v0alpha1"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/infra/httpclient/httpclientprovider"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/clientmiddleware"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
)

// ipRangeTestSecret is an obvious placeholder, not a deployed credential.
const ipRangeTestSecret = "ip-range-test-secret"

func signedIPRangePayload(requestID, address, internal string) string {
	return requestID + "\n" + address + "\n" + internal
}

func ipRangeMAC(payload string) string {
	mac := hmac.New(sha256.New, []byte(ipRangeTestSecret))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func assertSignedClient(t *testing.T, header http.Header, tcpHost string, callerRequestID string) {
	t.Helper()

	requestID := header.Get(clientmiddleware.GrafanaRequestID)
	signature := header.Get(clientmiddleware.GrafanaSignedRequestID)
	require.NotEmpty(t, requestID)
	if callerRequestID != "" {
		require.NotEqual(t, callerRequestID, requestID, "caller-supplied request id must be replaced and signed")
	}
	require.Empty(t, header.Get(clientmiddleware.GrafanaInternalRequest))
	require.Equal(t, tcpHost, header.Get(clientmiddleware.XRealIPHeader))
	require.NotEmpty(t, signature)

	idOnly := ipRangeMAC(requestID)
	require.NotEqual(t, idOnly, signature, "signature must cover the client address and internal flag, not only the request id")
	require.Equal(t, ipRangeMAC(signedIPRangePayload(requestID, tcpHost, "false")), signature)
}

type capturedHeader struct {
	mu     sync.Mutex
	header http.Header
}

func (c *capturedHeader) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.header = r.Header.Clone()
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
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

// stubLoader is the datasource loader the reverse proxy calls. Transport comes
// from the same provider DataSourceProxy is given, which installs the IP range
// header middleware when the feature is enabled.
type stubLoader struct {
	ds *datasourcesV0.DataSource
}

func (s stubLoader) PluginType() string { return datasources.DS_PROMETHEUS }

func (s stubLoader) DataSource(context.Context) (*datasourcesV0.DataSource, error) {
	return s.ds, nil
}

func (s stubLoader) GetHTTPTransport(_ context.Context, clientProvider httpclient.Provider) (http.RoundTripper, error) {
	return clientProvider.GetTransport(sdkhttpclient.Options{})
}

func (s stubLoader) DecryptedPassword(context.Context) (string, error) { return "", nil }

func (s stubLoader) DecryptedBasicAuthPassword(context.Context) (string, error) {
	return "", nil
}

func (s stubLoader) DecryptedValues(context.Context) (map[string]string, error) {
	return map[string]string{}, nil
}

func TestDataSourceProxyBindsTCPClient(t *testing.T) {
	var cap capturedHeader
	srv := httptest.NewServer(cap.handler())
	t.Cleanup(srv.Close)

	parsed, err := url.Parse(srv.URL)
	require.NoError(t, err)
	cfg := setting.NewCfg()
	cfg.IPRangeACEnabled = true
	cfg.IPRangeACSecretKey = ipRangeTestSecret
	cfg.IPRangeACAllowedURLs = []*url.URL{parsed}

	provider := httpclientprovider.New(cfg, &validations.OSSDataSourceRequestURLValidator{}, tracing.InitializeTracerForTest())
	loader := stubLoader{ds: &datasourcesV0.DataSource{
		Spec: datasourcesV0.UnstructuredSpec{Object: map[string]any{"url": srv.URL}},
	}}

	const tcpHost = "203.0.113.10"
	const callerRequestID = "caller-supplied-request-id"

	cases := []struct {
		name            string
		headers         map[string]string
		callerRequestID string
	}{
		{
			name: "X-Real-IP is not the signed client",
			headers: map[string]string{
				"X-Real-IP": "198.51.100.8",
			},
		},
		{
			name: "leading X-Forwarded-For is not the signed client",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.9, 198.51.100.10",
			},
		},
		{
			name: "caller request id is replaced",
			headers: map[string]string{
				"X-Real-IP":                       "198.51.100.8",
				clientmiddleware.GrafanaRequestID: callerRequestID,
			},
			callerRequestID: callerRequestID,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cap.reset()
			req := httptest.NewRequest(http.MethodGet, "http://grafana.local/api/datasources/proxy/1/query", nil)
			req.RemoteAddr = tcpHost + ":44321"
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			req = req.WithContext(identity.WithRequester(req.Context(), &user.SignedInUser{
				UserID: 1,
				OrgID:  1,
				Login:  "viewer",
			}))

			proxy, err := pluginproxy.NewDataSourceProxy(
				loader,
				nil,
				pluginproxy.HTTPContext{Req: req, Resp: httptest.NewRecorder()},
				"query",
				&pluginproxy.DataSourceProxySettings{},
				provider,
				nil,
				tracing.InitializeTracerForTest(),
				nil,
			)
			require.NoError(t, err)
			proxy.HandleRequest()

			got := cap.get()
			require.NotNil(t, got, "proxied query did not reach the allow-listed datasource")
			assertSignedClient(t, got, tcpHost, tc.callerRequestID)
		})
	}
}
