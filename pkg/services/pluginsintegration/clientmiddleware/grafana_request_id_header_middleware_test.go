package clientmiddleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/handlertest"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

func expectedIPRangeSignature(t *testing.T, secret, requestID, address, internal string) string {
	t.Helper()
	instance := hmac.New(sha256.New, []byte(secret))
	_, err := instance.Write([]byte(requestID + "\n" + address + "\n" + internal))
	require.NoError(t, err)
	return hex.EncodeToString(instance.Sum(nil))
}

func inboundRequestContext(req *http.Request) context.Context {
	return context.WithValue(context.Background(), ctxkey.Key{}, &contextmodel.ReqContext{
		Context:      &web.Context{Req: req},
		SignedInUser: &user.SignedInUser{},
	})
}

func Test_HostedGrafanaACHeaderMiddleware(t *testing.T) {
	t.Run("Should set Grafana request ID headers if the data source URL is in the allow list", func(t *testing.T) {
		cfg := setting.NewCfg()
		allowedURL := &url.URL{Scheme: "https", Host: "logs.grafana.net"}
		cfg.IPRangeACAllowedURLs = []*url.URL{allowedURL}
		cfg.IPRangeACSecretKey = "secret"
		cdt := handlertest.NewHandlerMiddlewareTest(t, handlertest.WithMiddlewares(NewHostedGrafanaACHeaderMiddleware(cfg)))

		ctx := inboundRequestContext(&http.Request{
			RemoteAddr: "1.2.3.4:5678",
			Header: map[string][]string{
				"X-Real-Ip":       {"9.9.9.9"},
				"X-Forwarded-For": {"8.8.8.8"},
			},
		})

		err := cdt.MiddlewareHandler.CallResource(ctx, &backend.CallResourceRequest{
			PluginContext: backend.PluginContext{
				DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{
					URL: "https://logs.grafana.net",
				},
			},
		}, nopCallResourceSender)
		require.NoError(t, err)

		require.Len(t, cdt.CallResourceReq.Headers[GrafanaRequestID], 1)
		require.Len(t, cdt.CallResourceReq.Headers[GrafanaSignedRequestID], 1)

		requestID := cdt.CallResourceReq.Headers[GrafanaRequestID][0]
		computed := expectedIPRangeSignature(t, cfg.IPRangeACSecretKey, requestID, "1.2.3.4", "false")
		require.Equal(t, computed, cdt.CallResourceReq.Headers[GrafanaSignedRequestID][0])

		require.Len(t, cdt.CallResourceReq.Headers[XRealIPHeader], 1)
		require.Equal(t, "1.2.3.4", cdt.CallResourceReq.Headers[XRealIPHeader][0])

		// Internal header should not be set
		require.Len(t, cdt.CallResourceReq.Headers[GrafanaInternalRequest], 0)
	})

	t.Run("Should set Grafana request ID headers for QueryChunkedData if the data source URL is in the allow list", func(t *testing.T) {
		cfg := setting.NewCfg()
		allowedURL := &url.URL{Scheme: "https", Host: "logs.grafana.net"}
		cfg.IPRangeACAllowedURLs = []*url.URL{allowedURL}
		cfg.IPRangeACSecretKey = "secret"
		cdt := handlertest.NewHandlerMiddlewareTest(t, handlertest.WithMiddlewares(NewHostedGrafanaACHeaderMiddleware(cfg)))

		ctx := inboundRequestContext(&http.Request{
			RemoteAddr: "1.2.3.4:5678",
			Header:     map[string][]string{"X-Real-Ip": {"9.9.9.9"}},
		})

		err := cdt.MiddlewareHandler.QueryChunkedData(ctx, &backend.QueryChunkedDataRequest{
			PluginContext: backend.PluginContext{
				DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{
					URL: "https://logs.grafana.net",
				},
			},
		}, nopChunkedWriter{})
		require.NoError(t, err)

		requestID := cdt.QueryChunkedDataReq.GetHTTPHeader(GrafanaRequestID)
		require.NotEmpty(t, requestID)

		computed := expectedIPRangeSignature(t, cfg.IPRangeACSecretKey, requestID, "1.2.3.4", "false")
		require.Equal(t, computed, cdt.QueryChunkedDataReq.GetHTTPHeader(GrafanaSignedRequestID))
		require.Equal(t, "1.2.3.4", cdt.QueryChunkedDataReq.GetHTTPHeader(XRealIPHeader))
	})

	t.Run("Should not set Grafana request ID headers if the data source URL is not in the allow list", func(t *testing.T) {
		cfg := setting.NewCfg()
		allowedURL := &url.URL{Scheme: "https", Host: "logs.grafana.net"}
		cfg.IPRangeACAllowedURLs = []*url.URL{allowedURL}
		cfg.IPRangeACSecretKey = "secret"
		cdt := handlertest.NewHandlerMiddlewareTest(t, handlertest.WithMiddlewares(NewHostedGrafanaACHeaderMiddleware(cfg)))

		ctx := inboundRequestContext(&http.Request{})

		err := cdt.MiddlewareHandler.CallResource(ctx, &backend.CallResourceRequest{
			PluginContext: backend.PluginContext{
				DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{
					URL: "https://logs.not-grafana.net",
				},
			},
		}, nopCallResourceSender)
		require.NoError(t, err)

		require.Len(t, cdt.CallResourceReq.Headers[GrafanaRequestID], 0)
		require.Len(t, cdt.CallResourceReq.Headers[GrafanaSignedRequestID], 0)
	})

	t.Run("Should set Grafana request ID headers if URL scheme and host match a URL from the allow list", func(t *testing.T) {
		cfg := setting.NewCfg()
		allowedURL := &url.URL{Scheme: "https", Host: "logs.grafana.net"}
		cfg.IPRangeACAllowedURLs = []*url.URL{allowedURL}
		cfg.IPRangeACSecretKey = "secret"
		cdt := handlertest.NewHandlerMiddlewareTest(t, handlertest.WithMiddlewares(NewHostedGrafanaACHeaderMiddleware(cfg)))

		ctx := inboundRequestContext(&http.Request{RemoteAddr: "1.2.3.4:5678"})

		err := cdt.MiddlewareHandler.CallResource(ctx, &backend.CallResourceRequest{
			PluginContext: backend.PluginContext{
				DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{
					URL: "https://logs.grafana.net/abc/../some/path",
				},
			},
		}, nopCallResourceSender)
		require.NoError(t, err)

		require.Len(t, cdt.CallResourceReq.Headers[GrafanaRequestID], 1)
		require.Len(t, cdt.CallResourceReq.Headers[GrafanaSignedRequestID], 1)
	})

	t.Run("Should set Grafana internal request header only if there is no inbound request", func(t *testing.T) {
		cfg := setting.NewCfg()
		allowedURL := &url.URL{Scheme: "https", Host: "logs.grafana.net"}
		cfg.IPRangeACAllowedURLs = []*url.URL{allowedURL}
		cfg.IPRangeACSecretKey = "secret"
		cdt := handlertest.NewHandlerMiddlewareTest(t, handlertest.WithMiddlewares(NewHostedGrafanaACHeaderMiddleware(cfg)))

		err := cdt.MiddlewareHandler.CallResource(context.Background(), &backend.CallResourceRequest{
			PluginContext: backend.PluginContext{
				DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{
					URL: "https://logs.grafana.net",
				},
			},
		}, nopCallResourceSender)
		require.NoError(t, err)
		require.Equal(t, "true", cdt.CallResourceReq.Headers[GrafanaInternalRequest][0])
		require.Len(t, cdt.CallResourceReq.Headers[XRealIPHeader], 0)

		requestID := cdt.CallResourceReq.Headers[GrafanaRequestID][0]
		computed := expectedIPRangeSignature(t, cfg.IPRangeACSecretKey, requestID, "", "true")
		require.Equal(t, computed, cdt.CallResourceReq.Headers[GrafanaSignedRequestID][0])
	})

	t.Run("Should not mark an inbound request without a known client address as internal", func(t *testing.T) {
		cfg := setting.NewCfg()
		allowedURL := &url.URL{Scheme: "https", Host: "logs.grafana.net"}
		cfg.IPRangeACAllowedURLs = []*url.URL{allowedURL}
		cfg.IPRangeACSecretKey = "secret"
		cdt := handlertest.NewHandlerMiddlewareTest(t, handlertest.WithMiddlewares(NewHostedGrafanaACHeaderMiddleware(cfg)))

		ctx := inboundRequestContext(&http.Request{Header: map[string][]string{"X-Real-Ip": {"9.9.9.9"}}})

		err := cdt.MiddlewareHandler.CallResource(ctx, &backend.CallResourceRequest{
			PluginContext: backend.PluginContext{
				DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{
					URL: "https://logs.grafana.net",
				},
			},
		}, nopCallResourceSender)
		require.NoError(t, err)
		require.Len(t, cdt.CallResourceReq.Headers[GrafanaInternalRequest], 0)
		require.Len(t, cdt.CallResourceReq.Headers[XRealIPHeader], 0)

		requestID := cdt.CallResourceReq.Headers[GrafanaRequestID][0]
		computed := expectedIPRangeSignature(t, cfg.IPRangeACSecretKey, requestID, "", "false")
		require.Equal(t, computed, cdt.CallResourceReq.Headers[GrafanaSignedRequestID][0])
	})

	t.Run("Should replace caller-supplied IP range headers", func(t *testing.T) {
		cfg := setting.NewCfg()
		allowedURL := &url.URL{Scheme: "https", Host: "logs.grafana.net"}
		cfg.IPRangeACAllowedURLs = []*url.URL{allowedURL}
		cfg.IPRangeACSecretKey = "secret"
		cdt := handlertest.NewHandlerMiddlewareTest(t, handlertest.WithMiddlewares(NewHostedGrafanaACHeaderMiddleware(cfg)))

		ctx := inboundRequestContext(&http.Request{RemoteAddr: "1.2.3.4:5678"})

		err := cdt.MiddlewareHandler.CallResource(ctx, &backend.CallResourceRequest{
			PluginContext: backend.PluginContext{
				DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{
					URL: "https://logs.grafana.net",
				},
			},
			Headers: map[string][]string{
				GrafanaRequestID:       {"caller-id"},
				GrafanaSignedRequestID: {"caller-signature"},
				GrafanaInternalRequest: {"true"},
				"x-real-ip":            {"9.9.9.9"},
			},
		}, nopCallResourceSender)
		require.NoError(t, err)

		headers := cdt.CallResourceReq.GetHTTPHeaders()
		require.Empty(t, headers.Values(GrafanaInternalRequest))
		require.Equal(t, []string{"1.2.3.4"}, headers.Values(XRealIPHeader))
		require.Len(t, headers.Values(GrafanaRequestID), 1)
		requestID := headers.Get(GrafanaRequestID)
		require.NotEqual(t, "caller-id", requestID)
		computed := expectedIPRangeSignature(t, cfg.IPRangeACSecretKey, requestID, "1.2.3.4", "false")
		require.Equal(t, []string{computed}, headers.Values(GrafanaSignedRequestID))
	})
}

func TestClientAddress(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	testCases := []struct {
		description    string
		remoteAddr     string
		headers        http.Header
		trustedProxies []netip.Prefix
		expected       string
	}{
		{
			description: "uses the TCP peer and ignores forwarding headers without trusted proxies",
			remoteAddr:  "203.0.113.10:44321",
			headers: http.Header{
				"X-Real-Ip":       {"198.51.100.8"},
				"X-Forwarded-For": {"198.51.100.9"},
			},
			expected: "203.0.113.10",
		},
		{
			description: "normalizes IPv6 peers",
			remoteAddr:  "[2001:db8::1%eth0]:44321",
			expected:    "2001:db8::1",
		},
		{
			description: "returns empty when the peer is unknown",
			remoteAddr:  "",
			headers:     http.Header{"X-Real-Ip": {"198.51.100.8"}},
			expected:    "",
		},
		{
			description:    "ignores X-Forwarded-For when the peer is not a trusted proxy",
			remoteAddr:     "203.0.113.10:44321",
			headers:        http.Header{"X-Forwarded-For": {"198.51.100.9"}},
			trustedProxies: trusted,
			expected:       "203.0.113.10",
		},
		{
			description:    "uses the address the trusted proxy appended",
			remoteAddr:     "10.0.0.1:44321",
			headers:        http.Header{"X-Forwarded-For": {"198.51.100.9, 203.0.113.10"}},
			trustedProxies: trusted,
			expected:       "203.0.113.10",
		},
		{
			description:    "follows a chain of trusted proxies",
			remoteAddr:     "10.0.0.1:44321",
			headers:        http.Header{"X-Forwarded-For": {"198.51.100.9", "203.0.113.10, 10.0.0.2"}},
			trustedProxies: trusted,
			expected:       "203.0.113.10",
		},
		{
			description:    "never uses X-Real-IP, even from a trusted proxy",
			remoteAddr:     "10.0.0.1:44321",
			headers:        http.Header{"X-Real-Ip": {"198.51.100.8"}},
			trustedProxies: trusted,
			expected:       "10.0.0.1",
		},
		{
			description:    "stops at an invalid X-Forwarded-For entry",
			remoteAddr:     "10.0.0.1:44321",
			headers:        http.Header{"X-Forwarded-For": {"198.51.100.9, not-an-ip"}},
			trustedProxies: trusted,
			expected:       "10.0.0.1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			req := &http.Request{RemoteAddr: tc.remoteAddr, Header: tc.headers}
			if req.Header == nil {
				req.Header = http.Header{}
			}
			require.Equal(t, tc.expected, ClientAddress(req, tc.trustedProxies))
		})
	}
}
