package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/setting"
)

func TestReverseProxyGnetReq_CallerSuppliedForwardedClientIP(t *testing.T) {
	const (
		peerAddr = "192.0.2.10:34567"
		peerHost = "192.0.2.10"
	)
	spoofed := []string{"203.0.113.50", "198.51.100.8", "198.51.100.23"}

	var got http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	proxy := ReverseProxyGnetReq(log.New("test"), "plugins", "test", upstream.URL, "")
	proxy.Transport = &http.Transport{}

	req := httptest.NewRequest(http.MethodGet, "/api/gnet/plugins", nil)
	req.RemoteAddr = peerAddr
	req.Header.Set("X-Forwarded-For", spoofed[0]+", "+spoofed[1])
	req.Header.Set("X-Real-IP", spoofed[2])
	req.Header.Set("Forwarded", "for="+spoofed[0])
	req = req.WithContext(contexthandler.WithAuthHTTPHeaders(req.Context(), setting.NewCfg()))

	proxy.ServeHTTP(httptest.NewRecorder(), req)

	requireOnlyAcceptedClientIP(t, got, peerHost, spoofed...)
}

func requireOnlyAcceptedClientIP(t *testing.T, header http.Header, peerHost string, spoofed ...string) {
	t.Helper()
	require.NotNil(t, header)

	var hops []string
	for _, value := range header.Values("X-Forwarded-For") {
		for part := range strings.SplitSeq(value, ",") {
			hop := strings.TrimSpace(part)
			if hop != "" {
				hops = append(hops, hop)
			}
		}
	}
	require.NotEmpty(t, hops, "X-Forwarded-For must be the TCP peer Grafana accepted")
	for _, hop := range hops {
		require.Equal(t, peerHost, hop, "X-Forwarded-For=%q X-Real-IP=%q Forwarded=%q", header.Get("X-Forwarded-For"), header.Get("X-Real-IP"), header.Get("Forwarded"))
	}

	if realIP := strings.TrimSpace(header.Get("X-Real-IP")); realIP != "" {
		require.Equal(t, peerHost, realIP)
	}

	for _, addr := range spoofed {
		require.NotContains(t, header.Get("X-Forwarded-For"), addr)
		require.NotContains(t, header.Get("X-Real-IP"), addr)
		require.NotContains(t, header.Get("Forwarded"), addr)
	}
}
