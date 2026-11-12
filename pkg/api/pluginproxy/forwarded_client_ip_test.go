package pluginproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

func TestDataSourceProxy_CallerSuppliedForwardedClientIP(t *testing.T) {
	t.Run("ipv4 peer", func(t *testing.T) {
		const (
			peerAddr = "192.0.2.10:34567"
			peerHost = "192.0.2.10"
		)
		spoofed := []string{"203.0.113.50", "198.51.100.8", "198.51.100.23"}
		header := proxyDatasource(t, peerAddr, spoofed)
		requireOnlyAcceptedClientIP(t, header, peerHost, spoofed...)
	})

	t.Run("ipv6 peer", func(t *testing.T) {
		const (
			peerAddr = "[2001:db8::10]:34567"
			peerHost = "2001:db8::10"
		)
		spoofed := []string{"2001:db8::ffff"}
		header := proxyDatasource(t, peerAddr, []string{spoofed[0], spoofed[0], spoofed[0]})
		requireOnlyAcceptedClientIP(t, header, peerHost, spoofed...)
	})

	t.Run("no caller forwarding headers still sends the peer", func(t *testing.T) {
		const (
			peerAddr = "192.0.2.10:34567"
			peerHost = "192.0.2.10"
		)
		header := proxyDatasource(t, peerAddr, nil)
		requireOnlyAcceptedClientIP(t, header, peerHost)
	})
}

func proxyDatasource(t *testing.T, peerAddr string, spoofed []string) http.Header {
	t.Helper()

	var got http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	req := httptest.NewRequest(http.MethodGet, "/api/datasources/proxy/uid/prom/api/v1/query?query=up", nil)
	req.RemoteAddr = peerAddr
	if len(spoofed) == 3 {
		req.Header.Set("X-Forwarded-For", spoofed[0]+", "+spoofed[1])
		req.Header.Set("X-Real-IP", spoofed[2])
		req.Header.Set("Forwarded", "for="+spoofed[0])
	}
	req = req.WithContext(contexthandler.WithAuthHTTPHeaders(req.Context(), setting.NewCfg()))
	req = req.WithContext(identity.WithRequester(req.Context(), &user.SignedInUser{
		UserID: 1, OrgID: 1, Login: "viewer", OrgRole: org.RoleViewer,
	}))

	ctx := &contextmodel.ReqContext{
		SignedInUser: &user.SignedInUser{UserID: 1, OrgID: 1, Login: "viewer", OrgRole: org.RoleViewer},
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(http.MethodGet, httptest.NewRecorder()),
		},
	}
	ds := &datasources.DataSource{URL: upstream.URL, Type: datasources.DS_PROMETHEUS}
	proxy, err := setupDSProxyTest(t, ctx, ds, nil, "api/v1/query")
	require.NoError(t, err)
	proxy.HandleRequest()
	require.NotNil(t, got, "datasource proxy did not reach the upstream")
	return got
}

func TestPluginProxy_CallerSuppliedForwardedClientIP(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodGet, "/api/plugin-proxy/my-app/api/v1/query", nil)
	req.RemoteAddr = peerAddr
	req.Header.Set("X-Forwarded-For", spoofed[0]+", "+spoofed[1])
	req.Header.Set("X-Real-IP", spoofed[2])
	req.Header.Set("Forwarded", "for="+spoofed[0])
	req = req.WithContext(contexthandler.WithAuthHTTPHeaders(req.Context(), setting.NewCfg()))

	proxy, err := NewPluginProxy(
		&pluginsettings.DTO{PluginID: "my-app", JSONData: map[string]any{}},
		[]*plugins.Route{{Path: "api/v1/query", Method: http.MethodGet, URL: upstream.URL}},
		req,
		web.NewResponseWriter(http.MethodGet, httptest.NewRecorder()),
		&user.SignedInUser{UserID: 1, OrgID: 1, Login: "viewer", OrgRole: org.RoleViewer},
		"api/v1/query",
		false,
		false,
		nil,
		tracing.InitializeTracerForTest(),
		&http.Transport{},
		acimpl.ProvideAccessControl(featuremgmt.WithFeatures()),
		featuremgmt.WithFeatures(),
	)
	require.NoError(t, err)
	proxy.HandleRequest()

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
