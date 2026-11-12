package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/client"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/plugins/manager/registry"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

func TestPluginResource_CallerSuppliedForwardedClientIP(t *testing.T) {
	const (
		pluginID = "test-app"
		peerAddr = "192.0.2.10:34567"
		peerHost = "192.0.2.10"
	)
	spoofed := []string{"203.0.113.50", "198.51.100.8", "198.51.100.23"}

	var got http.Header
	fake := &pluginfakes.FakePluginClient{
		CallResourceHandlerFunc: func(_ context.Context, req *backend.CallResourceRequest, sender backend.CallResourceResponseSender) error {
			got = http.Header(req.Headers).Clone()
			return sender.Send(&backend.CallResourceResponse{
				Status:  http.StatusOK,
				Headers: map[string][]string{"Content-Type": {"application/json"}},
				Body:    []byte(`{}`),
			})
		},
	}
	p := &plugins.Plugin{JSONData: plugins.JSONData{ID: pluginID, Backend: true}}
	p.RegisterClient(fake)
	reg := registry.NewInMemory()
	require.NoError(t, reg.Add(context.Background(), p))

	hs := &HTTPServer{pluginClient: client.ProvideService(reg)}

	req := httptest.NewRequest(http.MethodGet, "/api/plugins/"+pluginID+"/resources/api/v1/query", nil)
	req.RemoteAddr = peerAddr
	req.Header.Set("X-Forwarded-For", spoofed[0]+", "+spoofed[1])
	req.Header.Set("X-Real-IP", spoofed[2])
	req.Header.Set("Forwarded", "for="+spoofed[0])
	req = req.WithContext(contexthandler.WithAuthHTTPHeaders(req.Context(), setting.NewCfg()))
	req = web.SetURLParams(req, map[string]string{"*": "api/v1/query"})

	cloned, err := hs.pluginResourceRequest(&contextmodel.ReqContext{Context: &web.Context{Req: req}})
	require.NoError(t, err)
	err = hs.makePluginResourceRequest(httptest.NewRecorder(), cloned, backend.PluginContext{PluginID: pluginID})
	require.NoError(t, err)

	requireOnlyAcceptedClientIP(t, got, peerHost, spoofed...)
}
