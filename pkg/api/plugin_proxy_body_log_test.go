package api

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// maxLoggedPluginProxyBody matches the limit enforced for every caller of the
// shared plugin-proxy request logger. http.MaxBytesReader may consume one
// extra byte when it checks the limit.
const maxLoggedPluginProxyBody = 1024

func TestLegacyPluginProxyRequestBodyLoggingIsBounded(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("https_proxy", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	closed := closedTCPAddr(t)
	viewer := &user.SignedInUser{UserID: 7, OrgID: 1, Login: "viewer", OrgRole: org.RoleViewer}

	t.Run("logging enabled does not buffer the caller body", func(t *testing.T) {
		n := postLegacyPluginProxy(t, true, viewer, closed, bytes.Repeat([]byte("E"), 256*1024))
		require.LessOrEqualf(t, n, maxLoggedPluginProxyBody+1,
			"legacy plugin proxy read %d bytes of a caller-supplied body before the upstream dial failed; logging must read at most a %d byte prefix",
			n, maxLoggedPluginProxyBody)
	})

	t.Run("logging disabled does not read the body", func(t *testing.T) {
		n := postLegacyPluginProxy(t, false, viewer, closed, bytes.Repeat([]byte("F"), 64*1024))
		require.Zero(t, n)
	})
}

func postLegacyPluginProxy(t *testing.T, logging bool, signedIn *user.SignedInUser, upstream string, payload []byte) int {
	t.Helper()

	const pluginID = "test-app"
	reader := &countingReadCloser{data: payload}
	req := httptest.NewRequest(http.MethodPost, "http://grafana.example/api/plugin-proxy/"+pluginID+"/echo", reader)
	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	req = web.SetURLParams(req, map[string]string{":pluginId": pluginID})

	hs := &HTTPServer{
		Cfg:           &setting.Cfg{DataProxyLogging: logging},
		Features:      featuremgmt.WithFeatures(),
		AccessControl: acimpl.ProvideAccessControl(featuremgmt.WithFeatures()),
		pluginStore: pluginstore.NewFakePluginStore(pluginstore.Plugin{
			JSONData: plugins.JSONData{
				ID:   pluginID,
				Type: plugins.TypeApp,
				Routes: []*plugins.Route{{
					Path:   "echo",
					Method: http.MethodPost,
					URL:    "http://" + upstream + "/upstream",
				}},
			},
		}),
		PluginSettings: &pluginsettings.FakePluginSettings{
			Plugins: map[string]*pluginsettings.DTO{
				pluginID: {PluginID: pluginID, OrgID: signedIn.OrgID, Enabled: true, JSONData: map[string]any{}},
			},
		},
		SecretsService: fakes.FakeSecretsService{},
		tracer:         tracing.InitializeTracerForTest(),
	}

	hs.ProxyPluginRequest(&contextmodel.ReqContext{
		Context:      &web.Context{Req: req, Resp: web.NewResponseWriter(http.MethodPost, httptest.NewRecorder())},
		SignedInUser: signedIn,
	})
	return reader.n
}

func closedTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
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
