package appplugin

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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	apppluginV0 "github.com/grafana/grafana/pkg/apis/appplugin/v0alpha1"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/user"
)

// maxLoggedPluginProxyBody matches the limit enforced for the shared
// plugin-proxy request logger. http.MaxBytesReader may consume one extra byte
// when it checks the limit.
const maxLoggedPluginProxyBody = 1024

func TestAppPluginConnectProxyRequestBodyLoggingIsBounded(t *testing.T) {
	viewer := &user.SignedInUser{UserID: 7, OrgID: 1, Login: "viewer", OrgRole: org.RoleViewer}

	t.Run("logging enabled does not read past the prefix before dialing", func(t *testing.T) {
		n := postConnectProxy(t, true, viewer, bytes.Repeat([]byte("G"), 256*1024))
		require.LessOrEqualf(t, n, maxLoggedPluginProxyBody+1,
			"app plugin connect proxy read %d bytes of a caller-supplied body before dialing the upstream; logging must read at most a %d byte prefix",
			n, maxLoggedPluginProxyBody)
	})

	t.Run("logging disabled does not read the body before dialing", func(t *testing.T) {
		n := postConnectProxy(t, false, viewer, bytes.Repeat([]byte("H"), 64*1024))
		require.Zero(t, n)
	})
}

func postConnectProxy(t *testing.T, logging bool, signedIn *user.SignedInUser, payload []byte) int {
	t.Helper()

	reader := &countingReadCloser{data: payload}
	var dialed bool
	proxyREST := &subProxyREST{
		pluginID: "test-app",
		routes: []*plugins.Route{{
			Path:   "echo",
			Method: http.MethodPost,
			URL:    "http://127.0.0.1:9/upstream",
		}},
		settingsProvider: func(context.Context) (*apppluginV0.Settings, pluginsettings.DecryptedSecureJSONLoader, error) {
			return &apppluginV0.Settings{}, nil, nil
		},
		DataProxyLogging: logging,
		tracer:           tracing.InitializeTracerForTest(),
		features:         featuremgmt.WithFeatures(),
		pluginProxyTransport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialed = true
				return nil, errors.New("stop before writing the request body")
			},
		},
	}

	ctx := identity.WithRequester(context.Background(), signedIn)
	ctx = request.WithNamespace(ctx, "default")
	handler, err := proxyREST.Connect(ctx, apppluginV0.INSTANCE_NAME, nil, &recordingResponder{})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "http://grafana.example/apis/test.ext.grafana.app/v0alpha1/namespaces/default/app/instance/proxy/echo", reader)
	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	require.True(t, dialed, "the connect proxy must attempt to dial the upstream so the test observes only the bytes read before that dial")
	return reader.n
}

type recordingResponder struct {
	err error
}

func (r *recordingResponder) Object(int, runtime.Object) {}

func (r *recordingResponder) Error(err error) { r.err = err }

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
