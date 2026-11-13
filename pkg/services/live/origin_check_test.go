package live

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/centrifugal/protocol"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// victimLiveUserID is the centrifuge user id ProvideService derives from the
// signed-in user attached to the websocket request.
const victimLiveUserID = "42"

// dashboardChannel is a channel the signed-in user is allowed to subscribe to
// and publish on. The fake dashboard access service grants both.
const dashboardChannel = "default/grafana/dashboard/uid/abc"

// TestLiveOriginComparison is the origin decision used by every Live websocket.
// A missing port is the scheme default (80 for http, 443 for https), not a match
// for every port, and the request Host header is not an allowlist.
func TestLiveOriginComparison(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		origin         string
		appURL         string
		host           string
		allowedOrigins []string
		allowed        bool
	}{
		{
			name:    "omitted http port does not match a non-default root port",
			origin:  "http://localhost",
			appURL:  "http://localhost:3000/",
			host:    "localhost:3000",
			allowed: false,
		},
		{
			name:    "omitted http port matches case-insensitively only when the root port is the default",
			origin:  "http://LOCALHOST",
			appURL:  "http://localhost:3000/",
			host:    "localhost:3000",
			allowed: false,
		},
		{
			name:    "omitted https port does not match a non-default root port",
			origin:  "https://grafana.example",
			appURL:  "https://grafana.example:8443/grafana/",
			host:    "grafana.example:8443",
			allowed: false,
		},
		{
			name:    "omitted http port matches the default port",
			origin:  "http://localhost",
			appURL:  "http://localhost:80/",
			host:    "localhost",
			allowed: true,
		},
		{
			name:    "omitted https port matches the default port",
			origin:  "https://www.example.com",
			appURL:  "https://www.example.com:443/grafana/",
			host:    "www.example.com",
			allowed: true,
		},
		{
			name:    "root URL without a port is the scheme default",
			origin:  "http://localhost",
			appURL:  "http://localhost/",
			host:    "localhost",
			allowed: true,
		},
		{
			name:    "explicit port does not match a root URL that uses the default port",
			origin:  "http://localhost:3000",
			appURL:  "http://localhost/",
			host:    "localhost:3000",
			allowed: false,
		},
		{
			name:    "matching explicit origin is allowed",
			origin:  "http://localhost:3000",
			appURL:  "http://localhost:3000/",
			host:    "localhost:3000",
			allowed: true,
		},
		{
			name:    "different explicit port is rejected",
			origin:  "http://localhost:8000",
			appURL:  "http://localhost:3000/",
			host:    "localhost:3000",
			allowed: false,
		},
		{
			name:    "different scheme is rejected when the origin host equals the request host",
			origin:  "http://grafana.example",
			appURL:  "https://grafana.example/",
			host:    "grafana.example",
			allowed: false,
		},
		{
			name:    "request host equal to the origin host does not bypass the root URL",
			origin:  "http://evil.example",
			appURL:  "http://localhost:3000/",
			host:    "evil.example",
			allowed: false,
		},
		{
			name:           "configured allowed origin is still accepted",
			origin:         "https://test.example.com",
			appURL:         "http://localhost:3000/",
			host:           "localhost:3000",
			allowedOrigins: []string{"https://test.example.com"},
			allowed:        true,
		},
		{
			name:    "different hostname is rejected",
			origin:  "http://evil.example",
			appURL:  "http://localhost:3000/",
			host:    "localhost:3000",
			allowed: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			appURL, err := url.Parse(tc.appURL)
			require.NoError(t, err)
			globs, err := setting.GetAllowedOriginGlobs(tc.allowedOrigins)
			require.NoError(t, err)

			check := getCheckOriginFunc(appURL, tc.allowedOrigins, globs)
			r := httptest.NewRequest(http.MethodGet, tc.appURL, nil)
			r.Host = tc.host
			r.Header.Set("Origin", tc.origin)
			require.Equal(t, tc.allowed, check(r), "origin %s app %s host %s", tc.origin, tc.appURL, tc.host)
		})
	}
}

// TestLiveWebsocketOriginIsTheConnectionGate dials the handlers ProvideService
// registers. The origin check runs inside the websocket upgrade, and the
// upgrade is what attaches the signed-in user to the Live connection.
func TestLiveWebsocketOriginIsTheConnectionGate(t *testing.T) {
	cfg := setting.NewCfg()
	// Shipped root URL: conf/defaults.ini sets root_url from protocol, domain and http_port.
	cfg.AppURL = "http://localhost:3000/"
	cfg.LiveMaxConnections = 100
	cfg.LiveAllowedOrigins = []string{"http://extra.example"}

	g, err := ProvideService(cfg,
		routing.NewRouteRegister(),
		nil, nil, nil,
		nil,
		&usagestats.UsageStatsMock{T: t},
		featuremgmt.WithFeatures(),
		&dashboards.FakeDashboardService{},
		nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = g.node.Shutdown(context.Background())
	})

	victim := &user.SignedInUser{
		UserID:    42,
		OrgID:     1,
		Namespace: "default",
		OrgRole:   identity.RoleViewer,
		Login:     "victim",
	}

	liveHandler := g.websocketHandler.(func(*contextmodel.ReqContext))
	pushHandler := g.pushWebsocketHandler.(func(*contextmodel.ReqContext))
	pipelineHandler := g.pushPipelineWebsocketHandler.(func(*contextmodel.ReqContext))

	mux := http.NewServeMux()
	mux.Handle("/api/live/ws", liveRequestHandler(liveHandler, victim, nil))
	mux.Handle("/api/live/push/stream1", liveRequestHandler(pushHandler, victim, map[string]string{":streamId": "stream1"}))
	mux.Handle("/api/live/pipeline/push/default/grafana/dashboard/uid/abc", liveRequestHandler(pipelineHandler, victim, map[string]string{"*": "default/grafana/dashboard/uid/abc"}))

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	wsURL := "ws" + server.URL[len("http"):] + "/api/live/ws"
	pushURL := "ws" + server.URL[len("http"):] + "/api/live/push/stream1"
	pipelineURL := "ws" + server.URL[len("http"):] + "/api/live/pipeline/push/default/grafana/dashboard/uid/abc"

	t.Run("matching root origin subscribes and publishes as the signed-in user", func(t *testing.T) {
		conn := requireLiveUpgrade(t, wsURL, "http://localhost:3000", "localhost:3000")
		defer conn.Close()
		exerciseVictimSession(t, conn, g)
		conn.Close()
		require.Eventually(t, func() bool {
			return len(g.node.Hub().UserConnections(victimLiveUserID)) == 0
		}, time.Second, 10*time.Millisecond)
	})

	t.Run("omitted default port cannot use the signed-in live session", func(t *testing.T) {
		refuseLiveUpgrade(t, g, wsURL, "http://localhost", "localhost:3000")
	})

	t.Run("origin host matching the request host cannot use the signed-in live session", func(t *testing.T) {
		refuseLiveUpgrade(t, g, wsURL, "http://evil.example", "evil.example")
	})

	t.Run("different scheme with the same host cannot use the signed-in live session", func(t *testing.T) {
		refuseLiveUpgrade(t, g, wsURL, "https://localhost:3000", "localhost:3000")
	})

	t.Run("configured allowed origin can connect", func(t *testing.T) {
		conn := requireLiveUpgrade(t, wsURL, "http://extra.example", "localhost:3000")
		defer conn.Close()
		exerciseVictimSession(t, conn, g)
		conn.Close()
		require.Eventually(t, func() bool {
			return len(g.node.Hub().UserConnections(victimLiveUserID)) == 0
		}, time.Second, 10*time.Millisecond)
	})

	t.Run("push socket rejects an omitted port and a host-only match", func(t *testing.T) {
		conn := requireLiveUpgrade(t, pushURL, "http://localhost:3000", "localhost:3000")
		conn.Close()
		refuseUpgrade(t, pushURL, "http://localhost", "localhost:3000")
		refuseUpgrade(t, pushURL, "http://evil.example", "evil.example")
	})

	t.Run("pipeline push socket rejects an omitted port and a host-only match", func(t *testing.T) {
		conn := requireLiveUpgrade(t, pipelineURL, "http://localhost:3000", "localhost:3000")
		conn.Close()
		refuseUpgrade(t, pipelineURL, "http://localhost", "localhost:3000")
		refuseUpgrade(t, pipelineURL, "http://evil.example", "evil.example")
	})
}

func liveRequestHandler(handler func(*contextmodel.ReqContext), user *user.SignedInUser, params map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if params != nil {
			r = web.SetURLParams(r, params)
		}
		handler(&contextmodel.ReqContext{
			Context: &web.Context{
				Req:  r,
				Resp: web.NewResponseWriter(r.Method, w),
			},
			SignedInUser: user,
			IsSignedIn:   true,
		})
	})
}

func dialLive(url, origin, host string) (*websocket.Conn, *http.Response, error) {
	header := http.Header{}
	header.Set("Origin", origin)
	if host != "" {
		header.Set("Host", host)
	}
	return websocket.DefaultDialer.Dial(url, header)
}

func requireLiveUpgrade(t *testing.T, url, origin, host string) *websocket.Conn {
	t.Helper()
	conn, resp, err := dialLive(url, origin, host)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	require.NoError(t, err, "origin %s host %s status %v", origin, host, statusOf(resp))
	return conn
}

func refuseUpgrade(t *testing.T, url, origin, host string) {
	t.Helper()
	conn, resp, err := dialLive(url, origin, host)
	if conn != nil {
		_ = conn.Close()
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err, "origin %s host %s was upgraded", origin, host)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "origin %s host %s", origin, host)
}

func refuseLiveUpgrade(t *testing.T, g *GrafanaLive, url, origin, host string) {
	t.Helper()
	conn, resp, err := dialLive(url, origin, host)
	if err == nil {
		defer conn.Close()
		exerciseVictimSession(t, conn, g)
		t.Fatalf("origin %s with host %s opened a Live socket as user %s and used the dashboard channel", origin, host, victimLiveUserID)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "origin %s host %s", origin, host)
	require.Empty(t, g.node.Hub().UserConnections(victimLiveUserID))
}

func exerciseVictimSession(t *testing.T, conn *websocket.Conn, g *GrafanaLive) {
	t.Helper()

	writeCommand(t, conn, &protocol.Command{Id: 1, Connect: &protocol.ConnectRequest{}})
	connectReply := readCommandReply(t, conn, 1)
	require.Nil(t, connectReply.Error, "connect: %+v", connectReply.Error)
	require.NotNil(t, connectReply.Connect)

	conns := g.node.Hub().UserConnections(victimLiveUserID)
	require.Len(t, conns, 1)
	for _, client := range conns {
		require.Equal(t, victimLiveUserID, client.UserID())
	}

	writeCommand(t, conn, &protocol.Command{
		Id:        2,
		Subscribe: &protocol.SubscribeRequest{Channel: dashboardChannel},
	})
	subscribeReply := readCommandReply(t, conn, 2)
	require.Nil(t, subscribeReply.Error, "subscribe: %+v", subscribeReply.Error)
	require.NotNil(t, subscribeReply.Subscribe)

	event, err := json.Marshal(map[string]string{
		"uid":    "abc",
		"action": "editing-started",
	})
	require.NoError(t, err)
	writeCommand(t, conn, &protocol.Command{
		Id: 3,
		Publish: &protocol.PublishRequest{
			Channel: dashboardChannel,
			Data:    event,
		},
	})
	publishReply := readCommandReply(t, conn, 3)
	require.Nil(t, publishReply.Error, "publish: %+v", publishReply.Error)
	require.NotNil(t, publishReply.Publish)
}

func writeCommand(t *testing.T, conn *websocket.Conn, cmd *protocol.Command) {
	t.Helper()
	payload, err := json.Marshal(cmd)
	require.NoError(t, err)
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, payload))
}

func readCommandReply(t *testing.T, conn *websocket.Conn, id uint32) protocol.Reply {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	for {
		_, data, err := conn.ReadMessage()
		require.NoError(t, err)
		for _, line := range bytesSplitLines(data) {
			if len(line) == 0 || string(line) == "{}" {
				continue
			}
			var reply protocol.Reply
			require.NoError(t, json.Unmarshal(line, &reply), "line %s", line)
			if reply.Id == id {
				return reply
			}
		}
	}
}

func bytesSplitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, trimSpace(data[start:i]))
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, trimSpace(data[start:]))
	}
	return lines
}

func trimSpace(b []byte) []byte {
	i := 0
	j := len(b)
	for i < j && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\t' || b[j-1] == '\r') {
		j--
	}
	return b[i:j]
}

func statusOf(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}
