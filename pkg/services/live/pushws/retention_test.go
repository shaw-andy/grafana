package pushws

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/live/livecontext"
	"github.com/grafana/grafana/pkg/services/live/managedstream"
	"github.com/grafana/grafana/pkg/services/user"
)

const (
	maxWebsocketChannels = 64
	maxWebsocketFrames   = 32
)

func TestPushWebsocketRetention(t *testing.T) {
	newHarness := func() (*managedstream.MemoryFrameCache, func(streamID string) (*httptest.Server, <-chan struct{})) {
		cache := managedstream.NewMemoryFrameCache()
		runner := managedstream.NewRunner(func(string, string, []byte) error { return nil }, nil, cache)
		handler := NewHandler(runner, Config{CheckOrigin: func(*http.Request) bool { return true }})
		user := &user.SignedInUser{UserID: 7, OrgID: 1, OrgRole: "Editor", Namespace: "default"}
		// done is closed when ServeHTTP returns, which is after every message
		// read before the connection closed has been pushed.
		serve := func(streamID string) (*httptest.Server, <-chan struct{}) {
			done := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				ctx := identity.WithRequester(r.Context(), user)
				ctx = livecontext.SetContextStreamID(ctx, streamID)
				handler.ServeHTTP(w, r.WithContext(ctx))
			}))
			return srv, done
		}
		return cache, serve
	}

	dial := func(t *testing.T, srv *httptest.Server) *websocket.Conn {
		t.Helper()
		wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
		conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		require.NoError(t, err)
		return conn
	}

	t.Run("one message with many measurements", func(t *testing.T) {
		cache, serve := newHarness()
		srv, done := serve("one")
		defer srv.Close()
		conn := dial(t, srv)

		var body strings.Builder
		for i := 0; i < maxWebsocketFrames+8; i++ {
			fmt.Fprintf(&body, "m%d v=1\n", i)
		}
		require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(body.String())))
		require.NoError(t, conn.Close())
		waitFor(t, done)

		channels, err := cache.GetActiveChannels("default")
		require.NoError(t, err)
		require.LessOrEqualf(t, len(channels), maxWebsocketFrames,
			"one websocket message stored %d frames", len(channels))
	})

	t.Run("many stream ids", func(t *testing.T) {
		cache, serve := newHarness()
		const extra = 8
		var conns []*websocket.Conn
		var dones []<-chan struct{}
		var servers []*httptest.Server
		t.Cleanup(func() {
			for _, conn := range conns {
				_ = conn.Close()
			}
			for _, srv := range servers {
				srv.Close()
			}
		})

		for i := 0; i < maxWebsocketChannels+extra; i++ {
			srv, done := serve(fmt.Sprintf("ws%d", i))
			servers = append(servers, srv)
			dones = append(dones, done)
			conn := dial(t, srv)
			conns = append(conns, conn)
			require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte("cpu v=1\n")))
			require.NoError(t, conn.Close())
		}
		for _, done := range dones {
			waitFor(t, done)
		}

		channels, err := cache.GetActiveChannels("default")
		require.NoError(t, err)
		require.LessOrEqualf(t, len(channels), maxWebsocketChannels,
			"websocket push stored %d channels", len(channels))
	})
}

func waitFor(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("push handler did not finish")
	}
}
