package api

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// TestHTTP2InitialWindowSettingsDoNotScaleWithStreams fails while Grafana is
// built with a Go net/http that, on every SETTINGS_INITIAL_WINDOW_SIZE frame,
// walks every open HTTP/2 stream and updates its flow-control window.
//
// protocol=h2 enables that server for any peer that can complete the TLS
// handshake. socket_h2 uses the same configureTLS branch and ServeTLS.
// No login is required: /healthz writes its body before authentication. A zero
// send window keeps the HTTP/2 response flush, and therefore the stream, open.
// The assertion passes once processing one of those SETTINGS frames is
// constant work per connection.
func TestHTTP2InitialWindowSettingsDoNotScaleWithStreams(t *testing.T) {
	addr, started := startH2Server(t)

	const settings = 80000
	one := floodInitialWindow(t, addr, 1, settings, started)
	many := floodInitialWindow(t, addr, 250, settings, started)
	ratio := float64(many) / float64(one)
	t.Logf("server SETTINGS_INITIAL_WINDOW_SIZE cost: 1 stream=%s 250 streams=%s ratio=%.2f", one, many, ratio)
	// Go 1.26.6 measures about 3.5x here. The fixed server updates one
	// connection window and stays near 1x.
	if ratio > 2.5 {
		t.Fatalf("SETTINGS_INITIAL_WINDOW_SIZE cost scaled with open streams (250 streams %s, 1 stream %s, ratio %.2f)", many, one, ratio)
	}
}

func startH2Server(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	cfg := setting.NewCfg()
	cfg.Protocol = setting.HTTP2Scheme
	cfg.MinTLSVersion = "TLS1.2"
	cfg.Domain = "127.0.0.1"

	var started atomic.Int64
	hs := &HTTPServer{
		Cfg: cfg,
		log: log.NewNopLogger(),
	}
	mux := web.New()
	mux.Use(func(ctx *web.Context) {
		if ctx.Req.URL.Path == "/healthz" && ctx.Req.Method == http.MethodGet {
			started.Add(1)
		}
		hs.healthzHandler(ctx)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	// Same server construction and TLS/HTTP/2 switch as HTTPServer.Run.
	hs.httpSrv = &http.Server{
		Handler:     mux,
		ReadTimeout: hs.Cfg.ReadTimeout,
	}
	if err := hs.configureTLS(); err != nil {
		t.Fatalf("configureTLS: %v", err)
	}
	go func() {
		_ = hs.httpSrv.ServeTLS(ln, "", "")
	}()
	t.Cleanup(func() { hs.httpSrv.Close() })
	return ln.Addr().String(), &started
}

func floodInitialWindow(t *testing.T, addr string, streams, settings int, started *atomic.Int64) time.Duration {
	t.Helper()
	started.Store(0)

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		ServerName:         "127.0.0.1",
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("negotiated %s, want h2", got)
	}

	bw := bufio.NewWriterSize(conn, 256<<10)
	wf := http2.NewFramer(bw, nil)
	rf := http2.NewFramer(nil, bufio.NewReaderSize(conn, 256<<10))
	if _, err = io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatalf("preface: %v", err)
	}
	// Zero window so the response body cannot be flushed and the streams stay open.
	if err = wf.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
		t.Fatalf("settings: %v", err)
	}
	if err = bw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err = readHandshake(conn, rf, wf, bw); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	var hdr bytes.Buffer
	enc := hpack.NewEncoder(&hdr)
	for i := 0; i < streams; i++ {
		hdr.Reset()
		for _, hf := range []hpack.HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: addr},
			{Name: ":path", Value: "/healthz"},
		} {
			if err = enc.WriteField(hf); err != nil {
				t.Fatalf("hpack: %v", err)
			}
		}
		block := append([]byte(nil), hdr.Bytes()...)
		if err = wf.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      uint32(1 + 2*i),
			BlockFragment: block,
			EndStream:     true,
			EndHeaders:    true,
		}); err != nil {
			t.Fatalf("headers: %v", err)
		}
	}
	if err = bw.Flush(); err != nil {
		t.Fatalf("flush headers: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for started.Load() != int64(streams) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := started.Load(); got != int64(streams) {
		t.Fatalf("open streams: handlers started %d, want %d", got, streams)
	}
	// The handler's Write only fills the HTTP/2 buffer. Give the response
	// flush time to block on the zero window before the timed flood.
	time.Sleep(100 * time.Millisecond)

	done := make(chan error, 1)
	go func() {
		for {
			frame, err := rf.ReadFrame()
			if err != nil {
				done <- err
				return
			}
			switch frame := frame.(type) {
			case *http2.PingFrame:
				if frame.IsAck() {
					done <- nil
					return
				}
			case *http2.GoAwayFrame:
				done <- fmt.Errorf("goaway %v %q", frame.ErrCode, frame.DebugData())
				return
			}
		}
	}()

	start := time.Now()
	for i := 0; i < settings; i++ {
		// Repeating the same value still updates every stream. Raising it
		// would release the blocked response body and drop the streams.
		if err = wf.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
			t.Fatalf("window settings: %v", err)
		}
		if i%128 == 127 {
			if err = bw.Flush(); err != nil {
				t.Fatalf("flush settings: %v", err)
			}
		}
	}
	var ping [8]byte
	binary.BigEndian.PutUint64(ping[:], uint64(streams))
	if err = wf.WritePing(false, ping); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err = bw.Flush(); err != nil {
		t.Fatalf("flush ping: %v", err)
	}

	select {
	case err = <-done:
		if err != nil {
			t.Fatalf("waiting for the server to finish the SETTINGS frames: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("timed out waiting for the server to finish the SETTINGS frames")
	}
	return time.Since(start)
}

func readHandshake(conn net.Conn, rf, wf *http2.Framer, bw *bufio.Writer) error {
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	defer conn.SetReadDeadline(time.Time{})
	sawSettings := false
	sawAck := false
	for !sawSettings || !sawAck {
		frame, err := rf.ReadFrame()
		if err != nil {
			return err
		}
		settings, ok := frame.(*http2.SettingsFrame)
		if !ok {
			continue
		}
		if settings.IsAck() {
			sawAck = true
			continue
		}
		sawSettings = true
		if err = wf.WriteSettingsAck(); err != nil {
			return err
		}
		if err = bw.Flush(); err != nil {
			return err
		}
	}
	return nil
}
