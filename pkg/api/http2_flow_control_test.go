package api

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
)

// TestHTTP2ResetDoesNotRefundUnreadConnectionWindow checks CVE-2026-78663 against
// the HTTP/2 server HTTPServer starts for protocol h2 and socket_h2.
//
// A client sends almost a full connection window of DATA and then RST_STREAM
// while the handler is still running and has not read the body. The connection
// window must still count those unread bytes, so a new stream cannot send more
// than the single byte of window that remains. LoginPost reads request bodies
// through http.MaxBytesReader; the handler here does the same after the reset
// has been processed.
func TestHTTP2ResetDoesNotRefundUnreadConnectionWindow(t *testing.T) {
	for _, protocol := range []setting.Scheme{setting.HTTP2Scheme, setting.SocketHTTP2Scheme} {
		t.Run(string(protocol), func(t *testing.T) {
			testHTTP2ResetDoesNotRefundUnreadConnectionWindow(t, protocol)
		})
	}
}

func testHTTP2ResetDoesNotRefundUnreadConnectionWindow(t *testing.T, protocol setting.Scheme) {
	t.Helper()

	const connLimit = 65535 // stdlib minimum; equal to the HTTP/2 initial window, so no extra WINDOW_UPDATE is required

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandlers := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseHandlers)

	started := make(chan struct{})
	resetSeen := make(chan struct{})
	var startOnce sync.Once
	var resetOnce sync.Once

	var mu sync.Mutex
	reads := map[string]int{}

	hs := &HTTPServer{
		log: log.New("http2-flow-control-test"),
		Cfg: &setting.Cfg{
			Protocol:      protocol,
			MinTLSVersion: "TLS1.2",
			Domain:        "127.0.0.1",
		},
		httpSrv: &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id := r.Header.Get("X-Stream")
				if id == "1" {
					// CloseNotify fires from closeStream after the reset refund,
					// which is the point where unread DATA is still buffered.
					notify := w.(http.CloseNotifier).CloseNotify()
					startOnce.Do(func() { close(started) })
					<-notify
					resetOnce.Do(func() { close(resetSeen) })
				}
				<-release
				// Same cap LoginPost applies before the body is consumed.
				body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPreAuthFormBodySize))
				mu.Lock()
				reads[id] = len(body)
				mu.Unlock()
			}),
			HTTP2: &http.HTTP2Config{
				MaxReceiveBufferPerConnection: connLimit,
				MaxReceiveBufferPerStream:     connLimit,
			},
		},
	}
	require.NoError(t, hs.configureTLS())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		_ = hs.httpSrv.ServeTLS(ln, "", "")
	}()
	t.Cleanup(func() { _ = hs.httpSrv.Close() })

	tlsConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		ServerName:         "127.0.0.1",
		MinVersion:         tls.VersionTLS12,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = tlsConn.Close() })
	require.Equal(t, "h2", tlsConn.ConnectionState().NegotiatedProtocol)

	readFr := http2.NewFramer(io.Discard, tlsConn)
	writeFr := http2.NewFramer(tlsConn, nil)
	_, err = io.WriteString(tlsConn, http2.ClientPreface)
	require.NoError(t, err)
	require.NoError(t, writeFr.WriteSettings())

	connWindow, streamWindow, maxFrame := readServerHTTP2Preface(t, tlsConn, readFr, writeFr)
	require.LessOrEqual(t, int(connWindow), maxPreAuthFormBodySize, "handler body cap must cover the connection window")
	require.GreaterOrEqual(t, streamWindow, connWindow, "stream window must be able to fill the connection window")
	require.Greater(t, maxFrame, uint32(0))

	flowControlErr := make(chan struct{}, 1)
	go func() {
		for {
			frame, err := readFr.ReadFrame()
			if err != nil {
				return
			}
			switch f := frame.(type) {
			case *http2.RSTStreamFrame:
				if f.ErrCode == http2.ErrCodeFlowControl && f.Header().StreamID == 3 {
					flowControlErr <- struct{}{}
					return
				}
			case *http2.GoAwayFrame:
				if f.ErrCode == http2.ErrCodeFlowControl {
					flowControlErr <- struct{}{}
					return
				}
			}
		}
	}()

	firstSend := int(connWindow) - 1
	require.NoError(t, writeHeaders(writeFr, 1, "1"))
	require.NoError(t, writeDataChunks(writeFr, 1, firstSend, maxFrame, false))

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not start")
	}
	require.NoError(t, writeFr.WriteRSTStream(1, http2.ErrCodeCancel))

	select {
	case <-resetSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not finish resetting the first stream")
	}

	const secondSend = 2
	require.NoError(t, writeHeaders(writeFr, 3, "3"))
	require.NoError(t, writeDataChunks(writeFr, 3, secondSend, maxFrame, true))

	select {
	case <-flowControlErr:
		return
	case <-time.After(2 * time.Second):
	}

	releaseHandlers()
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		_, ok1 := reads["1"]
		_, ok3 := reads["3"]
		return ok1 && ok3
	}, 5*time.Second, 10*time.Millisecond)

	mu.Lock()
	gotFirst, gotSecond := reads["1"], reads["3"]
	mu.Unlock()
	t.Fatalf("protocol %s accepted %d bytes on a new stream while %d unread bytes from a reset stream were still buffered (connection window %d, first stream read %d). Reset refunded connection flow control for data the handler had not consumed.",
		protocol, gotSecond, firstSend, connWindow, gotFirst)
}

func readServerHTTP2Preface(t *testing.T, conn net.Conn, readFr, writeFr *http2.Framer) (connWindow, streamWindow, maxFrame uint32) {
	t.Helper()
	connWindow = 65535
	streamWindow = 65535
	maxFrame = 16384

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	sawSettings := false
	for {
		frame, err := readFr.ReadFrame()
		if err != nil {
			require.True(t, sawSettings, "reading server preface: %v", err)
			break
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			require.NoError(t, f.ForeachSetting(func(s http2.Setting) error {
				switch s.ID {
				case http2.SettingInitialWindowSize:
					streamWindow = s.Val
				case http2.SettingMaxFrameSize:
					maxFrame = s.Val
				}
				return nil
			}))
			require.NoError(t, writeFr.WriteSettingsAck())
			sawSettings = true
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
		case *http2.WindowUpdateFrame:
			if f.Header().StreamID == 0 {
				connWindow += f.Increment
			}
		}
	}
	require.NoError(t, conn.SetReadDeadline(time.Time{}))
	return connWindow, streamWindow, maxFrame
}

func writeHeaders(fr *http2.Framer, streamID uint32, streamTag string) error {
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	fields := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/login"},
		{Name: ":authority", Value: "127.0.0.1"},
		{Name: "content-type", Value: "application/json"},
		{Name: "x-stream", Value: streamTag},
	}
	for _, field := range fields {
		if err := enc.WriteField(field); err != nil {
			return err
		}
	}
	return fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: block.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	})
}

func writeDataChunks(fr *http2.Framer, streamID uint32, n int, maxFrame uint32, endStream bool) error {
	payload := bytes.Repeat([]byte("a"), n)
	if n == 0 {
		return fr.WriteData(streamID, endStream, nil)
	}
	for len(payload) > 0 {
		chunk := payload
		if uint32(len(chunk)) > maxFrame {
			chunk = payload[:maxFrame]
		}
		payload = payload[len(chunk):]
		if err := fr.WriteData(streamID, endStream && len(payload) == 0, chunk); err != nil {
			return err
		}
	}
	return nil
}
