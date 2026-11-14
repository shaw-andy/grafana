package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// http2InitialWindowSize is the connection and stream flow-control window
// every HTTP/2 peer starts with, before a WINDOW_UPDATE or SETTINGS change.
const http2InitialWindowSize = 65535

// TestHTTP2ServerDoesNotRefundConnectionFlowControlTwice sends a request body
// and then resets the stream, the way a client does against a Grafana server
// that was started with protocol h2 or socket_h2. The handler reads that body
// through web.Bind, which is what POST handlers such as login do.
//
// The handler waits until the reset has been written so the read happens
// after the reset is processed. Connection-level flow-control credit for
// those bytes must be returned once. Returning it again when the handler
// reads the buffered body lets the client exceed the connection window.
func TestHTTP2ServerDoesNotRefundConnectionFlowControlTwice(t *testing.T) {
	for _, protocol := range []setting.Scheme{setting.HTTP2Scheme, setting.SocketHTTP2Scheme} {
		t.Run(string(protocol), func(t *testing.T) {
			refunded, payload := runHTTP2FlowControlProbe(t, protocol)
			// A correct server returns this credit once. It may leave less than
			// 4KiB unsent: that is the minimum connection window update the
			// HTTP/2 server will write, so a smaller remainder stays local.
			const maxUnsentWindowUpdate = 4 << 10
			if refunded > payload || payload-refunded >= maxUnsentWindowUpdate {
				t.Fatalf("connection-level flow control refunded %d bytes for a %d byte body that was reset and then read; credit for that body must be returned once", refunded, payload)
			}
		})
	}
}

// runHTTP2FlowControlProbe starts the server the same way HTTPServer.Run does
// for h2 and socket_h2: configureTLS, then ServeTLS.
func runHTTP2FlowControlProbe(t *testing.T, protocol setting.Scheme) (refunded, payload int) {
	t.Helper()

	certFile, keyFile := writeTestCertificate(t)
	cfg := setting.NewCfg()
	cfg.Protocol = protocol
	cfg.MinTLSVersion = "TLS1.2"
	cfg.CertFile = certFile
	cfg.KeyFile = keyFile
	cfg.Domain = "localhost"

	entered := make(chan struct{})
	release := make(chan struct{})
	bound := make(chan bindResult, 1)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		var form struct {
			User     string `json:"user"`
			Password string `json:"password"`
		}
		err := web.Bind(r, &form)
		bound <- bindResult{userLen: len(form.User), err: err}
		w.WriteHeader(http.StatusNoContent)
	})

	var ln net.Listener
	var err error
	switch protocol {
	case setting.SocketHTTP2Scheme:
		dir, err := os.MkdirTemp("/tmp", "gfh2")
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		ln, err = net.Listen("unix", filepath.Join(dir, "s"))
		require.NoError(t, err)
	default:
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
	}

	hs := &HTTPServer{Cfg: cfg, log: log.NewNopLogger()}
	srv := &http.Server{Handler: handler, ReadTimeout: cfg.ReadTimeout}
	hs.httpSrv = srv
	require.NoError(t, hs.configureTLS())
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	raw, err := dialListener(ln)
	require.NoError(t, err)
	tlsConn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS12,
		ServerName:         "localhost",
	})
	require.NoError(t, tlsConn.Handshake())
	require.Equal(t, "h2", tlsConn.ConnectionState().NegotiatedProtocol)
	defer tlsConn.Close()

	refunded, payload = resetStreamAndRead(t, tlsConn, entered, release, bound)
	return refunded, payload
}

type bindResult struct {
	userLen int
	err     error
}

func resetStreamAndRead(t *testing.T, conn net.Conn, entered <-chan struct{}, release chan struct{}, bound <-chan bindResult) (int, int) {
	t.Helper()

	fr := http2.NewFramer(conn, conn)
	_, err := io.WriteString(conn, http2.ClientPreface)
	require.NoError(t, err)
	require.NoError(t, fr.WriteSettings())

	connWindow := http2InitialWindowSize
	streamWindow := http2InitialWindowSize
	maxFrame := 16 << 10
	gotSettings := false
	readDeadline := time.Now().Add(3 * time.Second)
	for !gotSettings {
		frame, err := readFrame(conn, fr, time.Until(readDeadline))
		require.NoError(t, err)
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			gotSettings = true
			if v, ok := f.Value(http2.SettingInitialWindowSize); ok {
				streamWindow = int(v)
			}
			if v, ok := f.Value(http2.SettingMaxFrameSize); ok && v > 0 {
				maxFrame = int(v)
			}
			require.NoError(t, fr.WriteSettingsAck())
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				connWindow += int(f.Increment)
			}
		}
		if time.Now().After(readDeadline) {
			break
		}
	}
	require.True(t, gotSettings, "server did not send SETTINGS")

	// The connection WINDOW_UPDATE is written just after SETTINGS. Read the
	// frames already buffered before declaring the window.
	for connWindow == http2InitialWindowSize {
		frame, err := readFrame(conn, fr, 2*time.Second)
		require.NoError(t, err)
		wu, ok := frame.(*http2.WindowUpdateFrame)
		if ok && wu.StreamID == 0 {
			connWindow += int(wu.Increment)
		}
	}

	payload := connWindow
	if streamWindow < payload {
		payload = streamWindow
	}
	require.Greater(t, payload, 0)

	const prefix = `{"user":"`
	const suffix = `","password":"pw"}`
	wantUserLen := payload - len(prefix) - len(suffix)
	require.Greater(t, wantUserLen, 0)
	body := jsonBody(payload)
	require.Len(t, body, payload)

	hdr := encodePostHeaders(authorityFor(conn), "/login")
	require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hdr,
		EndHeaders:    true,
	}))

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("handler was not called")
	}

	for off := 0; off < len(body); {
		n := maxFrame
		if n > len(body)-off {
			n = len(body) - off
		}
		require.NoError(t, fr.WriteData(1, false, body[off:off+n]))
		off += n
	}
	require.NoError(t, fr.WriteRSTStream(1, http2.ErrCodeCancel))

	// Give the server time to process the reset before the handler reads.
	// A refund that arrives here was issued for the reset itself.
	refunded := 0
	rstDeadline := time.Now().Add(time.Second)
	for time.Now().Before(rstDeadline) {
		frame, err := readFrame(conn, fr, time.Until(rstDeadline))
		if isTimeout(err) {
			break
		}
		require.NoError(t, err)
		if wu, ok := frame.(*http2.WindowUpdateFrame); ok && wu.StreamID == 0 {
			refunded += int(wu.Increment)
			if refunded >= payload {
				break
			}
		}
	}

	updates := make(chan int, 1024)
	stopping := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			frame, err := fr.ReadFrame()
			if err != nil {
				select {
				case <-stopping:
					return
				default:
				}
				if isTimeout(err) {
					continue
				}
				return
			}
			if wu, ok := frame.(*http2.WindowUpdateFrame); ok && wu.StreamID == 0 {
				updates <- int(wu.Increment)
			}
		}
	}()

	close(release)
	select {
	case result := <-bound:
		require.Equal(t, wantUserLen, result.userLen, "handler did not read the buffered body (bind error: %v)", result.err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish reading the body")
	}
	time.Sleep(300 * time.Millisecond)
	close(stopping)
	<-readerDone
	for {
		select {
		case n := <-updates:
			refunded += n
		default:
			return refunded, payload
		}
	}
}

func jsonBody(n int) []byte {
	const prefix = `{"user":"`
	const suffix = `","password":"pw"}`
	pad := n - len(prefix) - len(suffix)
	body := make([]byte, 0, n)
	body = append(body, prefix...)
	body = append(body, bytes.Repeat([]byte("a"), pad)...)
	body = append(body, suffix...)
	return body
}

func encodePostHeaders(authority, path string) []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	fields := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: path},
		{Name: ":authority", Value: authority},
		{Name: "content-type", Value: "application/json"},
	}
	for _, field := range fields {
		if err := enc.WriteField(field); err != nil {
			panic(err)
		}
	}
	return buf.Bytes()
}

func authorityFor(conn net.Conn) string {
	if conn.RemoteAddr().Network() == "unix" {
		return "localhost"
	}
	return conn.RemoteAddr().String()
}

func dialListener(ln net.Listener) (net.Conn, error) {
	switch addr := ln.Addr().(type) {
	case *net.UnixAddr:
		return net.Dial("unix", addr.Name)
	default:
		return net.Dial(addr.Network(), addr.String())
	}
}

func readFrame(conn net.Conn, fr *http2.Framer, d time.Duration) (http2.Frame, error) {
	if d <= 0 {
		d = time.Millisecond
	}
	_ = conn.SetReadDeadline(time.Now().Add(d))
	return fr.ReadFrame()
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func writeTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}
