package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// TestHTTP2ResetDoesNotDoubleRefundConnectionWindow checks CVE-2026-78663 against
// the HTTP/2 server Grafana starts for protocol=h2 and protocol=socket_h2.
//
// Those protocols leave TLSNextProto nil and call ServeTLS, so the process serves
// the standard library HTTP/2 server. A client can send a body and then RST_STREAM.
// Pre-auth handlers (login, signup, password reset, invite completion) read that
// body through MaxBytesReader and web.Bind. The connection flow-control window
// must not grow past the window the server advertised before the body arrived:
// the reset refund and the later body read must not both return the same bytes.
func TestHTTP2ResetDoesNotDoubleRefundConnectionWindow(t *testing.T) {
	t.Run("h2", func(t *testing.T) {
		assertSingleConnectionRefund(t, setting.HTTP2Scheme)
	})
	t.Run("socket_h2", func(t *testing.T) {
		assertSingleConnectionRefund(t, setting.SocketHTTP2Scheme)
	})
}

func assertSingleConnectionRefund(t *testing.T, protocol setting.Scheme) {
	t.Helper()

	const userPadding = 12000
	body := []byte(`{"user":"` + strings.Repeat("a", userPadding) + `"}`)
	require.GreaterOrEqual(t, len(body), 4096, "body must be large enough that a flow-control refund is flushed")

	var gotUser string
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		// Same reads as LoginPost and the other pre-auth form handlers.
		r.Body = http.MaxBytesReader(w, r.Body, maxPreAuthFormBodySize)
		var form struct {
			User string `json:"user"`
		}
		_ = web.Bind(r, &form)
		gotUser = form.User
		close(finished)
		w.WriteHeader(http.StatusBadRequest)
	})

	addr, cleanup := startGrafanaHTTP2Server(t, protocol, handler)
	defer cleanup()

	client := dialH2(t, protocol, addr)
	defer client.Close()

	settled := client.settleWindow(t)
	client.writeHeaders(t, "/login", addr, len(body))

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("handler was not called")
	}

	client.writeData(t, body)
	client.writeRST(t)

	// The handler is still blocked, so any credit restored here is the reset
	// refund of buffered data. A fixed server may instead restore that credit
	// only when the handler reads; give the server time to process the frames
	// either way before unblocking the read.
	deadline := time.Now().Add(2 * time.Second)
	for {
		cur, _, goaway := client.snapshot()
		if goaway != "" {
			t.Fatalf("server sent GOAWAY after reset: %s", goaway)
		}
		if cur > settled {
			t.Fatalf("connection window grew from %d to %d before the handler read %d bytes", settled, cur, len(body))
		}
		if cur >= settled || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(release)
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish reading the body")
	}

	final := client.waitStable(t, 400*time.Millisecond, 3*time.Second)
	if final > settled {
		t.Fatalf("connection window grew from %d to %d after a %d-byte body was reset and then read (handler consumed %d user bytes): flow-control credit was returned twice",
			settled, final, len(body), len(gotUser))
	}
	if final < settled {
		t.Fatalf("connection window fell from %d to %d; the server never returned the %d-byte body, so the reset-and-read path did not run (handler consumed %d user bytes)",
			settled, final, len(body), len(gotUser))
	}
}

func startGrafanaHTTP2Server(t *testing.T, protocol setting.Scheme, handler http.Handler) (string, func()) {
	t.Helper()

	certFile, keyFile := writeServerCert(t)
	cfg := setting.NewCfg()
	cfg.Protocol = protocol
	cfg.MinTLSVersion = "TLS1.2"
	cfg.CertFile = certFile
	cfg.KeyFile = keyFile
	cfg.ReadTimeout = 0

	hs := &HTTPServer{
		log: log.New("http2-flow"),
		Cfg: cfg,
	}
	hs.httpSrv = &http.Server{
		Handler:     handler,
		ReadTimeout: cfg.ReadTimeout,
	}
	require.NoError(t, hs.configureTLS())

	var ln net.Listener
	var addr string
	var err error
	if protocol == setting.SocketHTTP2Scheme {
		addr = filepath.Join(os.TempDir(), strings.ReplaceAll(t.Name(), "/", "_")+".sock")
		_ = os.Remove(addr)
		ln, err = net.ListenUnix("unix", &net.UnixAddr{Name: addr, Net: "unix"})
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			addr = ln.Addr().String()
		}
	}
	require.NoError(t, err)

	serveErr := make(chan error, 1)
	go func() {
		err := hs.httpSrv.ServeTLS(ln, "", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	cleanup := func() {
		_ = hs.httpSrv.Close()
		if protocol == setting.SocketHTTP2Scheme {
			_ = os.Remove(addr)
		}
	}
	t.Cleanup(func() {
		select {
		case err := <-serveErr:
			t.Errorf("HTTP/2 server: %v", err)
		default:
		}
	})
	return addr, cleanup
}

func writeServerCert(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	writePEM(t, certFile, "CERTIFICATE", der)
	writePEM(t, keyFile, "EC PRIVATE KEY", keyDER)
	return certFile, keyFile
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: typ, Bytes: der}))
}

const (
	http2FrameData         = 0x0
	http2FrameHeaders      = 0x1
	http2FrameRSTStream    = 0x3
	http2FrameSettings     = 0x4
	http2FrameGoAway       = 0x7
	http2FrameWindowUpdate = 0x8
	http2FlagSettingsAck   = 0x1
	http2FlagEndHeaders    = 0x4
	http2ErrCodeCancel     = 0x8
	http2ClientPreface     = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	http2InitialWindow     = 65535
)

// h2Client is a frame reader and writer built from the net/http HTTP/2 frame
// layout (9-byte header, WINDOW_UPDATE increment in the 4-byte payload).
type h2Client struct {
	t       *testing.T
	conn    net.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	window  int64
	updates int
	goaway  string
}

func dialH2(t *testing.T, protocol setting.Scheme, addr string) *h2Client {
	t.Helper()
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS12,
	}
	var raw net.Conn
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for {
		if protocol == setting.SocketHTTP2Scheme {
			raw, err = net.DialTimeout("unix", addr, 200*time.Millisecond)
		} else {
			raw, err = net.DialTimeout("tcp", addr, 200*time.Millisecond)
		}
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			require.NoError(t, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	conn := tls.Client(raw, tlsCfg)
	require.NoError(t, conn.Handshake())
	require.Equal(t, "h2", conn.ConnectionState().NegotiatedProtocol)

	c := &h2Client{t: t, conn: conn, window: http2InitialWindow}
	go c.readLoop()

	_, err = io.WriteString(conn, http2ClientPreface)
	require.NoError(t, err)
	c.writeFrame(http2FrameSettings, 0, 0, nil)
	return c
}

func (c *h2Client) Close() {
	_ = c.conn.Close()
}

func (c *h2Client) readLoop() {
	for {
		var hdr [9]byte
		if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
			return
		}
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		typ := hdr[3]
		flags := hdr[4]
		streamID := binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff
		payload := make([]byte, length)
		if _, err := io.ReadFull(c.conn, payload); err != nil {
			return
		}
		switch typ {
		case http2FrameWindowUpdate:
			if streamID == 0 && len(payload) == 4 {
				inc := binary.BigEndian.Uint32(payload) & 0x7fffffff
				c.mu.Lock()
				c.window += int64(inc)
				c.updates++
				c.mu.Unlock()
			}
		case http2FrameSettings:
			if flags&http2FlagSettingsAck == 0 {
				c.writeFrame(http2FrameSettings, http2FlagSettingsAck, 0, nil)
			}
		case http2FrameGoAway:
			code := uint32(0)
			if len(payload) >= 8 {
				code = binary.BigEndian.Uint32(payload[4:8])
			}
			c.mu.Lock()
			c.goaway = "code=" + itoa(uint64(code))
			c.mu.Unlock()
		}
	}
}

func (c *h2Client) snapshot() (window int64, updates int, goaway string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.window, c.updates, c.goaway
}

func (c *h2Client) settleWindow(t *testing.T) int64 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, updates, goaway := c.snapshot()
		if goaway != "" {
			t.Fatalf("server sent GOAWAY before the request: %s", goaway)
		}
		if updates >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not advertise a connection flow-control window")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return c.waitStable(t, 200*time.Millisecond, 3*time.Second)
}

func (c *h2Client) waitStable(t *testing.T, quiet, timeout time.Duration) int64 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last, _, goaway := c.snapshot()
	if goaway != "" {
		t.Fatalf("server sent GOAWAY: %s", goaway)
	}
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		cur, _, goaway := c.snapshot()
		if goaway != "" {
			t.Fatalf("server sent GOAWAY: %s", goaway)
		}
		if cur != last {
			last = cur
			stableSince = time.Now()
			continue
		}
		if time.Since(stableSince) >= quiet {
			return cur
		}
	}
	cur, _, _ := c.snapshot()
	return cur
}

func (c *h2Client) writeHeaders(t *testing.T, path, authority string, contentLength int) {
	t.Helper()
	var block []byte
	block = appendLiteral(block, ":method", "POST")
	block = appendLiteral(block, ":scheme", "https")
	block = appendLiteral(block, ":path", path)
	block = appendLiteral(block, ":authority", authority)
	block = appendLiteral(block, "content-type", "application/json")
	block = appendLiteral(block, "content-length", itoa(uint64(contentLength)))
	c.writeFrame(http2FrameHeaders, http2FlagEndHeaders, 1, block)
}

func (c *h2Client) writeData(t *testing.T, body []byte) {
	t.Helper()
	const maxFrame = 16384
	for len(body) > 0 {
		n := len(body)
		if n > maxFrame {
			n = maxFrame
		}
		c.writeFrame(http2FrameData, 0, 1, body[:n])
		c.mu.Lock()
		c.window -= int64(n)
		c.mu.Unlock()
		body = body[n:]
	}
}

func (c *h2Client) writeRST(t *testing.T) {
	t.Helper()
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], http2ErrCodeCancel)
	c.writeFrame(http2FrameRSTStream, 0, 1, payload[:])
}

func (c *h2Client) writeFrame(typ, flags byte, streamID uint32, payload []byte) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	var hdr [9]byte
	n := len(payload)
	hdr[0] = byte(n >> 16)
	hdr[1] = byte(n >> 8)
	hdr[2] = byte(n)
	hdr[3] = typ
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:], streamID)
	_, _ = c.conn.Write(hdr[:])
	if len(payload) > 0 {
		_, _ = c.conn.Write(payload)
	}
}

func appendLiteral(dst []byte, name, value string) []byte {
	// Literal header field without indexing, new name (RFC 7541 §6.2.2).
	dst = append(dst, 0x00)
	dst = appendHPackString(dst, name)
	dst = appendHPackString(dst, value)
	return dst
}

func appendHPackString(dst []byte, s string) []byte {
	// 7-bit integer length, Huffman bit clear. Matches hpack.readString.
	n := len(s)
	if n < 127 {
		dst = append(dst, byte(n))
	} else {
		dst = append(dst, 127)
		rest := n - 127
		for rest >= 128 {
			dst = append(dst, byte(rest)|0x80)
			rest >>= 7
		}
		dst = append(dst, byte(rest))
	}
	return append(dst, s...)
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
