package api

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/middleware/loggermw"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// maxServerTimeout is the longest a connection may live while it is still
// sending an unfinished request, sitting idle on a keep-alive, or refusing
// to read the response. net/http treats a zero ReadTimeout and a zero
// ReadHeaderTimeout as no deadline, and an unset IdleTimeout falls back to
// ReadTimeout, so a shipped read_timeout of 0 leaves every one of those
// deadlines unset. The slack covers scheduling delay past a 30s deadline.
const (
	maxServerTimeout = 30 * time.Second
	closeSlack       = 5 * time.Second
)

func TestHTTPServerConnectionDeadlines(t *testing.T) {
	shippedCfg := loadShippedCfg(t)
	shipped := startGrafanaHTTPServer(t, shippedCfg, true)

	zeroCfg := loadShippedCfg(t)
	zeroCfg.ReadTimeout = 0
	zero := startGrafanaHTTPServer(t, zeroCfg, false)

	tlsCfg := loadShippedCfg(t)
	tlsCfg.ReadTimeout = 0
	tlsCfg.Protocol = setting.HTTPSScheme
	tlsSrv := startGrafanaHTTPServer(t, tlsCfg, false)

	t.Run("shipped read_timeout is bounded", func(t *testing.T) {
		if shippedCfg.ReadTimeout <= 0 || shippedCfg.ReadTimeout > maxServerTimeout {
			t.Fatalf("conf/defaults.ini read_timeout = %s; a shipped server must bound the whole request to a positive duration of at most %s", shippedCfg.ReadTimeout, maxServerTimeout)
		}
	})

	t.Run("shipped server listens on every interface", func(t *testing.T) {
		require.Equal(t, setting.DefaultHTTPAddr, shippedCfg.HTTPAddr)
		// net.Listen("tcp", "0.0.0.0:port") is a wildcard listen. On a host
		// that can map IPv4, Go binds the IPv6 wildcard with IPV6_V6ONLY
		// cleared, which accepts IPv4 and IPv6 on every interface.
		if !procListensOnWildcard(t, shipped.port) {
			t.Fatalf("HTTPServer.Run port %d is not an IPv4 or IPv6 wildcard listener", shipped.port)
		}
	})

	t.Run("slow headers on the shipped server", func(t *testing.T) {
		t.Parallel()
		conn := dial(t, shipped.addr)
		_, err := conn.Write([]byte("GET /healthz HTTP/1.1\r\nX-Slow: "))
		require.NoError(t, err)
		stop := drip(conn, time.Second)
		defer close(stop)
		expectPeerClose(t, conn, maxServerTimeout+closeSlack, shipped.hs)
	})

	t.Run("slow request body on the shipped server", func(t *testing.T) {
		t.Parallel()
		conn := dial(t, shipped.addr)
		_, err := conn.Write([]byte("POST /body-timeout-probe HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100000000\r\n\r\n"))
		require.NoError(t, err)
		stop := drip(conn, time.Second)
		defer close(stop)
		expectPeerClose(t, conn, maxServerTimeout+closeSlack, shipped.hs)
	})

	t.Run("idle keep-alive on the shipped server", func(t *testing.T) {
		t.Parallel()
		expectIdleClose(t, shipped.addr, shipped.hs)
	})

	t.Run("slow response reader on the shipped server", func(t *testing.T) {
		t.Parallel()
		expectWriteTimeoutClose(t, shipped.addr, shipped.hs)
	})

	t.Run("slow headers when read_timeout is zero", func(t *testing.T) {
		t.Parallel()
		conn := dial(t, zero.addr)
		_, err := conn.Write([]byte("GET /healthz HTTP/1.1\r\nX-Slow: "))
		require.NoError(t, err)
		stop := drip(conn, time.Second)
		defer close(stop)
		expectPeerClose(t, conn, maxServerTimeout+closeSlack, zero.hs)
	})

	t.Run("idle keep-alive when read_timeout is zero", func(t *testing.T) {
		t.Parallel()
		expectIdleClose(t, zero.addr, zero.hs)
	})

	t.Run("slow response reader when read_timeout is zero", func(t *testing.T) {
		t.Parallel()
		expectWriteTimeoutClose(t, zero.addr, zero.hs)
	})

	t.Run("stalled TLS handshake when read_timeout is zero", func(t *testing.T) {
		t.Parallel()
		conn := dial(t, tlsSrv.addr)
		// A TLS record header that looks like a handshake, followed by a body
		// that is never finished. crypto/tls waits in readFromUntil for the
		// declared payload, and the HTTP server's handshake deadline is the
		// minimum positive ReadHeaderTimeout, ReadTimeout, or WriteTimeout.
		_, err := conn.Write([]byte{0x16, 0x03, 0x01, 0x20, 0x00})
		require.NoError(t, err)
		stop := drip(conn, time.Second)
		defer close(stop)
		expectPeerClose(t, conn, maxServerTimeout+closeSlack, tlsSrv.hs)
	})
}

type runningServer struct {
	hs   *HTTPServer
	addr string
	port int
}

func loadShippedCfg(t *testing.T) *setting.Cfg {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Join(filepath.Dir(file), "../..")

	cfg := setting.NewCfg()
	err := cfg.Load(setting.CommandLineArgs{
		HomePath: root,
		Config:   filepath.Join(root, "conf", "defaults.ini"),
		// Keep the test from creating log files under data/log.
		Args: []string{"cfg:log.mode=console"},
	})
	require.NoError(t, err)
	cfg.EnableGzip = false
	return cfg
}

func startGrafanaHTTPServer(t *testing.T, cfg *setting.Cfg, allInterfaces bool) *runningServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	var listener net.Listener
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if allInterfaces {
		cfg.HTTPPort = strconv.Itoa(port)
		// HTTPAddr stays at the shipped value. Run builds the listen address
		// from it and opens the socket itself.
	} else {
		listener, err = net.Listen("tcp", addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = listener.Close() })
	}

	features := featuremgmt.WithFeatures()
	reg := prometheus.NewRegistry()
	hs := &HTTPServer{
		log:              log.New("http-server-timeout-test"),
		web:              web.New(),
		RouteRegister:    routing.NewRouteRegister(middleware.ProvideRouteOperationName),
		Cfg:              cfg,
		Features:         features,
		promRegister:     reg,
		LoggerMiddleware: loggermw.Provide(cfg, features),
		Csrf:             csrf.ProvideCSRFFilter(cfg),
		tracer:           tracing.NewNoopTracerService(),
		Listener:         listener,
	}
	// Registered before applyRoutes, so these probes run before ContextHandler
	// and observe the net/http deadlines without the rest of the stack.
	hs.web.Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/body-timeout-probe":
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusNoContent)
		case "/write-timeout-probe":
			writeUntilError(w)
		}
	}))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errCh := make(chan error, 1)
	go func() {
		errCh <- hs.Run(ctx)
	}()

	deadline := time.Now().Add(20 * time.Second)
	for {
		select {
		case runErr := <-errCh:
			t.Fatalf("HTTPServer.Run exited before accepting connections: %v", runErr)
		default:
		}
		conn, dialErr := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("HTTPServer.Run did not accept connections on %s: %v", addr, dialErr)
		}
		time.Sleep(20 * time.Millisecond)
	}

	return &runningServer{hs: hs, addr: addr, port: port}
}

func writeUntilError(w http.ResponseWriter) {
	flusher, _ := w.(http.Flusher)
	buf := bytes.Repeat([]byte("X"), 32*1024)
	for {
		if _, err := w.Write(buf); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// drip keeps the connection from looking idle at the TCP layer. The HTTP
// deadlines under test are set once, when the connection is accepted, and are
// not extended by further bytes.
func drip(conn net.Conn, every time.Duration) chan struct{} {
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		var b byte = 'a'
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if _, err := conn.Write([]byte{b}); err != nil {
					return
				}
			}
		}
	}()
	return stop
}

func expectPeerClose(t *testing.T, conn net.Conn, limit time.Duration, hs *HTTPServer) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(limit))
	buf := make([]byte, 1024)
	for {
		_, err := conn.Read(buf)
		if err == nil {
			continue
		}
		if isTimeout(err) {
			t.Fatalf("connection still open after %s (%s)", limit, describeTimeouts(hs))
		}
		return
	}
}

func expectIdleClose(t *testing.T, addr string, hs *HTTPServer) {
	t.Helper()
	conn := dial(t, addr)
	reader := bufio.NewReader(conn)
	_, err := conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if strings.EqualFold(resp.Header.Get("Connection"), "close") {
		t.Fatal("response asked the client to close; the idle deadline was not observable")
	}

	_ = conn.SetReadDeadline(time.Now().Add(maxServerTimeout + closeSlack))
	buf := make([]byte, 1)
	for {
		_, err := reader.Read(buf)
		if err == nil {
			continue
		}
		if isTimeout(err) {
			t.Fatalf("idle keep-alive still open after %s (%s)", maxServerTimeout+closeSlack, describeTimeouts(hs))
		}
		return
	}
}

func expectWriteTimeoutClose(t *testing.T, addr string, hs *HTTPServer) {
	t.Helper()
	conn := dial(t, addr)
	_, err := conn.Write([]byte("GET /write-timeout-probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
	require.NoError(t, err)

	// Read the status line so the handler has started, then stop. Leaving
	// the body unread fills the TCP window and blocks the handler in Write.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, status, "200")

	_ = conn.SetReadDeadline(time.Now().Add(maxServerTimeout + closeSlack))
	buf := make([]byte, 32*1024)
	for {
		_, err := reader.Read(buf)
		if err == nil {
			// Drain whatever already arrived, then wait. A WriteTimeout
			// closes the connection; an unset one leaves this read blocked
			// once the receive window is full.
			continue
		}
		if isTimeout(err) {
			t.Fatalf("slow reader still held the connection after %s (%s)", maxServerTimeout+closeSlack, describeTimeouts(hs))
		}
		return
	}
}

func describeTimeouts(hs *HTTPServer) string {
	if hs == nil || hs.httpSrv == nil {
		return "http.Server was not constructed"
	}
	s := hs.httpSrv
	return fmt.Sprintf("ReadTimeout=%s ReadHeaderTimeout=%s IdleTimeout=%s WriteTimeout=%s cfg.ReadTimeout=%s",
		s.ReadTimeout, s.ReadHeaderTimeout, s.IdleTimeout, s.WriteTimeout, hs.Cfg.ReadTimeout)
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// procListensOnWildcard reports whether the kernel has a LISTEN socket on
// 0.0.0.0 or :: for port. /proc prints the local address as hex, with the
// port in network order; all zeros is the wildcard.
func procListensOnWildcard(t *testing.T, port int) bool {
	t.Helper()
	portHex := fmt.Sprintf("%04X", port)
	if procHasListen(t, "/proc/net/tcp", "00000000:"+portHex) {
		return true
	}
	return procHasListen(t, "/proc/net/tcp6", "00000000000000000000000000000000:"+portHex)
}

func procHasListen(t *testing.T, path, local string) bool {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// fields[3] is the TCP state. 0A is LISTEN.
		if fields[1] == local && fields[3] == "0A" {
			return true
		}
	}
	return false
}
