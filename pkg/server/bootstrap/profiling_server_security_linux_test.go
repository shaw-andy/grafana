//go:build linux

package bootstrap

import (
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestProfilingWriteTimeoutStopsStalledResponse covers WriteTimeout, which the
// read-header and idle checks do not. Those deadlines are applied before the
// request is read and after the handler returns. A handler blocked in Write
// is bounded only by WriteTimeout. The client clamps its receive window so
// the goroutine dump cannot be buffered and the handler stays in Write.
func TestProfilingWriteTimeoutStopsStalledResponse(t *testing.T) {
	setProfilingEnv(t, "", "", "")
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	for i := 0; i < 4000; i++ {
		go func() { <-stop }()
	}

	addr := startLoopbackProfiling(t, Diagnostics{
		Profile:     true,
		ProfileAddr: "127.0.0.1",
	})
	conn := dialProfiling(t, addr)
	defer conn.Close()
	clampProfilingWindow(t, conn)

	_, err := conn.Write([]byte("GET /debug/pprof/goroutine?debug=2 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	_, _ = conn.Read(buf)
	assertConnectionClosed(t, conn, profilingMaxHold)
}

func clampProfilingWindow(t *testing.T, conn net.Conn) {
	t.Helper()
	tcp, ok := conn.(*net.TCPConn)
	require.True(t, ok)
	raw, err := tcp.SyscallConn()
	require.NoError(t, err)
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		// TCP_WINDOW_CLAMP is 10 in linux/tcp.h and syscall.TCP_WINDOW_CLAMP.
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_WINDOW_CLAMP, 2048)
	})
	require.NoError(t, err)
	require.NoError(t, sockErr)
}
