package bootstrap

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
)

// profilingMaxHold is the longest a profiling client may keep a connection
// open without the server closing it. ReadHeaderTimeout (or ReadTimeout),
// WriteTimeout, and IdleTimeout on the profiling server must be positive and
// no greater than this, otherwise a reachable client can hold a connection
// open with no deadline.
const profilingMaxHold = 5 * time.Second

// profilingPaths are the handlers setupProfiling serves. net/http/pprof
// registers the /debug/pprof/ routes on the default mux, and godeltaprof
// registers the delta_* routes on the same mux. Both packages are imported
// for that side effect by this package.
var profilingPaths = []string{
	"/debug/pprof/",
	"/debug/pprof/cmdline",
	"/debug/pprof/symbol",
	"/debug/pprof/heap",
	"/debug/pprof/heap?debug=1",
	"/debug/pprof/allocs",
	"/debug/pprof/block",
	"/debug/pprof/mutex",
	"/debug/pprof/goroutine",
	"/debug/pprof/goroutine?debug=2",
	"/debug/pprof/threadcreate",
	"/debug/pprof/profile?seconds=1",
	"/debug/pprof/trace?seconds=1",
	"/debug/pprof/delta_heap",
	"/debug/pprof/delta_block",
	"/debug/pprof/delta_mutex",
}

// profilingCanary is retained on the heap for the life of a test so a profile
// response can be checked for live process memory. It is a marker, not a credential.
var profilingCanary = []byte("profiling-canary-retained-on-heap")

func TestProfilingStaysOffUnlessEnabled(t *testing.T) {
	setProfilingEnv(t, "", "", "")
	port := freePort(t)
	err := setupDiagnostics(Diagnostics{
		Profile:     false,
		ProfileAddr: "127.0.0.1",
		ProfilePort: port,
	}, log.NewNopLogger())
	require.NoError(t, err)

	addr := net.JoinHostPort("127.0.0.1", strconv.FormatUint(port, 10))
	if profilingResponded(addr, time.Second) {
		t.Fatalf("profiling server accepted a connection on %s while profiling was disabled", addr)
	}
}

func TestProfilingRejectsUnauthenticatedProfileRequests(t *testing.T) {
	setProfilingEnv(t, "", "", "")
	retainProfilingCanary(t)
	blockWithCanaryArgument(t)

	addr := startLoopbackProfiling(t, Diagnostics{
		Profile:     true,
		ProfileAddr: "localhost",
	})
	assertProfilesRequireCredential(t, addr)
}

func TestProfilingRejectsUnauthenticatedRequestsWhenEnabledByEnv(t *testing.T) {
	// The flag is off. GF_DIAGNOSTICS_PROFILING_ENABLED is the other production switch.
	setProfilingEnv(t, "true", "127.0.0.1", "")
	retainProfilingCanary(t)

	addr := startLoopbackProfiling(t, Diagnostics{
		Profile:     false,
		ProfileAddr: "127.0.0.1",
	})
	assertProfilesRequireCredential(t, addr)
}

func TestProfilingServerDoesNotRunDefaultMuxHandlers(t *testing.T) {
	setProfilingEnv(t, "", "", "")
	var invoked atomic.Bool
	sentinelPath := fmt.Sprintf("/default-mux-sentinel-%d", time.Now().UnixNano())
	http.HandleFunc(sentinelPath, func(w http.ResponseWriter, r *http.Request) {
		invoked.Store(true)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("sentinel-served"))
	})

	addr := startLoopbackProfiling(t, Diagnostics{
		Profile:     true,
		ProfileAddr: "127.0.0.1",
	})
	status, body := getProfiling(t, addr, sentinelPath, "")
	if invoked.Load() || bytes.Contains(body, []byte("sentinel-served")) {
		t.Fatalf("profiling server ran a handler registered only on the default mux, status %d", status)
	}
}

func TestProfilingRefusesNonLoopbackBind(t *testing.T) {
	cases := []struct {
		name     string
		flag     bool
		flagAddr string
		envOn    string
		envAddr  string
	}{
		{name: "flag 0.0.0.0", flag: true, flagAddr: "0.0.0.0"},
		{name: "flag empty address", flag: true, flagAddr: ""},
		{name: "env overrides loopback flag", flag: true, flagAddr: "127.0.0.1", envOn: "true", envAddr: "0.0.0.0"},
		{name: "env enables and binds all interfaces", flag: false, flagAddr: "127.0.0.1", envOn: "true", envAddr: "0.0.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setProfilingEnv(t, tc.envOn, tc.envAddr, "")
			port := freePort(t)
			err := setupDiagnostics(Diagnostics{
				Profile:     tc.flag,
				ProfileAddr: tc.flagAddr,
				ProfilePort: port,
			}, log.NewNopLogger())

			probe := net.JoinHostPort("127.0.0.1", strconv.FormatUint(port, 10))
			served := profilingResponded(probe, 2*time.Second)
			if err == nil || served {
				t.Fatalf("non-loopback profiling bind must fail before it accepts connections (err=%v, served=%v, probe=%s)", err, served, probe)
			}
		})
	}
}

func TestProfilingClosesSlowConnections(t *testing.T) {
	setProfilingEnv(t, "", "", "")
	addr := startLoopbackProfiling(t, Diagnostics{
		Profile:     true,
		ProfileAddr: "127.0.0.1",
	})

	t.Run("partial request", func(t *testing.T) {
		conn := dialProfiling(t, addr)
		defer conn.Close()
		_, err := conn.Write([]byte("GET /debug/pprof/heap HTTP/1.1\r\nHost: 127.0.0.1\r\n"))
		require.NoError(t, err)
		// Headers are unfinished. The server must drop the connection.
		assertConnectionClosed(t, conn, profilingMaxHold)
	})

	t.Run("idle after response", func(t *testing.T) {
		conn := dialProfiling(t, addr)
		defer conn.Close()
		reader := bufio.NewReader(conn)
		_, err := conn.Write([]byte("GET /debug/pprof/cmdline HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n"))
		require.NoError(t, err)
		resp, err := http.ReadResponse(reader, nil)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assertReaderClosed(t, reader, conn, profilingMaxHold)
	})
}

func assertProfilesRequireCredential(t *testing.T, addr string) {
	t.Helper()
	headers := []struct {
		name  string
		value string
	}{
		{name: "no authorization", value: ""},
		{name: "unrecognized authorization", value: "Bearer placeholder-not-a-credential"},
	}
	for _, header := range headers {
		t.Run(header.name, func(t *testing.T) {
			for _, path := range profilingPaths {
				t.Run(path, func(t *testing.T) {
					status, body := getProfiling(t, addr, path, header.value)
					if status != http.StatusUnauthorized && status != http.StatusForbidden {
						t.Fatalf("GET %s returned %d, want 401 or 403; %s", path, status, describeProfilingBody(body))
					}
					if bytes.Contains(body, profilingCanary) {
						t.Fatalf("GET %s response contained retained process memory", path)
					}
				})
			}
		})
	}
}

func startLoopbackProfiling(t *testing.T, d Diagnostics) string {
	t.Helper()
	if d.ProfilePort == 0 {
		d.ProfilePort = freePort(t)
	}
	err := setupDiagnostics(d, log.NewNopLogger())
	require.NoError(t, err)
	addr := net.JoinHostPort(d.ProfileAddr, strconv.FormatUint(d.ProfilePort, 10))
	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		conn, dialErr := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return addr
		}
		last = dialErr
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("profiling server did not accept connections on %s: %v", addr, last)
	return ""
}

func setProfilingEnv(t *testing.T, enabled, addr, port string) {
	t.Helper()
	t.Setenv(profilingEnabledEnvName, enabled)
	t.Setenv(profilingAddrEnvName, addr)
	t.Setenv(profilingPortEnvName, port)
	t.Setenv(profilingBlockRateEnvName, "")
	t.Setenv(profilingMutexRateEnvName, "")
}

func freePort(t *testing.T) uint64 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return uint64(port)
}

func getProfiling(t *testing.T, addr, path, authorization string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+path, nil)
	require.NoError(t, err)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

func profilingResponded(addr string, within time.Duration) bool {
	client := &http.Client{
		Timeout: within,
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + addr + "/debug/pprof/cmdline")
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		resp.Body.Close()
		return true
	}
	return false
}

func dialProfiling(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	return conn
}

func assertConnectionClosed(t *testing.T, conn net.Conn, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	buf := make([]byte, 1024)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("profiling server left the connection open for %s", within)
		}
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(remaining)))
		_, err := conn.Read(buf)
		if err == nil {
			continue
		}
		var netErr net.Error
		if ok := errorAsNet(err, &netErr); ok && netErr.Timeout() {
			t.Fatalf("profiling server left the connection open for %s", within)
		}
		return
	}
}

func assertReaderClosed(t *testing.T, reader *bufio.Reader, conn net.Conn, within time.Duration) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(within)))
	_, err := reader.ReadByte()
	if err == nil {
		assertReaderClosed(t, reader, conn, time.Until(time.Now().Add(within)))
		return
	}
	var netErr net.Error
	if ok := errorAsNet(err, &netErr); ok && netErr.Timeout() {
		t.Fatalf("profiling server left an idle connection open for %s", within)
	}
}

func errorAsNet(err error, target *net.Error) bool {
	netErr, ok := err.(net.Error)
	if !ok {
		return false
	}
	*target = netErr
	return true
}

func retainProfilingCanary(t *testing.T) {
	t.Helper()
	escaped := append([]byte(nil), profilingCanary...)
	t.Cleanup(func() { runtime.KeepAlive(escaped) })
}

func blockWithCanaryArgument(t *testing.T) {
	t.Helper()
	canary := string(profilingCanary) + "-arg"
	started := make(chan struct{})
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func(retained string) {
		close(started)
		<-stop
		runtime.KeepAlive(retained)
	}(canary)
	<-started
}

func describeProfilingBody(body []byte) string {
	canary := bytes.Contains(body, profilingCanary)
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err == nil {
			raw, _ := io.ReadAll(io.LimitReader(zr, 1<<20))
			_ = zr.Close()
			return fmt.Sprintf("gzip profile %d bytes, decompressed canary=%v alloc_space=%v", len(body), bytes.Contains(raw, profilingCanary), bytes.Contains(raw, []byte("alloc_space")))
		}
	}
	prefix := body
	if len(prefix) > 80 {
		prefix = prefix[:80]
	}
	return fmt.Sprintf("%d bytes canary=%v prefix=%q", len(body), canary, prefix)
}
