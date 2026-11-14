package web

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestMacaronCONNECTDoesNotDesync covers the main Grafana router. It only
// registers GET, POST, PUT, DELETE, PATCH, OPTIONS and HEAD, so CONNECT falls
// through to NotFound. A non-2xx response does not turn the connection into a
// tunnel, which is the condition CVE-2026-94439 needs.
func TestMacaronCONNECTDoesNotDesync(t *testing.T) {
	// Route registration goes through Router.handle so this test does not pull
	// in the macaron handler wrapper. CONNECT is not one of the methods handle
	// accepts, so it never reaches a handler that writes 2xx.
	r := NewRouter()
	var followed atomic.Bool
	r.notFound = func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet && req.URL.Path == "/smuggled-followup" {
			followed.Store(true)
		}
		http.NotFound(w, req)
	}
	r.handle("GET", "/api/health", func(w http.ResponseWriter, _ *http.Request, _ map[string]string) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	const request = "CONNECT /api/health HTTP/1.1\r\nHost: grafana.example\r\n\r\n" +
		"GET /smuggled-followup HTTP/1.1\r\nHost: grafana.example\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && !followed.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		t.Fatalf("HTTP/1 CONNECT /api/health returned %d; the main router must not answer CONNECT with 2xx (follow-up parsed: %v)", resp.StatusCode, followed.Load())
	}
}
