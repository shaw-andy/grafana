package router

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	connectDesyncLegitBody  = "legitimate-response"
	connectDesyncPoisonBody = "poisoned-response"
)

// connectRejectingUpstream is an HTTP/1.1 server that answers CONNECT with a
// non-2xx keep-alive response and does not read that request's body. The
// unread bytes are the next request on the connection. It waits until a
// following request has also arrived, then writes the response to the unread
// body before the response to the following request.
type connectRejectingUpstream struct {
	ln net.Listener

	mu   sync.Mutex
	seen []string
}

func newConnectRejectingUpstream(t *testing.T) *connectRejectingUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	u := &connectRejectingUpstream{ln: ln}
	go u.serve()
	t.Cleanup(func() { ln.Close() })
	return u
}

func (u *connectRejectingUpstream) url() string {
	return "http://" + u.ln.Addr().String()
}

func (u *connectRejectingUpstream) record(line string) {
	u.mu.Lock()
	u.seen = append(u.seen, line)
	u.mu.Unlock()
}

func (u *connectRejectingUpstream) requests() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]string, len(u.seen))
	copy(out, u.seen)
	return out
}

func (u *connectRejectingUpstream) serve() {
	for {
		conn, err := u.ln.Accept()
		if err != nil {
			return
		}
		go u.serveConn(conn)
	}
}

func (u *connectRejectingUpstream) serveConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	u.record(req.Method + " " + req.URL.RequestURI())
	if req.Method != http.MethodConnect {
		writeRawHTTPResponse(conn, http.StatusOK, connectDesyncLegitBody)
		return
	}
	// CONNECT has no request body. Leave whatever followed the headers on
	// the connection and keep the connection alive.
	writeRawHTTPResponse(conn, http.StatusForbidden, "")
	injected, err := http.ReadRequest(br)
	if err != nil {
		u.record("injected-read-error: " + err.Error())
		return
	}
	u.record("injected " + injected.Method + " " + injected.URL.RequestURI())
	next, err := http.ReadRequest(br)
	if err != nil {
		u.record("next-read-error: " + err.Error())
		return
	}
	u.record("next " + next.Method + " " + next.URL.RequestURI())
	// Answer the injected request first. A client that reused this
	// connection reads that response as the response to next.
	writeRawHTTPResponse(conn, http.StatusOK, connectDesyncPoisonBody)
	writeRawHTTPResponse(conn, http.StatusOK, connectDesyncLegitBody)
}

func writeRawHTTPResponse(conn net.Conn, code int, body string) {
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

// sharedProductTransport is the transport transportFor caches for a backend
// with no custom CA: a clone of http.DefaultTransport, shared by every
// forward backend that uses the same TLS settings.
func sharedProductTransport(t *testing.T) *http.Transport {
	t.Helper()
	loader := &cloudLoader{transports: map[tlsCacheKey]*http.Transport{}}
	first, err := loader.transportFor(tlsCacheKey{})
	if err != nil {
		t.Fatalf("transportFor: %v", err)
	}
	second, err := loader.transportFor(tlsCacheKey{})
	if err != nil {
		t.Fatalf("transportFor second: %v", err)
	}
	if first != second {
		t.Fatal("transportFor returned a different transport for the same TLS settings")
	}
	return first
}

func installForwardGroups(t *testing.T, upstream string, transport *http.Transport, groups ...string) *GrafanaRouter {
	t.Helper()
	var backends []Backend
	for _, group := range groups {
		backend, err := NewForwardBackend(metav1.APIGroup{Name: group}, forwardSpec(upstream), group, transport)
		if err != nil {
			t.Fatalf("NewForwardBackend(%s): %v", group, err)
		}
		backends = append(backends, backend)
	}
	rt := NewGrafanaRouter(staticLoader{backends: backends})
	if err := rt.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return rt
}

func mountRouter(rt *GrafanaRouter, unregistered http.Handler) http.Handler {
	next := http.NotFoundHandler()
	if unregistered != nil {
		rt.unregisteredGroupHandler = unregistered
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rt.HandleFunc(w, req, next)
	})
	httpRouter := mux.NewRouter()
	for _, path := range []string{"/apis", "/openapi/v3"} {
		httpRouter.Handle(path, handler)
		httpRouter.PathPrefix(path + "/").Handler(handler)
	}
	return httpRouter
}

// injectedCONNECTBody is a complete HTTP/1.1 request. A server that does not
// read a CONNECT body treats these bytes as the next request on the connection.
func injectedCONNECTBody() string {
	return "GET /injected HTTP/1.1\r\nHost: upstream\r\nContent-Length: 0\r\n\r\n"
}

func sendCONNECT(t *testing.T, client *http.Client, rawURL string) {
	t.Helper()
	body := injectedCONNECTBody()
	req, err := http.NewRequest(http.MethodConnect, rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatalf("connect request: %v", err)
	}
	req.ContentLength = int64(len(body))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatalf("CONNECT %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
}

func victimResponse(t *testing.T, client *http.Client, rawURL string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("victim request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read victim body: %v", err)
	}
	return resp.StatusCode, string(buf)
}

// assertReuseDoesNotReturnInjectedResponse sends a CONNECT with a body through
// handler, then a GET from a second client. The GET must be answered with the
// legitimate upstream response. Receiving the response written for the CONNECT
// body means the shared connection was reused while desynchronized.
func assertReuseDoesNotReturnInjectedResponse(t *testing.T, upstream *connectRejectingUpstream, handler http.Handler, connectPath, victimPath string) {
	t.Helper()
	front := httptest.NewServer(handler)
	t.Cleanup(front.Close)
	client := front.Client()

	sendCONNECT(t, client, front.URL+connectPath)
	code, body := victimResponse(t, client, front.URL+victimPath)
	if code != http.StatusOK || body != connectDesyncLegitBody {
		t.Fatalf("next caller got status %d body %q, want 200 %q; upstream saw %v",
			code, body, connectDesyncLegitBody, upstream.requests())
	}
}

func TestForwardCONNECTBodyDoesNotPoisonSharedTransport(t *testing.T) {
	upstream := newConnectRejectingUpstream(t)
	transport := sharedProductTransport(t)
	const attackerGroup = "attacker.grafana.app"
	const victimGroup = "victim.grafana.app"
	rt := installForwardGroups(t, upstream.url(), transport, attackerGroup, victimGroup)
	assertReuseDoesNotReturnInjectedResponse(t, upstream, mountRouter(rt, nil),
		"/apis/"+attackerGroup+"/v1/widgets",
		"/apis/"+victimGroup+"/v1/widgets")
}

func TestForwardOpenAPICONNECTBodyDoesNotPoisonSharedTransport(t *testing.T) {
	upstream := newConnectRejectingUpstream(t)
	transport := sharedProductTransport(t)
	const group = "openapi.grafana.app"
	rt := installForwardGroups(t, upstream.url(), transport, group)
	assertReuseDoesNotReturnInjectedResponse(t, upstream, mountRouter(rt, nil),
		"/openapi/v3/apis/"+group+"/v1",
		"/apis/"+group+"/v1/widgets")
}

func TestAggregateCONNECTBodyDoesNotPoisonSharedTransport(t *testing.T) {
	upstream := newConnectRejectingUpstream(t)
	transport := sharedProductTransport(t)
	target, err := http.NewRequest(http.MethodGet, upstream.url(), nil)
	if err != nil {
		t.Fatal(err)
	}
	const group = "aggregate.grafana.app"
	backend, err := newAggregateBackend("baas_apiserver", metav1.APIGroup{Name: group}, target.URL, transport)
	if err != nil {
		t.Fatalf("newAggregateBackend: %v", err)
	}
	rt := NewGrafanaRouter(staticLoader{backends: []Backend{backend}})
	if err := rt.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertReuseDoesNotReturnInjectedResponse(t, upstream, mountRouter(rt, nil),
		"/apis/"+group+"/v1/widgets",
		"/apis/"+group+"/v1/other")
}

func TestSingleTenantCONNECTBodyDoesNotPoisonSharedTransport(t *testing.T) {
	upstream := newConnectRejectingUpstream(t)
	st := newTestSingleTenantFallback(t)
	st.resolveHost = func(context.Context, int64) (string, error) { return upstream.url(), nil }
	st.transport = sharedProductTransport(t)
	rt := NewGrafanaRouter(staticLoader{})
	assertReuseDoesNotReturnInjectedResponse(t, upstream, mountRouter(rt, st),
		"/apis/st.grafana.app/v1/namespaces/stacks-123/widgets",
		"/apis/st.grafana.app/v1/namespaces/stacks-123/other")
}
