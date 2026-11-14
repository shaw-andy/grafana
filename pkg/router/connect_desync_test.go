package router

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/grafana/dskit/services"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
)

// followUpPath is the request pipelined after CONNECT. Handlers record it only
// when net/http parses it as a new request on the same connection.
const followUpPath = "/apis/smuggled-followup"

// TestHTTP1CONNECT2xxDoesNotParseFollowUp is the spec for CVE-2026-94439.
// A 2xx response to an HTTP/1 CONNECT turns the connection into a tunnel, so
// the server must not parse a later request on that connection. These cases
// fail on Go 1.26.6 because the handlers below answer CONNECT with 2xx and
// return without hijacking, and net/http then keeps serving HTTP.
func TestHTTP1CONNECT2xxDoesNotParseFollowUp(t *testing.T) {
	t.Run("discovery", func(t *testing.T) {
		srv := newRouterTargetServer(t, dummyRoutesLoader{})
		for _, path := range []string{"/apis", "/openapi/v3"} {
			t.Run(path, func(t *testing.T) {
				assertCONNECTDoesNotDesync(t, srv, path)
			})
		}
	})

	t.Run("dummy backend", func(t *testing.T) {
		const group = "dummy-backend-1.ext.grafana.app"
		srv := newRouterTargetServer(t, dummyRoutesLoader{groups: []string{group}})
		waitForGroup(t, srv, group)
		assertCONNECTDoesNotDesync(t, srv, "/apis/"+group+"/v0alpha1")
	})

	t.Run("forward backend", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("upstream"))
		}))
		t.Cleanup(upstream.Close)

		const group = "forward.example"
		backend, err := NewForwardBackend(metav1.APIGroup{
			Name: group,
			Versions: []metav1.GroupVersionForDiscovery{{
				GroupVersion: group + "/v1",
				Version:      "v1",
			}},
		}, forwardSpec(upstream.URL), "forward-key", &http.Transport{})
		if err != nil {
			t.Fatalf("NewForwardBackend: %v", err)
		}
		srv := newRouterTargetServer(t, staticBackendLoader{backends: []Backend{backend}})
		waitForGroup(t, srv, group)
		assertCONNECTDoesNotDesync(t, srv, "/apis/"+group+"/v1/widgets")
	})

	// Same registration as pkg/server/instrumentation_service.go newInstrumentationServer:
	// the module listener serves /metrics with promhttp and no method filter.
	t.Run("instrumentation metrics", func(t *testing.T) {
		router := mux.NewRouter()
		router.Handle("/metrics", promhttp.HandlerFor(prometheus.NewRegistry(), promhttp.HandlerOpts{EnableOpenMetrics: true}))
		followed := &atomic.Bool{}
		router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == followUpPath {
				followed.Store(true)
			}
			http.NotFound(w, r)
		})
		srv := httptest.NewServer(router)
		t.Cleanup(srv.Close)
		assertCONNECTDoesNotDesyncServer(t, srv, "/metrics", followed)
	})
}

type staticBackendLoader struct {
	backends []Backend
}

func (s staticBackendLoader) Load(context.Context) ([]Backend, error) { return s.backends, nil }
func (staticBackendLoader) Notify(context.Context) (<-chan struct{}, error) {
	return make(chan struct{}), nil
}

type recordingServer struct {
	server   *httptest.Server
	router   *GrafanaRouter
	followed *atomic.Bool
}

func newRouterTargetServer(t *testing.T, loader RoutesLoader) *recordingServer {
	t.Helper()
	cfg := setting.NewCfg()
	cfg.Target = []string{"router"}
	httpRouter := mux.NewRouter()
	followed := &atomic.Bool{}
	httpRouter.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == followUpPath {
			followed.Store(true)
		}
		http.NotFound(w, r)
	})

	svc, err := ProvideService(cfg, featuremgmt.WithFeatures(), loader, prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("ProvideService: %v", err)
	}
	if err := svc.RegisterTargetRoutes(httpRouter, nil); err != nil {
		t.Fatalf("RegisterTargetRoutes: %v", err)
	}
	if err := services.StartAndAwaitRunning(t.Context(), svc); err != nil {
		t.Fatalf("start router: %v", err)
	}
	t.Cleanup(func() {
		_ = services.StopAndAwaitTerminated(context.Background(), svc)
	})

	srv := httptest.NewServer(httpRouter)
	t.Cleanup(srv.Close)
	return &recordingServer{server: srv, router: svc.router, followed: followed}
}

func waitForGroup(t *testing.T, srv *recordingServer, group string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.router.KnownGroup(group) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("group %s was not published", group)
}

func assertCONNECTDoesNotDesync(t *testing.T, srv *recordingServer, path string) {
	t.Helper()
	srv.followed.Store(false)
	assertCONNECTDoesNotDesyncServer(t, srv.server, path, srv.followed)
}

func assertCONNECTDoesNotDesyncServer(t *testing.T, srv *httptest.Server, path string, followed *atomic.Bool) {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Path-form CONNECT (leading slash) is what net/http parses into URL.Path.
	// The follow-up is written before the response is read, the way a proxy
	// that has switched to tunnel mode forwards the next bytes.
	request := "CONNECT " + path + " HTTP/1.1\r\nHost: grafana.example\r\n\r\n" +
		"GET " + followUpPath + " HTTP/1.1\r\nHost: grafana.example\r\n\r\n"
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
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && followed.Load() {
		t.Fatalf("HTTP/1 CONNECT %s returned %d without hijacking and the server parsed %s on the same connection", path, resp.StatusCode, followUpPath)
	}
}
