package api

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
)

// trailerNameLen is the length of names produced by trailerNames.
// The fixed HTTP/2 server charges len(name)+32 for every field a Trailer
// header declares, against the same budget as MAX_HEADER_LIST_SIZE.
const trailerNameLen = 8

// headerListBudget is the HTTP/2 MAX_HEADER_LIST_SIZE net/http derives from
// Server.MaxHeaderBytes. A non-positive MaxHeaderBytes uses DefaultMaxHeaderBytes
// (1 MiB), then adds 32 bytes for each of 10 typical headers.
func headerListBudget(maxHeaderBytes int) int {
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = 1 << 20
	}
	return maxHeaderBytes + 10*32
}

// overBudgetTrailerCount is large enough that per-field accounting exceeds
// headerListBudget, while the raw Trailer header still fits in that budget.
func overBudgetTrailerCount(maxHeaderBytes int) int {
	budget := headerListBudget(maxHeaderBytes)
	return budget/(trailerNameLen+32) + 8
}

func trailerNames(n int) []string {
	names := make([]string, n)
	for i := 0; i < n; i++ {
		names[i] = "T" + leftPad(i, trailerNameLen-1)
	}
	return names
}

func leftPad(n, width int) string {
	buf := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf)
}

func rawTrailerFieldSize(n int) int {
	valueLen := n*trailerNameLen + (n - 1)
	return len("trailer") + valueLen + 32
}

// trailerProbe records the request the HTTP server actually hands to its handler.
type trailerProbe struct {
	mu     sync.Mutex
	called bool
	keys   int
	proto  string
}

func (p *trailerProbe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.called = true
	p.keys = len(r.Trailer)
	p.proto = r.Proto
	p.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (p *trailerProbe) reset() {
	p.mu.Lock()
	p.called = false
	p.keys = 0
	p.proto = ""
	p.mu.Unlock()
}

func (p *trailerProbe) snapshot() (called bool, keys int, proto string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.called, p.keys, p.proto
}

func h2Client(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2:  true,
		DisableCompression: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		},
	}
	if dial != nil {
		tr.DialContext = dial
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: tr}
}

func doTrailerRequest(client *http.Client, url string, names []string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if len(names) > 0 {
		req.Trailer = make(http.Header, len(names))
		for _, name := range names {
			req.Trailer[name] = nil
		}
	}
	return client.Do(req)
}

// TestHTTP2TrailerDeclarationStaysWithinHeaderBudget sends a client Trailer
// header through the HTTP/2 servers HTTPServer actually starts.
//
// The header's raw size fits in Server.MaxHeaderBytes. Counting each declared
// trailer field the way a normal header field is counted does not. The handler
// must not observe that declaration: the server has to reject it first.
func TestHTTP2TrailerDeclarationStaysWithinHeaderBudget(t *testing.T) {
	t.Run("protocol h2 default limit", func(t *testing.T) {
		testGrafanaH2TrailerBudget(t, setting.HTTP2Scheme, 0)
	})
	t.Run("protocol h2 explicit limit", func(t *testing.T) {
		testGrafanaH2TrailerBudget(t, setting.HTTP2Scheme, 4096)
	})
	t.Run("protocol socket_h2 default limit", func(t *testing.T) {
		testGrafanaH2TrailerBudget(t, setting.SocketHTTP2Scheme, 0)
	})
}

func testGrafanaH2TrailerBudget(t *testing.T, scheme setting.Scheme, maxHeaderBytes int) {
	t.Helper()

	budget := headerListBudget(maxHeaderBytes)
	attackCount := overBudgetTrailerCount(maxHeaderBytes)
	rawSize := rawTrailerFieldSize(attackCount)
	// Other request fields (pseudo-headers, user-agent) also share the raw budget.
	// Keep the Trailer field itself well under it so a server that only counts
	// raw header bytes still accepts the request.
	require.Less(t, rawSize+512, budget, "attack payload must fit in the raw header budget")
	require.Greater(t, attackCount*(trailerNameLen+32), budget)

	probe := &trailerProbe{}
	cfg := setting.NewCfg()
	cfg.Protocol = scheme
	cfg.Domain = "localhost"
	cfg.MinTLSVersion = "TLS1.2"
	hs := &HTTPServer{
		Cfg: cfg,
		log: log.New("h2-trailer-budget-test"),
	}
	// Same server shape as HTTPServer.Run: configureTLS decides whether this
	// listener speaks HTTP/2, then ServeTLS takes the connection.
	hs.httpSrv = &http.Server{
		Handler:        probe,
		MaxHeaderBytes: maxHeaderBytes,
		ReadTimeout:    cfg.ReadTimeout,
		ErrorLog:       stdlog.New(io.Discard, "", 0),
	}
	require.NoError(t, hs.configureTLS())

	var (
		ln     net.Listener
		err    error
		rawURL string
		client *http.Client
	)
	if scheme == setting.SocketHTTP2Scheme {
		sock := filepath.Join(t.TempDir(), "grafana.sock")
		ln, err = net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
		require.NoError(t, err)
		rawURL = "https://localhost/probe"
		client = h2Client(func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		})
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		rawURL = "https://" + ln.Addr().String() + "/probe"
		client = h2Client(nil)
	}

	errCh := make(chan error, 1)
	go func() {
		serveErr := hs.httpSrv.ServeTLS(ln, "", "")
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		errCh <- serveErr
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = hs.httpSrv.Shutdown(ctx)
		<-errCh
	})

	control := trailerNames(4)
	var controlResp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		probe.reset()
		controlResp, err = doTrailerRequest(client, rawURL, control)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("HTTP/2 control request was not served: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.Equal(t, http.StatusNoContent, controlResp.StatusCode)
	controlResp.Body.Close()
	called, keys, proto := probe.snapshot()
	require.True(t, called, "control request did not reach the handler")
	require.Equal(t, "HTTP/2.0", proto)
	require.Equal(t, len(control), keys)

	probe.reset()
	attackResp, attackErr := doTrailerRequest(client, rawURL, trailerNames(attackCount))
	called, keys, proto = probe.snapshot()
	if called {
		t.Fatalf("HTTP/2 handler saw %d trailer fields (proto %s) from a Trailer header of %d raw bytes; per-field size %d exceeds header list budget %d and must be rejected before the handler",
			keys, proto, rawSize, attackCount*(trailerNameLen+32), budget)
	}
	if attackErr != nil {
		require.NotContains(t, attackErr.Error(), "advertised limit", "client did not send the trailer header")
		return
	}
	require.NotNil(t, attackResp)
	defer attackResp.Body.Close()
	_, _ = io.Copy(io.Discard, attackResp.Body)
	require.Equalf(t, http.StatusRequestHeaderFieldsTooLarge, attackResp.StatusCode, "over-budget Trailer header must be rejected")
}
