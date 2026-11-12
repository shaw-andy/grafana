package tracing_test

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// queryCanary is the request query Grafana's tracing middleware copies onto
// the server span. It must be distinctive enough that it cannot appear in a
// TLS ClientHello for 127.0.0.1.
const queryCanary = "panel=trace-export-canary"
const tracedRequestTarget = "/api/dashboards/uid/abc?" + queryCanary

// TestOTLPExport_ShippedDefaultsDialWithTLS is the operator path from
// conf/defaults.ini: set only the collector address and leave insecure unset.
// The exporter must open a TLS handshake (system trust store) and must not
// put the request URL, including its query string, on a plaintext connection.
func TestOTLPExport_ShippedDefaultsDialWithTLS(t *testing.T) {
	assertCollectorSeesTLS(t, func(t *testing.T, address string) *tracing.TracingConfig {
		t.Helper()
		return loadTracingConfig(t, address, "")
	})
}

// TestOTLPExport_EmptyInsecureDialsWithTLS covers an explicitly blank
// insecure key, which ini parses as the same empty value the defaults file ships.
func TestOTLPExport_EmptyInsecureDialsWithTLS(t *testing.T) {
	assertCollectorSeesTLS(t, func(t *testing.T, address string) *tracing.TracingConfig {
		t.Helper()
		return parseTracingConfig(t, `
[tracing.opentelemetry]
sampler_type = const
sampler_param = 1
[tracing.opentelemetry.otlp]
address = `+address+`
insecure =
`)
	})
}

// TestOTLPExport_OmittedInsecureDialsWithTLS covers a config that never
// mentions the insecure key. The code default must be TLS, same as a blank key.
func TestOTLPExport_OmittedInsecureDialsWithTLS(t *testing.T) {
	assertCollectorSeesTLS(t, func(t *testing.T, address string) *tracing.TracingConfig {
		t.Helper()
		return parseTracingConfig(t, `
[tracing.opentelemetry]
sampler_type = const
sampler_param = 1
[tracing.opentelemetry.otlp]
address = `+address+`
`)
	})
}

// TestOTLPExport_ExplicitInsecureExportsRequestURLInCleartext locks the
// opt-in: insecure=true still exports the middleware's URL attribute, query
// string included, as plaintext gRPC.
func TestOTLPExport_ExplicitInsecureExportsRequestURLInCleartext(t *testing.T) {
	col := startPlaintextCollector(t)
	cfg := loadTracingConfig(t, col.addr, "true")
	require.True(t, cfg.OTelExporterEnabled())
	require.True(t, cfg.Insecure)

	exportTracedRequest(t, cfg)

	require.NotEmpty(t, col.spans(), "plaintext collector received no spans")
	var urls []string
	var paths []string
	for _, span := range col.spans() {
		for _, attr := range span.GetAttributes() {
			switch attr.GetKey() {
			case "http.url":
				urls = append(urls, attr.GetValue().GetStringValue())
			case "url.path":
				paths = append(paths, attr.GetValue().GetStringValue())
			}
		}
	}
	require.Contains(t, urls, tracedRequestTarget)
	require.Contains(t, paths, "/api/dashboards/uid/abc")

	conns := col.clientBytes()
	require.NotEmpty(t, conns)
	require.True(t, bytes.HasPrefix(conns[0], []byte(http2.ClientPreface)), "explicit insecure export was not plaintext HTTP/2; prefix %q", printablePrefix(conns[0]))
	require.True(t, bytesContain(conns, []byte(queryCanary)), "query string was not on the plaintext connection")
}

// TestOTLPExport_ExplicitSecureDialsWithTLS locks the existing opt-out so a
// fix for the default does not drop the TLS credential path.
func TestOTLPExport_ExplicitSecureDialsWithTLS(t *testing.T) {
	assertCollectorSeesTLS(t, func(t *testing.T, address string) *tracing.TracingConfig {
		t.Helper()
		cfg := loadTracingConfig(t, address, "false")
		require.False(t, cfg.Insecure)
		return cfg
	})
}

func assertCollectorSeesTLS(t *testing.T, cfgFor func(t *testing.T, address string) *tracing.TracingConfig) {
	t.Helper()
	col := startPlaintextCollector(t)
	cfg := cfgFor(t, col.addr)
	require.True(t, cfg.OTelExporterEnabled(), "OTLP export did not turn on when the collector address was set")
	require.Equal(t, col.addr, cfg.Address)

	exportTracedRequest(t, cfg)

	for _, span := range col.spans() {
		for _, attr := range span.GetAttributes() {
			if attr.GetKey() == "http.url" || attr.GetKey() == "url.path" {
				require.NotContains(t, attr.GetValue().GetStringValue(), queryCanary, "request attribute %q reached the plaintext collector", attr.GetKey())
			}
		}
	}

	conns := col.clientBytes()
	require.NotEmpty(t, conns, "exporter never connected to the configured collector")
	for i, conn := range conns {
		require.NotEmpty(t, conn)
		// crypto/tls writes a handshake record first. 22 is recordTypeHandshake.
		require.Equalf(t, byte(22), conn[0], "connection %d did not start a TLS handshake; prefix %q", i, printablePrefix(conn))
		require.Falsef(t, bytes.Contains(conn, []byte(queryCanary)), "connection %d carried the request query string in the clear", i)
	}
}

func exportTracedRequest(t *testing.T, cfg *tracing.TracingConfig) {
	t.Helper()
	clearExporterEnv(t)

	ots, err := tracing.ProvideService(cfg)
	require.NoError(t, err)
	require.NoError(t, ots.StartAsync(context.Background()))
	require.NoError(t, ots.AwaitRunning(context.Background()))
	t.Cleanup(func() {
		ots.StopAsync()
		stopCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = ots.AwaitTerminated(stopCtx)
	})

	m := web.New()
	m.UseMiddleware(middleware.RequestTracing(ots.OtelTracer(), middleware.ShouldTraceAllPaths))
	m.Get("/api/dashboards/uid/abc", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tracedRequestTarget, nil))
	require.Equal(t, http.StatusOK, rec.Code)

	// stopping() shuts the provider down, which flushes the batch exporter
	// onto the collector socket before the test inspects it.
	ots.StopAsync()
	stopCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = ots.AwaitTerminated(stopCtx)
}

func loadTracingConfig(t *testing.T, address, insecure string) *tracing.TracingConfig {
	t.Helper()
	clearExporterEnv(t)

	body := "[paths]\ndata = " + filepath.Join(t.TempDir(), "data") + "\nlogs = " + filepath.Join(t.TempDir(), "log") + "\nplugins = " + filepath.Join(t.TempDir(), "plugins") + "\n[tracing.opentelemetry.otlp]\naddress = " + address + "\n"
	if insecure != "" {
		body += "insecure = " + insecure + "\n"
	}
	custom := filepath.Join(t.TempDir(), "custom.ini")
	require.NoError(t, os.WriteFile(custom, []byte(body), 0o600))

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: grafanaRoot(t),
		Config:   custom,
	}))
	tc, err := tracing.ParseTracingConfig(cfg)
	require.NoError(t, err)
	return tc
}

func parseTracingConfig(t *testing.T, ini string) *tracing.TracingConfig {
	t.Helper()
	clearExporterEnv(t)
	cfg := setting.NewCfg()
	require.NoError(t, cfg.Raw.Append([]byte(ini)))
	provider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	tc, err := tracing.ProvideTracingConfig(provider)
	require.NoError(t, err)
	return tc
}

func grafanaRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "conf", "defaults.ini")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "conf/defaults.ini not found from %s", dir)
		dir = parent
	}
}

func clearExporterEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"JAEGER_AGENT_HOST",
		"JAEGER_AGENT_PORT",
		"GF_TRACING_JAEGER_ADDRESS",
		"GF_TRACING_OPENTELEMETRY_JAEGER_ADDRESS",
		"GF_TRACING_OPENTELEMETRY_OTLP_ADDRESS",
		"GF_TRACING_OPENTELEMETRY_OTLP_INSECURE",
		"GF_TRACING_OPENTELEMETRY_SAMPLER_TYPE",
		"GF_TRACING_OPENTELEMETRY_SAMPLER_PARAM",
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_INSECURE",
		"OTEL_EXPORTER_OTLP_TRACES_INSECURE",
		"OTEL_EXPORTER_OTLP_CERTIFICATE",
		"OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE",
	} {
		t.Setenv(key, "")
	}
}

type plaintextCollector struct {
	addr string

	mu    sync.Mutex
	conns [][]byte
	got   []*tracepb.Span
}

func startPlaintextCollector(t *testing.T) *plaintextCollector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	col := &plaintextCollector{addr: ln.Addr().String()}
	srv := grpc.NewServer()
	collectortracepb.RegisterTraceServiceServer(srv, &traceService{col: col})
	go func() {
		_ = srv.Serve(&tapListener{Listener: ln, col: col})
	}()
	t.Cleanup(func() {
		srv.Stop()
	})
	return col
}

func (c *plaintextCollector) spans() []*tracepb.Span {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*tracepb.Span, len(c.got))
	copy(out, c.got)
	return out
}

func (c *plaintextCollector) clientBytes() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.conns))
	for i, conn := range c.conns {
		out[i] = append([]byte(nil), conn...)
	}
	return out
}

func (c *plaintextCollector) addSpan(span *tracepb.Span) {
	c.mu.Lock()
	c.got = append(c.got, span)
	c.mu.Unlock()
}

func (c *plaintextCollector) newConnBuf() *indexedBuffer {
	buf := &bytes.Buffer{}
	c.mu.Lock()
	c.conns = append(c.conns, nil)
	idx := len(c.conns) - 1
	c.mu.Unlock()
	return &indexedBuffer{buf: buf, col: c, idx: idx}
}

type indexedBuffer struct {
	buf *bytes.Buffer
	col *plaintextCollector
	idx int
}

func (b *indexedBuffer) Write(p []byte) (int, error) {
	n, err := b.buf.Write(p)
	b.col.mu.Lock()
	b.col.conns[b.idx] = append([]byte(nil), b.buf.Bytes()...)
	b.col.mu.Unlock()
	return n, err
}

type tapListener struct {
	net.Listener
	col *plaintextCollector
}

func (l *tapListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tapConn{Conn: conn, rec: l.col.newConnBuf()}, nil
}

type tapConn struct {
	net.Conn
	rec *indexedBuffer
}

func (c *tapConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		_, _ = c.rec.Write(p[:n])
	}
	return n, err
}

type traceService struct {
	collectortracepb.UnimplementedTraceServiceServer
	col *plaintextCollector
}

func (s *traceService) Export(_ context.Context, req *collectortracepb.ExportTraceServiceRequest) (*collectortracepb.ExportTraceServiceResponse, error) {
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			for _, span := range ss.GetSpans() {
				s.col.addSpan(span)
			}
		}
	}
	return &collectortracepb.ExportTraceServiceResponse{}, nil
}

func bytesContain(chunks [][]byte, needle []byte) bool {
	return bytes.Contains(bytes.Join(chunks, nil), needle)
}

func printablePrefix(b []byte) string {
	if len(b) > 24 {
		b = b[:24]
	}
	return string(b)
}
