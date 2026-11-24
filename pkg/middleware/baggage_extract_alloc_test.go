package middleware

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/baggage"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/web"
)

// baggageHeaderLimit is the W3C maximum baggage.Parse accepts. The margin is
// eight times that size: enough for request setup, far below the extra
// allocations from materializing every property of a dense header.
const baggageHeaderLimit = 8192

func TestRequestTracingPublicRouteDenseBaggageDoesNotAmplifyAllocations(t *testing.T) {
	// Empty propagation is the default (conf/defaults.ini, ParseTracingConfig).
	// initOpentelemetryTracer then installs the W3C baggage propagator.
	_, err := tracing.ProvideService(tracing.NewEmptyTracingConfig())
	require.NoError(t, err)

	dense := denseBaggageHeader("namespace", "stacks-1")
	sparse := sparseBaggageHeader("namespace", "stacks-1", len(dense))
	require.LessOrEqual(t, len(dense), baggageHeaderLimit)
	require.GreaterOrEqual(t, strings.Count(dense, ";"), 1000)

	// /login is registered without an auth handler. RequestTracing is the
	// middleware that runs before that handler and extracts baggage.
	tracer := sdktrace.NewTracerProvider().Tracer("test")
	var got string
	mux := web.New()
	mux.UseMiddleware(RequestTracing(tracer, ShouldTraceWithExceptions))
	mux.Get("/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = baggage.FromContext(r.Context()).Member("namespace").Value()
		w.WriteHeader(http.StatusOK)
	}))

	serve := func(header string) string {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req.Header.Set("baggage", header)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		return got
	}

	require.True(t, ShouldTraceWithExceptions(httptest.NewRequest(http.MethodGet, "/login", nil)))
	require.Equal(t, "stacks-1", serve(dense))
	require.True(t, strings.HasPrefix(serve(sparse), "stacks-1"))
	require.Greater(t, len(serve(sparse)), len("stacks-1"))

	const runs = 20
	sparseBytes := allocatedBytes(runs, func() { serve(sparse) })
	denseBytes := allocatedBytes(runs, func() { serve(dense) })
	limit := sparseBytes + uint64(len(dense)*8)
	if denseBytes > limit {
		t.Fatalf("dense baggage header of %d bytes allocated %d bytes/request through RequestTracing; sparse header of the same size allocated %d (limit %d)", len(dense), denseBytes, sparseBytes, limit)
	}
}

func denseBaggageHeader(key, value string) string {
	prefix := key + "=" + value
	n := (baggageHeaderLimit - len(prefix)) / len(";a")
	return prefix + strings.Repeat(";a", n)
}

func sparseBaggageHeader(key, value string, size int) string {
	prefix := key + "=" + value
	return prefix + strings.Repeat("x", size-len(prefix))
}

func allocatedBytes(n int, fn func()) uint64 {
	fn()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < n; i++ {
		fn()
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / uint64(n)
}
