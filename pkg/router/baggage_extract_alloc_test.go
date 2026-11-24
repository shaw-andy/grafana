package router

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/baggage"

	"github.com/grafana/grafana/pkg/infra/tracing"
)

const baggageHeaderLimit = 8192

func TestTraceRouterRequestDenseBaggageDoesNotAmplifyAllocations(t *testing.T) {
	_, err := tracing.ProvideService(tracing.NewEmptyTracingConfig())
	require.NoError(t, err)

	dense := denseBaggageHeader("namespace", "stacks-1")
	sparse := sparseBaggageHeader("namespace", "stacks-1", len(dense))
	require.LessOrEqual(t, len(dense), baggageHeaderLimit)
	require.GreaterOrEqual(t, strings.Count(dense, ";"), 1000)

	t.Logf("propagator fields %v", otel.GetTextMapPropagator().Fields())
	serve := func(header string) string {
		req := httptest.NewRequest(http.MethodGet, "/apis/example.grafana.app/v1/things", nil)
		req.Header.Set("baggage", header)
		rec, traced, done := traceRouterRequest(httptest.NewRecorder(), req, "router.backend", "example.grafana.app")
		done()
		require.Equal(t, http.StatusOK, rec.status)
		return baggage.FromContext(traced.Context()).Member("namespace").Value()
	}

	require.Equal(t, "stacks-1", serve(dense))
	require.True(t, strings.HasPrefix(serve(sparse), "stacks-1"))
	require.Greater(t, len(serve(sparse)), len("stacks-1"))

	const runs = 20
	sparseBytes := allocatedBytes(runs, func() { serve(sparse) })
	denseBytes := allocatedBytes(runs, func() { serve(dense) })
	limit := sparseBytes + uint64(len(dense)*8)
	if denseBytes > limit {
		t.Fatalf("dense baggage header of %d bytes allocated %d bytes/request through traceRouterRequest; sparse header of the same size allocated %d (limit %d)", len(dense), denseBytes, sparseBytes, limit)
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
