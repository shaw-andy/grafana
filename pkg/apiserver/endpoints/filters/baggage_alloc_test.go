package filters

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"

	"github.com/grafana/grafana/pkg/infra/tracing"
)

const maxDenseBaggageAllocDelta = 96 * 1024

func TestTracingHTTPLogFilterDenseBaggageAllocation(t *testing.T) {
	prev := otel.GetTextMapPropagator()
	t.Cleanup(func() { otel.SetTextMapPropagator(prev) })
	_ = tracing.NewNoopTracerService()

	header := denseBaggageHeader()
	handler := WithTracingHTTPLoggingAttributes(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	serve := func(baggageHeader string) int {
		req := httptest.NewRequest(http.MethodGet, "/apis/example/v1/things", nil)
		req.Header.Set("baggage", baggageHeader)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	require.Equal(t, http.StatusOK, serve("namespace=v"))
	require.Equal(t, http.StatusOK, serve(header))
	delta := allocDelta(func() { serve("namespace=v") }, func() { serve(header) })
	require.LessOrEqualf(t, delta, int64(maxDenseBaggageAllocDelta),
		"apiserver tracing filter allocated %d extra bytes parsing baggage", delta)
}

func denseBaggageHeader() string {
	const want = 8191
	prefix := "namespace=v"
	prop := ";a"
	n := (want - len(prefix)) / len(prop)
	header := prefix + strings.Repeat(prop, n)
	if len(header) != want {
		panic("dense baggage header has unexpected length")
	}
	return header
}

func allocDelta(small, dense func()) int64 {
	small()
	dense()
	return int64(minAllocated(3, dense)) - int64(minAllocated(3, small))
}

func minAllocated(n int, fn func()) uint64 {
	var min uint64
	for i := range n {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		fn()
		runtime.ReadMemStats(&after)
		delta := after.TotalAlloc - before.TotalAlloc
		if i == 0 || delta < min {
			min = delta
		}
	}
	return min
}
