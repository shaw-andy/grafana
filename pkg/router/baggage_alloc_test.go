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

const maxDenseBaggageAllocDelta = 96 * 1024

func TestRouterExtractsDenseBaggageWithinAllocBudget(t *testing.T) {
	prev := otel.GetTextMapPropagator()
	t.Cleanup(func() { otel.SetTextMapPropagator(prev) })
	_ = tracing.NewNoopTracerService()

	header := denseBaggageHeader()
	var member string
	extract := func(baggageHeader string) {
		req := httptest.NewRequest(http.MethodGet, "/apis/example.grafana.app/v1/things", nil)
		req.Header.Set("baggage", baggageHeader)
		_, out, done := traceRouterRequest(httptest.NewRecorder(), req, "router.backend", "example.grafana.app")
		member = baggage.FromContext(out.Context()).Member("namespace").Value()
		done()
	}

	extract("namespace=v")
	require.Equal(t, "v", member)
	extract(header)
	require.Equal(t, "v", member)

	delta := allocDelta(func() { extract("namespace=v") }, func() { extract(header) })
	require.LessOrEqualf(t, delta, int64(maxDenseBaggageAllocDelta),
		"router extract allocated %d extra bytes parsing baggage", delta)
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
