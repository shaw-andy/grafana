package filters

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"

	"github.com/grafana/grafana/pkg/infra/tracing"
)

// maxInboundBaggageAllocDelta is the extra memory one valid, densely populated
// baggage header may allocate compared with the same header without properties.
// go.opentelemetry.io/otel v1.46.0 materializes every property during extract.
// v1.47.0 keeps that list opaque.
const maxInboundBaggageAllocDelta = 64 << 10

func TestInboundBaggageDoesNotAmplifyAllocation(t *testing.T) {
	dense := denseBaggageHeader()
	require.LessOrEqual(t, len(dense), 8191)

	installBaggagePropagator(t)

	handler := WithTracingHTTPLoggingAttributes(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	serve := func(header string) {
		req := httptest.NewRequest(http.MethodGet, "/apis/test.grafana.app/v1/resources", nil)
		req.Header.Set("baggage", header)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusNoContent, rec.Code)
	}

	serve("namespace=ok")
	serve(dense)

	delta := minAllocDelta(t, 8, func() { serve("namespace=ok") }, func() { serve(dense) })
	require.LessOrEqualf(t, delta, uint64(maxInboundBaggageAllocDelta),
		"apiserver tracing log filter allocated %d extra bytes extracting a %d-byte baggage header; limit is %d",
		delta, len(dense), maxInboundBaggageAllocDelta)
}

func installBaggagePropagator(t *testing.T) {
	t.Helper()
	prevPropagator := otel.GetTextMapPropagator()
	prevTracer := otel.GetTracerProvider()
	t.Cleanup(func() {
		otel.SetTextMapPropagator(prevPropagator)
		otel.SetTracerProvider(prevTracer)
	})

	cfg := tracing.NewEmptyTracingConfig()
	_, err := tracing.ProvideService(cfg)
	require.NoError(t, err)
	require.Contains(t, otel.GetTextMapPropagator().Fields(), "baggage")
}

func denseBaggageHeader() string {
	const max = 8191
	const prefix = "namespace=ok"
	const prop = ";a"
	n := (max - len(prefix)) / len(prop)
	var b strings.Builder
	b.Grow(len(prefix) + n*len(prop))
	b.WriteString(prefix)
	for i := 0; i < n; i++ {
		b.WriteString(prop)
	}
	return b.String()
}

func minAllocDelta(t *testing.T, iterations int, light, dense func()) uint64 {
	t.Helper()
	light()
	dense()

	measure := func(fn func()) uint64 {
		runtime.GC()
		prev := debug.SetGCPercent(-1)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for i := 0; i < iterations; i++ {
			fn()
		}
		runtime.ReadMemStats(&after)
		debug.SetGCPercent(prev)
		return after.TotalAlloc - before.TotalAlloc
	}

	min := ^uint64(0)
	for sample := 0; sample < 3; sample++ {
		base := measure(light)
		heavy := measure(dense)
		var delta uint64
		if heavy > base {
			delta = (heavy - base) / uint64(iterations)
		}
		if delta < min {
			min = delta
		}
	}
	return min
}
