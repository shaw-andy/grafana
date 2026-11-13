package middleware

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/web"
)

// maxInboundBaggageAllocDelta is the extra memory one valid, densely populated
// baggage header may allocate compared with the same header without properties.
// go.opentelemetry.io/otel v1.46.0 materializes every property during
// propagation.Baggage.Extract (about 1.5MB for an 8190-byte header on
// HeaderCarrier, which exposes multiple values). v1.47.0 keeps that list opaque.
const maxInboundBaggageAllocDelta = 64 << 10

func TestInboundBaggageDoesNotAmplifyAllocation(t *testing.T) {
	dense := denseBaggageHeader()
	require.LessOrEqual(t, len(dense), 8191)
	require.Greater(t, strings.Count(dense, ";"), 4000)

	for _, propagation := range []string{"", "w3c"} {
		t.Run(propagationName(propagation), func(t *testing.T) {
			installBaggagePropagator(t, propagation)

			tracer := noop.NewTracerProvider().Tracer("test")
			// RequestTracing is installed on the HTTP mux before authentication.
			// The handler stands in for that later unauthorized response.
			mux := web.New()
			mux.UseMiddleware(RequestTracing(tracer, ShouldTraceAllPaths))
			mux.Get("/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				baggageAllocSink = baggage.FromContext(r.Context()).Member("namespace").Value()
				w.WriteHeader(http.StatusUnauthorized)
			}))

			serve := func(header string) string {
				req := httptest.NewRequest(http.MethodGet, "/login", nil)
				req.Header.Set("baggage", header)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)
				require.Equal(t, http.StatusUnauthorized, rec.Code)
				return baggageAllocSink
			}

			require.Equal(t, "ok", serve("namespace=ok"))
			require.Equal(t, "ok", serve(dense))

			delta := minAllocDelta(t, 8, func() { serve("namespace=ok") }, func() { serve(dense) })
			require.LessOrEqualf(t, delta, uint64(maxInboundBaggageAllocDelta),
				"request tracing allocated %d extra bytes extracting a %d-byte baggage header before authentication; limit is %d",
				delta, len(dense), maxInboundBaggageAllocDelta)
		})
	}
}

func propagationName(propagation string) string {
	if propagation == "" {
		return "default"
	}
	return propagation
}

func installBaggagePropagator(t *testing.T, propagation string) {
	t.Helper()
	prevPropagator := otel.GetTextMapPropagator()
	prevTracer := otel.GetTracerProvider()
	t.Cleanup(func() {
		otel.SetTextMapPropagator(prevPropagator)
		otel.SetTracerProvider(prevTracer)
	})

	cfg := tracing.NewEmptyTracingConfig()
	cfg.Propagation = propagation
	_, err := tracing.ProvideService(cfg)
	require.NoError(t, err)
	require.Contains(t, otel.GetTextMapPropagator().Fields(), "baggage")
}

var baggageAllocSink string

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
