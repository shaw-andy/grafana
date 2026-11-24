package middleware

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/web"
)

// maxExtraBaggageAllocBytes is the most a valid, densely populated baggage
// header may allocate beyond a same-sized header that carries one member and
// no properties. Parsing in otel 1.46 materializes every property several
// times (about 1.5MB for an 8192-byte header). Keeping the property list
// opaque, as otel 1.47 does, stays within a few kilobytes of the plain header.
const maxExtraBaggageAllocBytes = 256 * 1024

func TestRequestTracing_DenseBaggageAllocations(t *testing.T) {
	for _, propagation := range []string{"", "w3c"} {
		t.Run("propagation="+propagationName(propagation), func(t *testing.T) {
			installBaggagePropagator(t, propagation)

			dense, sparse := baggageHeaderPair()
			require.LessOrEqual(t, len(dense), 8192)
			require.Equal(t, len(dense), len(sparse))

			denseBytes, denseNS := requestTracingAlloc(t, dense)
			sparseBytes, sparseNS := requestTracingAlloc(t, sparse)
			require.Equal(t, "prod", denseNS)
			require.NotEmpty(t, sparseNS)
			extra := int64(denseBytes) - int64(sparseBytes)
			if extra > maxExtraBaggageAllocBytes {
				t.Fatalf("dense baggage header allocated %d extra bytes (dense %d, plain %d, header %d); extraction materializes every property",
					extra, denseBytes, sparseBytes, len(dense))
			}
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
	previous := otel.GetTextMapPropagator()
	t.Cleanup(func() { otel.SetTextMapPropagator(previous) })

	cfg := tracing.NewEmptyTracingConfig()
	cfg.Propagation = propagation
	_, err := tracing.ProvideService(cfg)
	require.NoError(t, err)
	require.Contains(t, otel.GetTextMapPropagator().Fields(), "baggage")
}

func requestTracingAlloc(t *testing.T, header string) (uint64, string) {
	t.Helper()
	tracer := noop.NewTracerProvider().Tracer("baggage-alloc")
	var namespace string
	bytes := allocatedBytes(func() {
		m := web.New()
		// RequestTracing is installed before authentication on the main server.
		// The handler answers 401 and still observes baggage already extracted.
		m.Use(RequestTracing(tracer, ShouldTraceWithExceptions))
		m.Get("/login", func(w http.ResponseWriter, r *http.Request) {
			namespace = baggage.FromContext(r.Context()).Member("namespace").Value()
			w.WriteHeader(http.StatusUnauthorized)
		})

		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req.Header.Set("baggage", header)
		rec := httptest.NewRecorder()
		m.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	})
	return bytes, namespace
}

func baggageHeaderPair() (dense, sparse string) {
	const limit = 8192
	const prefix = "namespace=prod"
	dense = prefix + strings.Repeat(";a", (limit-len(prefix))/2)
	sparse = "namespace=" + strings.Repeat("a", limit-len("namespace="))
	return dense, sparse
}

func allocatedBytes(fn func()) uint64 {
	const iterations = 20
	// Warm the path so one-time initialization is not part of the comparison.
	fn()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range iterations {
		fn()
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / iterations
}
