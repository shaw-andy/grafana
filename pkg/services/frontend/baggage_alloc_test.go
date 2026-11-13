package frontend

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/endpoints/request"
)

// maxInboundBaggageAllocDelta is the extra memory one valid, densely populated
// baggage header may allocate compared with the same header without properties.
// go.opentelemetry.io/otel v1.46.0 materializes every property during
// baggage.Parse (about 900KB for an 8190-byte header). v1.47.0 keeps the
// property list opaque and stays near the size of the header.
const maxInboundBaggageAllocDelta = 64 << 10

func TestInboundBaggageDoesNotAmplifyAllocation(t *testing.T) {
	dense := denseBaggageHeader()
	require.LessOrEqual(t, len(dense), 8191)
	require.Greater(t, strings.Count(dense, ";"), 4000)

	service := &frontendService{}
	handler := service.contextMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		namespace, _ := request.NamespaceFrom(r.Context())
		baggageAllocSink = namespace
		w.WriteHeader(http.StatusUnauthorized)
	}))

	serve := func(header string) string {
		req := httptest.NewRequest(http.MethodGet, "/-/health", nil)
		req.Header.Set("baggage", header)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		return baggageAllocSink
	}

	require.Equal(t, "ok", serve("namespace=ok"))
	require.Equal(t, "ok", serve(dense))

	delta := minAllocDelta(t, 8, func() { serve("namespace=ok") }, func() { serve(dense) })
	require.LessOrEqualf(t, delta, uint64(maxInboundBaggageAllocDelta),
		"frontend context middleware allocated %d extra bytes parsing a %d-byte baggage header on an unauthenticated request; limit is %d",
		delta, len(dense), maxInboundBaggageAllocDelta)
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
