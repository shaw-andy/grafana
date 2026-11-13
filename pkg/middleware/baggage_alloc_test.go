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

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/web"
)

// maxDenseBaggageAllocDelta bounds the extra allocation of one request that
// carries a valid 8191-byte baggage header. The budget sits above the
// opaque-metadata parser and below the eager property materialization in
// otel v1.46.0.
const maxDenseBaggageAllocDelta = 96 * 1024

func TestRequestTracingDenseBaggageAllocation(t *testing.T) {
	prev := otel.GetTextMapPropagator()
	t.Cleanup(func() { otel.SetTextMapPropagator(prev) })
	tracer := tracing.NewNoopTracerService()

	t.Run("public healthz", func(t *testing.T) {
		code, member, delta := traceRequest(t, tracer, "/healthz", denseBaggageHeader(), http.StatusOK)
		require.Equal(t, http.StatusOK, code)
		require.Equal(t, "v", member)
		require.LessOrEqualf(t, delta, int64(maxDenseBaggageAllocDelta),
			"public /healthz allocated %d extra bytes parsing baggage", delta)
	})

	t.Run("protected route refuses after extract", func(t *testing.T) {
		code, member, delta := traceRequest(t, tracer, "/login", denseBaggageHeader(), http.StatusUnauthorized)
		require.Equal(t, http.StatusUnauthorized, code)
		require.Equal(t, "v", member, "baggage was extracted before the request was refused")
		require.LessOrEqualf(t, delta, int64(maxDenseBaggageAllocDelta),
			"refused /login allocated %d extra bytes parsing baggage", delta)
	})

	t.Run("untraced api health does not parse baggage", func(t *testing.T) {
		code, member, delta := traceRequest(t, tracer, "/api/health", denseBaggageHeader(), http.StatusOK)
		require.Equal(t, http.StatusOK, code)
		require.Empty(t, member)
		require.LessOrEqualf(t, delta, int64(maxDenseBaggageAllocDelta),
			"untraced /api/health allocated %d extra bytes", delta)
	})
}

func traceRequest(t *testing.T, tracer tracing.Tracer, path, header string, protectedStatus int) (int, string, int64) {
	t.Helper()

	serve := func(baggageHeader string) (int, string) {
		var member string
		m := web.New()
		m.UseMiddleware(RequestTracing(tracer, ShouldTraceWithExceptions))
		m.UseMiddleware(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				member = baggage.FromContext(r.Context()).Member("namespace").Value()
				if r.URL.Path == "/healthz" || r.URL.Path == "/api/health" {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(protectedStatus)
			})
		})

		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("baggage", baggageHeader)
		rec := httptest.NewRecorder()
		m.ServeHTTP(rec, req)
		return rec.Code, member
	}

	smallCode, smallMember := serve("namespace=v")
	denseCode, denseMember := serve(header)
	require.Equal(t, smallCode, denseCode)
	if path != "/api/health" {
		require.Equal(t, "v", smallMember)
	}

	delta := allocDelta(func() { serve("namespace=v") }, func() { serve(header) })
	return denseCode, denseMember, delta
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
