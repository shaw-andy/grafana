package frontend

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/web"
)

// maxDenseBaggageAllocDelta bounds the extra allocation of one unauthenticated
// frontend request carrying a valid 8191-byte baggage header. otel v1.46.0
// materializes every property inside baggage.Parse; v1.47.0 does not.
const maxDenseBaggageAllocDelta = 96 * 1024

func TestFrontendBaggageParseAllocation(t *testing.T) {
	prev := otel.GetTextMapPropagator()
	t.Cleanup(func() { otel.SetTextMapPropagator(prev) })
	tracer := tracing.NewNoopTracerService()
	header := denseBaggageHeader()
	require.Equal(t, 8191, len(header))

	t.Run("context middleware parses baggage on a public route", func(t *testing.T) {
		code, namespace, delta := serveFrontend(t, tracer, false, header)
		require.Equal(t, http.StatusOK, code)
		require.Equal(t, "v", namespace)
		require.LessOrEqualf(t, delta, int64(maxDenseBaggageAllocDelta),
			"context middleware allocated %d extra bytes parsing baggage", delta)
	})

	t.Run("request tracing and context middleware both parse baggage", func(t *testing.T) {
		code, namespace, delta := serveFrontend(t, tracer, true, header)
		require.Equal(t, http.StatusOK, code)
		require.Equal(t, "v", namespace)
		require.LessOrEqualf(t, delta, int64(maxDenseBaggageAllocDelta),
			"frontend chain allocated %d extra bytes parsing baggage", delta)
	})
}

func serveFrontend(t *testing.T, tracer tracing.Tracer, withRequestTracing bool, header string) (int, string, int64) {
	t.Helper()

	serve := func(baggageHeader string) (int, string) {
		var namespace string
		svc := &frontendService{}
		m := web.New()
		if withRequestTracing {
			m.UseMiddleware(middleware.RequestTracing(tracer, middleware.ShouldTraceAllPaths))
		}
		m.UseMiddleware(svc.contextMiddleware())
		m.Get("/-/health", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			namespace, _ = request.NamespaceFrom(r.Context())
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		}))

		req := httptest.NewRequest(http.MethodGet, "/-/health", nil)
		req.Header.Set("baggage", baggageHeader)
		rec := httptest.NewRecorder()
		m.ServeHTTP(rec, req)
		return rec.Code, namespace
	}

	_, smallNamespace := serve("namespace=v")
	require.Equal(t, "v", smallNamespace)

	denseCode, denseNamespace := serve(header)
	delta := allocDelta(func() { serve("namespace=v") }, func() { serve(header) })
	return denseCode, denseNamespace, delta
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
