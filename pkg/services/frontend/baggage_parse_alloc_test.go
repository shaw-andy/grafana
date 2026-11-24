package frontend

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/endpoints/request"
)

// The W3C baggage limit is 8192 bytes. A member packed with property tokens
// stays inside that limit, but otel baggage.Parse through v1.46 materializes
// every property. Parsing must keep the member value and stay within a small
// margin of an equally long header that has no properties.
const baggageHeaderLimit = 8192

func TestContextMiddlewareDenseBaggageDoesNotAmplifyAllocations(t *testing.T) {
	// contextMiddleware is installed for every frontend-server request and does
	// not authenticate. A client that can reach that server supplies the header.
	dense := denseBaggageHeader("namespace", "stacks-1")
	sparse := sparseBaggageHeader("namespace", "stacks-1", len(dense))
	require.LessOrEqual(t, len(dense), baggageHeaderLimit)
	require.GreaterOrEqual(t, strings.Count(dense, ";"), 1000)

	service := &frontendService{}
	var got string
	handler := service.contextMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = request.NamespaceFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	serve := func(header string) string {
		req := httptest.NewRequest(http.MethodGet, "/-/health", nil)
		req.Header.Set("baggage", header)
		handler.ServeHTTP(httptest.NewRecorder(), req)
		return got
	}

	require.Equal(t, "stacks-1", serve(dense))
	// The sparse header keeps the same key and pads the value, so the
	// property-free parse still has to return that value.
	require.True(t, strings.HasPrefix(serve(sparse), "stacks-1"))
	require.Greater(t, len(serve(sparse)), len("stacks-1"))

	const runs = 20
	sparseBytes := allocatedBytes(runs, func() { serve(sparse) })
	denseBytes := allocatedBytes(runs, func() { serve(dense) })
	limit := sparseBytes + uint64(len(dense)*8)
	if denseBytes > limit {
		t.Fatalf("dense baggage header of %d bytes allocated %d bytes/request through contextMiddleware; sparse header of the same size allocated %d (limit %d)", len(dense), denseBytes, sparseBytes, limit)
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
