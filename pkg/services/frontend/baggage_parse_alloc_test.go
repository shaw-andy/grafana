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

// maxExtraBaggageAllocBytes is the most a valid, densely populated baggage
// header may allocate beyond a same-sized header with one member and no
// properties. baggage.Parse in otel 1.46 materializes every property (about
// 1MB for an 8192-byte header). otel 1.47 validates that list without
// materializing it, so the two headers allocate about the same amount.
const maxExtraBaggageAllocBytes = 256 * 1024

func TestContextMiddleware_DenseBaggageAllocations(t *testing.T) {
	dense, sparse := baggageHeaderPair()
	require.LessOrEqual(t, len(dense), 8192)
	require.Equal(t, len(dense), len(sparse))

	// No signed-in user: the frontend service parses baggage before any auth.
	service := &frontendService{}
	denseBytes, denseNS := frontendBaggageAlloc(t, service, dense)
	sparseBytes, sparseNS := frontendBaggageAlloc(t, service, sparse)
	require.Equal(t, "prod", denseNS)
	require.NotEmpty(t, sparseNS)

	extra := int64(denseBytes) - int64(sparseBytes)
	if extra > maxExtraBaggageAllocBytes {
		t.Fatalf("dense baggage header allocated %d extra bytes (dense %d, plain %d, header %d); parsing materializes every property",
			extra, denseBytes, sparseBytes, len(dense))
	}
}

func frontendBaggageAlloc(t *testing.T, service *frontendService, header string) (uint64, string) {
	t.Helper()
	var namespace string
	handler := service.contextMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		namespace, _ = request.NamespaceFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	bytes := allocatedBytes(func() {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "example.test"
		req.Header.Set("baggage", header)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
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
