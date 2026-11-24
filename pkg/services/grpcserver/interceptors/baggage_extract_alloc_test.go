package interceptors

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/baggage"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"

	"github.com/grafana/grafana/pkg/infra/tracing"
)

// maxExtraBaggageAllocBytes is the most a valid, densely populated baggage
// header may allocate beyond a same-sized header with one member and no
// properties. See the middleware test for the otel 1.46 versus 1.47 gap.
const maxExtraBaggageAllocBytes = 256 * 1024

func TestOTelGRPCTagRPC_DenseBaggageAllocations(t *testing.T) {
	previous := otel.GetTextMapPropagator()
	t.Cleanup(func() { otel.SetTextMapPropagator(previous) })
	_, err := tracing.ProvideService(tracing.NewEmptyTracingConfig())
	require.NoError(t, err)
	require.Contains(t, otel.GetTextMapPropagator().Fields(), "baggage")

	// The gRPC server captures the global propagator when the stats handler is built.
	handler := otelgrpc.NewServerHandler()

	dense, sparse := baggageHeaderPair()
	require.LessOrEqual(t, len(dense), 8192)
	require.Equal(t, len(dense), len(sparse))

	denseBytes, denseNS := tagRPCAlloc(t, handler, dense)
	sparseBytes, sparseNS := tagRPCAlloc(t, handler, sparse)
	require.Equal(t, "prod", denseNS)
	require.NotEmpty(t, sparseNS)

	extra := int64(denseBytes) - int64(sparseBytes)
	if extra > maxExtraBaggageAllocBytes {
		t.Fatalf("dense baggage header allocated %d extra bytes (dense %d, plain %d, header %d); extraction materializes every property",
			extra, denseBytes, sparseBytes, len(dense))
	}
}

func tagRPCAlloc(t *testing.T, handler stats.Handler, header string) (uint64, string) {
	t.Helper()
	var namespace string
	bytes := allocatedBytes(func() {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("baggage", header))
		// handleStream calls TagRPC before the auth interceptor chain.
		ctx = handler.TagRPC(ctx, &stats.RPCTagInfo{FullMethodName: "/grafana.test.Service/Method"})
		namespace = baggage.FromContext(ctx).Member("namespace").Value()
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
