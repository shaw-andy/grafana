package interceptors

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/baggage"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"

	"github.com/grafana/grafana/pkg/infra/tracing"
)

const baggageHeaderLimit = 8192

func TestGRPCStatsHandlerDenseBaggageDoesNotAmplifyAllocations(t *testing.T) {
	// service.go installs this handler on every gRPC server. grpc.Server
	// calls TagRPC from handleStream before the auth interceptor runs.
	// The handler reads the global propagator when it is constructed.
	_, err := tracing.ProvideService(tracing.NewEmptyTracingConfig())
	require.NoError(t, err)
	handler := otelgrpc.NewServerHandler()

	dense := denseBaggageHeader("namespace", "stacks-1")
	sparse := sparseBaggageHeader("namespace", "stacks-1", len(dense))
	require.LessOrEqual(t, len(dense), baggageHeaderLimit)
	require.GreaterOrEqual(t, strings.Count(dense, ";"), 1000)

	extract := func(header string) string {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("baggage", header))
		ctx = handler.TagRPC(ctx, &stats.RPCTagInfo{FullMethodName: "/grpc.health.v1.Health/Check"})
		return baggage.FromContext(ctx).Member("namespace").Value()
	}

	require.Equal(t, "stacks-1", extract(dense))
	require.True(t, strings.HasPrefix(extract(sparse), "stacks-1"))
	require.Greater(t, len(extract(sparse)), len("stacks-1"))

	const runs = 20
	sparseBytes := allocatedBytes(runs, func() { extract(sparse) })
	denseBytes := allocatedBytes(runs, func() { extract(dense) })
	limit := sparseBytes + uint64(len(dense)*8)
	if denseBytes > limit {
		t.Fatalf("dense baggage header of %d bytes allocated %d bytes/request through otelgrpc TagRPC; sparse header of the same size allocated %d (limit %d)", len(dense), denseBytes, sparseBytes, limit)
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
