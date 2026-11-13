package tracing

import (
	"context"
	"net/http"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/propagation"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
)

// maxDenseBaggageAllocDelta is the extra bytes a single extract of a valid
// 8191-byte baggage header may allocate compared with a one-member header.
// otel v1.46.0 materializes every property and spends about 778KiB in
// baggage.Parse and about 1.3MiB in propagation.Baggage.Extract. v1.47.0
// keeps that metadata opaque and stays under 32KiB for the same input.
const maxDenseBaggageAllocDelta = 96 * 1024

func TestDefaultTracingConfigExtractsDenseBaggageWithinAllocBudget(t *testing.T) {
	cfg := &setting.Cfg{Raw: ini.Empty()}
	tc, err := ParseTracingConfig(cfg)
	require.NoError(t, err)
	require.Empty(t, tc.Propagation)
	require.Equal(t, noopExporter, tc.enabled)

	prev := otel.GetTextMapPropagator()
	t.Cleanup(func() { otel.SetTextMapPropagator(prev) })

	ots := &TracingService{cfg: tc, log: log.New("tracing-test")}
	require.NoError(t, ots.initOpentelemetryTracer())

	small := "namespace=v"
	dense := denseBaggageHeader()
	require.Equal(t, 8191, len(dense))

	var got string
	delta := allocDelta(
		func() { got = extractNamespace(small) },
		func() { got = extractNamespace(dense) },
	)
	require.Equal(t, "v", got, "default propagator must still expose the baggage member")
	require.LessOrEqualf(t, delta, int64(maxDenseBaggageAllocDelta),
		"extracting a %d-byte baggage header allocated %d extra bytes", len(dense), delta)

	over := dense + ";a"
	require.Greater(t, len(over), 8192)
	require.Empty(t, extractNamespace(over), "input over the 8192-byte limit must not be accepted")
}

func extractNamespace(header string) string {
	carrier := propagation.HeaderCarrier(http.Header{"Baggage": []string{header}})
	ctx := otel.GetTextMapPropagator().Extract(context.Background(), carrier)
	return baggage.FromContext(ctx).Member("namespace").Value()
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
	smallBytes := minAllocated(3, small)
	denseBytes := minAllocated(3, dense)
	return int64(denseBytes) - int64(smallBytes)
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
