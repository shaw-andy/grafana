package mathexp

import (
	"fmt"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/tracing"
)

// binaryMathOps are every operator parsed as a binary node. Each one is
// evaluated by walkBinary, which estimates the pair walk and then walks it
// again to build unions. Unary operators, reductions, and SQL expressions do
// not take that path.
var binaryMathOps = []string{
	"+", "-", "*", "/", "%", "**",
	"==", "!=", ">", "<", ">=", "<=",
	"&&", "||",
}

// defaultMathMemoryLimit is the expressions.math_expression_memory_limit
// default applied by readExpressionsSettings when the setting is unset.
const defaultMathMemoryLimit int64 = 1 << 30

// A nested pair walk over largeN inputs is several times slower than this on
// the machine these tests were calibrated against, including one several
// times faster. An implementation that stops once the running estimate
// exceeds the limit, rejects an oversized input, or matches labels without
// visiting every pair returns well under it.
const maxBoundedPairWalk = 100 * time.Millisecond

func distinctLabels(side string) func(int) data.Labels {
	return func(i int) data.Labels {
		// One label each, so len(labels) matches across sides, but the keys
		// differ so the sets are not equal and neither contains the other.
		return data.Labels{side: fmt.Sprintf("v-%d", i)}
	}
}

func matchedLabels(i int) data.Labels {
	return data.Labels{"id": fmt.Sprintf("v-%d", i)}
}

func supersetLabels(i int) data.Labels {
	return data.Labels{"svc": "api", "ep": fmt.Sprintf("e-%d", i)}
}

func subsetLabels(i int) data.Labels {
	return data.Labels{"svc": "api"}
}

func seriesResults(n int, labels func(int) data.Labels) Results {
	values := make(Values, n)
	point := tp{time.Unix(1, 0), new(1.0)}
	for i := range n {
		values[i] = makeSeries("s", labels(i), point)
	}
	return Results{Values: values}
}

func numberResults(n int, labels func(int) data.Labels) Results {
	values := make(Values, n)
	value := 1.0
	for i := range n {
		values[i] = makeNumber("n", labels(i), &value)
	}
	return Results{Values: values}
}

func valueResults(kind string, n int, labels func(int) data.Labels) Results {
	if kind == "number" {
		return numberResults(n, labels)
	}
	return seriesResults(n, labels)
}

type pairRun struct {
	elapsed  time.Duration
	err      error
	values   Values
	parseErr error
}

func runBinary(expr string, a, b Results, limit int64) pairRun {
	parsed, err := New(expr)
	if err != nil {
		return pairRun{parseErr: err}
	}
	start := time.Now()
	res, execErr := parsed.Execute("C", Vars{"A": a, "B": b}, tracing.InitializeTracerForTest(), WithMemoryLimit(limit))
	return pairRun{elapsed: time.Since(start), err: execErr, values: res.Values}
}

func TestBinaryPairWalk_distinctEqualLengthLabelsAreBounded(t *testing.T) {
	// Equal label-map lengths take the "invalid union" branch, which adds
	// nothing to the byte estimate. The 1 GiB limit therefore never rejects
	// the input, and both the estimate and the union visit every pair.
	const n = 3000
	for _, kind := range []string{"series", "number"} {
		t.Run(kind, func(t *testing.T) {
			left := valueResults(kind, n, distinctLabels("left"))
			right := valueResults(kind, n, distinctLabels("right"))
			for _, op := range binaryMathOps {
				t.Run(op, func(t *testing.T) {
					got := runBinary(fmt.Sprintf("$A %s $B", op), left, right, defaultMathMemoryLimit)
					require.NoError(t, got.parseErr)
					if got.elapsed > maxBoundedPairWalk {
						t.Fatalf("%s %s over %d series with distinct equal-length labels took %s; comparison work was treated as free and both pair walks ran to completion", kind, op, n, got.elapsed)
					}
				})
			}
		})
	}
}

func TestBinaryPairWalk_distinctLabelsScaleWithSeriesProduct(t *testing.T) {
	// Four times the series is sixteen times the pairs. The large run has to
	// stay in the same band as the small run, which a second full walk of
	// every pair cannot do.
	const smallN, largeN = 800, 3200
	small := runBinary("$A + $B",
		seriesResults(smallN, distinctLabels("left")),
		seriesResults(smallN, distinctLabels("right")),
		defaultMathMemoryLimit)
	large := runBinary("$A + $B",
		seriesResults(largeN, distinctLabels("left")),
		seriesResults(largeN, distinctLabels("right")),
		defaultMathMemoryLimit)
	require.NoError(t, small.parseErr)
	require.NoError(t, large.parseErr)
	ceiling := small.elapsed*5 + 25*time.Millisecond
	if large.elapsed > ceiling || large.elapsed > maxBoundedPairWalk {
		t.Fatalf("distinct-label addition scaled with the pair product: %d series took %s, %d series took %s (ceiling %s)", smallN, small.elapsed, largeN, large.elapsed, ceiling)
	}
}

func TestBinaryPairWalk_emptyLabelsStopWhenRunningEstimateExceedsLimit(t *testing.T) {
	// Empty labels match every pair. The byte total is checked only after
	// estimateBinaryMemory has already visited every pair, and a limit that
	// the first pair already exceeds must stop the walk there. The same
	// bound applies to every binary operator and to both series and numbers.
	const n = 4500
	for _, kind := range []string{"series", "number"} {
		t.Run(kind, func(t *testing.T) {
			left := valueResults(kind, n, func(int) data.Labels { return data.Labels{} })
			right := valueResults(kind, n, func(int) data.Labels { return data.Labels{} })
			for _, op := range binaryMathOps {
				t.Run(op, func(t *testing.T) {
					got := runBinary(fmt.Sprintf("$A %s $B", op), left, right, 1)
					require.NoError(t, got.parseErr)
					if got.elapsed > maxBoundedPairWalk || got.err == nil {
						t.Fatalf("%s %s over %d unlabeled series took %s (err=%v); the pair walk kept going after the running estimate passed the limit", kind, op, n, got.elapsed, got.err)
					}
					require.Empty(t, got.values)
				})
			}
		})
	}
}

func TestBinaryPairWalk_emptyLabelsDoNotRescanAfterEstimate(t *testing.T) {
	// Both sizes are over the limit, so a walk that accumulates the estimate
	// and checks it inside the loop spends the same tiny amount of work on
	// each. A walk that finishes every pair and only then compares the total
	// grows with the product.
	const smallN, largeN = 1500, 6000
	limit := int64(1)
	small := runBinary("$A + $B",
		seriesResults(smallN, func(int) data.Labels { return data.Labels{} }),
		seriesResults(smallN, func(int) data.Labels { return data.Labels{} }),
		limit)
	large := runBinary("$A + $B",
		seriesResults(largeN, func(int) data.Labels { return data.Labels{} }),
		seriesResults(largeN, func(int) data.Labels { return data.Labels{} }),
		limit)
	require.NoError(t, small.parseErr)
	require.NoError(t, large.parseErr)
	if small.err == nil || large.err == nil {
		t.Fatalf("unlabeled series under a 1-byte limit returned success (small err=%v large err=%v)", small.err, large.err)
	}
	ceiling := small.elapsed*5 + 25*time.Millisecond
	if large.elapsed > ceiling || large.elapsed > maxBoundedPairWalk {
		t.Fatalf("estimate was finished for every pair before the limit was applied: %d series took %s, %d series took %s (ceiling %s)", smallN, small.elapsed, largeN, large.elapsed, ceiling)
	}
}

func TestBinaryPairWalk_defaultLimitRejectsCartesianBeforeFullScan(t *testing.T) {
	// 20000 x 20000 one-point series are far past the default 1 GiB estimate.
	// Stopping when the running total crosses that limit is a small fraction
	// of visiting every pair. The union must not run after the estimate fails.
	const n = 20000
	got := runBinary("$A + $B",
		seriesResults(n, func(int) data.Labels { return data.Labels{} }),
		seriesResults(n, func(int) data.Labels { return data.Labels{} }),
		defaultMathMemoryLimit)
	require.NoError(t, got.parseErr)
	if got.elapsed > time.Second || got.err == nil || len(got.values) != 0 {
		t.Fatalf("default 1 GiB limit on %d unlabeled series took %s and produced %d values (err=%v); the full pair product was visited before the limit was applied", n, got.elapsed, len(got.values), got.err)
	}
}

func TestBinaryPairWalk_matchedLabelsUnderLimitAreBounded(t *testing.T) {
	// Matching labels of this size stay far under 1 GiB, so the estimate
	// allows the operation. The union then walks every pair again. Bounding
	// only the over-limit branch leaves this second walk in place.
	const n = 3000
	got := runBinary("$A + $B",
		seriesResults(n, matchedLabels),
		seriesResults(n, matchedLabels),
		defaultMathMemoryLimit)
	require.NoError(t, got.parseErr)
	if got.elapsed > maxBoundedPairWalk {
		t.Fatalf("matched-label addition of %d series took %s while still under the memory limit; the pair walk ran to completion after the estimate allowed it", n, got.elapsed)
	}
	if got.err == nil {
		require.Len(t, got.values, n)
	}
}

func TestBinaryPairWalk_subsetLabelsStopWhenRunningEstimateExceedsLimit(t *testing.T) {
	// Different label-map lengths fall through to Contains. Every superset
	// series matches every subset series, and the limit is applied only
	// after that whole product has been visited.
	const n = 4500
	got := runBinary("$A + $B",
		seriesResults(n, supersetLabels),
		seriesResults(n, subsetLabels),
		1)
	require.NoError(t, got.parseErr)
	if got.elapsed > maxBoundedPairWalk || got.err == nil || len(got.values) != 0 {
		t.Fatalf("subset-label addition of %d series took %s and produced %d values (err=%v); Contains pairs were all visited before the limit was applied", n, got.elapsed, len(got.values), got.err)
	}
}
