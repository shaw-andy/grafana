package macros

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/types"
)

// repeatedMacroToken is the expansion of $__timeTo for fixedTimeRange (the range end).
const repeatedMacroToken = "datetime('2018-03-15T13:34:00Z')"

// intervalMacroToken is the expansion of $__interval when the query JSON sets interval to 5m
// and the datasource interval is unset. 5m is 300000ms.
const intervalMacroToken = "300000ms"

func fixedTimeRange() backend.TimeRange {
	from := time.Date(2018, 3, 15, 13, 0, 0, 0, time.UTC)
	return backend.TimeRange{From: from, To: from.Add(34 * time.Minute)}
}

// TestKqlInterpolateRepeatedMacrosScaleLinearly fails while KqlInterpolate appends
// each macro replacement onto a growing string. Four times as many macros then costs
// about sixteen times as much copying. A linear builder, or a rejection that happens
// before that copying, stays under the limit. A successful result must be the real
// expansion, so returning a short string quickly does not pass.
func TestKqlInterpolateRepeatedMacrosScaleLinearly(t *testing.T) {
	const smallN = 4000
	const largeN = 32000 // 8x smallN; quadratic copying is ~64x, linear work is ~8x

	run := func(n int) (string, error) {
		kql := strings.Repeat("$__timeTo", n)
		return KqlInterpolate(backend.DataQuery{TimeRange: fixedTimeRange()}, types.DatasourceInfo{}, kql, "TimeGenerated")
	}

	assertMacroExpansionScalesLinearly(t, smallN, largeN, repeatedMacroToken, run)
}

// TestKqlInterpolateIntervalDoesNotReparseQueryJSON fails while every $__interval
// match with a zero Interval unmarshals the whole query JSON. Parsing once per
// query, or rejecting the query before that loop, keeps the larger case in budget.
func TestKqlInterpolateIntervalDoesNotReparseQueryJSON(t *testing.T) {
	const padBytes = 512 * 1024
	pad := strings.Repeat("x", padBytes)

	run := func(n int) (string, error) {
		kql := strings.Repeat("$__interval", n)
		raw := []byte(fmt.Sprintf(`{"interval":"5m","query":%q,"pad":"%s"}`, kql, pad))
		return KqlInterpolate(backend.DataQuery{
			TimeRange: fixedTimeRange(),
			JSON:      raw,
		}, types.DatasourceInfo{}, kql, "TimeGenerated")
	}

	// Warm the regexp compile and the allocator, then compare one parse against a few hundred.
	_, _ = run(1)
	one := medianElapsed(t, 5, func() (string, error) { return run(1) })
	manyN := 400
	manyElapsed, manyOut, manyErr := elapsed(func() (string, error) { return run(manyN) })

	// Re-parsing the padded JSON once per macro is hundreds of times one parse.
	// Computing the interval once stays near one parse.
	limit := 40 * one
	if manyElapsed >= limit {
		t.Fatalf("$__interval x%d on a %d byte query JSON took %s; one occurrence took %s (limit %s). Each match re-parses the query JSON when Interval is zero",
			manyN, padBytes, manyElapsed, one, limit)
	}
	if manyErr == nil {
		require.Equal(t, manyN, strings.Count(manyOut, intervalMacroToken))
	}
}

func assertMacroExpansionScalesLinearly(t *testing.T, smallN, largeN int, token string, run func(int) (string, error)) {
	t.Helper()
	_, _ = run(32)

	smallElapsed, smallOut, smallErr := elapsed(func() (string, error) { return run(smallN) })
	largeElapsed, largeOut, largeErr := elapsed(func() (string, error) { return run(largeN) })

	factor := float64(largeN) / float64(smallN)
	ratio := float64(largeElapsed) / float64(smallElapsed)
	// Midway between linear (factor) and quadratic (factor^2). 8x macros => limit 16x time.
	limit := factor * 2
	if ratio >= limit {
		t.Fatalf("expanding %d macros took %s and %d macros took %s (%.1fx, limit %.1fx). Replacement copying scales with the square of the macro count",
			smallN, smallElapsed, largeN, largeElapsed, ratio, limit)
	}
	if smallErr == nil {
		require.Equal(t, smallN, strings.Count(smallOut, token), "small expansion")
	}
	if largeErr == nil {
		require.Equal(t, largeN, strings.Count(largeOut, token), "large expansion")
	}
}

func elapsed(fn func() (string, error)) (time.Duration, string, error) {
	start := time.Now()
	out, err := fn()
	return time.Since(start), out, err
}

func medianElapsed(t *testing.T, samples int, fn func() (string, error)) time.Duration {
	t.Helper()
	durations := make([]time.Duration, samples)
	for i := range durations {
		dur, out, err := elapsed(fn)
		durations[i] = dur
		if err == nil && i == samples-1 {
			require.Contains(t, out, intervalMacroToken)
		}
	}
	for i := 1; i < len(durations); i++ {
		v := durations[i]
		j := i
		for j > 0 && durations[j-1] > v {
			durations[j] = durations[j-1]
			j--
		}
		durations[j] = v
	}
	return durations[len(durations)/2]
}
