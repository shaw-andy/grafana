package resourcegraph

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/kinds/dataquery"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/types"
)

// repeatedMacroToken is the expansion of $__timeTo for the time range these tests use (the range end).
const repeatedMacroToken = "datetime('2018-03-15T13:34:00Z')"

func fixedTimeRange() backend.TimeRange {
	from := time.Date(2018, 3, 15, 13, 0, 0, 0, time.UTC)
	return backend.TimeRange{From: from, To: from.Add(34 * time.Minute)}
}

// TestBuildResourceGraphQueryRepeatedMacrosScaleLinearly covers the Azure Resource
// Graph query text, which buildQuery interpolates before any Azure request.
func TestBuildResourceGraphQueryRepeatedMacrosScaleLinearly(t *testing.T) {
	ds := &AzureResourceGraphDatasource{}
	run := func(n int) (string, error) {
		model := argJSONQuery{}
		model.AzureResourceGraph.Query = strings.Repeat("$__timeTo", n)
		model.AzureResourceGraph.ResultFormat = "table"
		raw, err := json.Marshal(model)
		require.NoError(t, err)
		built, err := ds.buildQuery(backend.DataQuery{
			RefID:     "A",
			QueryType: string(dataquery.AzureQueryTypeAzureResourceGraph),
			TimeRange: fixedTimeRange(),
			JSON:      raw,
		}, types.DatasourceInfo{})
		if err != nil {
			return "", err
		}
		return built.InterpolatedQuery, nil
	}

	_, _ = run(32)
	smallElapsed, smallOut, smallErr := elapsed(func() (string, error) { return run(4000) })
	largeElapsed, largeOut, largeErr := elapsed(func() (string, error) { return run(32000) })

	ratio := float64(largeElapsed) / float64(smallElapsed)
	const limit = 16.0 // 8x macros; linear work is ~8x, quadratic copying is ~64x
	if ratio >= limit {
		t.Fatalf("expanding 4000 macros took %s and 32000 macros took %s (%.1fx, limit %.1fx). Replacement copying scales with the square of the macro count",
			smallElapsed, largeElapsed, ratio, limit)
	}
	if smallErr == nil {
		require.Equal(t, 4000, strings.Count(smallOut, repeatedMacroToken))
	}
	if largeErr == nil {
		require.Equal(t, 32000, strings.Count(largeOut, repeatedMacroToken))
	}
}

func elapsed(fn func() (string, error)) (time.Duration, string, error) {
	start := time.Now()
	out, err := fn()
	return time.Since(start), out, err
}
