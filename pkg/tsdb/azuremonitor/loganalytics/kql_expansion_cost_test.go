package loganalytics

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
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

// TestBuildLogAnalyticsQueryRepeatedMacrosScaleLinearly covers the Azure Log Analytics
// query text, which buildLogAnalyticsQuery interpolates before any Azure request.
func TestBuildLogAnalyticsQueryRepeatedMacrosScaleLinearly(t *testing.T) {
	appInsights := regexp.MustCompile("(?i)providers/microsoft.insights/components")
	run := func(n int) (string, error) {
		queryText := strings.Repeat("$__timeTo", n)
		model := types.LogJSONQuery{
			AzureLogAnalytics: dataquery.AzureLogsQuery{Query: &queryText},
		}
		raw, err := json.Marshal(model)
		require.NoError(t, err)
		built, err := buildLogAnalyticsQuery(backend.DataQuery{
			RefID:     "A",
			QueryType: string(dataquery.AzureQueryTypeLogAnalytics),
			TimeRange: fixedTimeRange(),
			JSON:      raw,
		}, types.DatasourceInfo{}, appInsights, false)
		if err != nil {
			return "", err
		}
		return built.Query, nil
	}
	assertMacroExpansionScalesLinearly(t, 4000, 32000, 1, repeatedMacroToken, run)
}

// TestBuildAppInsightsQueryRepeatedMacrosScaleLinearly covers Azure Traces.
// Filter values are copied into the KQL and then interpolated, including the
// explore queries, before any correlation or query request.
func TestBuildAppInsightsQueryRepeatedMacrosScaleLinearly(t *testing.T) {
	appInsights := regexp.MustCompile("(?i)providers/microsoft.insights/components")
	run := func(n int) (string, error) {
		model := types.TracesJSONQuery{
			AzureTraces: dataquery.AzureTracesQuery{
				Resources: []string{"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws"},
				Filters: []dataquery.AzureTracesFilter{{
					Property:  "message",
					Operation: "eq",
					Filters:   []string{strings.Repeat("$__timeTo", n)},
				}},
			},
		}
		raw, err := json.Marshal(model)
		require.NoError(t, err)
		built, err := buildAppInsightsQuery(context.Background(), backend.DataQuery{
			RefID:     "A",
			QueryType: string(dataquery.AzureQueryTypeAzureTraces),
			TimeRange: fixedTimeRange(),
			JSON:      raw,
		}, types.DatasourceInfo{}, appInsights, log.NewNullLogger())
		if err != nil {
			return "", err
		}
		// The trace query, the explore query, and the parent-span explore query each expand the filter.
		return built.Query + built.TraceExploreQuery + built.TraceParentExploreQuery, nil
	}
	assertMacroExpansionScalesLinearly(t, 4000, 32000, 3, repeatedMacroToken, run)
}

func assertMacroExpansionScalesLinearly(t *testing.T, smallN, largeN, copies int, token string, run func(int) (string, error)) {
	t.Helper()
	_, _ = run(32)

	smallElapsed, smallOut, smallErr := elapsed(func() (string, error) { return run(smallN) })
	largeElapsed, largeOut, largeErr := elapsed(func() (string, error) { return run(largeN) })

	factor := float64(largeN) / float64(smallN)
	ratio := float64(largeElapsed) / float64(smallElapsed)
	limit := factor * 2
	if ratio >= limit {
		t.Fatalf("expanding %d macros took %s and %d macros took %s (%.1fx, limit %.1fx). Replacement copying scales with the square of the macro count",
			smallN, smallElapsed, largeN, largeElapsed, ratio, limit)
	}
	if smallErr == nil {
		require.Equal(t, smallN*copies, strings.Count(smallOut, token), "small expansion")
	}
	if largeErr == nil {
		require.Equal(t, largeN*copies, strings.Count(largeOut, token), "large expansion")
	}
}

func elapsed(fn func() (string, error)) (time.Duration, string, error) {
	start := time.Now()
	out, err := fn()
	return time.Since(start), out, err
}
