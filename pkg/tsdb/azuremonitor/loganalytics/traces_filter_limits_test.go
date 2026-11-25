package loganalytics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"

	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/kinds/dataquery"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/types"
)

// These match the limits enforced on the query path. A query at the limit is
// still built, and every generated traces query keeps the same clauses.
const (
	azureTracesMaxFilters      = 100
	azureTracesMaxFilterValues = 100
)

func TestAzureTracesQueryBuildsFilterClauseForEveryGeneratedQueryAtTheLimit(t *testing.T) {
	t.Run("azure traces", func(t *testing.T) {
		assertBuiltTracesQueriesAtFilterLimit(t, string(dataquery.AzureQueryTypeAzureTraces))
	})
	t.Run("trace exemplar", func(t *testing.T) {
		assertBuiltTracesQueriesAtFilterLimit(t, string(dataquery.AzureQueryTypeTraceExemplar))
	})
}

func TestAzureTracesQueryBuildsOneFilterWithTheMaximumValues(t *testing.T) {
	values := make([]string, azureTracesMaxFilterValues)
	quoted := make([]string, len(values))
	for i := range values {
		values[i] = fmt.Sprintf("v%d", i)
		quoted[i] = fmt.Sprintf(`"%s"`, values[i])
	}
	clause := fmt.Sprintf(`| where city in (%s)`, strings.Join(quoted, ","))
	filters := []dataquery.AzureTracesFilter{{
		Property:  "city",
		Operation: "eq",
		Filters:   values,
	}}

	got := buildTracesQueriesForFilters(t, string(dataquery.AzureQueryTypeAzureTraces), "", filters)
	require.Contains(t, got.Query, clause)
	require.Contains(t, got.TraceExploreQuery, clause)
	require.Contains(t, got.TraceParentExploreQuery, clause)
}

func assertBuiltTracesQueriesAtFilterLimit(t *testing.T, queryType string) {
	t.Helper()
	filters := make([]dataquery.AzureTracesFilter, azureTracesMaxFilters)
	clauses := make([]string, len(filters))
	for i := range filters {
		op := "eq"
		kqlOp := "in"
		if i == len(filters)-1 {
			op = "ne"
			kqlOp = "!in"
		}
		value := fmt.Sprintf("v%d", i)
		filters[i] = dataquery.AzureTracesFilter{
			Property:  "name",
			Operation: op,
			Filters:   []string{value},
		}
		clauses[i] = fmt.Sprintf(`| where name %s ("%s")`, kqlOp, value)
	}

	// Exemplars only build KQL after correlation returns another resource, and
	// that lookup requires an operation id. Azure Traces builds all three
	// queries from the filters with no operation id and no Azure call.
	operationID := ""
	if queryType == string(dataquery.AzureQueryTypeTraceExemplar) {
		operationID = "op-1"
	}
	got := buildTracesQueriesForFilters(t, queryType, operationID, filters)
	for _, clause := range clauses {
		require.Contains(t, got.Query, clause)
		require.Contains(t, got.TraceExploreQuery, clause)
		require.Contains(t, got.TraceParentExploreQuery, clause)
	}
	require.Contains(t, got.TraceParentExploreQuery, "${__data.fields.parentSpanID}")
	require.NotContains(t, got.TraceLogsExploreQuery, `| where name `)
	if operationID == "" {
		require.Contains(t, got.TraceExploreQuery, "${__data.fields.traceID}")
		require.NotContains(t, got.Query, "${__data.fields.traceID}")
		require.Contains(t, got.TraceLogsExploreQuery, `${__data.fields.traceID}`)
		return
	}
	require.Contains(t, got.Query, operationID)
	require.Equal(t, got.Query, got.TraceExploreQuery)
	require.Contains(t, got.TraceLogsExploreQuery, operationID)
}

func buildTracesQueriesForFilters(t *testing.T, queryType, operationID string, filters []dataquery.AzureTracesFilter) *AzureLogAnalyticsQuery {
	t.Helper()
	azureTraces := map[string]any{
		"resources":    []string{"/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Insights/components/r1"},
		"resultFormat": "table",
		"traceTypes":   []string{"requests"},
		"filters":      filters,
	}
	if operationID != "" {
		azureTraces["operationId"] = operationID
	}
	body, err := json.Marshal(map[string]any{
		"queryType":   queryType,
		"azureTraces": azureTraces,
	})
	require.NoError(t, err)

	from := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	query := backend.DataQuery{
		RefID:     "A",
		QueryType: queryType,
		TimeRange: backend.TimeRange{From: from, To: from.Add(time.Hour)},
		JSON:      body,
	}
	dsInfo := types.DatasourceInfo{
		Settings: types.AzureMonitorSettings{SubscriptionId: "test-sub"},
	}
	if operationID != "" {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, writeErr := w.Write([]byte(`{"properties":{"resources":["/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Insights/components/other"]}}`))
			require.NoError(t, writeErr)
		}))
		t.Cleanup(srv.Close)
		dsInfo.Services = map[string]types.DatasourceService{
			"Azure Monitor": {URL: srv.URL, HTTPClient: srv.Client(), Logger: log.NewNullLogger()},
		}
	}
	appInsightsRegExp := regexp.MustCompile(`(?i)providers/microsoft.insights/components`)
	got, err := buildAppInsightsQuery(context.Background(), query, dsInfo, appInsightsRegExp, log.NewNullLogger())
	require.NoError(t, err)
	require.NotNil(t, got)
	return got
}
