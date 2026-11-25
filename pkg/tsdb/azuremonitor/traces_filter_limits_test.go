package azuremonitor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/instancemgmt"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"github.com/grafana/grafana-plugin-sdk-go/config"
	"github.com/grafana/grafana-plugin-sdk-go/experimental/featuretoggles"

	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/kinds/dataquery"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/loganalytics"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/types"
)

// A traces query may carry at most this many filter objects, and each object
// may carry at most this many values. Larger input must be rejected before
// the KQL filter clause is built and before Azure is contacted. The clause is
// appended with string concatenation, so a few thousand filters copy tens of
// megabytes and a few hundred thousand copy tens of gigabytes, on every
// generated query.
const (
	azureTracesMaxFilters      = 100
	azureTracesMaxFilterValues = 100

	// Measured on the unfixed builder: 1600 one-value filters allocate about
	// 70MB while copying the growing clause. Refusal has to stay under this.
	azureTracesFilterRefusalAllocBudget = 8 << 20
)

func TestAzureTracesQueryRejectsOversizedFiltersBeforeContactingAzure(t *testing.T) {
	t.Run("one past the filter limit", func(t *testing.T) {
		assertTracesFiltersRefused(t, string(dataquery.AzureQueryTypeAzureTraces), azureTracesMaxFilters+1, 1)
	})
	t.Run("one past the per-filter value limit", func(t *testing.T) {
		assertTracesFiltersRefused(t, string(dataquery.AzureQueryTypeAzureTraces), 1, azureTracesMaxFilterValues+1)
	})
	t.Run("empty filters still count toward the limit", func(t *testing.T) {
		assertTracesFiltersRefused(t, string(dataquery.AzureQueryTypeAzureTraces), azureTracesMaxFilters+1, 0)
	})
	t.Run("trace exemplar uses the same limit", func(t *testing.T) {
		assertTraceExemplarFiltersRefused(t, azureTracesMaxFilters+1, 1)
	})
	t.Run("trace exemplar value limit", func(t *testing.T) {
		assertTraceExemplarFiltersRefused(t, 1, azureTracesMaxFilterValues+1)
	})
}

func TestAzureTracesQueryRefusesThousandsOfFiltersBeforeCopyingTheClause(t *testing.T) {
	// Enough filters that concatenation is many times the budget, and still
	// small enough that the unfixed builder returns in well under a second.
	const filters = 1600
	body := tracesQueryJSON(t, string(dataquery.AzureQueryTypeAzureTraces), repeatedTraceFilters(filters, 1))
	requests := 0
	svc := newTracesQueryService(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "azure should not be contacted", http.StatusInternalServerError)
	})

	var resp *backend.QueryDataResponse
	var err error
	alloc := allocsDuring(func() {
		resp, err = svc.QueryData(context.Background(), tracesQueryRequest(body, string(dataquery.AzureQueryTypeAzureTraces)))
	})

	require.LessOrEqualf(t, alloc, uint64(azureTracesFilterRefusalAllocBudget),
		"refusing %d filters allocated %d bytes; the filter clause is still being built before the query is refused", filters, alloc)
	require.Zero(t, requests, "Azure was contacted while refusing an oversized traces filter list")
	requireFilterLimitError(t, resp, err)
}

func TestAzureTracesQuerySendsAFilterWithinTheLimit(t *testing.T) {
	body := tracesQueryJSON(t, string(dataquery.AzureQueryTypeAzureTraces), []map[string]any{
		{"property": "appId", "operation": "eq", "filters": []string{"test-app"}},
		{"property": "clientId", "operation": "ne", "filters": []string{"test-client"}},
	})
	var got []byte
	svc := newTracesQueryService(t, func(w http.ResponseWriter, r *http.Request) {
		var readErr error
		got, readErr = io.ReadAll(r.Body)
		require.NoError(t, readErr)
		http.Error(w, "stop after capturing the query", http.StatusInternalServerError)
	})

	resp, err := svc.QueryData(context.Background(), tracesQueryRequest(body, string(dataquery.AzureQueryTypeAzureTraces)))
	require.NoError(t, err)
	require.Error(t, resp.Responses["A"].Error)
	require.NotContains(t, strings.ToLower(resp.Responses["A"].Error.Error()), "too many")
	var payload struct {
		Query string `json:"query"`
	}
	require.NoError(t, json.Unmarshal(got, &payload))
	require.Contains(t, payload.Query, `| where appId in ("test-app")`)
	require.Contains(t, payload.Query, `| where clientId !in ("test-client")`)
}

type tracesInstance struct {
	info types.DatasourceInfo
}

func (f tracesInstance) Get(context.Context, backend.PluginContext) (instancemgmt.Instance, error) {
	return f.info, nil
}

func (f tracesInstance) Do(context.Context, backend.PluginContext, instancemgmt.InstanceCallbackFunc) error {
	return nil
}

func newTracesQueryService(t *testing.T, handler http.HandlerFunc) *Service {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := srv.Client()
	logger := log.NewNullLogger()
	info := types.DatasourceInfo{
		Settings: types.AzureMonitorSettings{SubscriptionId: "test-sub"},
		Services: map[string]types.DatasourceService{
			azureMonitor:      {URL: srv.URL, HTTPClient: client},
			azureLogAnalytics: {URL: srv.URL, HTTPClient: client},
			azureTraces:       {URL: srv.URL, HTTPClient: client},
			traceExemplar:     {URL: srv.URL, HTTPClient: client},
		},
		Routes: map[string]types.AzRoute{
			azurePortal: {URL: "https://portal.example.invalid"},
		},
	}
	svc := &Service{
		im: tracesInstance{info: info},
		executors: map[string]azDatasourceExecutor{
			azureTraces:   &loganalytics.AzureLogAnalyticsDatasource{Logger: logger},
			traceExemplar: &loganalytics.AzureLogAnalyticsDatasource{Logger: logger},
		},
		logger: logger,
	}
	svc.queryMux = svc.newQueryMux()
	return svc
}

func assertTracesFiltersRefused(t *testing.T, queryType string, filters, values int) {
	t.Helper()
	body := tracesQueryJSON(t, queryType, repeatedTraceFilters(filters, values))
	requests := 0
	svc := newTracesQueryService(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "azure should not be contacted", http.StatusInternalServerError)
	})

	resp, err := svc.QueryData(context.Background(), tracesQueryRequest(body, queryType))
	require.Zero(t, requests, "Azure was contacted while refusing an oversized traces filter list")
	requireFilterLimitError(t, resp, err)
}

// Trace exemplars reach the same filter builder only after the correlation
// lookup returns a resource. That lookup is part of the path; building and
// sending the KQL query is not.
func assertTraceExemplarFiltersRefused(t *testing.T, filters, values int) {
	t.Helper()
	body := tracesQueryJSON(t, string(dataquery.AzureQueryTypeTraceExemplar), repeatedTraceFilters(filters, values))
	var model map[string]any
	require.NoError(t, json.Unmarshal(body, &model))
	model["azureTraces"].(map[string]any)["operationId"] = "op-1"
	body, err := json.Marshal(model)
	require.NoError(t, err)

	queryPosts := 0
	svc := newTracesQueryService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, writeErr := w.Write([]byte(`{"properties":{"resources":["/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Insights/components/other"]}}`))
			require.NoError(t, writeErr)
			return
		}
		queryPosts++
		http.Error(w, "kql query should not be sent", http.StatusInternalServerError)
	})
	ctx := config.WithGrafanaConfig(context.Background(), config.NewGrafanaCfg(map[string]string{
		featuretoggles.EnabledFeatures: "azureMonitorPrometheusExemplars",
	}))

	resp, queryErr := svc.QueryData(ctx, tracesQueryRequest(body, string(dataquery.AzureQueryTypeTraceExemplar)))
	require.Zero(t, queryPosts, "the traces KQL query was sent while refusing an oversized filter list")
	requireFilterLimitError(t, resp, queryErr)
}

func requireFilterLimitError(t *testing.T, resp *backend.QueryDataResponse, err error) {
	t.Helper()
	if err == nil {
		require.NotNil(t, resp)
		res, ok := resp.Responses["A"]
		require.True(t, ok, "missing response for ref A")
		err = res.Error
	}
	require.Error(t, err)
	msg := strings.ToLower(err.Error())
	require.Contains(t, msg, "too many")
	require.Contains(t, msg, "filter")
}

func tracesQueryRequest(body []byte, queryType string) *backend.QueryDataRequest {
	from := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	return &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{
			DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{},
		},
		Queries: []backend.DataQuery{{
			RefID:     "A",
			QueryType: queryType,
			TimeRange: backend.TimeRange{From: from, To: from.Add(time.Hour)},
			JSON:      body,
		}},
	}
}

func tracesQueryJSON(t *testing.T, queryType string, filters []map[string]any) []byte {
	t.Helper()
	payload := map[string]any{
		"queryType": queryType,
		"azureTraces": map[string]any{
			"resources":    []string{"/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Insights/components/r1"},
			"resultFormat": "table",
			"traceTypes":   []string{"requests"},
			"filters":      filters,
		},
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	return body
}

func repeatedTraceFilters(filters, values int) []map[string]any {
	vals := make([]string, values)
	for i := range vals {
		vals[i] = "b"
	}
	out := make([]map[string]any, filters)
	for i := range out {
		out[i] = map[string]any{
			"property":  "a",
			"operation": "eq",
			"filters":   vals,
		}
	}
	return out
}

func allocsDuring(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}
