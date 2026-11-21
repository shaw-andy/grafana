package loganalytics

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"github.com/grafana/grafana-plugin-sdk-go/config"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/kinds/dataquery"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/types"
)

// executableKusto returns the query text that Kusto would treat as code.
// Quoted strings, // comments, and ['identifier'] names are blanked so a later
// check can see whether attacker text is still a statement.
func executableKusto(kql string) string {
	var b strings.Builder
	for i := 0; i < len(kql); {
		switch {
		case strings.HasPrefix(kql[i:], "//"):
			for i < len(kql) && kql[i] != '\n' {
				i++
			}
		case kql[i] == '"' || kql[i] == '\'':
			i = skipKustoString(kql, i, kql[i])
			b.WriteByte(' ')
		case strings.HasPrefix(kql[i:], "['"):
			i = skipKustoIdentifier(kql, i)
			b.WriteByte(' ')
		default:
			b.WriteByte(kql[i])
			i++
		}
	}
	return strings.Join(strings.Fields(strings.ToLower(b.String())), " ")
}

func skipKustoString(s string, i int, quote byte) int {
	i++
	for i < len(s) {
		if s[i] == quote && i+1 < len(s) && s[i+1] == quote {
			i += 2
			continue
		}
		if s[i] == quote {
			return i + 1
		}
		i++
	}
	return i
}

func skipKustoIdentifier(s string, i int) int {
	i += 2
	for i < len(s) {
		if s[i] == '\'' && i+1 < len(s) && s[i+1] == '\'' {
			i += 2
			continue
		}
		if s[i] == '\'' && i+1 < len(s) && s[i+1] == ']' {
			return i + 2
		}
		i++
	}
	return i
}

// traceTagRewrite is the Kusto statement produced by the reported filter text.
// A long literal is what `extend <column> = 1` assigns, and it is distinct from
// the generated `extend tags = bag_merge(...)` clause.
func traceTagRewrite(kql string) (tags bool, serviceTags bool) {
	exec := executableKusto(kql)
	return strings.Contains(exec, "extend tags = 1"), strings.Contains(exec, "extend servicetags = 1")
}

func TestExecutableKustoHidesQuotedAttackText(t *testing.T) {
	t.Parallel()
	quoted := `| where ['1 == 1 | extend tags = 1 //'] in ("x") | extend tags = bag_merge(customDimensions, customMeasurements)`
	tags, serviceTags := traceTagRewrite(quoted)
	require.False(t, tags)
	require.False(t, serviceTags)

	raw := `| extend tags = bag_merge(customDimensions, customMeasurements) | where 1 == 1 | extend tags = 1 // in ("x")`
	tags, _ = traceTagRewrite(raw)
	require.True(t, tags)
}

func traceQueryJSON(t *testing.T, traces map[string]any) []byte {
	t.Helper()
	body := map[string]any{
		"queryType":   "Azure Traces",
		"azureTraces": traces,
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	return raw
}

func testTimeRange() backend.TimeRange {
	from := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	return backend.TimeRange{From: from, To: from.Add(time.Hour)}
}

func appInsightsResource() string {
	return "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Insights/components/app"
}

// azureLongTagResponse is the Log Analytics query response shape for a long
// column: the column type is "long" and the cell is a JSON number.
// https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/response-format
// https://learn.microsoft.com/en-us/kusto/query/scalar-data-types/long
func azureTraceResponse(tagsJSON, tagsType, serviceTagsJSON, serviceTagsType string) string {
	return `{
		"tables": [{
			"name": "PrimaryResult",
			"columns": [
				{"name": "startTime", "type": "datetime"},
				{"name": "itemType", "type": "string"},
				{"name": "serviceName", "type": "string"},
				{"name": "duration", "type": "real"},
				{"name": "traceID", "type": "string"},
				{"name": "spanID", "type": "string"},
				{"name": "parentSpanID", "type": "string"},
				{"name": "operationName", "type": "string"},
				{"name": "serviceTags", "type": "` + serviceTagsType + `"},
				{"name": "tags", "type": "` + tagsType + `"},
				{"name": "itemId", "type": "string"},
				{"name": "resource", "type": "string"}
			],
			"rows": [[
				"2020-01-02T03:04:05Z",
				"request",
				"web",
				1.5,
				"trace-id",
				"span-id",
				"parent-id",
				"GET /",
				` + serviceTagsJSON + `,
				` + tagsJSON + `,
				"item-id",
				"/subscriptions/test-sub/resource"
			]]
		}]
	}`
}

func newTagResponseServer(t *testing.T, responseFor func(query string) string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !strings.Contains(string(body), `"query"`) {
			_, _ = w.Write([]byte(`{
				"id": "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Insights/components/app",
				"name": "app",
				"type": "microsoft.insights/transactions",
				"properties": {"resources": ["/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Insights/components/app"]}
			}`))
			return
		}
		var payload struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(responseFor(payload.Query)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func tracesDatasourceInfo(serverURL string) types.DatasourceInfo {
	return types.DatasourceInfo{
		DatasourceUID:  "azure-monitor",
		DatasourceName: "Azure Monitor",
		Routes: map[string]types.AzRoute{
			types.RouteAzurePortal: {URL: "https://portal.example"},
		},
		Services: map[string]types.DatasourceService{
			"Azure Monitor": {URL: serverURL, HTTPClient: http.DefaultClient},
		},
		Settings: types.AzureMonitorSettings{SubscriptionId: "test-sub"},
	}
}

func TestAzureTracesFilterCannotRewriteTagColumns(t *testing.T) {
	ctx := context.Background()
	dsInfo := tracesDatasourceInfo("http://127.0.0.1")
	ds := &AzureLogAnalyticsDatasource{Logger: log.NewNullLogger()}

	t.Run("ordinary filter is still applied", func(t *testing.T) {
		raw := traceQueryJSON(t, map[string]any{
			"resources":    []string{appInsightsResource()},
			"resultFormat": string(dataquery.ResultFormatTrace),
			"traceTypes":   []string{"requests"},
			"filters": []map[string]any{{
				"property":  "url",
				"operation": "eq",
				"filters":   []string{"zz-unique-filter-value"},
			}},
		})
		built, err := ds.buildQuery(ctx, backend.DataQuery{
			RefID:     "A",
			QueryType: string(dataquery.AzureQueryTypeAzureTraces),
			TimeRange: testTimeRange(),
			JSON:      raw,
		}, dsInfo, false)
		require.NoError(t, err)
		require.Contains(t, built.Query, "zz-unique-filter-value")
		tags, serviceTags := traceTagRewrite(built.Query)
		require.False(t, tags)
		require.False(t, serviceTags)
	})

	cases := []struct {
		name      string
		queryType string
		traces    map[string]any
		toggle    bool
	}{
		{
			name:      "filter property appends extend tags",
			queryType: string(dataquery.AzureQueryTypeAzureTraces),
			traces: map[string]any{
				"resources":    []string{appInsightsResource()},
				"resultFormat": string(dataquery.ResultFormatTrace),
				"traceTypes":   []string{"requests"},
				"filters": []map[string]any{{
					"property":  "1 == 1 | extend tags = 1 //",
					"operation": "eq",
					"filters":   []string{"x"},
				}},
			},
		},
		{
			name:      "filter property appends extend serviceTags",
			queryType: string(dataquery.AzureQueryTypeAzureTraces),
			traces: map[string]any{
				"resources":    []string{appInsightsResource()},
				"resultFormat": string(dataquery.ResultFormatTrace),
				"traceTypes":   []string{"requests"},
				"filters": []map[string]any{{
					"property":  "1 == 1 | extend serviceTags = 1 //",
					"operation": "eq",
					"filters":   []string{"x"},
				}},
			},
		},
		{
			// The leading quote currently opens a Kusto string, so this text is not executable yet.
			// Wrapping the property in [''] without escaping that quote makes the extend executable.
			name:      "filter property breaks out of a bracket identifier",
			queryType: string(dataquery.AzureQueryTypeAzureTraces),
			traces: map[string]any{
				"resources":    []string{appInsightsResource()},
				"resultFormat": string(dataquery.ResultFormatTrace),
				"traceTypes":   []string{"requests"},
				"filters": []map[string]any{{
					"property":  "1'] | extend tags = 1 //",
					"operation": "eq",
					"filters":   []string{"x"},
				}},
			},
		},
		{
			name:      "filter value breaks out of its quotes",
			queryType: string(dataquery.AzureQueryTypeAzureTraces),
			traces: map[string]any{
				"resources":    []string{appInsightsResource()},
				"resultFormat": string(dataquery.ResultFormatTrace),
				"traceTypes":   []string{"requests"},
				"filters": []map[string]any{{
					"property":  "url",
					"operation": "eq",
					"filters":   []string{`") | extend tags = 1 //`},
				}},
			},
		},
		{
			name:      "operation id breaks out of its quotes",
			queryType: string(dataquery.AzureQueryTypeAzureTraces),
			traces: map[string]any{
				"resources":    []string{appInsightsResource()},
				"resultFormat": string(dataquery.ResultFormatTrace),
				"traceTypes":   []string{"requests"},
				// Close the surrounding where-expression, then comment out the rest of the one-line query
				// so the later bag_merge does not overwrite the integer column.
				"operationId": `x') or true | extend tags = 1 //`,
			},
		},
		{
			name:      "trace type is appended as raw kusto",
			queryType: string(dataquery.AzureQueryTypeAzureTraces),
			traces: map[string]any{
				"resources":    []string{appInsightsResource()},
				"resultFormat": string(dataquery.ResultFormatTrace),
				"traceTypes":   []string{"requests | extend tags = 1 //"},
			},
		},
		{
			name:      "extra resource breaks out of app quotes",
			queryType: string(dataquery.AzureQueryTypeAzureTraces),
			traces: map[string]any{
				"resources": []string{
					appInsightsResource(),
					`/subscriptions/x') | extend tags = 1 //`,
				},
				"resultFormat": string(dataquery.ResultFormatTrace),
				"traceTypes":   []string{"requests"},
			},
		},
		{
			name:      "trace exemplar filter property appends extend tags",
			queryType: string(dataquery.AzureQueryTypeTraceExemplar),
			toggle:    true,
			traces: map[string]any{
				"resources":    []string{appInsightsResource()},
				"resultFormat": string(dataquery.ResultFormatTrace),
				"traceTypes":   []string{"requests"},
				"operationId":  "trace-id",
				"filters": []map[string]any{{
					"property":  "1 == 1 | extend tags = 1 //",
					"operation": "eq",
					"filters":   []string{"x"},
				}},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			queryCtx := ctx
			if tt.toggle {
				queryCtx = config.WithGrafanaConfig(ctx, config.NewGrafanaCfg(map[string]string{
					"GF_INSTANCE_FEATURE_TOGGLES_ENABLE": "azureMonitorPrometheusExemplars",
				}))
			}
			srv := newTagResponseServer(t, func(string) string {
				return azureTraceResponse(`"{}"`, "dynamic", `"{}"`, "dynamic")
			})
			info := tracesDatasourceInfo(srv.URL)
			built, err := ds.buildQuery(queryCtx, backend.DataQuery{
				RefID:     "A",
				QueryType: tt.queryType,
				TimeRange: testTimeRange(),
				JSON:      traceQueryJSON(t, tt.traces),
			}, info, false)
			if err != nil {
				// A transport failure is not a rejection of the attacker text.
				require.NotContains(t, err.Error(), "correlation")
				require.NotContains(t, strings.ToLower(err.Error()), "connection")
				require.NotContains(t, strings.ToLower(err.Error()), "dial")
				return
			}
			for _, kql := range []string{built.Query, built.TraceExploreQuery, built.TraceParentExploreQuery} {
				tags, serviceTags := traceTagRewrite(kql)
				require.Falsef(t, tags, "executable query rewrites tags: %s", kql)
				require.Falsef(t, serviceTags, "executable query rewrites serviceTags: %s", kql)
			}
		})
	}
}

func TestExecuteQueryRejectsNonStringTraceTags(t *testing.T) {
	cases := []struct {
		name       string
		column     string
		columnType string
		cell       string
		queryType  dataquery.AzureQueryType
		wantErr    bool
	}{
		{name: "tags json string", column: "tags", columnType: "dynamic", cell: `"{\"k\":\"v\"}"`, queryType: dataquery.AzureQueryTypeAzureTraces},
		{name: "tags null", column: "tags", columnType: "dynamic", cell: "null", queryType: dataquery.AzureQueryTypeAzureTraces},
		{name: "serviceTags json string", column: "serviceTags", columnType: "dynamic", cell: `"{\"cloud_RoleName\":\"web\"}"`, queryType: dataquery.AzureQueryTypeAzureTraces},
		{name: "tags long", column: "tags", columnType: "long", cell: "1", queryType: dataquery.AzureQueryTypeAzureTraces, wantErr: true},
		{name: "tags int", column: "tags", columnType: "int", cell: "1", queryType: dataquery.AzureQueryTypeAzureTraces, wantErr: true},
		{name: "tags real", column: "tags", columnType: "real", cell: "1.5", queryType: dataquery.AzureQueryTypeAzureTraces, wantErr: true},
		{name: "tags bool", column: "tags", columnType: "bool", cell: "true", queryType: dataquery.AzureQueryTypeAzureTraces, wantErr: true},
		{name: "tags object", column: "tags", columnType: "dynamic", cell: `{"k":"v"}`, queryType: dataquery.AzureQueryTypeAzureTraces, wantErr: true},
		{name: "tags array", column: "tags", columnType: "dynamic", cell: `["v"]`, queryType: dataquery.AzureQueryTypeAzureTraces, wantErr: true},
		{name: "serviceTags long", column: "serviceTags", columnType: "long", cell: "1", queryType: dataquery.AzureQueryTypeAzureTraces, wantErr: true},
		{name: "serviceTags bool", column: "serviceTags", columnType: "bool", cell: "false", queryType: dataquery.AzureQueryTypeAzureTraces, wantErr: true},
		{name: "serviceTags object", column: "serviceTags", columnType: "object", cell: `{"cloud_RoleName":"web"}`, queryType: dataquery.AzureQueryTypeAzureTraces, wantErr: true},
		{name: "exemplar tags long", column: "tags", columnType: "long", cell: "1", queryType: dataquery.AzureQueryTypeTraceExemplar, wantErr: true},
		{name: "exemplar serviceTags object", column: "serviceTags", columnType: "dynamic", cell: `{"cloud_RoleName":1}`, queryType: dataquery.AzureQueryTypeTraceExemplar, wantErr: true},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tagsCell, tagsType := `"{\"k\":\"v\"}"`, "dynamic"
			serviceCell, serviceType := `"{\"cloud_RoleName\":\"web\"}"`, "dynamic"
			if tt.column == "tags" {
				tagsCell, tagsType = tt.cell, tt.columnType
			} else {
				serviceCell, serviceType = tt.cell, tt.columnType
			}
			body := azureTraceResponse(tagsCell, tagsType, serviceCell, serviceType)
			srv := newTagResponseServer(t, func(string) string { return body })
			ds := &AzureLogAnalyticsDatasource{Logger: log.NewNullLogger()}
			resource := appInsightsResource()
			_, err := ds.executeQuery(context.Background(), &AzureLogAnalyticsQuery{
				RefID:        "A",
				Query:        "traces",
				QueryType:    tt.queryType,
				ResultFormat: dataquery.ResultFormatTrace,
				URL:          "v1/apps/app/query",
				Resources:    []string{resource},
				JSON: traceQueryJSON(t, map[string]any{
					"resources":    []string{resource},
					"resultFormat": string(dataquery.ResultFormatTrace),
				}),
				TimeRange:     testTimeRange(),
				DashboardTime: true,
				TimeColumn:    "timestamp",
			}, tracesDatasourceInfo(srv.URL), srv.Client(), srv.URL)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestAzureTracesInjectedFilterReachesNumericTagConversion(t *testing.T) {
	var sent string
	srv := newTagResponseServer(t, func(query string) string {
		sent = query
		tagsJSON, tagsType := `"{\"k\":\"v\"}"`, "dynamic"
		serviceJSON, serviceType := `"{\"cloud_RoleName\":\"web\"}"`, "dynamic"
		tags, serviceTags := traceTagRewrite(query)
		if tags {
			tagsJSON, tagsType = "1", "long"
		}
		if serviceTags {
			serviceJSON, serviceType = "1", "long"
		}
		return azureTraceResponse(tagsJSON, tagsType, serviceJSON, serviceType)
	})

	raw := traceQueryJSON(t, map[string]any{
		"resources":    []string{appInsightsResource()},
		"resultFormat": string(dataquery.ResultFormatTrace),
		"traceTypes":   []string{"requests"},
		"filters": []map[string]any{{
			"property":  "1 == 1 | extend tags = 1 //",
			"operation": "eq",
			"filters":   []string{"x"},
		}},
	})
	ds := &AzureLogAnalyticsDatasource{Logger: log.NewNullLogger()}
	resp, err := ds.ExecuteTimeSeriesQuery(context.Background(), []backend.DataQuery{{
		RefID:     "A",
		QueryType: string(dataquery.AzureQueryTypeAzureTraces),
		TimeRange: testTimeRange(),
		JSON:      raw,
	}}, tracesDatasourceInfo(srv.URL), srv.Client(), srv.URL, false)
	require.NoError(t, err)
	got := resp.Responses["A"]

	tagsRewritten, _ := traceTagRewrite(sent)
	if tagsRewritten {
		require.Error(t, got.Error)
		require.Empty(t, got.Frames)
		return
	}
	require.NoError(t, got.Error)
	require.NotEmpty(t, got.Frames)
}
