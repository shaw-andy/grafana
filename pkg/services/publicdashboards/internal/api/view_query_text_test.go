package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing/licensingtest"
	publicdashboards "github.com/grafana/grafana/pkg/services/publicdashboards/internal"
	"github.com/grafana/grafana/pkg/services/publicdashboards/internal/models"
	"github.com/grafana/grafana/pkg/services/publicdashboards/internal/service"
	"github.com/grafana/grafana/pkg/setting"
)

// Query text the public view must not return. These are the strings stored in
// fields the sanitizer does not delete: CloudWatch sqlExpression, expression,
// and the Insights builder object; Graphite target and targetFull; and nested
// Azure query objects. expr, query, and rawSql are included because those are
// the fields the sanitizer already removes.
const (
	hiddenPrometheusExpr          = "hiddenPrometheusExprGoGoroutines"
	hiddenInfluxQuery             = "hiddenInfluxQueryBuckets"
	hiddenMssqlRawSql             = "hiddenMssqlRawSqlLoginsCount"
	hiddenCloudWatchSQL           = "hiddenCloudWatchSqlExpressionCpu"
	hiddenCloudWatchMath          = "hiddenCloudWatchMathExpressionCpu"
	hiddenCloudWatchLogs          = "hiddenCloudWatchLogsInsightsFilter"
	hiddenCloudWatchSQLBuilder    = "hiddenCloudWatchSqlBuilderNetworkPackets"
	hiddenCloudWatchLogGroup      = "hiddenCloudWatchLogGroupApi"
	hiddenGraphiteTarget          = "hiddenGraphiteTargetServersCpu"
	hiddenGraphiteTargetFull      = "hiddenGraphiteTargetFullNestedCpu"
	hiddenGraphiteRowTarget       = "hiddenGraphiteRowTargetDisk"
	hiddenAzureLogsQuery          = "hiddenAzureLogsKqlHeartbeat"
	hiddenAzureLogsResource       = "hiddenAzureLogsResourceWorkspace"
	hiddenAzureTracesQuery        = "hiddenAzureTracesKqlRequests"
	hiddenAzureResourceGraphQuery = "hiddenAzureResourceGraphKqlResources"
)

func TestViewPublicDashboardHidesQueryText(t *testing.T) {
	t.Run("legacy dashboard panels and collapsed rows", func(t *testing.T) {
		body := viewPublicDashboard(t, legacyDashboardWithQueryText(), "")
		assertPublicViewHidesQueryText(t, body, []string{
			"Ops overview",
			"Visible CPU panel",
			"Visible disk panel",
			`"refId":"A"`,
			`"type":"timeseries"`,
		}, []string{
			hiddenPrometheusExpr,
			hiddenInfluxQuery,
			hiddenMssqlRawSql,
			hiddenCloudWatchSQL,
			hiddenCloudWatchMath,
			hiddenCloudWatchLogs,
			hiddenCloudWatchSQLBuilder,
			hiddenCloudWatchLogGroup,
			hiddenGraphiteTarget,
			hiddenGraphiteTargetFull,
			hiddenGraphiteRowTarget,
			hiddenAzureLogsQuery,
			hiddenAzureLogsResource,
			hiddenAzureTracesQuery,
			hiddenAzureResourceGraphQuery,
		})
	})

	t.Run("v2 dashboard elements", func(t *testing.T) {
		body := viewPublicDashboard(t, v2DashboardWithQueryText(), "v2beta1")
		assertPublicViewHidesQueryText(t, body, []string{
			"Ops overview v2",
			"Visible CPU panel",
			`"refId":"A"`,
		}, []string{
			hiddenPrometheusExpr,
			hiddenCloudWatchSQL,
			hiddenCloudWatchMath,
			hiddenCloudWatchLogs,
			hiddenCloudWatchSQLBuilder,
			hiddenCloudWatchLogGroup,
			hiddenGraphiteTarget,
			hiddenGraphiteTargetFull,
			hiddenAzureLogsQuery,
			hiddenAzureLogsResource,
			hiddenAzureTracesQuery,
			hiddenAzureResourceGraphQuery,
		})
	})
}

// viewPublicDashboard serves GET /api/public/dashboards/{accessToken} through the
// registered public route and the real view service. The dashboard document is
// the unstructured spec GetDashboard returns; the fake only checks that the
// loaded dashboard is the one the access token points at.
func viewPublicDashboard(t *testing.T, dashboardData *simplejson.Json, apiVersion string) string {
	t.Helper()

	const (
		dashboardUID = "dashuid0001"
		orgID        = int64(1)
	)
	accessToken := uuid.NewString()

	dash := &dashboards.Dashboard{
		UID:        dashboardUID,
		OrgID:      orgID,
		Data:       dashboardData,
		APIVersion: apiVersion,
	}

	store := &publicdashboards.FakePublicDashboardStore{}
	store.On("FindByAccessToken", mock.Anything, accessToken).Return(&models.PublicDashboard{
		Uid:          "pubdashuid1",
		DashboardUid: dashboardUID,
		OrgId:        orgID,
		IsEnabled:    true,
		Share:        models.PublicShareType,
	}, nil)

	dashboardService := &dashboards.FakeDashboardService{}
	dashboardService.On("GetDashboard", mock.Anything, mock.MatchedBy(func(query *dashboards.GetDashboardQuery) bool {
		return query != nil && query.UID == dashboardUID && query.OrgID == orgID
	})).Return(dash, nil)

	license := licensingtest.NewFakeLicensing()
	license.On("FeatureEnabled", models.FeaturePublicDashboardsEmailSharing).Return(false)

	features := featuremgmt.WithFeatures()
	svc := service.ProvideService(
		setting.NewCfg(),
		features,
		store,
		nil,
		nil,
		acimpl.ProvideAccessControl(features),
		service.ProvideServiceWrapper(store),
		dashboardService,
		license,
	)

	server := setupTestServer(t, nil, svc, anonymousUser)
	response := callAPI(server, http.MethodGet, "/api/public/dashboards/"+accessToken, nil, t)
	require.Equal(t, http.StatusOK, response.Code, "public view response: %s", response.Body.String())

	var payload map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &payload))
	meta, ok := payload["meta"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, false, meta["canEdit"])
	require.Equal(t, false, meta["canSave"])

	return response.Body.String()
}

func assertPublicViewHidesQueryText(t *testing.T, body string, kept []string, hidden []string) {
	t.Helper()

	for _, text := range kept {
		require.Contains(t, body, text)
	}

	var leaked []string
	for _, text := range hidden {
		if strings.Contains(body, text) {
			leaked = append(leaked, text)
		}
	}
	require.Empty(t, leaked, "public dashboard view returned query text")
}

func legacyDashboardWithQueryText() *simplejson.Json {
	return simplejson.NewFromAny(map[string]any{
		"title": "Ops overview",
		"timepicker": map[string]any{
			"hidden": false,
		},
		"panels": []any{
			map[string]any{
				"id":    1,
				"type":  "timeseries",
				"title": "Visible CPU panel",
				"gridPos": map[string]any{
					"h": 8, "w": 12, "x": 0, "y": 0,
				},
				"targets": []any{
					map[string]any{
						"refId": "A",
						"datasource": map[string]any{
							"type": "prometheus",
							"uid":  "prom",
						},
						"expr": hiddenPrometheusExpr,
					},
					map[string]any{
						"refId": "B",
						"datasource": map[string]any{
							"type": "influxdb",
							"uid":  "influx",
						},
						"query": hiddenInfluxQuery,
					},
					map[string]any{
						"refId": "C",
						"datasource": map[string]any{
							"type": "mssql",
							"uid":  "mssql",
						},
						"rawSql": hiddenMssqlRawSql,
					},
					cloudWatchInsightsTarget("D"),
					cloudWatchMathTarget("E"),
					cloudWatchLogsTarget("F"),
					graphiteTarget("G", hiddenGraphiteTarget, hiddenGraphiteTargetFull),
					azureMonitorTarget("H"),
				},
			},
			map[string]any{
				"id":        2,
				"type":      "row",
				"title":     "Collapsed row",
				"collapsed": true,
				"panels": []any{
					map[string]any{
						"id":    3,
						"type":  "timeseries",
						"title": "Visible disk panel",
						"targets": []any{
							graphiteTarget("A", hiddenGraphiteRowTarget, hiddenGraphiteTargetFull),
						},
					},
				},
			},
		},
	})
}

func v2DashboardWithQueryText() *simplejson.Json {
	return simplejson.NewFromAny(map[string]any{
		"title": "Ops overview v2",
		"elements": map[string]any{
			"panel-1": map[string]any{
				"kind": "Panel",
				"spec": map[string]any{
					"id":    1,
					"title": "Visible CPU panel",
					"data": map[string]any{
						"kind": "QueryGroup",
						"spec": map[string]any{
							"queries": []any{
								v2Query("A", "prometheus", map[string]any{
									"expr": hiddenPrometheusExpr,
								}),
								v2Query("B", "cloudwatch", map[string]any{
									"refId":         "B",
									"queryMode":     "Metrics",
									"sqlExpression": hiddenCloudWatchSQL,
									"sql": map[string]any{
										"from": map[string]any{
											"type": "property",
											"property": map[string]any{
												"type": "string",
												"name": hiddenCloudWatchSQLBuilder,
											},
										},
									},
								}),
								v2Query("C", "cloudwatch", map[string]any{
									"refId":      "C",
									"queryMode":  "Metrics",
									"expression": hiddenCloudWatchMath,
								}),
								v2Query("D", "cloudwatch", map[string]any{
									"refId":      "D",
									"queryMode":  "Logs",
									"expression": hiddenCloudWatchLogs,
									"logGroups": []any{
										map[string]any{"name": hiddenCloudWatchLogGroup, "arn": "arn:aws:logs:us-east-1:000000000000:log-group:" + hiddenCloudWatchLogGroup},
									},
								}),
								v2Query("E", "graphite", map[string]any{
									"refId":      "E",
									"target":     hiddenGraphiteTarget,
									"targetFull": hiddenGraphiteTargetFull,
								}),
								v2Query("F", "grafana-azure-monitor-datasource", map[string]any{
									"refId":     "F",
									"queryType": "Azure Log Analytics",
									"azureLogAnalytics": map[string]any{
										"query": hiddenAzureLogsQuery,
										"resources": []any{
											"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/" + hiddenAzureLogsResource,
										},
									},
									"azureTraces": map[string]any{
										"query": hiddenAzureTracesQuery,
									},
									"azureResourceGraph": map[string]any{
										"query": hiddenAzureResourceGraphQuery,
									},
								}),
							},
						},
					},
				},
			},
		},
	})
}

func v2Query(refID, group string, spec map[string]any) map[string]any {
	return map[string]any{
		"kind": "PanelQuery",
		"spec": map[string]any{
			"refId":  refID,
			"hidden": false,
			"query": map[string]any{
				"kind":    "DataQuery",
				"group":   group,
				"version": "v0",
				"spec":    spec,
			},
		},
	}
}

func cloudWatchInsightsTarget(refID string) map[string]any {
	return map[string]any{
		"refId": refID,
		"datasource": map[string]any{
			"type": "cloudwatch",
			"uid":  "cloudwatch",
		},
		"queryMode":       "Metrics",
		"metricQueryType": 1,
		"id":              "q1",
		"region":          "us-east-1",
		"sqlExpression":   hiddenCloudWatchSQL,
		"sql": map[string]any{
			"from": map[string]any{
				"type": "property",
				"property": map[string]any{
					"type": "string",
					"name": hiddenCloudWatchSQLBuilder,
				},
			},
		},
	}
}

func cloudWatchMathTarget(refID string) map[string]any {
	return map[string]any{
		"refId": refID,
		"datasource": map[string]any{
			"type": "cloudwatch",
			"uid":  "cloudwatch",
		},
		"queryMode":  "Metrics",
		"id":         "q2",
		"region":     "us-east-1",
		"expression": hiddenCloudWatchMath,
	}
}

func cloudWatchLogsTarget(refID string) map[string]any {
	return map[string]any{
		"refId": refID,
		"datasource": map[string]any{
			"type": "cloudwatch",
			"uid":  "cloudwatch",
		},
		"queryMode":  "Logs",
		"id":         "q3",
		"region":     "us-east-1",
		"expression": hiddenCloudWatchLogs,
		"logGroups": []any{
			map[string]any{
				"name": hiddenCloudWatchLogGroup,
				"arn":  "arn:aws:logs:us-east-1:000000000000:log-group:" + hiddenCloudWatchLogGroup,
			},
		},
	}
}

func graphiteTarget(refID, target, targetFull string) map[string]any {
	return map[string]any{
		"refId": refID,
		"datasource": map[string]any{
			"type": "graphite",
			"uid":  "graphite",
		},
		"target":     target,
		"targetFull": targetFull,
	}
}

func azureMonitorTarget(refID string) map[string]any {
	return map[string]any{
		"refId": refID,
		"datasource": map[string]any{
			"type": "grafana-azure-monitor-datasource",
			"uid":  "azure",
		},
		"queryType": "Azure Log Analytics",
		"azureLogAnalytics": map[string]any{
			"query": hiddenAzureLogsQuery,
			"resources": []any{
				"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/" + hiddenAzureLogsResource,
			},
		},
		"azureTraces": map[string]any{
			"query": hiddenAzureTracesQuery,
		},
		"azureResourceGraph": map[string]any{
			"query": hiddenAzureResourceGraphQuery,
		},
	}
}
