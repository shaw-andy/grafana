package dashboardsnapshots

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	snapshot "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/user"
)

const (
	promExpr     = "sum(rate(payments_api_annotation_query[5m]))"
	promDSUID    = "prom_ds_uid_annotation_7f3a"
	sqlText      = "SELECT secret_col FROM billing_customers_annotation_query WHERE id = 42"
	sqlDSUID     = "mysql_ds_uid_annotation_9c1e"
	disabledSQL  = "SELECT secret_col FROM disabled_annotation_query_secret WHERE id = 1"
	builtinTag   = "builtin_annotation_query_internal_release"
	dashboardUID = "dashuid01"
)

func annotationQueryTokens() []string {
	return []string{promExpr, promDSUID, sqlText, sqlDSUID, disabledSQL, builtinTag}
}

func assertAnnotationQueriesRemoved(t *testing.T, payload []byte) {
	t.Helper()
	encoded := string(payload)
	for _, token := range annotationQueryTokens() {
		require.NotContains(t, encoded, token)
	}
	require.Contains(t, encoded, "Prom annotations")
	require.Contains(t, encoded, "SQL annotations")
	require.Contains(t, encoded, "Built-in annotations")
}

func schemaV2Dashboard() map[string]any {
	return map[string]any{
		"uid":   dashboardUID,
		"title": "Annotated dashboard",
		"annotations": []any{
			map[string]any{
				"kind": "AnnotationQuery",
				"spec": map[string]any{
					"name": "Prom annotations", "enable": true, "hide": false, "iconColor": "red", "builtIn": false,
					"query": map[string]any{
						"kind": "DataQuery", "group": "prometheus", "version": "v0",
						"datasource": map[string]any{"name": promDSUID},
						"spec":       map[string]any{"expr": promExpr, "refId": "Anno"},
					},
				},
			},
			map[string]any{
				"kind": "AnnotationQuery",
				"spec": map[string]any{
					"name": "SQL annotations", "enable": true, "hide": false, "iconColor": "blue", "builtIn": false,
					"query": map[string]any{
						"kind": "DataQuery", "group": "mysql", "version": "v0",
						"datasource": map[string]any{"name": sqlDSUID},
						"spec":       map[string]any{"rawSql": sqlText, "refId": "Anno"},
					},
				},
			},
			map[string]any{
				"kind": "AnnotationQuery",
				"spec": map[string]any{
					"name": "Disabled SQL", "enable": false, "hide": true, "iconColor": "purple", "builtIn": false,
					"query": map[string]any{
						"kind": "DataQuery", "group": "mysql", "version": "v0",
						"datasource": map[string]any{"name": sqlDSUID},
						"spec":       map[string]any{"rawSql": disabledSQL, "refId": "Anno"},
					},
				},
			},
			map[string]any{
				"kind": "AnnotationQuery",
				"spec": map[string]any{
					"name": "Built-in annotations", "enable": true, "hide": true, "iconColor": "rgba(0, 211, 255, 1)", "builtIn": true,
					"query": map[string]any{
						"kind": "DataQuery", "group": "grafana", "version": "v0",
						"datasource": map[string]any{"name": "grafana"},
						"spec":       map[string]any{"tags": []any{builtinTag}, "type": "dashboard"},
					},
				},
			},
		},
	}
}

func schemaV1Dashboard() map[string]any {
	return map[string]any{
		"uid":   dashboardUID,
		"title": "Annotated dashboard",
		"annotations": map[string]any{
			"list": []any{
				map[string]any{
					"name": "Prom annotations", "enable": true, "iconColor": "red",
					"datasource": map[string]any{"type": "prometheus", "uid": promDSUID},
					"target":     map[string]any{"expr": promExpr, "refId": "Anno"},
				},
				map[string]any{
					"name": "SQL annotations", "enable": true, "iconColor": "blue",
					"datasource": map[string]any{"type": "mysql", "uid": sqlDSUID},
					"target":     map[string]any{"rawSql": sqlText, "refId": "Anno"},
				},
				map[string]any{
					"name": "Disabled SQL", "enable": false, "iconColor": "purple",
					"datasource": map[string]any{"type": "mysql", "uid": sqlDSUID},
					"target":     map[string]any{"rawSql": disabledSQL, "refId": "Anno"},
				},
				map[string]any{
					"name": "Built-in annotations", "enable": true, "iconColor": "rgba(0, 211, 255, 1)", "builtIn": 1, "type": "dashboard",
					"datasource": map[string]any{"type": "datasource", "uid": "grafana"},
					"target":     map[string]any{"tags": []any{builtinTag}, "type": "dashboard"},
				},
			},
		},
	}
}

func unstructuredDashboard(t *testing.T, dashboard map[string]any) *common.Unstructured {
	t.Helper()
	raw, err := json.Marshal(dashboard)
	require.NoError(t, err)
	parsed := &common.Unstructured{}
	require.NoError(t, json.Unmarshal(raw, parsed))
	return parsed
}

func externalSnapshotServer(t *testing.T) (*httptest.Server, *[]byte) {
	t.Helper()
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		body, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"key":       "external-key",
			"deleteKey": "external-delete-key",
			"url":       "https://snapshots.example/dashboard/snapshot/external-key",
			"deleteUrl": "https://snapshots.example/api/snapshots-delete/external-delete-key",
		})
	}))
	t.Cleanup(server.Close)
	return server, &body
}

func TestSnapshotCreateDropsAnnotationQueries(t *testing.T) {
	testUser := createTestUser()
	cases := []struct {
		name      string
		dashboard map[string]any
	}{
		{name: "schema v2", dashboard: schemaV2Dashboard()},
		{name: "schema v1", dashboard: schemaV1Dashboard()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("local save", func(t *testing.T) {
				mockService := NewMockService(t)
				var saved []byte
				mockService.On("ValidateDashboardExists", mock.Anything, int64(1), dashboardUID).Return(nil)
				mockService.On("CreateDashboardSnapshot", mock.Anything, mock.Anything).
					Run(func(args mock.Arguments) {
						cmd := args.Get(1).(*CreateDashboardSnapshotCommand)
						raw, err := cmd.Dashboard.MarshalJSON()
						require.NoError(t, err)
						saved = raw
					}).
					Return(&DashboardSnapshot{Key: "local-key", DeleteKey: "local-delete-key"}, nil)

				req, err := http.NewRequest(http.MethodPost, "/api/snapshots", nil)
				require.NoError(t, err)
				req = req.WithContext(identity.WithRequester(req.Context(), testUser))
				ctx, recorder := createReqContext(t, req, testUser)

				CreateDashboardSnapshot(ctx, snapshot.SnapshotSharingOptions{SnapshotsEnabled: true}, CreateDashboardSnapshotCommand{
					DashboardCreateCommand: snapshot.DashboardCreateCommand{
						Dashboard: unstructuredDashboard(t, tc.dashboard),
						Name:      "Annotated dashboard",
					},
				}, mockService)

				require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
				assertAnnotationQueriesRemoved(t, saved)
			})

			t.Run("external publish", func(t *testing.T) {
				server, posted := externalSnapshotServer(t)
				mockService := NewMockService(t)
				mockService.On("ValidateDashboardExists", mock.Anything, int64(1), dashboardUID).Return(nil)
				mockService.On("CreateDashboardSnapshot", mock.Anything, mock.Anything).
					Return(&DashboardSnapshot{Key: "external-key", DeleteKey: "external-delete-key"}, nil)

				req, err := http.NewRequest(http.MethodPost, "/api/snapshots", nil)
				require.NoError(t, err)
				req = req.WithContext(identity.WithRequester(req.Context(), testUser))
				ctx, recorder := createReqContext(t, req, testUser)

				CreateDashboardSnapshot(ctx, snapshot.SnapshotSharingOptions{
					SnapshotsEnabled:    true,
					ExternalEnabled:     true,
					ExternalSnapshotURL: server.URL,
				}, CreateDashboardSnapshotCommand{
					DashboardCreateCommand: snapshot.DashboardCreateCommand{
						Dashboard: unstructuredDashboard(t, tc.dashboard),
						Name:      "Annotated dashboard",
						External:  true,
					},
				}, mockService)

				require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
				require.NotEmpty(t, *posted)
				assertAnnotationQueriesRemoved(t, *posted)
			})

			t.Run("public mode", func(t *testing.T) {
				mockService := NewMockService(t)
				var saved []byte
				mockService.On("CreateDashboardSnapshot", mock.Anything, mock.Anything).
					Run(func(args mock.Arguments) {
						cmd := args.Get(1).(*CreateDashboardSnapshotCommand)
						raw, err := cmd.Dashboard.MarshalJSON()
						require.NoError(t, err)
						saved = raw
					}).
					Return(&DashboardSnapshot{Key: "public-key", DeleteKey: "public-delete-key"}, nil)

				req, err := http.NewRequest(http.MethodPost, "/api/snapshots", strings.NewReader(`{}`))
				require.NoError(t, err)
				ctx, recorder := createReqContext(t, req, &user.SignedInUser{})

				CreateDashboardSnapshotPublic(ctx, snapshot.SnapshotSharingOptions{SnapshotsEnabled: true}, CreateDashboardSnapshotCommand{
					DashboardCreateCommand: snapshot.DashboardCreateCommand{
						Dashboard: unstructuredDashboard(t, tc.dashboard),
						Name:      "Annotated dashboard",
					},
				}, mockService)

				require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
				assertAnnotationQueriesRemoved(t, saved)
			})
		})
	}
}
