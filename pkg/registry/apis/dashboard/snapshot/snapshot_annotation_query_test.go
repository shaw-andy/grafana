package snapshot

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/kube-openapi/pkg/common"

	authlib "github.com/grafana/authlib/types"
	dashv0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	grafanarest "github.com/grafana/grafana/pkg/apiserver/rest"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	acmock "github.com/grafana/grafana/pkg/services/accesscontrol/mock"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/user"
)

const (
	k8sPromExpr    = "sum(rate(payments_api_annotation_query[5m]))"
	k8sPromDSUID   = "prom_ds_uid_annotation_7f3a"
	k8sSQL         = "SELECT secret_col FROM billing_customers_annotation_query WHERE id = 42"
	k8sSQLDSUID    = "mysql_ds_uid_annotation_9c1e"
	k8sDisabledSQL = "SELECT secret_col FROM disabled_annotation_query_secret WHERE id = 1"
	k8sBuiltinTag  = "builtin_annotation_query_internal_release"
)

func k8sAnnotationTokens() []string {
	return []string{k8sPromExpr, k8sPromDSUID, k8sSQL, k8sSQLDSUID, k8sDisabledSQL, k8sBuiltinTag}
}

func requireAnnotationQueriesRemoved(t *testing.T, payload []byte) {
	t.Helper()
	encoded := string(payload)
	for _, token := range k8sAnnotationTokens() {
		require.NotContains(t, encoded, token)
	}
	require.Contains(t, encoded, "Prom annotations")
	require.Contains(t, encoded, "SQL annotations")
}

func k8sDashboard(schema string) map[string]any {
	if schema == "v1" {
		return map[string]any{
			"uid":   "dashuid01",
			"title": "Annotated dashboard",
			"annotations": map[string]any{
				"list": []any{
					map[string]any{
						"name": "Prom annotations", "enable": true, "iconColor": "red",
						"datasource": map[string]any{"type": "prometheus", "uid": k8sPromDSUID},
						"target":     map[string]any{"expr": k8sPromExpr, "refId": "Anno"},
					},
					map[string]any{
						"name": "SQL annotations", "enable": true, "iconColor": "blue",
						"datasource": map[string]any{"type": "mysql", "uid": k8sSQLDSUID},
						"target":     map[string]any{"rawSql": k8sSQL, "refId": "Anno"},
					},
					map[string]any{
						"name": "Disabled SQL", "enable": false, "iconColor": "purple",
						"datasource": map[string]any{"type": "mysql", "uid": k8sSQLDSUID},
						"target":     map[string]any{"rawSql": k8sDisabledSQL, "refId": "Anno"},
					},
					map[string]any{
						"name": "Built-in annotations", "enable": true, "builtIn": 1, "type": "dashboard", "iconColor": "rgba(0, 211, 255, 1)",
						"target": map[string]any{"tags": []any{k8sBuiltinTag}, "type": "dashboard"},
					},
				},
			},
		}
	}
	return map[string]any{
		"uid":   "dashuid01",
		"title": "Annotated dashboard",
		"annotations": []any{
			map[string]any{
				"kind": "AnnotationQuery",
				"spec": map[string]any{
					"name": "Prom annotations", "enable": true, "hide": false, "iconColor": "red", "builtIn": false,
					"query": map[string]any{
						"kind": "DataQuery", "group": "prometheus", "version": "v0",
						"datasource": map[string]any{"name": k8sPromDSUID},
						"spec":       map[string]any{"expr": k8sPromExpr, "refId": "Anno"},
					},
				},
			},
			map[string]any{
				"kind": "AnnotationQuery",
				"spec": map[string]any{
					"name": "SQL annotations", "enable": true, "hide": false, "iconColor": "blue", "builtIn": false,
					"query": map[string]any{
						"kind": "DataQuery", "group": "mysql", "version": "v0",
						"datasource": map[string]any{"name": k8sSQLDSUID},
						"spec":       map[string]any{"rawSql": k8sSQL, "refId": "Anno"},
					},
				},
			},
			map[string]any{
				"kind": "AnnotationQuery",
				"spec": map[string]any{
					"name": "Disabled SQL", "enable": false, "hide": true, "iconColor": "purple", "builtIn": false,
					"query": map[string]any{
						"kind": "DataQuery", "group": "mysql", "version": "v0",
						"datasource": map[string]any{"name": k8sSQLDSUID},
						"spec":       map[string]any{"rawSql": k8sDisabledSQL, "refId": "Anno"},
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
						"spec":       map[string]any{"tags": []any{k8sBuiltinTag}, "type": "dashboard"},
					},
				},
			},
		},
	}
}

func TestKubernetesSnapshotCreateDropsAnnotationQueries(t *testing.T) {
	const orgID int64 = 1
	namespace := authlib.OrgNamespaceFormatter(orgID)
	editor := &user.SignedInUser{UserID: 1, OrgID: orgID}

	cases := []string{"v2", "v1"}
	for _, schema := range cases {
		t.Run(schema, func(t *testing.T) {
			t.Run("local save", func(t *testing.T) {
				setKubernetesSnapshotsToggle(t, true)
				var created *dashv0.Snapshot
				status, _ := postKubernetesSnapshot(t, namespace, editor, k8sDashboard(schema), false, "", func(storage *grafanarest.MockStorage) {
					storage.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
						Run(func(args mock.Arguments) {
							created = args.Get(1).(*dashv0.Snapshot)
						}).
						Return(&dashv0.Snapshot{}, nil)
				})
				require.Equal(t, http.StatusOK, status)
				require.NotNil(t, created)
				raw, err := json.Marshal(created.Spec.Dashboard)
				require.NoError(t, err)
				requireAnnotationQueriesRemoved(t, raw)
			})

			t.Run("external legacy publish", func(t *testing.T) {
				setExternalSnapshotsK8SAPIPushToggle(t, false)
				var posted []byte
				external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var err error
					posted, err = io.ReadAll(r.Body)
					require.NoError(t, err)
					require.Equal(t, "/api/snapshots", r.URL.Path)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"key": "ext-key", "deleteKey": "ext-delete-key",
						"url": "https://snapshots.example/dashboard/snapshot/ext-key", "deleteUrl": "https://snapshots.example/api/snapshots-delete/ext-delete-key",
					})
				}))
				t.Cleanup(external.Close)

				status, _ := postKubernetesSnapshot(t, namespace, editor, k8sDashboard(schema), true, external.URL, func(storage *grafanarest.MockStorage) {
					storage.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
						Return(&dashv0.Snapshot{}, nil)
				})
				require.Equal(t, http.StatusOK, status)
				require.NotEmpty(t, posted)
				requireAnnotationQueriesRemoved(t, posted)
			})

			t.Run("external kubernetes publish", func(t *testing.T) {
				setExternalSnapshotsK8SAPIPushToggle(t, true)
				var posted []byte
				external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var err error
					posted, err = io.ReadAll(r.Body)
					require.NoError(t, err)
					require.Contains(t, r.URL.Path, "/apis/dashboard.grafana.app/v0alpha1/namespaces/default/snapshots/create")
					_ = json.NewEncoder(w).Encode(dashv0.DashboardCreateResponse{
						Key: "ext-key", DeleteKey: "ext-delete-key",
						URL: "https://snapshots.example/snapshots/ext-key", DeleteURL: "https://snapshots.example/api/snapshots-delete/ext-delete-key",
					})
				}))
				t.Cleanup(external.Close)

				status, _ := postKubernetesSnapshot(t, namespace, editor, k8sDashboard(schema), true, external.URL, func(storage *grafanarest.MockStorage) {
					storage.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
						Return(&dashv0.Snapshot{}, nil)
				})
				require.Equal(t, http.StatusOK, status)
				require.NotEmpty(t, posted)
				requireAnnotationQueriesRemoved(t, posted)
			})
		})
	}
}

func postKubernetesSnapshot(t *testing.T, namespace string, editor *user.SignedInUser, dashboard map[string]any, external bool, externalURL string, setupStorage func(*grafanarest.MockStorage)) (int, []byte) {
	t.Helper()
	dashboardService := dashboards.NewFakeDashboardService(t)
	dashboardService.On("GetDashboard", mock.Anything, &dashboards.GetDashboardQuery{
		UID:   "dashuid01",
		OrgID: editor.OrgID,
	}).Return(&dashboards.Dashboard{UID: "dashuid01", OrgID: editor.OrgID}, nil)

	mockStorage := grafanarest.NewMockStorage(t)
	setupStorage(mockStorage)

	routes := GetRoutes(
		dashv0.SnapshotSharingOptions{
			SnapshotsEnabled:    true,
			ExternalEnabled:     external,
			ExternalSnapshotURL: externalURL,
		},
		acmock.New().WithPermissions([]accesscontrol.Permission{{Action: dashboards.ActionSnapshotsCreate}}),
		map[string]common.OpenAPIDefinition{},
		func() rest.Storage { return mockStorage },
		dashboardService,
	)

	payload, err := json.Marshal(map[string]any{
		"name":      "Annotated dashboard",
		"expires":   3600,
		"external":  external,
		"dashboard": dashboard,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/snapshots/create", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(identity.WithRequester(req.Context(), editor))
	req = mux.SetURLVars(req, map[string]string{"namespace": namespace})

	recorder := httptest.NewRecorder()
	routes.Namespace[0].Handler(recorder, req)
	return recorder.Code, recorder.Body.Bytes()
}
