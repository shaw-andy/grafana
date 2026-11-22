package snapshot

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	registryrest "k8s.io/apiserver/pkg/registry/rest"
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

func TestKubernetesExternalSnapshotKeyMustStayInsideSnapshotAPI(t *testing.T) {
	setKubernetesSnapshotsToggle(t, true)

	const orgID int64 = 1
	namespace := authlib.OrgNamespaceFormatter(orgID)
	testUser := &user.SignedInUser{UserID: 1, OrgID: orgID}

	cases := []struct {
		name      string
		key       string
		deleteKey string
	}{
		{
			name:      "view key with parent segments",
			key:       strings.Repeat("../", 12) + "api/datasources/uid/victim-ds",
			deleteKey: "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
		},
		{
			name:      "view key with encoded parent segments",
			key:       strings.Repeat("%2e%2e/", 12) + "api/dashboards/uid/victim-dash",
			deleteKey: "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
		},
		{
			name:      "delete key with parent segments",
			key:       "abcdefghijklmnopqrstuvwxyz012345",
			deleteKey: strings.Repeat("../", 12) + "api/admin/users/7",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/snapshots", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				require.NoError(t, json.NewEncoder(w).Encode(map[string]string{
					"key":       tc.key,
					"deleteKey": tc.deleteKey,
					"url":       "https://snapshots.example/dashboard/snapshot/x",
					"deleteUrl": "https://snapshots.example/api/snapshots-delete/x",
				}))
			}))
			t.Cleanup(externalServer.Close)

			dashboardService := dashboards.NewFakeDashboardService(t)
			dashboardService.On("GetDashboard", mock.Anything, &dashboards.GetDashboardQuery{
				UID:   "dash-1",
				OrgID: orgID,
			}).Return(&dashboards.Dashboard{UID: "dash-1", OrgID: orgID}, nil)

			mockStorage := grafanarest.NewMockStorage(t)
			mockStorage.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(func(_ context.Context, obj runtime.Object, _ registryrest.ValidateObjectFunc, _ *metav1.CreateOptions) (runtime.Object, error) {
					snap, ok := obj.(*dashv0.Snapshot)
					require.True(t, ok)
					assert.NotContains(t, snap.Name, "..")
					assert.NotContains(t, snap.Name, "/")
					assert.NotContains(t, snap.Name, "%")
					if snap.Spec.DeleteKey != nil {
						assert.NotContains(t, *snap.Spec.DeleteKey, "..")
						assert.NotContains(t, *snap.Spec.DeleteKey, "/")
						assert.NotContains(t, *snap.Spec.DeleteKey, "%")
					}
					t.Errorf("snapshot stored before rejecting external key %q", snap.Name)
					return snap, nil
				}).Maybe()

			routes := GetRoutes(
				dashv0.SnapshotSharingOptions{
					SnapshotsEnabled:    true,
					ExternalEnabled:     true,
					ExternalSnapshotURL: externalServer.URL,
				},
				acmock.New().WithPermissions([]accesscontrol.Permission{{Action: dashboards.ActionSnapshotsCreate}}),
				map[string]common.OpenAPIDefinition{},
				func() registryrest.Storage { return mockStorage },
				dashboardService,
			)

			body, err := json.Marshal(map[string]any{
				"dashboard": map[string]any{"uid": "dash-1", "title": "test"},
				"name":      "external snapshot",
				"external":  true,
			})
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/snapshots/create", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(identity.WithRequester(req.Context(), testUser))
			req = mux.SetURLVars(req, map[string]string{"namespace": namespace})

			recorder := httptest.NewRecorder()
			routes.Namespace[0].Handler(recorder, req)

			assert.NotEqual(t, http.StatusOK, recorder.Code)
			responseBody := recorder.Body.String()
			assert.NotContains(t, responseBody, "..")
			assert.NotContains(t, responseBody, "%2e")
			assert.NotContains(t, responseBody, "datasources/uid")
			assert.NotContains(t, responseBody, "dashboards/uid")
			assert.NotContains(t, responseBody, "admin/users")
			mockStorage.AssertNotCalled(t, "Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
