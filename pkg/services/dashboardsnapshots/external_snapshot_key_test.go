package dashboardsnapshots

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	snapshot "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
)

// safeSnapshotKey matches the alphanumeric tokens util.GetRandomString produces for local keys.
const (
	safeSnapshotKey       = "abcdefghijklmnopqrstuvwxyz012345"
	safeSnapshotDeleteKey = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
)

func TestExternalSnapshotKeyMustStayInsideSnapshotAPI(t *testing.T) {
	t.Parallel()

	victimPaths := []struct {
		name      string
		key       string
		deleteKey string
	}{
		{
			name:      "view key with parent segments",
			key:       strings.Repeat("../", 12) + "api/datasources/uid/victim-ds",
			deleteKey: safeSnapshotDeleteKey,
		},
		{
			name:      "view key with encoded parent segments",
			key:       strings.Repeat("%2e%2e/", 12) + "api/dashboards/uid/victim-dash",
			deleteKey: safeSnapshotDeleteKey,
		},
		{
			name:      "delete key with parent segments",
			key:       safeSnapshotKey,
			deleteKey: strings.Repeat("../", 12) + "api/admin/users/7",
		},
		{
			name:      "delete key with encoded parent segments",
			key:       safeSnapshotKey,
			deleteKey: strings.Repeat("%2e%2e/", 12) + "api/admin/users/7",
		},
	}

	for _, tc := range victimPaths {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var posts int
			externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts++
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/api/snapshots", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
					"key":       tc.key,
					"deleteKey": tc.deleteKey,
					"url":       "https://snapshots.example/dashboard/snapshot/x",
					"deleteUrl": "https://snapshots.example/api/snapshots-delete/x",
				}))
			}))
			t.Cleanup(externalServer.Close)

			mockService := NewMockService(t)
			mockService.On("ValidateDashboardExists", mock.Anything, int64(1), "test-dashboard-uid").Return(nil)
			mockService.On("CreateDashboardSnapshot", mock.Anything, mock.Anything).
				Return(func(_ context.Context, cmd *CreateDashboardSnapshotCommand) (*DashboardSnapshot, error) {
					t.Errorf("snapshot stored before rejecting key %q deleteKey %q", cmd.Key, cmd.DeleteKey)
					return &DashboardSnapshot{Key: cmd.Key, DeleteKey: cmd.DeleteKey}, nil
				}).Maybe()

			cfg := snapshot.SnapshotSharingOptions{
				SnapshotsEnabled:    true,
				ExternalEnabled:     true,
				ExternalSnapshotURL: externalServer.URL,
			}
			testUser := createTestUser()
			cmd := CreateDashboardSnapshotCommand{
				DashboardCreateCommand: snapshot.DashboardCreateCommand{
					Dashboard: createTestDashboard(t),
					Name:      "External snapshot",
					External:  true,
				},
			}
			req, err := http.NewRequest(http.MethodPost, "/api/snapshots", nil)
			require.NoError(t, err)
			req = req.WithContext(identity.WithRequester(req.Context(), testUser))
			ctx, recorder := createReqContext(t, req, testUser)

			CreateDashboardSnapshot(ctx, cfg, cmd, mockService)

			require.Equal(t, 1, posts)
			assert.NotEqual(t, http.StatusOK, recorder.Code)
			body := recorder.Body.String()
			assert.NotContains(t, body, "..")
			assert.NotContains(t, body, "%2e")
			assert.NotContains(t, body, "%2E")
			assert.NotContains(t, body, "datasources/uid")
			assert.NotContains(t, body, "dashboards/uid")
			assert.NotContains(t, body, "admin/users")
			mockService.AssertNotCalled(t, "CreateDashboardSnapshot", mock.Anything, mock.Anything)
		})
	}

	t.Run("alphanumeric external key is returned", func(t *testing.T) {
		t.Parallel()

		externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"key":       safeSnapshotKey,
				"deleteKey": safeSnapshotDeleteKey,
				"url":       "https://snapshots.example/dashboard/snapshot/" + safeSnapshotKey,
				"deleteUrl": "https://snapshots.example/api/snapshots-delete/" + safeSnapshotDeleteKey,
			}))
		}))
		t.Cleanup(externalServer.Close)

		mockService := NewMockService(t)
		mockService.On("ValidateDashboardExists", mock.Anything, int64(1), "test-dashboard-uid").Return(nil)
		mockService.On("CreateDashboardSnapshot", mock.Anything, mock.Anything).
			Return(func(_ context.Context, cmd *CreateDashboardSnapshotCommand) (*DashboardSnapshot, error) {
				return &DashboardSnapshot{Key: cmd.Key, DeleteKey: cmd.DeleteKey}, nil
			})

		cfg := snapshot.SnapshotSharingOptions{
			SnapshotsEnabled:    true,
			ExternalEnabled:     true,
			ExternalSnapshotURL: externalServer.URL,
		}
		testUser := createTestUser()
		cmd := CreateDashboardSnapshotCommand{
			DashboardCreateCommand: snapshot.DashboardCreateCommand{
				Dashboard: createTestDashboard(t),
				Name:      "External snapshot",
				External:  true,
			},
		}
		req, err := http.NewRequest(http.MethodPost, "/api/snapshots", nil)
		require.NoError(t, err)
		req = req.WithContext(identity.WithRequester(req.Context(), testUser))
		ctx, recorder := createReqContext(t, req, testUser)

		CreateDashboardSnapshot(ctx, cfg, cmd, mockService)

		require.Equal(t, http.StatusOK, recorder.Code)
		var response map[string]any
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
		assert.Equal(t, safeSnapshotKey, response["key"])
		assert.Equal(t, safeSnapshotDeleteKey, response["deleteKey"])
		assert.NotContains(t, response["deleteUrl"], "..")
	})
}

func TestLocalSnapshotKeyMustStayInsideSnapshotAPI(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		key       string
		deleteKey string
	}{
		{
			name:      "caller supplied view key with parent segments",
			key:       strings.Repeat("../", 12) + "api/datasources/uid/victim-ds",
			deleteKey: safeSnapshotDeleteKey,
		},
		{
			name:      "caller supplied delete key with parent segments",
			key:       safeSnapshotKey,
			deleteKey: strings.Repeat("../", 12) + "api/admin/users/7",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockService := NewMockService(t)
			mockService.On("ValidateDashboardExists", mock.Anything, int64(1), "test-dashboard-uid").Return(nil)
			mockService.On("CreateDashboardSnapshot", mock.Anything, mock.Anything).
				Return(func(_ context.Context, cmd *CreateDashboardSnapshotCommand) (*DashboardSnapshot, error) {
					t.Errorf("snapshot stored before rejecting key %q deleteKey %q", cmd.Key, cmd.DeleteKey)
					return &DashboardSnapshot{Key: cmd.Key, DeleteKey: cmd.DeleteKey}, nil
				}).Maybe()

			cfg := snapshot.SnapshotSharingOptions{SnapshotsEnabled: true}
			testUser := createTestUser()
			cmd := CreateDashboardSnapshotCommand{
				DashboardCreateCommand: snapshot.DashboardCreateCommand{
					Dashboard: createTestDashboard(t),
					Name:      "Local snapshot",
				},
				Key:       tc.key,
				DeleteKey: tc.deleteKey,
			}
			req, err := http.NewRequest(http.MethodPost, "/api/snapshots", nil)
			require.NoError(t, err)
			req = req.WithContext(identity.WithRequester(req.Context(), testUser))
			ctx, recorder := createReqContext(t, req, testUser)

			CreateDashboardSnapshot(ctx, cfg, cmd, mockService)

			assert.NotEqual(t, http.StatusOK, recorder.Code)
			body := recorder.Body.String()
			assert.NotContains(t, body, "..")
			assert.NotContains(t, body, "datasources/uid")
			assert.NotContains(t, body, "admin/users")
			mockService.AssertNotCalled(t, "CreateDashboardSnapshot", mock.Anything, mock.Anything)
		})
	}
}
