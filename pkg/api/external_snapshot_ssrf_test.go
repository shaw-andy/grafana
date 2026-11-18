package api

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/dashboardsnapshots"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

func TestDashboardSnapshotAPIDoesNotRequestStoredInternalDeleteURL(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		if r.Header.Get("Authorization") != "" {
			t.Errorf("Authorization header was sent to the untrusted host")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(internal.Close)

	stored := internal.URL + "/latest/meta-data/iam/security-credentials/?x=/api/snapshots-delete/stored-key"
	dash, err := simplejson.NewJson([]byte(`{}`))
	require.NoError(t, err)

	svc := dashboardsnapshots.NewMockService(t)
	svc.On("GetDashboardSnapshot", mock.Anything, mock.Anything).Return(&dashboardsnapshots.DashboardSnapshot{
		ID:                1,
		OrgID:             1,
		UserID:            1,
		Key:               "snap-key",
		DeleteKey:         "stored-key",
		External:          true,
		ExternalDeleteURL: stored,
		Dashboard:         dash,
	}, nil)
	svc.On("DeleteDashboardSnapshot", mock.Anything, mock.Anything).
		Run(func(mock.Arguments) { t.Errorf("local snapshot deleted") }).
		Return(nil).Maybe()

	editor := authedUserWithPermissions(1, 1, []accesscontrol.Permission{
		{Action: dashboardsnapshots.ActionSnapshotsDelete},
	})

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		cfg := setting.NewCfg()
		cfg.SnapshotEnabled = true
		hs.Cfg = cfg
		hs.dashboardsnapshotsService = svc
		hs.AccessControl = acimpl.ProvideAccessControl(featuremgmt.WithFeatures())
	})

	deleteRes := signedSnapshotRequest(t, server, http.MethodDelete, "/api/snapshots/snap-key", editor)
	require.NotEqual(t, http.StatusOK, deleteRes)

	keyRes := signedSnapshotRequest(t, server, http.MethodGet, "/api/snapshots-delete/stored-key", editor)
	require.NotEqual(t, http.StatusOK, keyRes)

	mu.Lock()
	defer mu.Unlock()
	require.Zero(t, hits)
	svc.AssertNotCalled(t, "DeleteDashboardSnapshot", mock.Anything, mock.Anything)
}

func signedSnapshotRequest(t *testing.T, server *webtest.Server, method, path string, editor *user.SignedInUser) int {
	t.Helper()
	res, err := server.Send(webtest.RequestWithSignedInUser(server.NewRequest(method, path, nil), editor))
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	return res.StatusCode
}
