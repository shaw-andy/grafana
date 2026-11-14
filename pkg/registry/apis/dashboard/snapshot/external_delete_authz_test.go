package snapshot

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	authlib "github.com/grafana/authlib/types"
	dashV0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/dashboardsnapshots"
	dashsnapdb "github.com/grafana/grafana/pkg/services/dashboardsnapshots/database"
	snapshotsvc "github.com/grafana/grafana/pkg/services/dashboardsnapshots/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	secretsdb "github.com/grafana/grafana/pkg/services/secrets/database"
	secretsmanager "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web"
)

// When snapshots.kubernetesSnapshots is on, delete is served by the snapshot
// storage wrapper and legacy store. Neither checks that the caller owns the
// snapshot. The authorizer only requires the org-wide snapshots:delete
// permission, which the Editor role has. These tests fail while that path
// deletes another user's external snapshot, including when a second load
// returns a different snapshot than the one that was authorized.
func TestKubernetesExternalSnapshotDeleteAuthorization(t *testing.T) {
	featuremgmt.WithEnabledFlags(t, featuremgmt.FlagSnapshotsKubernetesSnapshots)

	sqlStore := db.NewTestStore(t)
	dashSvc := dashboards.NewFakeDashboardService(t)
	dashSvc.On("GetDashboard", mock.Anything, mock.Anything).Return(&dashboards.Dashboard{
		ID: 42, UID: "source-dash", OrgID: 1,
	}, nil).Maybe()
	secretsSvc := secretsmanager.SetupTestService(t, secretsdb.ProvideSecretsStore(sqlStore))
	inner := snapshotsvc.ProvideService(dashsnapdb.NewStore(sqlStore), secretsSvc, dashSvc)
	host := newExternalSnapshotHost(t)
	swap := &swappingSnapshotService{Service: inner}

	legacy := &SnapshotLegacyStore{
		ResourceInfo: dashV0.SnapshotResourceInfo,
		Service:      swap,
		Namespacer:   authlib.OrgNamespaceFormatter,
	}
	deleter := NewStorageWrapper(legacy, dashV0.SnapshotSharingOptions{
		SnapshotsEnabled:    true,
		ExternalEnabled:     true,
		ExternalSnapshotURL: host.url,
	}).(rest.GracefulDeleter)

	ac := acimpl.ProvideAccessControl(featuremgmt.WithFeatures())
	authz := NewSnapshotAuthorizer(ac)

	creator := snapshotUser(10, org.RoleEditor, dashboards.ActionSnapshotsCreate, dashboards.ActionSnapshotsDelete)
	editor := snapshotUser(20, org.RoleEditor, dashboards.ActionSnapshotsCreate, dashboards.ActionSnapshotsDelete)
	admin := snapshotUser(30, org.RoleAdmin, dashboards.ActionSnapshotsDelete)

	create := func(t *testing.T, owner *user.SignedInUser) createdExternalSnapshot {
		t.Helper()
		return createStoredExternalSnapshot(t, host, inner, owner)
	}

	t.Run("other editor cannot delete by the public view key", func(t *testing.T) {
		target := create(t, creator)
		ownedByEditor := create(t, editor)
		swap.arm(target.key, ownedByEditor.loaded)
		defer swap.disarm()
		host.reset()

		ctx := snapshotDeleteContext(editor)
		decision, reason, err := authz.Authorize(ctx, deleteAttrs(target.key))
		require.NoError(t, err)
		if decision != authorizer.DecisionAllow {
			require.Empty(t, host.calls(), reason)
			requireSnapshotPresent(t, inner, target.key)
			requireSnapshotPresent(t, inner, ownedByEditor.key)
			return
		}

		_, deleted, err := deleter.Delete(ctx, target.key, nil, &metav1.DeleteOptions{})
		require.Error(t, err)
		require.False(t, deleted)
		require.Empty(t, host.calls())
		requireSnapshotPresent(t, inner, target.key)
		requireSnapshotPresent(t, inner, ownedByEditor.key)
	})

	t.Run("creator can delete only the authorized snapshot", func(t *testing.T) {
		target := create(t, creator)
		someoneElse := create(t, editor)
		swap.arm(target.key, someoneElse.loaded)
		defer swap.disarm()
		host.reset()

		ctx := snapshotDeleteContext(creator)
		decision, _, err := authz.Authorize(ctx, deleteAttrs(target.key))
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision)

		_, _, err = deleter.Delete(ctx, target.key, nil, &metav1.DeleteOptions{})
		require.NoError(t, err)
		require.True(t, host.calledOnly(target.deleteKey))
		require.False(t, host.called(someoneElse.deleteKey))
		requireSnapshotAbsent(t, inner, target.key)
		requireSnapshotPresent(t, inner, someoneElse.key)
	})

	t.Run("org admin can delete another user's external snapshot", func(t *testing.T) {
		target := create(t, creator)
		someoneElse := create(t, editor)
		swap.arm(target.key, someoneElse.loaded)
		defer swap.disarm()
		host.reset()

		ctx := snapshotDeleteContext(admin)
		decision, _, err := authz.Authorize(ctx, deleteAttrs(target.key))
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision)

		_, _, err = deleter.Delete(ctx, target.key, nil, &metav1.DeleteOptions{})
		require.NoError(t, err)
		require.True(t, host.calledOnly(target.deleteKey))
		require.False(t, host.called(someoneElse.deleteKey))
		requireSnapshotAbsent(t, inner, target.key)
		requireSnapshotPresent(t, inner, someoneElse.key)
	})
}

func snapshotUser(id int64, role org.RoleType, actions ...string) *user.SignedInUser {
	perms := make([]accesscontrol.Permission, 0, len(actions)+1)
	perms = append(perms, accesscontrol.Permission{
		Action: dashboards.ActionDashboardsRead,
		Scope:  dashboards.ScopeDashboardsProvider.GetResourceScopeUID("source-dash"),
	})
	for _, action := range actions {
		perms = append(perms, accesscontrol.Permission{Action: action})
	}
	return &user.SignedInUser{
		UserID:  id,
		OrgID:   1,
		OrgRole: role,
		Permissions: map[int64]map[string][]string{
			1: accesscontrol.GroupScopesByActionContext(context.Background(), perms),
		},
	}
}

func snapshotDeleteContext(usr *user.SignedInUser) context.Context {
	ctx := k8srequest.WithNamespace(context.Background(), authlib.OrgNamespaceFormatter(usr.OrgID))
	return identity.WithRequester(ctx, usr)
}

func deleteAttrs(viewKey string) authorizer.AttributesRecord {
	return authorizer.AttributesRecord{
		ResourceRequest: true,
		Verb:            "delete",
		Namespace:       authlib.OrgNamespaceFormatter(1),
		APIGroup:        dashV0.GROUP,
		APIVersion:      dashV0.VERSION,
		Resource:        dashV0.SnapshotResourceInfo.GetName(),
		Name:            viewKey,
	}
}

type createdExternalSnapshot struct {
	key       string
	deleteKey string
	loaded    *dashboardsnapshots.DashboardSnapshot
}

func createStoredExternalSnapshot(t *testing.T, host *externalSnapshotHost, svc dashboardsnapshots.Service, owner *user.SignedInUser) createdExternalSnapshot {
	t.Helper()
	dashboard := &common.Unstructured{}
	require.NoError(t, json.Unmarshal([]byte(`{"id":42,"uid":"source-dash","title":"Source"}`), dashboard))
	req := httptest.NewRequest(http.MethodPost, "/api/snapshots/", nil)
	req = req.WithContext(identity.WithRequester(req.Context(), owner))
	rec := httptest.NewRecorder()
	ctx := &contextmodel.ReqContext{
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(http.MethodPost, rec),
		},
		SignedInUser: owner,
		IsSignedIn:   true,
		Logger:       log.NewNopLogger(),
	}
	dashboardsnapshots.CreateDashboardSnapshot(ctx, dashV0.SnapshotSharingOptions{
		SnapshotsEnabled:    true,
		ExternalEnabled:     true,
		ExternalSnapshotURL: host.url,
	}, dashboardsnapshots.CreateDashboardSnapshotCommand{
		DashboardCreateCommand: dashV0.DashboardCreateCommand{
			Name:      "shared",
			Expires:   3600,
			External:  true,
			Dashboard: dashboard,
		},
	}, svc)
	require.Equal(t, http.StatusOK, rec.Code, "create body: %s", rec.Body.String())

	var resp struct {
		Key       string `json:"key"`
		DeleteKey string `json:"deleteKey"`
		URL       string `json:"url"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Key)
	require.Contains(t, resp.URL, "/dashboard/snapshot/"+resp.Key)
	require.NotEqual(t, resp.Key, resp.DeleteKey)

	loaded, err := svc.GetDashboardSnapshot(context.Background(), &dashboardsnapshots.GetDashboardSnapshotQuery{Key: resp.Key})
	require.NoError(t, err)
	require.True(t, loaded.External)
	require.Zero(t, loaded.Dashboard.Get("id").MustInt64())
	require.Empty(t, loaded.Dashboard.Get("uid").MustString())
	return createdExternalSnapshot{key: resp.Key, deleteKey: resp.DeleteKey, loaded: loaded}
}

func requireSnapshotPresent(t *testing.T, svc dashboardsnapshots.Service, key string) {
	t.Helper()
	_, err := svc.GetDashboardSnapshot(context.Background(), &dashboardsnapshots.GetDashboardSnapshotQuery{Key: key})
	require.NoError(t, err)
}

func requireSnapshotAbsent(t *testing.T, svc dashboardsnapshots.Service, key string) {
	t.Helper()
	_, err := svc.GetDashboardSnapshot(context.Background(), &dashboardsnapshots.GetDashboardSnapshotQuery{Key: key})
	require.ErrorIs(t, err, dashboardsnapshots.ErrBaseNotFound)
}

type externalCall struct {
	method string
	path   string
}

type externalSnapshotHost struct {
	url  string
	next atomic.Int64
	mu   sync.Mutex
	seen []externalCall
}

func newExternalSnapshotHost(t *testing.T) *externalSnapshotHost {
	t.Helper()
	host := &externalSnapshotHost{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/snapshots":
			n := host.next.Add(1)
			viewKey := "viewkey" + itoa(n)
			deleteKey := "deletekey" + itoa(n)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"key":       viewKey,
				"deleteKey": deleteKey,
				"url":       host.url + "/dashboard/snapshot/" + viewKey,
				"deleteUrl": host.url + "/api/snapshots-delete/" + deleteKey,
			})
		case r.Method == http.MethodGet && len(r.URL.Path) > len("/api/snapshots-delete/"):
			host.mu.Lock()
			host.seen = append(host.seen, externalCall{method: r.Method, path: r.URL.Path})
			host.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	host.url = server.URL
	t.Cleanup(server.Close)
	return host
}

func (h *externalSnapshotHost) calls() []externalCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]externalCall, len(h.seen))
	copy(out, h.seen)
	return out
}

func (h *externalSnapshotHost) called(deleteKey string) bool {
	for _, call := range h.calls() {
		if call.path == "/api/snapshots-delete/"+deleteKey {
			return true
		}
	}
	return false
}

func (h *externalSnapshotHost) calledOnly(deleteKey string) bool {
	calls := h.calls()
	if len(calls) == 0 {
		return false
	}
	for _, call := range calls {
		if call.method != http.MethodGet || call.path != "/api/snapshots-delete/"+deleteKey {
			return false
		}
	}
	return true
}

func (h *externalSnapshotHost) reset() {
	h.mu.Lock()
	h.seen = nil
	h.mu.Unlock()
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

type swappingSnapshotService struct {
	dashboardsnapshots.Service
	mu           sync.Mutex
	watchKey     string
	targetDelete string
	swapped      *dashboardsnapshots.DashboardSnapshot
	gets         int
}

func (s *swappingSnapshotService) arm(viewKey string, swapped *dashboardsnapshots.DashboardSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.watchKey = viewKey
	s.targetDelete = ""
	s.gets = 0
	if swapped == nil {
		s.swapped = nil
		return
	}
	copied := *swapped
	s.swapped = &copied
}

func (s *swappingSnapshotService) disarm() {
	s.mu.Lock()
	s.watchKey = ""
	s.targetDelete = ""
	s.swapped = nil
	s.gets = 0
	s.mu.Unlock()
}

func (s *swappingSnapshotService) GetDashboardSnapshot(ctx context.Context, query *dashboardsnapshots.GetDashboardSnapshotQuery) (*dashboardsnapshots.DashboardSnapshot, error) {
	result, err := s.Service.GetDashboardSnapshot(ctx, query)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.watchKey == "" {
		return result, err
	}
	matches := query.Key == s.watchKey || (s.targetDelete != "" && query.DeleteKey == s.targetDelete)
	if !matches || err != nil || result == nil {
		return result, err
	}
	s.gets++
	if s.gets == 1 {
		s.targetDelete = result.DeleteKey
		return result, nil
	}
	if s.swapped == nil {
		return result, nil
	}
	return s.swapped, nil
}
