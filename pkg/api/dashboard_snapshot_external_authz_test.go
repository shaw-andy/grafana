package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/dashboardsnapshots"
	dashsnapdb "github.com/grafana/grafana/pkg/services/dashboardsnapshots/database"
	"github.com/grafana/grafana/pkg/services/dashboardsnapshots/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	secretsdb "github.com/grafana/grafana/pkg/services/secrets/database"
	secretsmanager "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// External snapshots are stored with an empty dashboard, so the delete handler's
// owner and dashboard-write checks do not run. These tests are the authorization
// spec for DELETE /api/snapshots/{key}: they fail while another editor can delete
// a snapshot using the public view key, and they pass once that delete is refused
// without calling the external delete URL.
func TestExternalSnapshotViewKeyDeleteAuthorization(t *testing.T) {
	featuremgmt.WithDisabledFlags(t, featuremgmt.FlagSnapshotsKubernetesSnapshots, featuremgmt.FlagExternalSnapshotsK8SAPIPush)

	previousAppURL := setting.AppUrl
	setting.AppUrl = "http://grafana.example/"
	t.Cleanup(func() { setting.AppUrl = previousAppURL })

	sqlStore := db.NewTestStore(t)
	secretsSvc := secretsmanager.SetupTestService(t, secretsdb.ProvideSecretsStore(sqlStore))
	dashSvc := dashboards.NewFakeDashboardService(t)
	dashSvc.On("GetDashboard", mock.Anything, mock.Anything).Return(&dashboards.Dashboard{
		ID:    42,
		UID:   "source-dash",
		OrgID: 1,
	}, nil).Maybe()
	inner := service.ProvideService(dashsnapdb.NewStore(sqlStore), secretsSvc, dashSvc)
	host := newGrafanaExternalSnapshotHost(t)
	swap := &swappingSnapshotService{Service: inner}

	ac := acimpl.ProvideAccessControl(featuremgmt.WithFeatures())
	ac.RegisterScopeAttributeResolver(dashboards.NewDashboardIDScopeResolver(dashSvc, nil))
	ac.RegisterScopeAttributeResolver(dashboards.NewDashboardUIDScopeResolver(dashSvc, nil))

	cfg := setting.NewCfg()
	cfg.SnapshotEnabled = true
	cfg.ExternalEnabled = true
	cfg.ExternalSnapshotUrl = host.url
	cfg.SnapshotPublicMode = false

	var hs *HTTPServer
	server := SetupAPITestServer(t, func(h *HTTPServer) {
		hs = h
		h.Cfg = cfg
		h.Features = featuremgmt.WithFeatures()
		h.dashboardsnapshotsService = swap
		h.DashboardService = dashSvc
		h.AccessControl = ac
	})

	env := &snapshotAuthzEnv{t: t, hs: hs, server: server, host: host, inner: inner, swap: swap}

	creator := env.user(10, org.RoleEditor,
		accesscontrol.Permission{Action: dashboardsnapshots.ActionSnapshotsCreate},
		accesscontrol.Permission{Action: dashboardsnapshots.ActionSnapshotsDelete},
		accesscontrol.Permission{Action: dashboards.ActionDashboardsRead, Scope: dashboards.ScopeDashboardsProvider.GetResourceScopeUID("source-dash")},
	)
	editor := env.user(20, org.RoleEditor,
		accesscontrol.Permission{Action: dashboardsnapshots.ActionSnapshotsCreate},
		accesscontrol.Permission{Action: dashboardsnapshots.ActionSnapshotsDelete},
		accesscontrol.Permission{Action: dashboards.ActionDashboardsRead, Scope: dashboards.ScopeDashboardsProvider.GetResourceScopeUID("source-dash")},
		// Write on a different dashboard must not authorize deleting this snapshot.
		accesscontrol.Permission{Action: dashboards.ActionDashboardsWrite, Scope: dashboards.ScopeDashboardsProvider.GetResourceScopeUID("other-dash")},
	)
	admin := env.user(30, org.RoleAdmin,
		accesscontrol.Permission{Action: dashboardsnapshots.ActionSnapshotsDelete},
	)
	viewer := env.user(40, org.RoleViewer,
		accesscontrol.Permission{Action: dashboardsnapshots.ActionSnapshotsRead},
	)
	otherOrg := env.user(20, org.RoleEditor,
		accesscontrol.Permission{Action: dashboardsnapshots.ActionSnapshotsDelete},
	)
	otherOrg.OrgID = 2
	otherOrg.Permissions = map[int64]map[string][]string{
		2: accesscontrol.GroupScopesByActionContext(context.Background(), []accesscontrol.Permission{
			{Action: dashboardsnapshots.ActionSnapshotsDelete},
		}),
	}

	t.Run("other editor cannot delete by the public view key", func(t *testing.T) {
		target := env.createExternal(creator)
		ownedByEditor := env.createExternal(editor)
		env.swap.arm(target.key, ownedByEditor.loaded)
		defer env.swap.disarm()
		env.host.reset()

		res := env.deleteByViewKey(editor, target.key)
		require.Empty(t, env.host.calls(), "external delete URL was called for a snapshot the editor does not own; status=%d body=%s", res.status, res.body)
		require.Equal(t, http.StatusForbidden, res.status, "body: %s", res.body)
		env.requirePresent(target.key)
		env.requirePresent(ownedByEditor.key)
	})

	t.Run("creator can delete and only the authorized external snapshot is removed", func(t *testing.T) {
		target := env.createExternal(creator)
		someoneElse := env.createExternal(editor)
		env.swap.arm(target.key, someoneElse.loaded)
		defer env.swap.disarm()
		env.host.reset()

		res := env.deleteByViewKey(creator, target.key)
		require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
		env.requireDeleteCall(target.deleteKey)
		require.False(t, env.host.called(someoneElse.deleteKey))
		env.requireAbsent(target.key)
		env.requirePresent(someoneElse.key)
	})

	t.Run("org admin can delete another user's external snapshot", func(t *testing.T) {
		target := env.createExternal(creator)
		someoneElse := env.createExternal(editor)
		env.swap.arm(target.key, someoneElse.loaded)
		defer env.swap.disarm()
		env.host.reset()

		res := env.deleteByViewKey(admin, target.key)
		require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
		env.requireDeleteCall(target.deleteKey)
		require.False(t, env.host.called(someoneElse.deleteKey))
		env.requireAbsent(target.key)
		env.requirePresent(someoneElse.key)
	})

	t.Run("viewer without snapshots delete is forbidden", func(t *testing.T) {
		target := env.createExternal(creator)
		env.host.reset()

		res := env.deleteByViewKey(viewer, target.key)
		require.Equal(t, http.StatusForbidden, res.status, "body: %s", res.body)
		require.Empty(t, env.host.calls())
		env.requirePresent(target.key)
	})

	t.Run("editor in another org cannot delete", func(t *testing.T) {
		target := env.createExternal(creator)
		env.host.reset()

		res := env.deleteByViewKey(otherOrg, target.key)
		require.GreaterOrEqual(t, res.status, 400, "body: %s", res.body)
		require.Less(t, res.status, 500, "body: %s", res.body)
		require.Empty(t, env.host.calls())
		env.requirePresent(target.key)
	})

	t.Run("other editor cannot delete a local snapshot without dashboard write", func(t *testing.T) {
		target := env.createLocal(creator)
		env.host.reset()

		res := env.deleteByViewKey(editor, target.key)
		require.Equal(t, http.StatusForbidden, res.status, "body: %s", res.body)
		require.Empty(t, env.host.calls())
		env.requirePresent(target.key)
	})
}

type snapshotAuthzEnv struct {
	t      *testing.T
	hs     *HTTPServer
	server *webtest.Server
	host   *grafanaExternalSnapshotHost
	inner  dashboardsnapshots.Service
	swap   *swappingSnapshotService
}

type createdSnapshot struct {
	key       string
	deleteKey string
	loaded    *dashboardsnapshots.DashboardSnapshot
}

type deleteResult struct {
	status int
	body   string
}

func (e *snapshotAuthzEnv) user(id int64, role org.RoleType, perms ...accesscontrol.Permission) *user.SignedInUser {
	e.t.Helper()
	return &user.SignedInUser{
		UserID:  id,
		OrgID:   1,
		OrgRole: role,
		Permissions: map[int64]map[string][]string{
			1: accesscontrol.GroupScopesByActionContext(context.Background(), perms),
		},
	}
}

func (e *snapshotAuthzEnv) createExternal(owner *user.SignedInUser) createdSnapshot {
	e.t.Helper()
	return e.create(owner, true)
}

func (e *snapshotAuthzEnv) createLocal(owner *user.SignedInUser) createdSnapshot {
	e.t.Helper()
	return e.create(owner, false)
}

func (e *snapshotAuthzEnv) create(owner *user.SignedInUser, external bool) createdSnapshot {
	e.t.Helper()
	body := `{"name":"shared","expires":3600,"external":false,"dashboard":{"id":42,"uid":"source-dash","title":"Source"}}`
	if external {
		body = `{"name":"shared","expires":3600,"external":true,"dashboard":{"id":42,"uid":"source-dash","title":"Source"}}`
	}
	req := httptest.NewRequest(http.MethodPost, "/api/snapshots/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(identity.WithRequester(req.Context(), owner))
	rec := httptest.NewRecorder()
	handler := e.hs.getCreatedSnapshotHandler().(func(*contextmodel.ReqContext))
	handler(&contextmodel.ReqContext{
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(http.MethodPost, rec),
		},
		SignedInUser: owner,
		IsSignedIn:   true,
		Logger:       log.NewNopLogger(),
	})
	require.Equal(e.t, http.StatusOK, rec.Code, "create body: %s", rec.Body.String())

	var resp struct {
		Key       string `json:"key"`
		DeleteKey string `json:"deleteKey"`
		URL       string `json:"url"`
		DeleteURL string `json:"deleteUrl"`
	}
	require.NoError(e.t, json.Unmarshal(rec.Body.Bytes(), &resp))
	viewKey := viewKeyFromSharedURL(e.t, resp.URL)
	require.Equal(e.t, resp.Key, viewKey)
	require.NotEmpty(e.t, resp.DeleteKey)
	require.NotEqual(e.t, viewKey, resp.DeleteKey)

	loaded, err := e.inner.GetDashboardSnapshot(context.Background(), &dashboardsnapshots.GetDashboardSnapshotQuery{Key: viewKey})
	require.NoError(e.t, err)
	if external {
		require.True(e.t, loaded.External)
		require.NotNil(e.t, loaded.Dashboard)
		require.Zero(e.t, loaded.Dashboard.Get("id").MustInt64())
		require.Empty(e.t, loaded.Dashboard.Get("uid").MustString())
		require.Contains(e.t, loaded.ExternalDeleteURL, "/api/snapshots-delete/"+resp.DeleteKey)
	}
	return createdSnapshot{key: viewKey, deleteKey: resp.DeleteKey, loaded: loaded}
}

func (e *snapshotAuthzEnv) deleteByViewKey(actor *user.SignedInUser, viewKey string) deleteResult {
	e.t.Helper()
	req := e.server.NewRequest(http.MethodDelete, "/api/snapshots/"+url.PathEscape(viewKey), nil)
	req = webtest.RequestWithSignedInUser(req, actor)
	res, err := e.server.Send(req)
	require.NoError(e.t, err)
	defer func() { _ = res.Body.Close() }()
	buf, err := io.ReadAll(res.Body)
	require.NoError(e.t, err)
	return deleteResult{status: res.StatusCode, body: string(buf)}
}

func (e *snapshotAuthzEnv) requirePresent(key string) {
	e.t.Helper()
	_, err := e.inner.GetDashboardSnapshot(context.Background(), &dashboardsnapshots.GetDashboardSnapshotQuery{Key: key})
	require.NoError(e.t, err)
}

func (e *snapshotAuthzEnv) requireAbsent(key string) {
	e.t.Helper()
	_, err := e.inner.GetDashboardSnapshot(context.Background(), &dashboardsnapshots.GetDashboardSnapshotQuery{Key: key})
	require.ErrorIs(e.t, err, dashboardsnapshots.ErrBaseNotFound)
}

func (e *snapshotAuthzEnv) requireDeleteCall(deleteKey string) {
	e.t.Helper()
	calls := e.host.calls()
	require.Len(e.t, calls, 1)
	require.Equal(e.t, http.MethodGet, calls[0].method)
	require.Equal(e.t, "/api/snapshots-delete/"+deleteKey, calls[0].path)
}

func viewKeyFromSharedURL(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	require.GreaterOrEqual(t, len(parts), 3)
	require.Equal(t, "dashboard", parts[len(parts)-3])
	require.Equal(t, "snapshot", parts[len(parts)-2])
	key := parts[len(parts)-1]
	require.NotEmpty(t, key)
	return key
}

// grafanaExternalSnapshotHost answers the external snapshot API the way this
// Grafana server does when it is the public snapshot host: the shared URL is
// dashboard/snapshot/{view key} and delete is GET /api/snapshots-delete/{delete key}.
type grafanaExternalSnapshotHost struct {
	url  string
	next atomic.Int64
	mu   sync.Mutex
	seen []externalCall
}

type externalCall struct {
	method string
	path   string
}

func newGrafanaExternalSnapshotHost(t *testing.T) *grafanaExternalSnapshotHost {
	t.Helper()
	host := &grafanaExternalSnapshotHost{}
	server := httptest.NewServer(http.HandlerFunc(host.serve))
	host.url = server.URL
	t.Cleanup(server.Close)
	return host
}

func (h *grafanaExternalSnapshotHost) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/snapshots":
		n := h.next.Add(1)
		viewKey := "viewkey" + itoa(n)
		deleteKey := "deletekey" + itoa(n)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key":       viewKey,
			"deleteKey": deleteKey,
			"url":       h.url + "/dashboard/snapshot/" + viewKey,
			"deleteUrl": h.url + "/api/snapshots-delete/" + deleteKey,
		})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/snapshots-delete/"):
		h.mu.Lock()
		h.seen = append(h.seen, externalCall{method: r.Method, path: r.URL.Path})
		h.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

func (h *grafanaExternalSnapshotHost) calls() []externalCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]externalCall, len(h.seen))
	copy(out, h.seen)
	return out
}

func (h *grafanaExternalSnapshotHost) called(deleteKey string) bool {
	for _, call := range h.calls() {
		if call.path == "/api/snapshots-delete/"+deleteKey {
			return true
		}
	}
	return false
}

func (h *grafanaExternalSnapshotHost) reset() {
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

// swappingSnapshotService returns the stored snapshot on the first load of the
// requested key and a different snapshot on every later load. A delete that
// checks one snapshot and then loads it again acts on the second snapshot and
// fails the test.
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
