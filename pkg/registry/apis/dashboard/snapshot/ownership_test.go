package snapshot

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	authlib "github.com/grafana/authlib/types"
	dashv0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/components/simplejson"
	acmock "github.com/grafana/grafana/pkg/services/accesscontrol/mock"
	grafanaauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/dashboardsnapshots"
)

const (
	viewKey         = "public-view-key"
	ownerDeleteKey  = "owner-delete-key"
	victimDeleteKey = "victim-delete-key"
	ownerUserID     = int64(7)
	victimUserID    = int64(99)
	dashboardUID    = "restricted-dash"
	dashboardID     = float64(42)
)

// scriptedSnapshotService returns a different snapshot on each lookup by view
// key. A lookup by delete key returns the snapshot that carries that key, so a
// later reload of an already chosen snapshot stays on that snapshot.
type scriptedSnapshotService struct {
	snaps   []dashboardsnapshots.DashboardSnapshot
	n       int
	deleted []string
}

func (s *scriptedSnapshotService) GetDashboardSnapshot(_ context.Context, q *dashboardsnapshots.GetDashboardSnapshotQuery) (*dashboardsnapshots.DashboardSnapshot, error) {
	if q != nil && q.Key == "" && q.DeleteKey != "" {
		for i := range s.snaps {
			if s.snaps[i].DeleteKey == q.DeleteKey {
				snap := s.snaps[i]
				return &snap, nil
			}
		}
		return nil, dashboardsnapshots.ErrBaseNotFound.Errorf("dashboard snapshot not found")
	}
	if len(s.snaps) == 0 {
		return nil, dashboardsnapshots.ErrBaseNotFound.Errorf("dashboard snapshot not found")
	}
	idx := s.n
	if idx >= len(s.snaps) {
		idx = len(s.snaps) - 1
	} else {
		s.n++
	}
	snap := s.snaps[idx]
	return &snap, nil
}

func (s *scriptedSnapshotService) DeleteDashboardSnapshot(_ context.Context, cmd *dashboardsnapshots.DeleteDashboardSnapshotCommand) error {
	if cmd != nil {
		s.deleted = append(s.deleted, cmd.DeleteKey)
	}
	return nil
}

func (s *scriptedSnapshotService) CreateDashboardSnapshot(context.Context, *dashboardsnapshots.CreateDashboardSnapshotCommand) (*dashboardsnapshots.DashboardSnapshot, error) {
	return nil, nil
}

func (s *scriptedSnapshotService) DeleteExpiredSnapshots(context.Context, *dashboardsnapshots.DeleteExpiredSnapshotsCommand) error {
	return nil
}

func (s *scriptedSnapshotService) SearchDashboardSnapshots(context.Context, *dashboardsnapshots.GetDashboardSnapshotsQuery) (dashboardsnapshots.DashboardSnapshotsList, error) {
	return nil, nil
}

func (s *scriptedSnapshotService) ValidateDashboardExists(context.Context, int64, string) error {
	return nil
}

// recordingDeleter is the inner store behind storageWrapper. Each Get returns
// the next object. Delete records the name it was asked to delete and does not
// look the object up again.
type recordingDeleter struct {
	gets    []*dashv0.Snapshot
	n       int
	deleted []string
}

func (d *recordingDeleter) New() runtime.Object { return &dashv0.Snapshot{} }
func (d *recordingDeleter) Destroy()            {}

func (d *recordingDeleter) Get(_ context.Context, _ string, _ *metav1.GetOptions) (runtime.Object, error) {
	if len(d.gets) == 0 {
		return nil, apierrors.NewNotFound(dashv0.SnapshotResourceInfo.GroupResource(), viewKey)
	}
	idx := d.n
	if idx >= len(d.gets) {
		idx = len(d.gets) - 1
	} else {
		d.n++
	}
	return d.gets[idx].DeepCopy(), nil
}

func (d *recordingDeleter) Delete(_ context.Context, name string, _ rest.ValidateObjectFunc, _ *metav1.DeleteOptions) (runtime.Object, bool, error) {
	d.deleted = append(d.deleted, name)
	return nil, true, nil
}

type externalHits struct {
	mu    sync.Mutex
	paths []string
}

func (h *externalHits) record(path string) {
	h.mu.Lock()
	h.paths = append(h.paths, path)
	h.mu.Unlock()
}

func (h *externalHits) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.paths))
	copy(out, h.paths)
	return out
}

func newExternalServer(t *testing.T) (*httptest.Server, *externalHits) {
	t.Helper()
	hits := &externalHits{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.record(r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server, hits
}

func editorCaller(id int64, extra map[string][]string) *identity.StaticRequester {
	perms := map[string][]string{
		dashboards.ActionSnapshotsDelete: {""},
	}
	for action, scopes := range extra {
		perms[action] = append(perms[action], scopes...)
	}
	return &identity.StaticRequester{
		Type:      authlib.TypeUser,
		UserID:    id,
		UserUID:   "editor-" + strconv.FormatInt(id, 10),
		OrgID:     1,
		OrgRole:   identity.RoleEditor,
		Namespace: authlib.OrgNamespaceFormatter(1),
		Permissions: map[int64]map[string][]string{
			1: perms,
		},
	}
}

func adminCaller() *identity.StaticRequester {
	user := editorCaller(3, nil)
	user.OrgRole = identity.RoleAdmin
	user.UserUID = "org-admin"
	return user
}

func callerContext(user identity.Requester) context.Context {
	ctx := k8srequest.WithNamespace(context.Background(), authlib.OrgNamespaceFormatter(user.GetOrgID()))
	return identity.WithRequester(ctx, user)
}

func modelSnapshot(deleteKey string, userID int64, externalBase string) dashboardsnapshots.DashboardSnapshot {
	snap := dashboardsnapshots.DashboardSnapshot{
		Name:      "incident",
		Key:       viewKey,
		DeleteKey: deleteKey,
		OrgID:     1,
		UserID:    userID,
		Dashboard: simplejson.NewFromAny(map[string]any{
			"uid": dashboardUID,
			"id":  dashboardID,
		}),
	}
	if externalBase != "" {
		snap.External = true
		snap.ExternalURL = externalBase + "/snapshot/" + viewKey
		snap.ExternalDeleteURL = externalBase + "/api/snapshots-delete/" + deleteKey
	}
	return snap
}

func k8sSnapshot(deleteKey, createdBy string, external bool) *dashv0.Snapshot {
	snap := &dashv0.Snapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      viewKey,
			Namespace: authlib.OrgNamespaceFormatter(1),
		},
		Spec: dashv0.SnapshotSpec{
			Dashboard: map[string]any{
				"uid": dashboardUID,
				"id":  dashboardID,
			},
			DeleteKey: &deleteKey,
		},
	}
	if external {
		ext := true
		snap.Spec.External = &ext
	}
	if createdBy != "" {
		meta, _ := utils.MetaAccessor(snap)
		meta.SetCreatedBy(createdBy)
	}
	return snap
}

func legacyStore(svc dashboardsnapshots.Service) *SnapshotLegacyStore {
	return &SnapshotLegacyStore{
		ResourceInfo: dashv0.SnapshotResourceInfo,
		Service:      svc,
		Namespacer:   authlib.OrgNamespaceFormatter,
	}
}

func deleteThroughWrapper(t *testing.T, inner rest.Storage, externalBase string, ctx context.Context) error {
	t.Helper()
	wrapper := NewStorageWrapper(inner, dashv0.SnapshotSharingOptions{ExternalSnapshotURL: externalBase})
	_, _, err := wrapper.(rest.GracefulDeleter).Delete(ctx, viewKey, nil, &metav1.DeleteOptions{})
	return err
}

func assertNoVictimSideEffect(t *testing.T, deleted []string, hits []string) {
	t.Helper()
	assert.NotContains(t, deleted, victimDeleteKey)
	for _, path := range hits {
		assert.NotContains(t, path, victimDeleteKey)
	}
}

func (h *externalHits) since(n int) []string {
	all := h.all()
	if n > len(all) {
		return nil
	}
	return all[n:]
}

func authorizeSnapshotDelete(t *testing.T, ctx context.Context, user identity.Requester) {
	t.Helper()
	setKubernetesSnapshotsToggle(t, true)

	attrs := authorizer.AttributesRecord{
		User:            user,
		ResourceRequest: true,
		APIGroup:        dashv0.GROUP,
		APIVersion:      dashv0.VERSION,
		Resource:        dashv0.SnapshotResourceInfo.GetName(),
		Verb:            "delete",
		Name:            viewKey,
		Namespace:       authlib.OrgNamespaceFormatter(user.GetOrgID()),
	}

	decision, _, err := grafanaauthorizer.NewNamespaceAuthorizer().Authorize(ctx, attrs)
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionNoOpinion, decision)

	decision, _, err = NewSnapshotAuthorizer(acmock.New()).Authorize(ctx, attrs)
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision)
}

func authorizeDeleteKey(t *testing.T, ctx context.Context, user identity.Requester) {
	t.Helper()
	setKubernetesSnapshotsToggle(t, true)

	attrs := authorizer.AttributesRecord{
		User:            user,
		ResourceRequest: true,
		APIGroup:        dashv0.GROUP,
		APIVersion:      dashv0.VERSION,
		Resource:        dashv0.SnapshotResourceInfo.GetName(),
		Verb:            "get",
		Subresource:     "deletekey",
		Name:            viewKey,
		Namespace:       authlib.OrgNamespaceFormatter(user.GetOrgID()),
	}
	decision, _, err := NewSnapshotAuthorizer(acmock.New()).Authorize(ctx, attrs)
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision)
}

func TestSnapshotDeleteRequiresOwnership(t *testing.T) {
	server, hits := newExternalServer(t)
	attacker := editorCaller(ownerUserID, nil)

	t.Run("editor with snapshots:delete cannot delete another user's snapshot", func(t *testing.T) {
		ctx := callerContext(attacker)
		authorizeSnapshotDelete(t, ctx, attacker)
		start := len(hits.all())

		svc := &scriptedSnapshotService{snaps: []dashboardsnapshots.DashboardSnapshot{
			modelSnapshot(victimDeleteKey, victimUserID, server.URL),
		}}
		err := deleteThroughWrapper(t, legacyStore(svc), server.URL, ctx)
		assertNoVictimSideEffect(t, svc.deleted, hits.since(start))
		require.Error(t, err)
		require.True(t, apierrors.IsNotFound(err), "got %v", err)
	})

	t.Run("legacy store delete cannot delete another user's snapshot", func(t *testing.T) {
		ctx := callerContext(attacker)
		start := len(hits.all())
		svc := &scriptedSnapshotService{snaps: []dashboardsnapshots.DashboardSnapshot{
			modelSnapshot(victimDeleteKey, victimUserID, server.URL),
		}}
		_, _, err := legacyStore(svc).Delete(ctx, viewKey, nil, &metav1.DeleteOptions{})
		assertNoVictimSideEffect(t, svc.deleted, hits.since(start))
		require.Error(t, err)
		require.True(t, apierrors.IsNotFound(err), "got %v", err)
	})

	t.Run("a later lookup must not delete a different snapshot", func(t *testing.T) {
		// The wrapper loads the snapshot, then the legacy store loads it again.
		// The second row is one this caller must not delete. Acting on that row
		// is a failure even when the first row would have been allowed.
		ctx := callerContext(attacker)
		start := len(hits.all())
		svc := &scriptedSnapshotService{snaps: []dashboardsnapshots.DashboardSnapshot{
			modelSnapshot(ownerDeleteKey, ownerUserID, ""),
			modelSnapshot(victimDeleteKey, victimUserID, server.URL),
		}}
		_ = deleteThroughWrapper(t, legacyStore(svc), server.URL, ctx)
		assertNoVictimSideEffect(t, svc.deleted, hits.since(start))
		if len(svc.deleted) > 0 {
			assert.Equal(t, []string{ownerDeleteKey}, svc.deleted)
		}
	})

	t.Run("storage wrapper enforces ownership when the inner store does not", func(t *testing.T) {
		ctx := callerContext(attacker)
		start := len(hits.all())
		inner := &recordingDeleter{gets: []*dashv0.Snapshot{
			k8sSnapshot(victimDeleteKey, authlib.NewTypeID(authlib.TypeUser, strconv.FormatInt(victimUserID, 10)), true),
			k8sSnapshot(ownerDeleteKey, attacker.GetUID(), true),
		}}
		err := deleteThroughWrapper(t, inner, server.URL, ctx)
		assert.Empty(t, inner.deleted)
		assertNoVictimSideEffect(t, nil, hits.since(start))
		require.Error(t, err)
		require.True(t, apierrors.IsNotFound(err), "got %v", err)
	})

	t.Run("wrapper does not external-delete a snapshot loaded after the authorized one", func(t *testing.T) {
		ctx := callerContext(attacker)
		start := len(hits.all())
		inner := &recordingDeleter{gets: []*dashv0.Snapshot{
			k8sSnapshot(ownerDeleteKey, attacker.GetUID(), false),
			k8sSnapshot(victimDeleteKey, authlib.NewTypeID(authlib.TypeUser, strconv.FormatInt(victimUserID, 10)), true),
		}}
		_ = deleteThroughWrapper(t, inner, server.URL, ctx)
		assertNoVictimSideEffect(t, nil, hits.since(start))
		for _, name := range inner.deleted {
			assert.Equal(t, viewKey, name)
		}
	})
}

func TestSnapshotDeleteAllowsOwnerWriterAndAdmin(t *testing.T) {
	server, hits := newExternalServer(t)

	cases := []struct {
		name string
		user *identity.StaticRequester
	}{
		{name: "owner", user: editorCaller(ownerUserID, nil)},
		{
			name: "dashboard uid write",
			user: editorCaller(4, map[string][]string{
				dashboards.ActionDashboardsWrite: {dashboards.ScopeDashboardsProvider.GetResourceScopeUID(dashboardUID)},
			}),
		},
		{
			name: "dashboard id write",
			user: editorCaller(5, map[string][]string{
				dashboards.ActionDashboardsWrite: {dashboards.ScopeDashboardsProvider.GetResourceScope(strconv.FormatInt(int64(dashboardID), 10))},
			}),
		},
		{
			name: "dashboard wildcard write",
			user: editorCaller(6, map[string][]string{
				dashboards.ActionDashboardsWrite: {dashboards.ScopeDashboardsAll},
			}),
		},
		{name: "org admin", user: adminCaller()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := callerContext(tc.user)
			before := len(hits.all())
			svc := &scriptedSnapshotService{snaps: []dashboardsnapshots.DashboardSnapshot{
				modelSnapshot(ownerDeleteKey, ownerUserID, server.URL),
			}}
			err := deleteThroughWrapper(t, legacyStore(svc), server.URL, ctx)
			require.NoError(t, err)
			assert.Equal(t, []string{ownerDeleteKey}, svc.deleted)
			assert.Greater(t, len(hits.all()), before)
		})
	}

	t.Run("unified object owned by caller uid", func(t *testing.T) {
		owner := editorCaller(ownerUserID, nil)
		ctx := callerContext(owner)
		inner := &recordingDeleter{gets: []*dashv0.Snapshot{
			k8sSnapshot(ownerDeleteKey, owner.GetUID(), false),
		}}
		err := deleteThroughWrapper(t, inner, server.URL, ctx)
		require.NoError(t, err)
		assert.Equal(t, []string{viewKey}, inner.deleted)
	})

	t.Run("unified object owned by caller internal id", func(t *testing.T) {
		owner := editorCaller(ownerUserID, nil)
		ctx := callerContext(owner)
		inner := &recordingDeleter{gets: []*dashv0.Snapshot{
			k8sSnapshot(ownerDeleteKey, owner.GetID(), false),
		}}
		err := deleteThroughWrapper(t, inner, server.URL, ctx)
		require.NoError(t, err)
		assert.Equal(t, []string{viewKey}, inner.deleted)
	})

	t.Run("write on a different dashboard is not enough", func(t *testing.T) {
		user := editorCaller(8, map[string][]string{
			dashboards.ActionDashboardsWrite: {dashboards.ScopeDashboardsProvider.GetResourceScopeUID("some-other-dash")},
		})
		ctx := callerContext(user)
		svc := &scriptedSnapshotService{snaps: []dashboardsnapshots.DashboardSnapshot{
			modelSnapshot(victimDeleteKey, victimUserID, server.URL),
		}}
		start := len(hits.all())
		err := deleteThroughWrapper(t, legacyStore(svc), server.URL, ctx)
		assertNoVictimSideEffect(t, svc.deleted, hits.since(start))
		require.Error(t, err)
		require.True(t, apierrors.IsNotFound(err), "got %v", err)
	})
}

func TestSnapshotDeleteKeyRequiresOwnership(t *testing.T) {
	attacker := editorCaller(ownerUserID, nil)

	connect := func(t *testing.T, getter rest.Getter, user identity.Requester) (*capturingResponder, error) {
		t.Helper()
		restStore, err := NewDeleteKeyREST(getter)
		require.NoError(t, err)
		responder := &capturingResponder{}
		handler, err := restStore.(rest.Connecter).Connect(callerContext(user), viewKey, nil, responder)
		if err != nil {
			return responder, err
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		body, readErr := io.ReadAll(recorder.Body)
		require.NoError(t, readErr)
		assert.NotContains(t, string(body), victimDeleteKey)
		return responder, responder.err
	}

	t.Run("editor with snapshots:delete cannot read another user's delete key", func(t *testing.T) {
		ctx := callerContext(attacker)
		authorizeDeleteKey(t, ctx, attacker)

		svc := &scriptedSnapshotService{snaps: []dashboardsnapshots.DashboardSnapshot{
			modelSnapshot(victimDeleteKey, victimUserID, ""),
			modelSnapshot(ownerDeleteKey, ownerUserID, ""),
		}}
		responder, err := connect(t, legacyStore(svc), attacker)
		require.Error(t, err)
		require.True(t, apierrors.IsNotFound(err), "got %v", err)
		if responder.obj != nil {
			got, ok := responder.obj.(*dashv0.DashboardSnapshotWithDeleteKey)
			require.True(t, ok)
			assert.NotEqual(t, victimDeleteKey, got.DeleteKey)
			assert.NotEqual(t, ownerDeleteKey, got.DeleteKey)
		}
	})

	t.Run("a later lookup must not supply the delete key", func(t *testing.T) {
		owner := editorCaller(ownerUserID, nil)
		svc := &scriptedSnapshotService{snaps: []dashboardsnapshots.DashboardSnapshot{
			modelSnapshot(ownerDeleteKey, ownerUserID, ""),
			modelSnapshot(victimDeleteKey, victimUserID, ""),
		}}
		responder, err := connect(t, legacyStore(svc), owner)
		require.NoError(t, err)
		got, ok := responder.obj.(*dashv0.DashboardSnapshotWithDeleteKey)
		require.True(t, ok)
		assert.Equal(t, ownerDeleteKey, got.DeleteKey)
	})

	t.Run("getter that returns a different object on the second read", func(t *testing.T) {
		owner := editorCaller(ownerUserID, nil)
		inner := &recordingDeleter{gets: []*dashv0.Snapshot{
			k8sSnapshot(ownerDeleteKey, owner.GetUID(), false),
			k8sSnapshot(victimDeleteKey, authlib.NewTypeID(authlib.TypeUser, strconv.FormatInt(victimUserID, 10)), false),
		}}
		responder, err := connect(t, inner, owner)
		require.NoError(t, err)
		got, ok := responder.obj.(*dashv0.DashboardSnapshotWithDeleteKey)
		require.True(t, ok)
		assert.Equal(t, ownerDeleteKey, got.DeleteKey)
	})
}

func TestSnapshotDeleteKeyAllowsOwnerWriterAndAdmin(t *testing.T) {
	cases := []struct {
		name string
		user *identity.StaticRequester
	}{
		{name: "owner", user: editorCaller(ownerUserID, nil)},
		{
			name: "dashboard uid write",
			user: editorCaller(4, map[string][]string{
				dashboards.ActionDashboardsWrite: {dashboards.ScopeDashboardsProvider.GetResourceScopeUID(dashboardUID)},
			}),
		},
		{
			name: "dashboard id write",
			user: editorCaller(5, map[string][]string{
				dashboards.ActionDashboardsWrite: {dashboards.ScopeDashboardsProvider.GetResourceScope(strconv.FormatInt(int64(dashboardID), 10))},
			}),
		},
		{name: "org admin", user: adminCaller()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &scriptedSnapshotService{snaps: []dashboardsnapshots.DashboardSnapshot{
				modelSnapshot(ownerDeleteKey, ownerUserID, ""),
			}}
			store, err := NewDeleteKeyREST(legacyStore(svc))
			require.NoError(t, err)
			responder := &capturingResponder{}
			handler, err := store.(rest.Connecter).Connect(callerContext(tc.user), viewKey, nil, responder)
			require.NoError(t, err)
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
			require.NoError(t, responder.err)
			got, ok := responder.obj.(*dashv0.DashboardSnapshotWithDeleteKey)
			require.True(t, ok)
			assert.Equal(t, ownerDeleteKey, got.DeleteKey)
		})
	}

	t.Run("unified object owned by caller uid", func(t *testing.T) {
		owner := editorCaller(ownerUserID, nil)
		inner := &recordingDeleter{gets: []*dashv0.Snapshot{
			k8sSnapshot(ownerDeleteKey, owner.GetUID(), false),
		}}
		store, err := NewDeleteKeyREST(inner)
		require.NoError(t, err)
		responder := &capturingResponder{}
		handler, err := store.(rest.Connecter).Connect(callerContext(owner), viewKey, nil, responder)
		require.NoError(t, err)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		require.NoError(t, responder.err)
		got, ok := responder.obj.(*dashv0.DashboardSnapshotWithDeleteKey)
		require.True(t, ok)
		assert.Equal(t, ownerDeleteKey, got.DeleteKey)
	})
}
