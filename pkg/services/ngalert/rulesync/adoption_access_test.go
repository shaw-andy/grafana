package rulesync

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	claims "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/ossaccesscontrol"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/dashboards/dashboardaccess"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/folder/foldertest"
	"github.com/grafana/grafana/pkg/services/ngalert/store"
	"github.com/grafana/grafana/pkg/util"
)

const (
	adoptionOrgID     int64 = 1
	adoptionEditorID  int64 = 42
	adoptionOtherID   int64 = 43
	adoptionDSUID           = "mimir"
	adoptionAttackUID       = "0sync"
)

// TestExternalRulerSync_EditorCannotAdoptSyncRootByTitle is the spec for the
// title-based root folder adoption bug. It fails while an Editor can plant a
// root folder whose title is the sync root and whose UID sorts first, and the
// worker then stores imported rules in that folder without removing the
// Editor's ability to delete it or change its permissions.
func TestExternalRulerSync_EditorCannotAdoptSyncRootByTitle(t *testing.T) {
	t.Run("folder created before the first sync", func(t *testing.T) {
		w, s, rs := newAdoptionHarness(t, false)
		creator := w.editor(adoptionEditorID)
		other := w.editor(adoptionOtherID)

		requireEditorCanReadDatasourceUID(t, creator)
		require.NoError(t, w.createRoot(creator, adoptionAttackUID, rootFolderTitle(adoptionDSUID)))
		requireServiceIdentitySeesRoot(t, w, adoptionAttackUID)

		s.SyncOrg(context.Background(), adoptionOrgID)

		assertSyncedRulesStayOutOfEditorControl(t, w, s, rs, creator, other)
	})

	t.Run("folder created after a worker-owned sync, adopted on the next upstream change", func(t *testing.T) {
		w, s, rs := newAdoptionHarness(t, false)
		creator := w.editor(adoptionEditorID)
		other := w.editor(adoptionOtherID)
		requireEditorCanReadDatasourceUID(t, creator)

		s.SyncOrg(context.Background(), adoptionOrgID)
		assertSyncedRulesStayOutOfEditorControl(t, w, s, rs, creator, other)
		workerUID := syncedRootUID(t, w, rs)
		require.Less(t, adoptionAttackUID, workerUID, "attacker UID must sort before the worker folder so GetNamespaceByTitle prefers it")

		require.NoError(t, w.createRoot(creator, adoptionAttackUID, rootFolderTitle(adoptionDSUID)))
		requireServiceIdentitySeesRoot(t, w, adoptionAttackUID)
		s.fetcher.(*fakeFetcher).hash++

		s.SyncOrg(context.Background(), adoptionOrgID)

		assertSyncedRulesStayOutOfEditorControl(t, w, s, rs, creator, other)
	})

	t.Run("per-org config resource uses the same folder adoption path", func(t *testing.T) {
		w, s, rs := newAdoptionHarness(t, true)
		creator := w.editor(adoptionEditorID)
		other := w.editor(adoptionOtherID)
		requireEditorCanReadDatasourceUID(t, creator)
		require.NoError(t, w.createRoot(creator, adoptionAttackUID, rootFolderTitle(adoptionDSUID)))
		requireServiceIdentitySeesRoot(t, w, adoptionAttackUID)

		s.SyncOrg(context.Background(), adoptionOrgID)

		assertSyncedRulesStayOutOfEditorControl(t, w, s, rs, creator, other)
	})
}

func newAdoptionHarness(t *testing.T, fromConfig bool) (*folderWorld, *ExternalRulerSyncer, *fakeRuleService) {
	t.Helper()
	w := newFolderWorld()
	rs := &fakeRuleService{}
	fetch := &fakeFetcher{cfg: upstreamGroup("ns1", "HighCPU"), hash: 1}
	var s *ExternalRulerSyncer
	if fromConfig {
		cs := newFakeConfigClient()
		cs.setSpec(adoptionOrgID, adoptionDSUID)
		s = newTestSyncerWithConfigClient(t, cs, fetch, rs)
	} else {
		s = newTestSyncer(t, fetch, rs)
		s.settings.ExternalRulerUID = adoptionDSUID
	}
	s.datasources = fakeDatasourceGetter{ds: &datasources.DataSource{Type: datasources.DS_PROMETHEUS, URL: "http://mimir.example/prometheus"}}
	s.namespaceStore = store.DBstore{FolderService: w}
	s.folderPermissions = &worldFolderPermissions{world: w}
	return w, s, rs
}

func requireEditorCanReadDatasourceUID(t *testing.T, editor identity.Requester) {
	t.Helper()
	// OSS grants fixed:datasources:reader to Viewer, and Editor includes Viewer.
	// GET /api/datasources authorizes datasources:read, then the OSS guardian
	// returns every datasource, including its UID.
	base := editor.GetPermissions()
	require.True(t, accesscontrol.EvalPermission(datasources.ActionRead).Evaluate(base),
		"default Editor must be allowed to call the datasource list endpoint")
	require.True(t, accesscontrol.EvalPermission(datasources.ActionRead, datasources.ScopeProvider.GetResourceScopeUID(adoptionDSUID)).Evaluate(base),
		"default Editor must be allowed to read the synced datasource UID")
}

func requireServiceIdentitySeesRoot(t *testing.T, w *folderWorld, uid string) {
	t.Helper()
	_, svc := identity.WithServiceIdentity(context.Background(), adoptionOrgID)
	kids, err := w.GetChildren(context.Background(), &folder.GetChildrenQuery{
		UID:          "",
		OrgID:        adoptionOrgID,
		SignedInUser: svc,
	})
	require.NoError(t, err)
	for _, k := range kids {
		if k.UID == uid {
			return
		}
	}
	t.Fatalf("service identity did not see root folder %s; the adoption lookup would not run", uid)
}

func assertSyncedRulesStayOutOfEditorControl(t *testing.T, w *folderWorld, s *ExternalRulerSyncer, rs *fakeRuleService, creator, other identity.Requester) {
	t.Helper()
	require.NotEmpty(t, rs.replaced, "sync must still import the ruler rules")
	ctx := context.Background()
	for _, g := range rs.replaced {
		require.NotEmpty(t, g.FolderUID)
		root := w.rootOf(g.FolderUID)
		require.NotEmpty(t, root)
		require.Falsef(t, w.can(creator, folder.ActionFoldersDelete, g.FolderUID),
			"creator can folders:delete a folder holding synced rules (%s, root %s)", g.FolderUID, root)
		require.Falsef(t, w.can(creator, folder.ActionFoldersPermissionsWrite, g.FolderUID),
			"creator can change permissions on a folder holding synced rules (%s, root %s)", g.FolderUID, root)
		require.Falsef(t, w.can(other, folder.ActionFoldersDelete, g.FolderUID),
			"another Editor can folders:delete a folder holding synced rules (%s, root %s)", g.FolderUID, root)
		managed, err := s.IsManagedFolder(ctx, adoptionOrgID, root)
		require.NoError(t, err)
		require.Truef(t, managed, "IsManagedFolder must follow the folder the rules were written to (%s), not a same-title folder", root)
		if root != adoptionAttackUID {
			attackManaged, err := s.IsManagedFolder(ctx, adoptionOrgID, adoptionAttackUID)
			require.NoError(t, err)
			require.False(t, attackManaged, "IsManagedFolder must not treat the Editor's folder as the sync root")
		}
	}
}

func syncedRootUID(t *testing.T, w *folderWorld, rs *fakeRuleService) string {
	t.Helper()
	require.NotEmpty(t, rs.replaced)
	return w.rootOf(rs.replaced[0].FolderUID)
}

// folderWorld is the folder service the namespace store calls during sync.
// Visibility of root folders follows Service.getRootFolders plus unified-store
// GetChildren: an empty FolderUIDs filter returns every root folder. Creating
// a root folder grants the creator Admin and the Editor/Viewer builtin roles
// Edit/View, which is what folderStorage.setDefaultFolderPermissions does.
// SetPermissions then replaces only the subjects it is given, which is what
// restrictFolderToAdmins does.
type folderWorld struct {
	*foldertest.FakeService
	byUID     map[string]*folder.Folder
	userGrant map[int64]map[string]string
	roleGrant map[string]map[string]string
	fixed     map[string][]string
}

func newFolderWorld() *folderWorld {
	generalRead := folder.ScopeFoldersProvider.GetResourceScopeUID(folder.GeneralFolderUID)
	return &folderWorld{
		FakeService: foldertest.NewFakeService(),
		byUID:       map[string]*folder.Folder{},
		userGrant:   map[int64]map[string]string{},
		roleGrant:   map[string]map[string]string{},
		// Fixed-role grants an Editor has before any folder ACL: folders:create
		// on the root (fixed:folders:creator), folders:read on the general folder
		// (fixed:folders.general:reader, inherited from Viewer), datasource read
		// (fixed:datasources:reader granted to Viewer when datasource permission
		// enforcement is off), and alert.rules:delete on every folder
		// (fixed:alerting.rules:writer).
		fixed: map[string][]string{
			folder.ActionFoldersCreate:             {generalRead},
			folder.ActionFoldersRead:               {generalRead},
			datasources.ActionRead:                 {datasources.ScopeAll},
			accesscontrol.ActionAlertingRuleRead:   {folder.ScopeFoldersAll},
			accesscontrol.ActionAlertingRuleCreate: {folder.ScopeFoldersAll},
			accesscontrol.ActionAlertingRuleUpdate: {folder.ScopeFoldersAll},
			accesscontrol.ActionAlertingRuleDelete: {folder.ScopeFoldersAll},
		},
	}
}

func (w *folderWorld) editor(id int64) identity.Requester {
	perms := make(map[string][]string, len(w.fixed))
	for action, scopes := range w.fixed {
		perms[action] = append([]string(nil), scopes...)
	}
	return &identity.StaticRequester{
		Type:        claims.TypeUser,
		UserID:      id,
		UserUID:     "editor",
		OrgID:       adoptionOrgID,
		OrgRole:     identity.RoleEditor,
		Login:       "editor",
		Permissions: map[int64]map[string][]string{adoptionOrgID: perms},
	}
}

func (w *folderWorld) createRoot(user identity.Requester, uid, title string) error {
	_, err := w.Create(context.Background(), &folder.CreateFolderCommand{
		UID:          uid,
		OrgID:        adoptionOrgID,
		Title:        title,
		ParentUID:    "",
		SignedInUser: user,
	})
	return err
}

func (w *folderWorld) Create(_ context.Context, cmd *folder.CreateFolderCommand) (*folder.Folder, error) {
	if cmd.SignedInUser == nil {
		return nil, folder.ErrBadRequest.Errorf("missing signed in user")
	}
	if !util.IsValidShortUID(cmd.UID) || util.IsShortUIDTooLong(cmd.UID) {
		return nil, folder.ErrInvalidUID
	}
	if cmd.UID == folder.GeneralFolderUID || cmd.UID == folder.SharedWithMeFolderUID {
		return nil, folder.ErrInvalidUID
	}
	title := strings.TrimSpace(cmd.Title)
	if title == "" {
		return nil, folder.ErrTitleEmpty
	}
	if strings.EqualFold(title, dashboards.RootFolderName) {
		return nil, folder.ErrNameExists.Errorf("a folder with that name already exists")
	}
	if _, exists := w.byUID[cmd.UID]; exists {
		return nil, folder.ErrNameExists.Errorf("a folder with that uid already exists")
	}
	parent := cmd.ParentUID
	if folder.IsRootFolderUID(parent) {
		parent = folder.GeneralFolderUID
	}
	if !accesscontrol.EvalPermission(folder.ActionFoldersCreate, folder.ScopeFoldersProvider.GetResourceScopeUID(parent)).Evaluate(cmd.SignedInUser.GetPermissions()) {
		return nil, folder.ErrAccessDenied
	}
	storedParent := cmd.ParentUID
	if folder.IsRootFolderUID(storedParent) {
		storedParent = ""
	}
	f := &folder.Folder{UID: cmd.UID, Title: title, OrgID: cmd.OrgID, ParentUID: storedParent}
	w.byUID[f.UID] = f
	w.grantDefaultOnCreate(cmd.SignedInUser, f.UID, cmd.ParentUID)
	return f, nil
}

func (w *folderWorld) grantDefaultOnCreate(user identity.Requester, uid, parentUID string) {
	// folderStorage.setDefaultFolderPermissions: nested folders get no grant of
	// their own; root folders grant the creator Admin when the identity is a
	// user or service account, and always grant Editor=Edit and Viewer=View.
	if !folder.IsRootFolderUID(parentUID) {
		return
	}
	if user.IsIdentityType(claims.TypeUser, claims.TypeServiceAccount) {
		if id, err := user.GetInternalID(); err == nil {
			w.setUser(id, uid, dashboardaccess.PERMISSION_ADMIN.String())
		}
	}
	w.setRole(string(identity.RoleEditor), uid, dashboardaccess.PERMISSION_EDIT.String())
	w.setRole(string(identity.RoleViewer), uid, dashboardaccess.PERMISSION_VIEW.String())
}

func (w *folderWorld) GetChildren(_ context.Context, q *folder.GetChildrenQuery) ([]*folder.FolderReference, error) {
	if q.SignedInUser == nil {
		return nil, folder.ErrBadRequest.Errorf("missing signed in user")
	}
	if q.UID == "" || q.UID == folder.GeneralFolderUID {
		return w.rootChildren(q), nil
	}
	action := folder.ActionFoldersRead
	if q.Permission == dashboardaccess.PERMISSION_EDIT {
		action = folder.ActionFoldersWrite
	}
	if !accesscontrol.EvalPermission(action, folder.ScopeFoldersProvider.GetResourceScopeUID(q.UID)).Evaluate(q.SignedInUser.GetPermissions()) {
		return nil, folder.ErrAccessDenied
	}
	return w.childrenOf(q.OrgID, q.UID), nil
}

func (w *folderWorld) rootChildren(q *folder.GetChildrenQuery) []*folder.FolderReference {
	// Same scope parsing as Service.getRootFolders. unifiedstore.GetChildren
	// adds a name filter only when FolderUIDs is non-empty, so an empty result
	// (including the service identity's "*" scope, which is neither folders:*
	// nor folders:uid:) returns every root folder.
	perms := q.SignedInUser.GetPermissions()
	var folderPermissions []string
	if q.Permission == dashboardaccess.PERMISSION_EDIT {
		folderPermissions = perms[folder.ActionFoldersWrite]
	} else {
		folderPermissions = perms[folder.ActionFoldersRead]
	}
	if len(folderPermissions) == 0 && !q.SignedInUser.GetIsGrafanaAdmin() {
		return nil
	}
	folderUIDs := make([]string, 0, len(folderPermissions))
	for _, p := range folderPermissions {
		if p == folder.ScopeFoldersAll {
			folderUIDs = nil
			break
		}
		if uid, found := strings.CutPrefix(p, folder.ScopeFoldersPrefix); found {
			if !slices.Contains(folderUIDs, uid) {
				folderUIDs = append(folderUIDs, uid)
			}
		}
	}
	kids := w.childrenOf(q.OrgID, "")
	if len(folderUIDs) == 0 {
		return kids
	}
	allowed := map[string]struct{}{}
	for _, uid := range folderUIDs {
		allowed[uid] = struct{}{}
	}
	out := make([]*folder.FolderReference, 0, len(kids))
	for _, k := range kids {
		if _, ok := allowed[k.UID]; ok {
			out = append(out, k)
		}
	}
	return out
}

func (w *folderWorld) childrenOf(orgID int64, parentUID string) []*folder.FolderReference {
	var out []*folder.FolderReference
	for _, f := range w.byUID {
		if f.OrgID == orgID && f.ParentUID == parentUID {
			out = append(out, f.ToFolderReference())
		}
	}
	return out
}

func (w *folderWorld) setUser(id int64, uid, level string) {
	if w.userGrant[id] == nil {
		w.userGrant[id] = map[string]string{}
	}
	if level == "" {
		delete(w.userGrant[id], uid)
		return
	}
	w.userGrant[id][uid] = level
}

func (w *folderWorld) setRole(role, uid, level string) {
	if w.roleGrant[role] == nil {
		w.roleGrant[role] = map[string]string{}
	}
	if level == "" {
		delete(w.roleGrant[role], uid)
		return
	}
	w.roleGrant[role][uid] = level
}

func (w *folderWorld) permissions(user identity.Requester) map[string][]string {
	out := map[string][]string{}
	for action, scopes := range w.fixed {
		out[action] = append([]string(nil), scopes...)
	}
	add := func(level, uid string) {
		scope := folder.ScopeFoldersProvider.GetResourceScopeUID(uid)
		for _, action := range actionsForFolderPermission(level) {
			if !slices.Contains(out[action], scope) {
				out[action] = append(out[action], scope)
			}
		}
	}
	if id, err := user.GetInternalID(); err == nil {
		for uid, level := range w.userGrant[id] {
			add(level, uid)
		}
	}
	for role, grants := range w.roleGrant {
		if !user.GetOrgRole().Includes(identity.RoleType(role)) {
			continue
		}
		for uid, level := range grants {
			add(level, uid)
		}
	}
	return out
}

func (w *folderWorld) can(user identity.Requester, action, folderUID string) bool {
	return accesscontrol.EvalPermission(action, w.scopesFor(folderUID)...).Evaluate(w.permissions(user))
}

func (w *folderWorld) scopesFor(uid string) []string {
	var scopes []string
	seen := map[string]bool{}
	for uid != "" && !seen[uid] {
		seen[uid] = true
		scopes = append(scopes, folder.ScopeFoldersProvider.GetResourceScopeUID(uid))
		f := w.byUID[uid]
		if f == nil || folder.IsRootFolderUID(f.ParentUID) {
			break
		}
		uid = f.ParentUID
	}
	return scopes
}

func (w *folderWorld) rootOf(uid string) string {
	seen := map[string]bool{}
	for uid != "" && !seen[uid] {
		seen[uid] = true
		f := w.byUID[uid]
		if f == nil || folder.IsRootFolderUID(f.ParentUID) {
			return uid
		}
		uid = f.ParentUID
	}
	return uid
}

func actionsForFolderPermission(level string) []string {
	switch level {
	case dashboardaccess.PERMISSION_VIEW.String():
		return slices.Concat(ossaccesscontrol.DashboardViewActions, ossaccesscontrol.NotebookViewActions, ossaccesscontrol.FolderViewActions)
	case dashboardaccess.PERMISSION_EDIT.String():
		return slices.Concat(ossaccesscontrol.DashboardEditActions, ossaccesscontrol.NotebookEditActions, ossaccesscontrol.FolderEditActions)
	case dashboardaccess.PERMISSION_ADMIN.String():
		return slices.Concat(ossaccesscontrol.DashboardAdminActions, ossaccesscontrol.NotebookAdminActions, ossaccesscontrol.FolderAdminActions)
	default:
		return nil
	}
}

type worldFolderPermissions struct {
	accesscontrol.FolderPermissionsService
	world *folderWorld
}

func (p *worldFolderPermissions) SetPermissions(_ context.Context, _ int64, resourceID string, cmds ...accesscontrol.SetResourcePermissionCommand) ([]accesscontrol.ResourcePermission, error) {
	for _, cmd := range cmds {
		switch {
		case cmd.UserID != 0:
			p.world.setUser(cmd.UserID, resourceID, cmd.Permission)
		case cmd.BuiltinRole != "":
			p.world.setRole(cmd.BuiltinRole, resourceID, cmd.Permission)
		}
	}
	return nil, nil
}
