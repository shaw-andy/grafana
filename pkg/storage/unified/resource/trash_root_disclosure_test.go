package resource_test

import (
	"context"
	"testing"

	"github.com/fullstorydev/grpchan/inprocgrpc"
	grpcAuth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	authnlib "github.com/grafana/authlib/authn"
	authzlib "github.com/grafana/authlib/authz"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/ossaccesscontrol"
	grafanaauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/authz"
	"github.com/grafana/grafana/pkg/services/authz/rbac"
	"github.com/grafana/grafana/pkg/services/authz/rbac/store"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// These tests exercise the trash list the dashboard and folder APIs serve.
// They fail while an empty folder is authorized as "has this action on any
// scope", and pass once only a grant on the general folder or a wildcard does.

const (
	trashVictimMarker = "secret-root-query-marker"
	trashNestedMarker = "secret-nested-query-marker"
	trashOwnMarker    = "own-deletion-marker"
	trashEditorUID    = "editor"
	trashDeleterUID   = "deleter"
	trashNamespace    = "default"
)

func TestTrashList_ScopedDashboardAdminCannotReadOtherRootDeletions(t *testing.T) {
	// Creator Admin on one root dashboard, which is what creating a root dashboard grants,
	// plus the Editor role's edit actions. Not admin of the root.
	perms := append(editorRolePermissions(),
		dashboardAdminGrant(dashboards.ScopeDashboardsProvider.GetResourceScopeUID("editor-dash"))...)
	assertRootTrashHidden(t, "dashboard.grafana.app", "dashboards", perms)
}

func TestTrashList_DashboardAdminActionSetCannotReadOtherRootDeletions(t *testing.T) {
	// onlyStoreActionSets persists the action set instead of the granular actions.
	scope := dashboards.ScopeDashboardsProvider.GetResourceScopeUID("editor-dash")
	perms := append(editorRolePermissions(), grant("dashboards:admin", scope))
	assertRootTrashHidden(t, "dashboard.grafana.app", "dashboards", perms)
}

func TestTrashList_ScopedFolderAdminCannotReadOtherRootDashboardDeletions(t *testing.T) {
	perms := append(editorRolePermissions(),
		folderAdminGrant(folder.ScopeFoldersProvider.GetResourceScopeUID("editor-folder"))...)
	assertRootTrashHidden(t, "dashboard.grafana.app", "dashboards", perms)
}

func TestTrashList_ScopedFolderAdminCannotReadOtherRootFolderDeletions(t *testing.T) {
	perms := append(editorRolePermissions(),
		folderAdminGrant(folder.ScopeFoldersProvider.GetResourceScopeUID("editor-folder"))...)
	assertRootTrashHidden(t, "folder.grafana.app", "folders", perms)
}

func TestTrashList_DeleterCanReadOwnRootDeletion(t *testing.T) {
	bodies := listTrash(t, trashEditorUID, nil, "dashboard.grafana.app", "dashboards", trashPage("dashboard.grafana.app", "Dashboard"))
	require.Contains(t, string(joinBodies(bodies)), trashOwnMarker)
	require.NotContains(t, string(joinBodies(bodies)), trashVictimMarker)
	require.NotContains(t, string(joinBodies(bodies)), trashNestedMarker)
}

func TestTrashList_EditorWithoutAdminGrantCannotReadRootTrash(t *testing.T) {
	bodies := listTrash(t, trashEditorUID, editorRolePermissions(), "dashboard.grafana.app", "dashboards", trashPage("dashboard.grafana.app", "Dashboard"))
	joined := string(joinBodies(bodies))
	require.NotContains(t, joined, trashVictimMarker)
	require.NotContains(t, joined, trashNestedMarker)
	require.Contains(t, joined, trashOwnMarker)
}

func TestTrashList_WildcardDashboardAdminCanReadRootTrash(t *testing.T) {
	var perms []accesscontrol.Permission
	for _, action := range ossaccesscontrol.DashboardAdminActions {
		perms = append(perms, grant(action, dashboards.ScopeDashboardsAll))
	}
	bodies := listTrash(t, trashEditorUID, perms, "dashboard.grafana.app", "dashboards", trashPage("dashboard.grafana.app", "Dashboard"))
	require.Contains(t, string(joinBodies(bodies)), trashVictimMarker)
}

func TestTrashList_GeneralFolderAdminCanReadRootTrash(t *testing.T) {
	scope := folder.ScopeFoldersProvider.GetResourceScopeUID(folder.GeneralFolderUID)
	perms := folderAdminGrant(scope)
	bodies := listTrash(t, trashEditorUID, perms, "dashboard.grafana.app", "dashboards", trashPage("dashboard.grafana.app", "Dashboard"))
	require.Contains(t, string(joinBodies(bodies)), trashVictimMarker)
}

func TestServiceAuthorizerAllowsSessionUserToListTrash(t *testing.T) {
	user := sessionUser(trashEditorUID)
	ctx := types.WithAuthInfo(context.Background(), user)
	authz := grafanaauthorizer.NewServiceAuthorizer()

	for _, resourceName := range []string{"dashboards", "folders"} {
		group := "dashboard.grafana.app"
		if resourceName == "folders" {
			group = "folder.grafana.app"
		}
		decision, _, err := authz.Authorize(ctx, authorizer.AttributesRecord{
			Verb:            utils.VerbList,
			APIGroup:        group,
			Resource:        resourceName,
			ResourceRequest: true,
			Namespace:       trashNamespace,
		})
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision, "session list of %s must reach storage", resourceName)
	}
}

func assertRootTrashHidden(t *testing.T, group, res string, perms []accesscontrol.Permission) {
	t.Helper()
	kind := "Dashboard"
	if res == "folders" {
		kind = "Folder"
	}
	bodies := listTrash(t, trashEditorUID, perms, group, res, trashPage(group, kind))
	joined := string(joinBodies(bodies))
	require.NotContains(t, joined, trashVictimMarker, "root object deleted by someone else")
	require.NotContains(t, joined, trashNestedMarker, "object in a folder the caller does not administer")
	require.Contains(t, joined, trashOwnMarker, "the caller still sees an object they deleted")
}

func listTrash(t *testing.T, userUID string, perms []accesscontrol.Permission, group, res string, objects []storedTrash) [][]byte {
	t.Helper()
	access, user := trashAccess(t, userUID, perms)
	srv, err := resource.NewUninitializedResourceServer(resource.ResourceServerOptions{
		Backend:      &trashListBackend{objects: objects},
		AccessClient: access,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = srv.Stop(context.Background())
	})

	ctx := types.WithAuthInfo(context.Background(), user)
	rsp, err := srv.List(ctx, &resourcepb.ListRequest{
		Source: resourcepb.ListRequest_TRASH,
		Limit:  50,
		Options: &resourcepb.ListOptions{
			Key: &resourcepb.ResourceKey{
				Namespace: trashNamespace,
				Group:     group,
				Resource:  res,
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, rsp.Error, "list error: %+v", rsp.Error)

	bodies := make([][]byte, 0, len(rsp.Items))
	for _, item := range rsp.Items {
		bodies = append(bodies, item.Value)
	}
	return bodies
}

func trashPage(group, kind string) []storedTrash {
	return []storedTrash{
		{
			name:   "restricted",
			folder: "",
			value:  deletedObject(group, kind, "restricted", "user:"+trashDeleterUID, trashVictimMarker),
		},
		{
			name:   "nested",
			folder: "other-parent",
			value:  deletedObject(group, kind, "nested", "user:"+trashDeleterUID, trashNestedMarker),
		},
		{
			name:   "own",
			folder: "",
			value:  deletedObject(group, kind, "own", "user:"+trashEditorUID, trashOwnMarker),
		},
	}
}

func deletedObject(group, kind, name, deletedBy, marker string) []byte {
	return []byte(`{"apiVersion":"` + group + `/v1","kind":"` + kind + `","metadata":{"name":"` + name + `","annotations":{"` + utils.AnnoKeyUpdatedBy + `":"` + deletedBy + `"}},"spec":{"title":"` + marker + `","targets":[{"expr":"` + marker + `"}]}}`)
}

func joinBodies(bodies [][]byte) []byte {
	var out []byte
	for _, body := range bodies {
		out = append(out, body...)
	}
	return out
}

func sessionUser(uid string) *identity.StaticRequester {
	// AccessClaimsHook copies these delegated permissions onto a session user,
	// which is what lets the service authorizer and the authz client proceed
	// to the user's own permissions.
	delegated := append([]string(nil), identity.ServiceIdentityClaims.Rest.DelegatedPermissions...)
	return &identity.StaticRequester{
		Type:      types.TypeUser,
		UserID:    7,
		UserUID:   uid,
		Namespace: trashNamespace,
		OrgID:     1,
		AccessTokenClaims: &authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{DelegatedPermissions: delegated},
		},
	}
}

func trashAccess(t *testing.T, userUID string, perms []accesscontrol.Permission) (types.AccessClient, types.AuthInfo) {
	t.Helper()
	general := folder.GeneralFolderUID
	parent := "other-parent"
	svc := rbac.NewTestService(userUID, perms, []store.Folder{
		{UID: folder.GeneralFolderUID},
		{UID: "editor-folder", ParentUID: &general},
		{UID: "other-parent", ParentUID: &general},
		{UID: "team-folder", ParentUID: &parent},
	})

	channel := &inprocgrpc.Channel{}
	authenticate := func(ctx context.Context) (context.Context, error) {
		// Same service identity the in-process authz server installs. The
		// caller's subject stays on the check request.
		return types.WithAuthInfo(ctx, authnlib.NewAccessTokenAuthInfo(authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{
				Namespace:   "*",
				Permissions: []string{"authz.grafana.app/userpermissions:get"},
			},
		})), nil
	}
	channel.WithServerUnaryInterceptor(grpcAuth.UnaryServerInterceptor(authenticate))
	authzv1.RegisterAuthzServiceServer(channel, svc)

	raw := authzlib.NewClient(channel, authzlib.WithCacheClientOption(&authz.NoopCache{}))
	limited := resource.NewAuthzLimitedClient(raw, resource.AuthzOptions{Registry: prometheus.NewRegistry()})
	return limited, sessionUser(userUID)
}

func editorRolePermissions() []accesscontrol.Permission {
	var perms []accesscontrol.Permission
	for _, action := range ossaccesscontrol.DashboardEditActions {
		perms = append(perms, grant(action, dashboards.ScopeDashboardsAll))
	}
	for _, action := range ossaccesscontrol.FolderEditActions {
		perms = append(perms, grant(action, folder.ScopeFoldersAll))
	}
	return perms
}

func dashboardAdminGrant(scope string) []accesscontrol.Permission {
	perms := []accesscontrol.Permission{grant("dashboards:admin", scope)}
	for _, action := range ossaccesscontrol.DashboardAdminActions {
		perms = append(perms, grant(action, scope))
	}
	return perms
}

func folderAdminGrant(scope string) []accesscontrol.Permission {
	actions := append([]string{"folders:admin"},
		ossaccesscontrol.DashboardAdminActions...)
	actions = append(actions, ossaccesscontrol.NotebookAdminActions...)
	actions = append(actions, ossaccesscontrol.FolderAdminActions...)
	perms := make([]accesscontrol.Permission, 0, len(actions))
	for _, action := range actions {
		perms = append(perms, grant(action, scope))
	}
	return perms
}

func grant(action, scope string) accesscontrol.Permission {
	kind, attribute, identifier := accesscontrol.SplitScope(scope)
	return accesscontrol.Permission{
		Action:     action,
		Scope:      scope,
		Kind:       kind,
		Attribute:  attribute,
		Identifier: identifier,
	}
}

type storedTrash struct {
	name   string
	folder string
	value  []byte
}

type trashListBackend struct {
	resource.UnimplementedStorageBackend
	objects []storedTrash
}

func (b *trashListBackend) ListHistory(_ context.Context, _ *resourcepb.ListRequest, callback func(resource.ListIterator) error) (int64, error) {
	return 2, callback(&trashListIter{objects: b.objects, pos: -1})
}

type trashListIter struct {
	objects []storedTrash
	pos     int
}

func (i *trashListIter) Next() bool {
	i.pos++
	return i.pos < len(i.objects)
}
func (i *trashListIter) Error() error           { return nil }
func (i *trashListIter) ContinueToken() string  { return "" }
func (i *trashListIter) ResourceVersion() int64 { return int64(i.pos + 1) }
func (i *trashListIter) Namespace() string      { return trashNamespace }
func (i *trashListIter) Name() string           { return i.objects[i.pos].name }
func (i *trashListIter) Folder() string         { return i.objects[i.pos].folder }
func (i *trashListIter) Value() []byte          { return i.objects[i.pos].value }
