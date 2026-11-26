package search

import (
	"context"
	"iter"
	"testing"

	"github.com/fullstorydev/grpchan/inprocgrpc"
	grpcAuth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	authnlib "github.com/grafana/authlib/authn"
	authzlib "github.com/grafana/authlib/authz"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/ossaccesscontrol"
	"github.com/grafana/grafana/pkg/services/authz"
	"github.com/grafana/grafana/pkg/services/authz/rbac"
	"github.com/grafana/grafana/pkg/services/authz/rbac/store"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// Search trash uses TrashAuthorizer.Prepare, which batches the same unscoped
// folder check listFromTrash sends one object at a time. Both call sites in
// bleve (the query searcher and the post-rank scan) go through trashAuthorized.

func TestTrashSearch_ScopedFolderAdminCannotReadOtherRootDeletions(t *testing.T) {
	scope := folder.ScopeFoldersProvider.GetResourceScopeUID("editor-folder")
	perms := folderAdminPermissions(scope)
	names := authorizedTrashNames(t, perms, []docInfo{
		{name: "restricted", folder: "", deletedBy: "user:deleter"},
		{name: "nested", folder: "other-parent", deletedBy: "user:deleter"},
		{name: "own", folder: "", deletedBy: "user:editor"},
	})
	require.NotContains(t, names, "restricted")
	require.NotContains(t, names, "nested")
	require.Contains(t, names, "own")
}

func TestTrashSearch_GeneralFolderAdminCanReadRootDeletions(t *testing.T) {
	scope := folder.ScopeFoldersProvider.GetResourceScopeUID(folder.GeneralFolderUID)
	names := authorizedTrashNames(t, folderAdminPermissions(scope), []docInfo{
		{name: "restricted", folder: "", deletedBy: "user:deleter"},
	})
	require.Contains(t, names, "restricted")
}

func authorizedTrashNames(t *testing.T, perms []accesscontrol.Permission, docs []docInfo) []string {
	t.Helper()
	access, user := searchTrashAccess(t, perms)
	authorizer := resource.NewTrashAuthorizer(access, user, &resourcepb.ResourceKey{
		Namespace: "default",
		Group:     "dashboard.grafana.app",
		Resource:  "dashboards",
	}, func(err error) {
		t.Errorf("trash authz check failed: %v", err)
	})

	candidates := func(yield func(docInfo) bool) {
		for _, doc := range docs {
			if !yield(doc) {
				return
			}
		}
	}

	var names []string
	for info, err := range trashAuthorized(context.Background(), iter.Seq[docInfo](candidates), authorizer) {
		require.NoError(t, err)
		names = append(names, info.name)
	}
	return names
}

func searchTrashAccess(t *testing.T, perms []accesscontrol.Permission) (types.AccessClient, types.AuthInfo) {
	t.Helper()
	general := folder.GeneralFolderUID
	svc := rbac.NewTestService("editor", perms, []store.Folder{
		{UID: folder.GeneralFolderUID},
		{UID: "editor-folder", ParentUID: &general},
		{UID: "other-parent", ParentUID: &general},
	})

	channel := &inprocgrpc.Channel{}
	channel.WithServerUnaryInterceptor(grpcAuth.UnaryServerInterceptor(func(ctx context.Context) (context.Context, error) {
		return types.WithAuthInfo(ctx, authnlib.NewAccessTokenAuthInfo(authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{
				Namespace:   "*",
				Permissions: []string{"authz.grafana.app/userpermissions:get"},
			},
		})), nil
	}))
	authzv1.RegisterAuthzServiceServer(channel, svc)
	raw := authzlib.NewClient(channel, authzlib.WithCacheClientOption(&authz.NoopCache{}))
	limited := resource.NewAuthzLimitedClient(raw, resource.AuthzOptions{Registry: prometheus.NewRegistry()})

	delegated := append([]string(nil), identity.ServiceIdentityClaims.Rest.DelegatedPermissions...)
	user := &identity.StaticRequester{
		Type:      types.TypeUser,
		UserID:    7,
		UserUID:   "editor",
		Namespace: "default",
		OrgID:     1,
		AccessTokenClaims: &authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{DelegatedPermissions: delegated},
		},
	}
	return limited, user
}

func folderAdminPermissions(scope string) []accesscontrol.Permission {
	actions := append([]string{"folders:admin"}, ossaccesscontrol.DashboardAdminActions...)
	actions = append(actions, ossaccesscontrol.FolderAdminActions...)
	perms := make([]accesscontrol.Permission, 0, len(actions))
	for _, action := range actions {
		kind, attribute, identifier := accesscontrol.SplitScope(scope)
		perms = append(perms, accesscontrol.Permission{
			Action: action, Scope: scope, Kind: kind, Attribute: attribute, Identifier: identifier,
		})
	}
	return perms
}
