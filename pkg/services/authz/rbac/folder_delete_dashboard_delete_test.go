package rbac

import (
	"context"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/types"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/ossaccesscontrol"
	"github.com/grafana/grafana/pkg/services/authz/rbac/store"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/folder"
)

// These checks are the ones AuthorizeDeleteByPath sends. A directory delete asks
// only for delete on the folder. A file delete asks for delete on the dashboard
// in that folder, with the folder id in the parent and no object name.
func TestFolderGrantAlsoAuthorizesDashboardDelete(t *testing.T) {
	const (
		namespace   = "org-12"
		userUID     = "editor"
		folderUID   = "secret"
		parentUID   = "parent"
		folderScope = "folders:uid:" + folderUID
	)

	callingService := authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{
		Claims: jwt.Claims{
			Subject:  types.NewTypeID(types.TypeAccessPolicy, "some-service"),
			Audience: []string{"authzservice"},
		},
		Rest: authn.AccessTokenClaims{Namespace: namespace},
	})

	folderDelete := &authzv1.CheckRequest{
		Namespace: namespace,
		Subject:   "user:" + userUID,
		Group:     "folder.grafana.app",
		Resource:  "folders",
		Verb:      utils.VerbDelete,
		Name:      folderUID,
		Folder:    parentUID,
	}
	dashboardDelete := &authzv1.CheckRequest{
		Namespace: namespace,
		Subject:   "user:" + userUID,
		Group:     "dashboard.grafana.app",
		Resource:  "dashboards",
		Verb:      utils.VerbDelete,
		Folder:    folderUID,
	}

	parent := parentUID
	folders := []store.Folder{{UID: parentUID}, {UID: folderUID, ParentUID: &parent}}

	// Permissions the folder permission API stores. onlyStoreActionSets (on by
	// default) stores the action set. The expanded Edit bundle is what the same
	// API stores when that flag is off, and what the legacy migration wrote.
	editBundle := append([]accesscontrol.Permission{}, permissionsForActions(
		append(append([]string{}, ossaccesscontrol.DashboardEditActions...), ossaccesscontrol.FolderEditActions...),
		folderScope,
	)...)

	cases := []struct {
		name        string
		permissions []accesscontrol.Permission
		folderOK    bool
		dashboardOK bool
	}{
		{
			name:        "folders:edit action set",
			permissions: []accesscontrol.Permission{{Action: "folders:edit", Scope: folderScope}},
			folderOK:    true,
			dashboardOK: true,
		},
		{
			name:        "folders:admin action set",
			permissions: []accesscontrol.Permission{{Action: "folders:admin", Scope: folderScope}},
			folderOK:    true,
			dashboardOK: true,
		},
		{
			name:        "expanded folder edit actions",
			permissions: editBundle,
			folderOK:    true,
			dashboardOK: true,
		},
		{
			name:        "folders:view action set",
			permissions: []accesscontrol.Permission{{Action: "folders:view", Scope: folderScope}},
			folderOK:    false,
			dashboardOK: false,
		},
		{
			name:        "folders:delete without dashboards:delete",
			permissions: []accesscontrol.Permission{{Action: folder.ActionFoldersDelete, Scope: folderScope}},
			folderOK:    true,
			dashboardOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewTestService(userUID, tc.permissions, folders)
			ctx := types.WithAuthInfo(context.Background(), callingService)

			folderResp, err := svc.Check(ctx, folderDelete)
			require.NoError(t, err)
			require.Equal(t, tc.folderOK, folderResp.GetAllowed(), "folder delete")

			dashResp, err := svc.Check(ctx, dashboardDelete)
			require.NoError(t, err)
			require.Equal(t, tc.dashboardOK, dashResp.GetAllowed(), "dashboard delete")
		})
	}

	// The lone folders:delete row is the only case above where the two answers differ.
	// Folder Edit, the grant the permission API stores, includes dashboards:delete.
	// Seeding the editor wildcard role is off unless resources_with_seeded_wildcard_access
	// lists folder; when it is on, that role grants both actions.
	require.Contains(t, ossaccesscontrol.DashboardEditActions, dashboards.ActionDashboardsDelete)
	require.NotContains(t, ossaccesscontrol.FolderEditActions, dashboards.ActionDashboardsDelete)
	require.Empty(t, ossaccesscontrol.FolderFixedRoleRegistrations(false))
	var editorActions []string
	for _, reg := range ossaccesscontrol.FolderFixedRoleRegistrations(true) {
		if reg.Role.Name != "fixed:folders:editor" {
			continue
		}
		require.Equal(t, []string{"Editor"}, reg.Grants)
		for _, perm := range reg.Role.Permissions {
			editorActions = append(editorActions, perm.Action)
		}
	}
	require.Contains(t, editorActions, folder.ActionFoldersDelete)
	require.Contains(t, editorActions, dashboards.ActionDashboardsDelete)
}

func permissionsForActions(actions []string, scope string) []accesscontrol.Permission {
	out := make([]accesscontrol.Permission, 0, len(actions))
	for _, action := range actions {
		out = append(out, accesscontrol.Permission{Action: action, Scope: scope})
	}
	return out
}
