package resourcepermissions

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/setting"
)

// folderEditActions mirrors ProvideFolderPermissions PermissionsToActions["Edit"]:
// DashboardEditActions (which contains dashboards:delete) concatenated with
// FolderEditActions (which contains folders:delete).
func folderEditActions() []string {
	return []string{
		dashboards.ActionDashboardsRead,
		"annotations:read",
		dashboards.ActionDashboardsWrite,
		dashboards.ActionDashboardsDelete,
		"annotations:write",
		"annotations:delete",
		"annotations:create",
		folder.ActionFoldersRead,
		folder.ActionFoldersWrite,
		folder.ActionFoldersDelete,
		dashboards.ActionDashboardsCreate,
	}
}

func TestMapPermissionFolderLevels(t *testing.T) {
	edit := folderEditActions()

	t.Run("action set only", func(t *testing.T) {
		svc := &Service{
			features: featuremgmt.WithFeatures(featuremgmt.FlagOnlyStoreActionSets),
			options: Options{
				Resource:             folder.ScopeFoldersRoot,
				PermissionsToActions: map[string][]string{"Edit": edit, "View": {folder.ActionFoldersRead}},
			},
		}
		actions, err := svc.mapPermission("Edit")
		require.NoError(t, err)
		require.Equal(t, []string{"folders:edit"}, actions)
	})

	t.Run("expanded edit stores folder delete and dashboard delete together", func(t *testing.T) {
		svc := &Service{
			features: featuremgmt.WithFeatures(),
			options: Options{
				Resource:             folder.ScopeFoldersRoot,
				PermissionsToActions: map[string][]string{"Edit": edit},
			},
		}
		actions, err := svc.mapPermission("Edit")
		require.NoError(t, err)
		require.Contains(t, actions, "folders:edit")
		require.Contains(t, actions, folder.ActionFoldersDelete)
		require.Contains(t, actions, dashboards.ActionDashboardsDelete)
	})

	// The shipped feature manager turns onlyStoreActionSets on. mapPermission then
	// returns the lowercased action-set name and does not consult PermissionsToActions,
	// so the permission string "Delete" is stored as folders:delete and nothing else.
	// SetUserPermission persists exactly these actions.
	t.Run("default manager stores Delete as folders:delete only", func(t *testing.T) {
		fm, err := featuremgmt.ProvideManagerService(setting.NewCfg())
		require.NoError(t, err)
		require.True(t, fm.IsEnabledGlobally(featuremgmt.FlagOnlyStoreActionSets))

		svc := &Service{
			features: fm,
			options: Options{
				Resource:             folder.ScopeFoldersRoot,
				PermissionsToActions: map[string][]string{"Edit": edit, "View": {folder.ActionFoldersRead}, "Admin": edit},
			},
		}
		actions, err := svc.mapPermission("Delete")
		require.NoError(t, err)
		require.Equal(t, []string{folder.ActionFoldersDelete}, actions)
		require.NotContains(t, actions, dashboards.ActionDashboardsDelete)
	})
}
