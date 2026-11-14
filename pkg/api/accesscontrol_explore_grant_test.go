package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/org"
)

// TestDatasourcesExploreGrantMatchesOrgRole checks the fixed roles declareFixedRoles
// registers for an OSS instance (viewers_can_edit false, datasource permissions not enforced).
func TestDatasourcesExploreGrantMatchesOrgRole(t *testing.T) {
	editor := permissionsGrantedTo(t, org.RoleEditor)
	_, editorCanExplore := editor[accesscontrol.ActionDatasourcesExplore]
	require.True(t, editorCanExplore)

	viewer := permissionsGrantedTo(t, org.RoleViewer)
	_, viewerCanExplore := viewer[accesscontrol.ActionDatasourcesExplore]
	require.False(t, viewerCanExplore)
	_, viewerCanReadDatasources := viewer[datasources.ActionRead]
	require.True(t, viewerCanReadDatasources)
}

func permissionsGrantedTo(t *testing.T, role identity.RoleType) map[string][]string {
	t.Helper()
	var permissions []accesscontrol.Permission
	for _, registration := range FixedRoleRegistrations(false, false) {
		if _, granted := accesscontrol.BuiltInRolesWithParents(registration.Grants)[string(role)]; !granted {
			continue
		}
		permissions = append(permissions, registration.Role.Permissions...)
	}
	grouped := accesscontrol.GroupScopesByActionContext(context.Background(), permissions)
	require.NotEmpty(t, grouped)
	return grouped
}
