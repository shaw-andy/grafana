package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/org"
)

func TestOSSViewerGrantedDatasourcesQuery(t *testing.T) {
	t.Run("oss grants viewer query on every datasource", func(t *testing.T) {
		reader := datasourcesReaderRegistration(t, false)
		require.Equal(t, []string{string(org.RoleViewer)}, reader.Grants)
		require.Contains(t, reader.Role.Permissions, ac.Permission{
			Action: datasources.ActionQuery,
			Scope:  datasources.ScopeAll,
		})

		granted := map[string][]string{}
		for _, permission := range reader.Role.Permissions {
			granted[permission.Action] = append(granted[permission.Action], permission.Scope)
		}
		// The datasource resource route authorizes this evaluator with no scope.
		require.True(t, ac.EvalPermission(datasources.ActionQuery).Evaluate(granted))
	})

	t.Run("enforced datasource permissions do not grant viewer query on every datasource", func(t *testing.T) {
		reader := datasourcesReaderRegistration(t, true)
		require.Equal(t, []string{string(org.RoleAdmin)}, reader.Grants)
		require.NotContains(t, reader.Grants, string(org.RoleViewer))
	})
}

func datasourcesReaderRegistration(t *testing.T, dsPermissionsEnforced bool) ac.RoleRegistration {
	t.Helper()
	for _, registration := range FixedRoleRegistrations(false, dsPermissionsEnforced) {
		if registration.Role.Name == datasourcesReaderRoleName {
			return registration
		}
	}
	t.Fatal("datasources reader role was not registered")
	return ac.RoleRegistration{}
}
