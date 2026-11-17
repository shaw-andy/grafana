package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/seeding"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/tsdb/grafanads"
)

// TestViewerBuiltinDatasourceQueryAllowsDSQueryRoute checks the permission a
// signed-in Viewer has on a default install. POST /api/ds/query is authorized
// with EvalPermission(datasources:query) and no scope, so any scope for that
// action is enough. The built-in datasource reader role grants that action
// for the grafana datasource to Viewer whether or not datasource permissions
// are enforced.
func TestViewerBuiltinDatasourceQueryAllowsDSQueryRoute(t *testing.T) {
	wantScope := datasources.ScopePrefix + grafanads.DatasourceUID

	for _, enforced := range []bool{false, true} {
		t.Run(enforcedName(enforced), func(t *testing.T) {
			perms := viewerPermissions(t, enforced)

			require.Contains(t, perms[datasources.ActionQuery], wantScope)
			require.True(t, accesscontrol.EvalPermission(datasources.ActionQuery).Evaluate(perms))
			require.True(t, accesscontrol.EvalPermission(datasources.ActionQuery, wantScope).Evaluate(perms))
		})
	}
}

func enforcedName(enforced bool) string {
	if enforced {
		return "dspermissions-enforced"
	}
	return "dspermissions-not-enforced"
}

func viewerPermissions(t *testing.T, dsPermissionsEnforced bool) map[string][]string {
	t.Helper()
	regs := FixedRoleRegistrations(false, dsPermissionsEnforced)
	desired := map[accesscontrol.SeedPermission]struct{}{}
	logger := log.New("test")
	for i := range regs {
		seeding.AppendDesiredPermissions(desired, logger, &regs[i].Role, regs[i].Grants, regs[i].Exclude)
	}

	perms := map[string][]string{}
	for sp := range desired {
		if sp.BuiltInRole != string(org.RoleViewer) {
			continue
		}
		perms[sp.Action] = append(perms[sp.Action], sp.Scope)
	}
	return perms
}
