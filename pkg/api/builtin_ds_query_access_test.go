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

// The built-in datasource reader role is registered for Viewer with query on
// the grafana datasource. Seeding copies that grant onto the Viewer basic role
// (and its parents). /api/ds/query then allows the request because its
// evaluator only requires the datasources:query action.
func TestViewerBuiltinDatasourceQuerySatisfiesDSQueryRoute(t *testing.T) {
	for _, enforced := range []bool{false, true} {
		regs := FixedRoleRegistrations(false, enforced)
		desired := map[accesscontrol.SeedPermission]struct{}{}
		for i := range regs {
			seeding.AppendDesiredPermissions(desired, log.New("test"), &regs[i].Role, regs[i].Grants, regs[i].Exclude)
		}

		perms := map[string][]string{}
		for sp := range desired {
			if sp.BuiltInRole != string(org.RoleViewer) {
				continue
			}
			perms[sp.Action] = append(perms[sp.Action], sp.Scope)
		}

		scope := datasources.ScopePrefix + grafanads.DatasourceUID
		require.Contains(t, perms[datasources.ActionQuery], scope)
		require.True(t, accesscontrol.EvalPermission(datasources.ActionQuery).Evaluate(perms))
	}
}
