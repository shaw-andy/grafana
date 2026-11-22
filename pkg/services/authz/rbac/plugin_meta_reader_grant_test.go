package rbac

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	pluginreg "github.com/grafana/grafana/pkg/registry/apps/plugins"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/org"
)

const routeSecretPluginName = "route-secret-external"

// TestViewerCanReadPluginMetadata checks the grant registered for Viewer against
// the authorizer mapping used for plugins.grafana.app metas GET and LIST.
func TestViewerCanReadPluginMetadata(t *testing.T) {
	svc := &Service{
		logger: log.New("rbac.test"),
		tracer: tracing.InitializeTracerForTest(),
		mapper: NewMapperRegistry(),
	}
	ctx := context.Background()
	viewerPerms := viewerPluginMetaPermissions()
	require.NotEmpty(t, viewerPerms)

	t.Run("registered viewer grant allows get and list of the installed plugin", func(t *testing.T) {
		allowed, err := authorizeMeta(ctx, svc, utils.VerbGet, routeSecretPluginName, viewerPerms)
		require.NoError(t, err)
		require.True(t, allowed)

		allowed, err = authorizeMeta(ctx, svc, utils.VerbList, "", viewerPerms)
		require.NoError(t, err)
		require.True(t, allowed)
	})

	t.Run("a grant for a different plugin does not allow this plugin", func(t *testing.T) {
		perms := []accesscontrol.Permission{{
			Action: pluginreg.ActionPluginsPluginsMetaRead,
			Scope:  "plugins.metas:uid:some-other-plugin",
		}}
		for i := range perms {
			perms[i].Kind, perms[i].Attribute, perms[i].Identifier = accesscontrol.SplitScope(perms[i].Scope)
		}
		allowed, err := authorizeMeta(ctx, svc, utils.VerbGet, routeSecretPluginName, perms)
		require.NoError(t, err)
		require.False(t, allowed)
	})

	t.Run("missing grant denies get and list", func(t *testing.T) {
		allowed, err := authorizeMeta(ctx, svc, utils.VerbGet, routeSecretPluginName, nil)
		require.NoError(t, err)
		require.False(t, allowed)

		allowed, err = authorizeMeta(ctx, svc, utils.VerbList, "", nil)
		require.NoError(t, err)
		require.False(t, allowed)
	})
}

func authorizeMeta(ctx context.Context, svc *Service, verb, name string, perms []accesscontrol.Permission) (bool, error) {
	action, _, err := svc.validateAction(ctx, "plugins.grafana.app", "metas", "", verb)
	if err != nil {
		return false, err
	}
	if action != pluginreg.ActionPluginsPluginsMetaRead {
		return false, fmt.Errorf("verb %s mapped to %s", verb, action)
	}
	mapping, ok := svc.mapper.Get("plugins.grafana.app", "metas", "")
	if !ok {
		return false, fmt.Errorf("plugins.grafana.app/metas is not in the authorizer mapping")
	}
	return svc.checkPermissionWithMapping(ctx, svc.getScopeMap(perms), &checkRequest{
		Namespace: types.NamespaceInfo{Value: "default", OrgID: 1},
		Group:     "plugins.grafana.app",
		Resource:  "metas",
		Verb:      verb,
		Name:      name,
		Action:    action,
	}, mapping, nil)
}

// viewerPluginMetaPermissions is the plugins.metas:read permission RegisterFixedRoles
// copies onto Viewer from FixedRoleRegistrations.
func viewerPluginMetaPermissions() []accesscontrol.Permission {
	var perms []accesscontrol.Permission
	for _, registration := range pluginreg.FixedRoleRegistrations() {
		recipients := accesscontrol.BuiltInRolesWithParents(registration.Grants)
		if _, ok := recipients[string(org.RoleViewer)]; !ok {
			continue
		}
		for _, perm := range registration.Role.Permissions {
			if perm.Action != pluginreg.ActionPluginsPluginsMetaRead {
				continue
			}
			perm.Kind, perm.Attribute, perm.Identifier = accesscontrol.SplitScope(perm.Scope)
			perms = append(perms, perm)
		}
	}
	return perms
}
