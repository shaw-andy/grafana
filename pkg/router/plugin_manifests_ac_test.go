package router

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/registry/apis/appplugin"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginaccesscontrol"
)

func requesterWithPermissions(permissions map[string][]string) *identity.StaticRequester {
	return &identity.StaticRequester{UserUID: "test-user", OrgID: 1, Permissions: map[int64]map[string][]string{1: permissions}}
}

func TestPluginManifestAccessControl(t *testing.T) {
	appAccess := accesscontrol.EvalPermission(pluginaccesscontrol.ActionAppAccess, "plugins:id:test-app")
	otherPermission := accesscontrol.EvalPermission("plugins:write", "plugins:id:test-app")
	testAppGrant := requesterWithPermissions(map[string][]string{
		pluginaccesscontrol.ActionAppAccess: {"plugins:id:test-app"},
		"plugins:write":                     {"plugins:id:test-app"},
	})
	for _, tc := range []struct {
		name      string
		user      identity.Requester
		evaluator accesscontrol.Evaluator
		allowed   bool
	}{
		{name: "granted app", user: testAppGrant, evaluator: appAccess, allowed: true},
		{name: "another app", user: testAppGrant, evaluator: accesscontrol.EvalPermission(pluginaccesscontrol.ActionAppAccess, "plugins:id:another-app")},
		{name: "unscoped app access", user: testAppGrant, evaluator: accesscontrol.EvalPermission(pluginaccesscontrol.ActionAppAccess)},
		{name: "unrelated action", user: testAppGrant, evaluator: otherPermission},
		{name: "empty action", user: testAppGrant, evaluator: accesscontrol.EvalPermission("")},
		{name: "all requires unrelated permission", user: testAppGrant, evaluator: accesscontrol.EvalAll(appAccess, otherPermission)},
		{name: "any accepts app access", user: testAppGrant, evaluator: accesscontrol.EvalAny(otherPermission, appAccess), allowed: true},
		{name: "wildcard grant", user: requesterWithPermissions(map[string][]string{
			pluginaccesscontrol.ActionAppAccess: {pluginaccesscontrol.ScopeProvider.GetResourceAllScope()},
		}), evaluator: appAccess, allowed: true},
		{name: "prefix grant", user: requesterWithPermissions(map[string][]string{
			pluginaccesscontrol.ActionAppAccess: {"plugins:id:test-*"},
		}), evaluator: appAccess, allowed: true},
		{name: "prefix grant for another app", user: requesterWithPermissions(map[string][]string{
			pluginaccesscontrol.ActionAppAccess: {"plugins:id:other-*"},
		}), evaluator: appAccess},
		{name: "wildcard before the end", user: requesterWithPermissions(map[string][]string{
			pluginaccesscontrol.ActionAppAccess: {"plugins:id:*-app", "plugins:id:te*t-app"},
		}), evaluator: appAccess},
		{name: "longer plugin id", user: requesterWithPermissions(map[string][]string{
			pluginaccesscontrol.ActionAppAccess: {"plugins:id:test-app-extra"},
		}), evaluator: appAccess},
		{name: "empty scope with unscoped check", user: requesterWithPermissions(map[string][]string{
			pluginaccesscontrol.ActionAppAccess: {""},
		}), evaluator: accesscontrol.EvalPermission(pluginaccesscontrol.ActionAppAccess)},
		{name: "grant in another org", user: &identity.StaticRequester{UserUID: "test-user", OrgID: 2, Permissions: map[int64]map[string][]string{
			1: {pluginaccesscontrol.ActionAppAccess: {"plugins:id:test-app"}},
		}}, evaluator: appAccess},
		{name: "no permissions", user: &identity.StaticRequester{UserUID: "test-user", OrgID: 1}, evaluator: appAccess},
		{name: "no requester", evaluator: appAccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, ac := range []accesscontrol.AccessControl{pluginManifestAccessControl{}, pluginManifestAccessControl{}.WithoutResolvers()} {
				allowed, err := ac.Evaluate(t.Context(), tc.user, tc.evaluator)
				require.NoError(t, err)
				require.Equal(t, tc.allowed, allowed)
			}
		})
	}
}

func TestPluginManifestAccessChecker(t *testing.T) {
	check := appplugin.NewPluginAccessChecker(pluginManifestAccessControl{})
	user := requesterWithPermissions(map[string][]string{
		pluginaccesscontrol.ActionAppAccess: {"plugins:id:test-app"},
	})

	decision, reason, err := check(t.Context(), user, "test-app")
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision)
	require.Empty(t, reason)

	decision, _, err = check(t.Context(), user, "other-app")
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionDeny, decision)

	decision, _, err = check(t.Context(), &identity.StaticRequester{UserUID: "test-user", OrgID: 1}, "test-app")
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionDeny, decision)
}
