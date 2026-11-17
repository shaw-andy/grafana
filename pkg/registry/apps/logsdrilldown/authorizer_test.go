package logsdrilldown_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
	k8suser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/request"

	claims "github.com/grafana/authlib/types"
	appsdkapiserver "github.com/grafana/grafana-app-sdk/k8s/apiserver"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	appregistry "github.com/grafana/grafana/pkg/registry/apps"
	"github.com/grafana/grafana/pkg/registry/apps/logsdrilldown"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/apiserver/appinstaller"
	grafanauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginaccesscontrol"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	// Plugin the delegated user is actually allowed to configure.
	scopedPluginID = "unrelated-plugin"
	// A different plugin id. The same grant must not satisfy its route check.
	otherPluginID = "another-plugin"
	objectName    = "org-defaults"
)

// Verbs the request parser can produce for these resources. "connect" is not
// covered: RequestInfoFactory does not emit it for the HTTP methods these
// routes use. logsdrilldowndefaultlabels list and get, and
// logsdrilldowndefaultcolumns get, are not part of this check.
func TestScopedPluginsWriteCannotChangeOrgLogsDrilldownDefaults(t *testing.T) {
	ga, installed := authorizerForEnabledApp(t)

	// One plugin id, the scope plugin routes enforce. Built the same way RBAC
	// sync groups stored permissions onto the signed-in user.
	singleScope := accesscontrol.GroupScopesByAction([]accesscontrol.Permission{{
		Action: pluginaccesscontrol.ActionWrite,
		Scope:  pluginaccesscontrol.ScopeProvider.GetResourceScope(scopedPluginID),
	}})
	require.Equal(t, []string{"plugins:id:" + scopedPluginID}, singleScope[pluginaccesscontrol.ActionWrite])
	require.True(t, pluginaccesscontrol.GetPluginRouteEvaluator(scopedPluginID, pluginaccesscontrol.ActionWrite).Evaluate(singleScope),
		"the grant authorizes the plugin it names")
	require.False(t, pluginaccesscontrol.GetPluginRouteEvaluator(otherPluginID, pluginaccesscontrol.ActionWrite).Evaluate(singleScope),
		"the same grant does not authorize a different plugin")

	// The fixed plugins writer role carries this scope. It matches every plugin
	// route and is still not a grant on the logs drilldown default objects.
	allPluginsScope := accesscontrol.GroupScopesByAction([]accesscontrol.Permission{{
		Action: pluginaccesscontrol.ActionWrite,
		Scope:  pluginaccesscontrol.ScopeProvider.GetResourceAllScope(),
	}})
	require.Equal(t, []string{pluginaccesscontrol.ScopeProvider.GetResourceAllScope()}, allPluginsScope[pluginaccesscontrol.ActionWrite])
	require.True(t, pluginaccesscontrol.GetPluginRouteEvaluator(scopedPluginID, pluginaccesscontrol.ActionWrite).Evaluate(allPluginsScope))
	require.True(t, pluginaccesscontrol.GetPluginRouteEvaluator(otherPluginID, pluginaccesscontrol.ActionWrite).Evaluate(allPluginsScope))

	editor := func(perms map[string][]string, orgID int64, namespace string) *identity.StaticRequester {
		return &identity.StaticRequester{
			Type:        claims.TypeUser,
			UserID:      42,
			UserUID:     "scoped-editor",
			Login:       "scoped-editor",
			OrgID:       orgID,
			OrgRole:     identity.RoleEditor,
			Namespace:   namespace,
			Permissions: map[int64]map[string][]string{orgID: perms},
		}
	}

	// Editor, not org admin: the org-role fallback allows these verbs, so a
	// fix that only stops returning Allow (and returns NoOpinion instead) still
	// fails. The subject is not a Grafana server admin, so the admin short-circuit
	// does not apply.
	subjects := []struct {
		name string
		user *identity.StaticRequester
	}{
		{name: "single plugin scope in default org", user: editor(singleScope, 1, "default")},
		{name: "single plugin scope in org-2", user: editor(singleScope, 2, "org-2")},
		{name: "all-plugins scope", user: editor(allPluginsScope, 1, "default")},
	}

	for _, subject := range subjects {
		t.Run(subject.name, func(t *testing.T) {
			for _, op := range deniedOperations() {
				t.Run(op.name, func(t *testing.T) {
					ctx, attr := authorizeRequest(t, subject.user, op.method, op.path(subject.user.GetNamespace()))
					require.Equal(t, op.resource, attr.GetResource())
					require.Equal(t, op.verb, attr.GetVerb(), "request parser verb")
					require.Equal(t, op.subresource, attr.GetSubresource())

					decision, reason, err := ga.Authorize(ctx, attr)
					require.NoError(t, err)
					require.Equal(t, authorizer.DecisionDeny, decision, "chain allowed %s (%s)", op.name, reason)

					// The authorizer registered for the app must deny itself. A
					// NoOpinion would let the org-role fallback allow an editor
					// for every verb that fallback permits.
					direct, directReason, err := installed.Authorize(ctx, attr)
					require.NoError(t, err)
					require.Equal(t, authorizer.DecisionDeny, direct, "installed authorizer allowed %s (%s)", op.name, directReason)
				})
			}
		})
	}
}

// Users who were not granted plugins:write stay denied, and an org admin who
// holds the fixed plugins writer role (plugins:*) keeps write access.
func TestLogsDrilldownDefaultsWriteBoundaries(t *testing.T) {
	ga, installed := authorizerForEnabledApp(t)
	create := deniedOperations()[0]

	t.Run("editor without plugins:write", func(t *testing.T) {
		user := &identity.StaticRequester{
			Type:      claims.TypeUser,
			UserID:    7,
			UserUID:   "plain-editor",
			Login:     "plain-editor",
			OrgID:     1,
			OrgRole:   identity.RoleEditor,
			Namespace: "default",
			Permissions: map[int64]map[string][]string{
				1: accesscontrol.GroupScopesByAction([]accesscontrol.Permission{{
					Action: "datasources:query",
					Scope:  "datasources:uid:logs",
				}}),
			},
		}
		ctx, attr := authorizeRequest(t, user, create.method, create.path("default"))
		decision, _, err := ga.Authorize(ctx, attr)
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionDeny, decision)
		direct, _, err := installed.Authorize(ctx, attr)
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionDeny, direct)
	})

	t.Run("org admin with fixed plugins writer scope", func(t *testing.T) {
		perms := accesscontrol.GroupScopesByAction([]accesscontrol.Permission{{
			Action: pluginaccesscontrol.ActionWrite,
			Scope:  pluginaccesscontrol.ScopeProvider.GetResourceAllScope(),
		}})
		user := &identity.StaticRequester{
			Type:        claims.TypeUser,
			UserID:      1,
			UserUID:     "org-admin",
			Login:       "org-admin",
			OrgID:       1,
			OrgRole:     identity.RoleAdmin,
			Namespace:   "default",
			Permissions: map[int64]map[string][]string{1: perms},
		}
		ctx, attr := authorizeRequest(t, user, create.method, create.path("default"))
		decision, reason, err := ga.Authorize(ctx, attr)
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision, "reason %s", reason)
	})
}

func TestLogsDrilldownAppRegisteredOnlyWhenFeatureEnabled(t *testing.T) {
	cfg := &setting.Cfg{}
	installer, err := logsdrilldown.RegisterAppInstaller(cfg, featuremgmt.WithFeatures())
	require.NoError(t, err)

	disabled := appregistry.ProvideAppInstallers(
		featuremgmt.WithFeatures(), cfg,
		nil, nil, nil, nil, nil, nil, nil, installer, nil, nil, nil, nil, nil, nil,
	)
	enabled := appregistry.ProvideAppInstallers(
		featuremgmt.WithFeatures(featuremgmt.FlagKubernetesLogsDrilldown), cfg,
		nil, nil, nil, nil, nil, nil, nil, installer, nil, nil, nil, nil, nil, nil,
	)

	require.NotContains(t, disabled, installer)
	require.Contains(t, enabled, installer)
}

type operation struct {
	name        string
	method      string
	verb        string
	resource    string
	subresource string
	path        func(namespace string) string
}

func deniedOperations() []operation {
	columns := "logsdrilldowndefaultcolumns"
	labels := "logsdrilldowndefaultlabels"
	ops := []operation{
		{name: "create columns", method: http.MethodPost, verb: "create", resource: columns},
		{name: "update columns", method: http.MethodPut, verb: "update", resource: columns, path: named(columns)},
		{name: "patch columns", method: http.MethodPatch, verb: "patch", resource: columns, path: named(columns)},
		{name: "delete columns", method: http.MethodDelete, verb: "delete", resource: columns, path: named(columns)},
		{name: "deletecollection columns", method: http.MethodDelete, verb: "deletecollection", resource: columns},
		{name: "list columns", method: http.MethodGet, verb: "list", resource: columns},
		{name: "watch columns", method: http.MethodGet, verb: "watch", resource: columns, path: watch(columns)},
		{name: "update columns status", method: http.MethodPut, verb: "update", resource: columns, subresource: "status", path: status(columns)},
		{name: "create labels", method: http.MethodPost, verb: "create", resource: labels},
		{name: "update labels", method: http.MethodPut, verb: "update", resource: labels, path: named(labels)},
		{name: "patch labels", method: http.MethodPatch, verb: "patch", resource: labels, path: named(labels)},
		{name: "delete labels", method: http.MethodDelete, verb: "delete", resource: labels, path: named(labels)},
		{name: "deletecollection labels", method: http.MethodDelete, verb: "deletecollection", resource: labels},
		{name: "watch labels", method: http.MethodGet, verb: "watch", resource: labels, path: watch(labels)},
		{name: "update labels status", method: http.MethodPut, verb: "update", resource: labels, subresource: "status", path: status(labels)},
	}
	for i := range ops {
		if ops[i].path == nil {
			resource := ops[i].resource
			ops[i].path = func(namespace string) string { return collection(namespace, resource) }
		}
	}
	return ops
}

func collection(namespace, resource string) string {
	return fmt.Sprintf("/apis/logsdrilldown.grafana.app/v1beta1/namespaces/%s/%s", namespace, resource)
}

func named(resource string) func(string) string {
	return func(namespace string) string {
		return collection(namespace, resource) + "/" + objectName
	}
}

func status(resource string) func(string) string {
	return func(namespace string) string {
		return collection(namespace, resource) + "/" + objectName + "/status"
	}
}

func watch(resource string) func(string) string {
	return func(namespace string) string {
		return collection(namespace, resource) + "?watch=true"
	}
}

func authorizerForEnabledApp(t *testing.T) (*grafanauthorizer.GrafanaAuthorizer, authorizer.Authorizer) {
	t.Helper()
	installer, err := logsdrilldown.RegisterAppInstaller(&setting.Cfg{}, featuremgmt.WithFeatures(featuremgmt.FlagKubernetesLogsDrilldown))
	require.NoError(t, err)
	installed := installer.GetAuthorizer()
	require.NotNil(t, installed)

	ga := grafanauthorizer.NewGrafanaBuiltInSTAuthorizer()
	appinstaller.RegisterAuthorizers(context.Background(), []appsdkapiserver.AppInstaller{installer}, ga)
	return ga, installed
}

func authorizeRequest(t *testing.T, user identity.Requester, method, path string) (context.Context, authorizer.Attributes) {
	t.Helper()
	req, err := http.NewRequest(method, path, nil)
	require.NoError(t, err)
	info, err := (&request.RequestInfoFactory{
		APIPrefixes:          sets.NewString("apis"),
		GrouplessAPIPrefixes: sets.NewString(),
	}).NewRequestInfo(req)
	require.NoError(t, err)

	ctx := identity.WithRequester(context.Background(), user)
	ctx = request.WithUser(ctx, &k8suser.DefaultInfo{Name: user.GetLogin(), UID: user.GetUID()})
	ctx = request.WithRequestInfo(ctx, info)

	attr, err := filters.GetAuthorizerAttributes(ctx)
	require.NoError(t, err)
	require.True(t, attr.IsResourceRequest())
	require.Equal(t, "logsdrilldown.grafana.app", attr.GetAPIGroup())
	require.Equal(t, "v1beta1", attr.GetAPIVersion())
	require.Equal(t, user.GetNamespace(), attr.GetNamespace())
	return ctx, attr
}
