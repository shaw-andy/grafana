package logsdrilldown_test

import (
	"context"
	"net/http"
	"testing"

	appsdkapiserver "github.com/grafana/grafana-app-sdk/k8s/apiserver"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
	k8suser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/registry/apps"
	"github.com/grafana/grafana/pkg/registry/apps/logsdrilldown"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/apiserver/appinstaller"
	grafanauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	logsDrilldownCollection = "/apis/logsdrilldown.grafana.app/v1alpha1/namespaces/default/logsdrilldowns"
	callerUID               = "calleruid"
	victimUID               = "victimuid"
	callerObject            = "logs:" + callerUID
	victimObject            = "logs:" + victimUID
)

// TestLogsDrilldownRoleFallbackDoesNotAuthorizePerUserPreferences drives the
// authorizer Grafana actually installs: the logs drilldown authorizer, then
// the organization-role authorizer. A caller who lacks datasources:explore
// must be refused for every verb the role authorizer would otherwise allow.
// The object name in each request is the object the decision is about.
func TestLogsDrilldownRoleFallbackDoesNotAuthorizePerUserPreferences(t *testing.T) {
	authz := installedAuthorizer(t)

	// Viewers are granted dashboards:read and are not granted datasources:explore
	// unless viewers_can_edit is on. The permission map is therefore non-empty,
	// which is the case that skips the empty-permission deny.
	viewer := requester(org.RoleViewer, false)
	// An editor whose explorer role was removed still has other permissions.
	editor := requester(org.RoleEditor, false)

	cases := []struct {
		name     string
		user     identity.Requester
		method   string
		path     string
		wantVerb string
		wantName string
	}{
		{name: "viewer get other user", user: viewer, method: http.MethodGet, path: logsDrilldownCollection + "/" + victimObject, wantVerb: "get", wantName: victimObject},
		{name: "viewer get own object", user: viewer, method: http.MethodGet, path: logsDrilldownCollection + "/" + callerObject, wantVerb: "get", wantName: callerObject},
		{name: "viewer list", user: viewer, method: http.MethodGet, path: logsDrilldownCollection, wantVerb: "list", wantName: ""},
		{name: "viewer watch collection", user: viewer, method: http.MethodGet, path: logsDrilldownCollection + "?watch=true", wantVerb: "watch", wantName: ""},
		{name: "viewer watch other user", user: viewer, method: http.MethodGet, path: logsDrilldownCollection + "?watch=true&fieldSelector=metadata.name=" + victimObject, wantVerb: "watch", wantName: victimObject},
		{name: "editor get other user", user: editor, method: http.MethodGet, path: logsDrilldownCollection + "/" + victimObject, wantVerb: "get", wantName: victimObject},
		{name: "editor list", user: editor, method: http.MethodGet, path: logsDrilldownCollection, wantVerb: "list", wantName: ""},
		{name: "editor watch collection", user: editor, method: http.MethodGet, path: logsDrilldownCollection + "?watch=true", wantVerb: "watch", wantName: ""},
		{name: "editor create", user: editor, method: http.MethodPost, path: logsDrilldownCollection, wantVerb: "create", wantName: ""},
		{name: "editor update other user", user: editor, method: http.MethodPut, path: logsDrilldownCollection + "/" + victimObject, wantVerb: "update", wantName: victimObject},
		{name: "editor update own object", user: editor, method: http.MethodPut, path: logsDrilldownCollection + "/" + callerObject, wantVerb: "update", wantName: callerObject},
		{name: "editor patch other user", user: editor, method: http.MethodPatch, path: logsDrilldownCollection + "/" + victimObject, wantVerb: "patch", wantName: victimObject},
		{name: "editor patch own object", user: editor, method: http.MethodPatch, path: logsDrilldownCollection + "/" + callerObject, wantVerb: "patch", wantName: callerObject},
		{name: "editor delete other user", user: editor, method: http.MethodDelete, path: logsDrilldownCollection + "/" + victimObject, wantVerb: "delete", wantName: victimObject},
		{name: "editor delete own object", user: editor, method: http.MethodDelete, path: logsDrilldownCollection + "/" + callerObject, wantVerb: "delete", wantName: callerObject},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := attributesFor(t, tc.method, tc.path)
			require.Equal(t, tc.wantVerb, attrs.GetVerb())
			require.Equal(t, tc.wantName, attrs.GetName())
			require.Equal(t, "logsdrilldowns", attrs.GetResource())
			require.True(t, attrs.IsResourceRequest())

			decision, reason, err := authz.Authorize(identity.WithRequester(context.Background(), tc.user), attrs)
			require.NoError(t, err)
			require.Equal(t, authorizer.DecisionDeny, decision, "reason=%q", reason)
		})
	}
}

// TestLogsDrilldownExploreGrantStillChecksObjectOwner covers the branch that
// runs only after datasources:explore is present. get and list currently skip
// the name check, so a caller with that permission can read another user's
// object. update, patch, and delete already compare the name; those cases keep
// that comparison tied to the object in the request.
func TestLogsDrilldownExploreGrantStillChecksObjectOwner(t *testing.T) {
	authz := installedAuthorizer(t)
	editor := requester(org.RoleEditor, true)

	cases := []struct {
		name     string
		method   string
		path     string
		wantVerb string
		wantName string
		want     authorizer.Decision
	}{
		{name: "get other user", method: http.MethodGet, path: logsDrilldownCollection + "/" + victimObject, wantVerb: "get", wantName: victimObject, want: authorizer.DecisionDeny},
		{name: "get own object", method: http.MethodGet, path: logsDrilldownCollection + "/" + callerObject, wantVerb: "get", wantName: callerObject, want: authorizer.DecisionAllow},
		{name: "list", method: http.MethodGet, path: logsDrilldownCollection, wantVerb: "list", wantName: "", want: authorizer.DecisionDeny},
		{name: "watch other user", method: http.MethodGet, path: logsDrilldownCollection + "?watch=true&fieldSelector=metadata.name=" + victimObject, wantVerb: "watch", wantName: victimObject, want: authorizer.DecisionDeny},
		{name: "update other user", method: http.MethodPut, path: logsDrilldownCollection + "/" + victimObject, wantVerb: "update", wantName: victimObject, want: authorizer.DecisionDeny},
		{name: "update own object", method: http.MethodPut, path: logsDrilldownCollection + "/" + callerObject, wantVerb: "update", wantName: callerObject, want: authorizer.DecisionAllow},
		{name: "patch other user", method: http.MethodPatch, path: logsDrilldownCollection + "/" + victimObject, wantVerb: "patch", wantName: victimObject, want: authorizer.DecisionDeny},
		{name: "patch own object", method: http.MethodPatch, path: logsDrilldownCollection + "/" + callerObject, wantVerb: "patch", wantName: callerObject, want: authorizer.DecisionAllow},
		{name: "delete other user", method: http.MethodDelete, path: logsDrilldownCollection + "/" + victimObject, wantVerb: "delete", wantName: victimObject, want: authorizer.DecisionDeny},
		{name: "delete own object", method: http.MethodDelete, path: logsDrilldownCollection + "/" + callerObject, wantVerb: "delete", wantName: callerObject, want: authorizer.DecisionAllow},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := attributesFor(t, tc.method, tc.path)
			require.Equal(t, tc.wantVerb, attrs.GetVerb())
			require.Equal(t, tc.wantName, attrs.GetName())

			decision, reason, err := authz.Authorize(identity.WithRequester(context.Background(), editor), attrs)
			require.NoError(t, err)
			require.Equal(t, tc.want, decision, "reason=%q", reason)
		})
	}
}

// deletecollection is a collection delete. The role authorizer does not allow
// it, so it is not part of the fallback. This locks that refusal.
func TestLogsDrilldownDeleteCollectionStaysDenied(t *testing.T) {
	authz := installedAuthorizer(t)
	editor := requester(org.RoleEditor, false)
	attrs := attributesFor(t, http.MethodDelete, logsDrilldownCollection)
	require.Equal(t, "deletecollection", attrs.GetVerb())
	require.Empty(t, attrs.GetName())

	decision, _, err := authz.Authorize(identity.WithRequester(context.Background(), editor), attrs)
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionDeny, decision)
}

func TestLogsDrilldownAPIRegisteredOnlyWhenFeatureEnabled(t *testing.T) {
	installer := newInstaller(t)

	off := appregistry.ProvideAppInstallers(featuremgmt.WithFeatures(), &setting.Cfg{}, nil, nil, nil, nil, nil, nil, nil, installer, nil, nil, nil, nil, nil, nil)
	require.NotContains(t, off, installer)

	on := appregistry.ProvideAppInstallers(featuremgmt.WithFeatures(featuremgmt.FlagKubernetesLogsDrilldown), &setting.Cfg{}, nil, nil, nil, nil, nil, nil, nil, installer, nil, nil, nil, nil, nil, nil)
	require.Contains(t, on, installer)
}

func installedAuthorizer(t *testing.T) authorizer.Authorizer {
	t.Helper()
	installer := newInstaller(t)
	versions := installer.GroupVersions()
	require.NotEmpty(t, versions)

	authz := grafanauthorizer.NewGrafanaBuiltInSTAuthorizer()
	appinstaller.RegisterAuthorizers(context.Background(), []appsdkapiserver.AppInstaller{installer}, authz)

	seenV1Alpha1 := false
	for _, gv := range versions {
		if gv.Group == "logsdrilldown.grafana.app" && gv.Version == "v1alpha1" {
			seenV1Alpha1 = true
		}
	}
	require.True(t, seenV1Alpha1, "logs drilldown v1alpha1 was not registered: %+v", versions)
	return authz
}

func newInstaller(t *testing.T) *logsdrilldown.LogsDrilldownAppInstaller {
	t.Helper()
	installer, err := logsdrilldown.RegisterAppInstaller(&setting.Cfg{}, featuremgmt.WithFeatures())
	require.NoError(t, err)
	require.NotNil(t, installer.GetAuthorizer())
	return installer
}

// requester builds the permission map a signed-in user carries after RBAC sync.
// explore is datasources:explore. Every non-empty case also has dashboards:read,
// which fixed:dashboards:viewer grants to Viewer.
func requester(role identity.RoleType, explore bool) *user.SignedInUser {
	perms := map[string][]string{
		dashboards.ActionDashboardsRead: {"dashboards:*"},
	}
	if explore {
		perms[accesscontrol.ActionDatasourcesExplore] = nil
	}
	return &user.SignedInUser{
		UserID:    7,
		UserUID:   callerUID,
		OrgID:     1,
		OrgRole:   role,
		Namespace: "default",
		Login:     "caller",
		Permissions: map[int64]map[string][]string{
			1: perms,
		},
	}
}

func attributesFor(t *testing.T, method, path string) authorizer.Attributes {
	t.Helper()
	factory := &request.RequestInfoFactory{
		APIPrefixes:          sets.NewString("apis"),
		GrouplessAPIPrefixes: sets.NewString(),
	}
	req, err := http.NewRequest(method, path, nil)
	require.NoError(t, err)
	info, err := factory.NewRequestInfo(req)
	require.NoError(t, err)

	return authorizer.AttributesRecord{
		User:            &k8suser.DefaultInfo{Name: "caller", Groups: []string{}},
		Verb:            info.Verb,
		Namespace:       info.Namespace,
		APIGroup:        info.APIGroup,
		APIVersion:      info.APIVersion,
		Resource:        info.Resource,
		Subresource:     info.Subresource,
		Name:            info.Name,
		ResourceRequest: info.IsResourceRequest,
		Path:            path,
	}
}
