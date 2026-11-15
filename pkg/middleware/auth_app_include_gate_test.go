package middleware

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log/logtest"
	"github.com/grafana/grafana/pkg/plugins"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/authn"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginaccesscontrol"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/web"
)

// permissionAccessControl evaluates with the real permission matcher against a
// permission map the test replaces between requests.
type permissionAccessControl struct {
	actest.FakeAccessControl
	permissions map[string][]string
}

func (p *permissionAccessControl) Evaluate(_ context.Context, _ identity.Requester, evaluator ac.Evaluator) (bool, error) {
	return evaluator.Evaluate(p.permissions), nil
}

// fixedRolePermissions is the permission set Grafana assigns to orgRole from the
// plugin fixed roles, including parent basic roles.
func fixedRolePermissions(orgRole org.RoleType) map[string][]string {
	perms := map[string][]string{}
	for _, reg := range pluginaccesscontrol.FixedRoleRegistrations(false) {
		if _, ok := ac.BuiltInRolesWithParents(reg.Grants)[string(orgRole)]; !ok {
			continue
		}
		for _, perm := range reg.Role.Permissions {
			perms[perm.Action] = append(perms[perm.Action], perm.Scope)
		}
	}
	return perms
}

func includeByPath(t *testing.T, data plugins.JSONData, path string) *plugins.Includes {
	t.Helper()
	for _, include := range data.Includes {
		if include.Path == path {
			return include
		}
	}
	t.Fatalf("plugin %s has no include %s", data.ID, path)
	return nil
}

func TestAppPluginIncludeRoleGatesEveryURL(t *testing.T) {
	// Loaded the same way an installed app is loaded. Admin includes keep a role
	// and no action. A Viewer include with no action is rewritten to plugins.app:access.
	extData, err := plugins.ReadPluginJSON(bytes.NewReader([]byte(`{
		"type": "app",
		"name": "Extensions shaped app",
		"id": "ext-app",
		"includes": [
			{
				"type": "page",
				"name": "Exposed components",
				"path": "/a/ext-app/exposed-components",
				"role": "Admin"
			}
		]
	}`)))
	require.NoError(t, err)
	exposed := includeByPath(t, extData, "/a/ext-app/exposed-components")
	require.Equal(t, org.RoleAdmin, exposed.Role)
	require.Empty(t, exposed.Action)

	mixedData, err := plugins.ReadPluginJSON(bytes.NewReader([]byte(`{
		"type": "app",
		"name": "Mixed app",
		"id": "test-app",
		"includes": [
			{"type": "page", "name": "Root", "path": "/a/test-app", "role": "Viewer"},
			{"type": "page", "name": "Editor", "path": "/a/test-app/editor-page", "role": "Editor"},
			{"type": "page", "name": "Admin", "path": "/a/test-app/admin-page", "role": "Admin"},
			{"type": "page", "name": "Secret", "path": "/a/test-app/secret", "role": "Viewer", "action": "test-app.secret:read"},
			{"type": "dashboard", "name": "Dash", "path": "/a/test-app/dash", "role": "Admin"}
		]
	}`)))
	require.NoError(t, err)
	root := includeByPath(t, mixedData, "/a/test-app")
	require.Equal(t, org.RoleViewer, root.Role)
	require.Equal(t, plugins.ActionAppAccess, root.Action)
	adminPage := includeByPath(t, mixedData, "/a/test-app/admin-page")
	require.Equal(t, org.RoleAdmin, adminPage.Role)
	require.Empty(t, adminPage.Action)
	secret := includeByPath(t, mixedData, "/a/test-app/secret")
	require.Equal(t, "test-app.secret:read", secret.Action)

	ps := pluginstore.NewFakePluginStore(
		pluginstore.Plugin{JSONData: extData},
		pluginstore.Plugin{JSONData: mixedData},
	)
	access := &permissionAccessControl{}

	const secretAction = "test-app.secret:read"
	viewer := fixedRolePermissions(org.RoleViewer)
	editor := fixedRolePermissions(org.RoleEditor)
	admin := fixedRolePermissions(org.RoleAdmin)
	viewerWithSecret := fixedRolePermissions(org.RoleViewer)
	viewerWithSecret[secretAction] = []string{}
	otherAppOnly := map[string][]string{
		pluginaccesscontrol.ActionAppAccess: {"plugins:id:other-app"},
	}

	tests := []struct {
		name         string
		role         org.RoleType
		perms        map[string][]string
		path         string
		wantCode     int
		wantReached  bool
		wantPluginID string
	}{
		{
			name:        "viewer is denied the exact admin include",
			role:        org.RoleViewer,
			perms:       viewer,
			path:        "/a/ext-app/exposed-components",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
		{
			name:        "viewer is denied an extra segment under the admin include",
			role:        org.RoleViewer,
			perms:       viewer,
			path:        "/a/ext-app/exposed-components/extra",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
		{
			name:        "viewer is denied the app root when no include covers it",
			role:        org.RoleViewer,
			perms:       viewer,
			path:        "/a/ext-app",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
		{
			name:        "viewer is denied an undeclared path under the app",
			role:        org.RoleViewer,
			perms:       viewer,
			path:        "/a/ext-app/other",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
		{
			name:        "viewer is denied a dot-segment path that lands under the admin include",
			role:        org.RoleViewer,
			perms:       viewer,
			path:        "/a/ext-app/other/../exposed-components/extra",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
		{
			name:        "viewer is denied a path whose raw prefix is allowed but whose cleaned path is under the admin include",
			role:        org.RoleViewer,
			perms:       viewer,
			path:        "/a/test-app/public/../admin-page/secret",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
		{
			name:        "viewer is denied the admin include with a trailing slash",
			role:        org.RoleViewer,
			perms:       viewer,
			path:        "/a/ext-app/exposed-components/",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
		{
			name:        "viewer is denied the admin include when a query is attached to a child path",
			role:        org.RoleViewer,
			perms:       viewer,
			path:        "/a/ext-app/exposed-components/extra?next=/a/ext-app",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
		{
			name:         "admin can open a child of the admin include",
			role:         org.RoleAdmin,
			perms:        admin,
			path:         "/a/ext-app/exposed-components/extra",
			wantCode:     http.StatusOK,
			wantReached:  true,
			wantPluginID: "ext-app",
		},
		{
			name:        "admin is denied an undeclared path under an app whose only include is the admin page",
			role:        org.RoleAdmin,
			perms:       admin,
			path:        "/a/ext-app/other",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
		{
			name:         "viewer can open a path under the viewer root include",
			role:         org.RoleViewer,
			perms:        viewer,
			path:         "/a/test-app/public",
			wantCode:     http.StatusOK,
			wantReached:  true,
			wantPluginID: "test-app",
		},
		{
			name:         "viewer can open the viewer root include itself",
			role:         org.RoleViewer,
			perms:        viewer,
			path:         "/a/test-app",
			wantCode:     http.StatusOK,
			wantReached:  true,
			wantPluginID: "test-app",
		},
		{
			name:        "viewer is denied a child of the admin include when a shorter viewer include also matches",
			role:        org.RoleViewer,
			perms:       viewer,
			path:        "/a/test-app/admin-page/secret",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
		{
			name:        "viewer is denied a child of the editor include",
			role:        org.RoleViewer,
			perms:       viewer,
			path:        "/a/test-app/editor-page/item",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
		{
			name:         "editor can open a child of the editor include",
			role:         org.RoleEditor,
			perms:        editor,
			path:         "/a/test-app/editor-page/item",
			wantCode:     http.StatusOK,
			wantReached:  true,
			wantPluginID: "test-app",
		},
		{
			name:        "editor is denied a child of the admin include",
			role:        org.RoleEditor,
			perms:       editor,
			path:        "/a/test-app/admin-page/item",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
		{
			name:         "admin can open a child of the admin include on the mixed app",
			role:         org.RoleAdmin,
			perms:        admin,
			path:         "/a/test-app/admin-page/secret",
			wantCode:     http.StatusOK,
			wantReached:  true,
			wantPluginID: "test-app",
		},
		{
			name:        "viewer is denied a child of an action include without that action",
			role:        org.RoleViewer,
			perms:       viewer,
			path:        "/a/test-app/secret/item",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
		{
			name:         "viewer with the page action can open a child of that include",
			role:         org.RoleViewer,
			perms:        viewerWithSecret,
			path:         "/a/test-app/secret/item",
			wantCode:     http.StatusOK,
			wantReached:  true,
			wantPluginID: "test-app",
		},
		{
			name:         "a lookalike segment is not treated as a child of the admin include",
			role:         org.RoleViewer,
			perms:        viewer,
			path:         "/a/test-app/admin-page-other",
			wantCode:     http.StatusOK,
			wantReached:  true,
			wantPluginID: "test-app",
		},
		{
			name:        "app access for a different plugin does not open this plugin",
			role:        org.RoleViewer,
			perms:       otherAppOnly,
			path:        "/a/test-app/public",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
		{
			name:        "a viewer without application access cannot open a path the page role would allow",
			role:        org.RoleViewer,
			perms:       map[string][]string{},
			path:        "/a/test-app/public",
			wantCode:    http.StatusFound,
			wantReached: false,
		},
	}

	middlewareScenario(t, "include role and action gate every url under the include", func(t *testing.T, sc *scenarioContext) {
		logger := &logtest.Fake{}
		var reached bool
		var servedPath string
		var servedPluginID string
		index := func(c *contextmodel.ReqContext) {
			reached = true
			servedPath = c.Req.URL.Path
			servedPluginID = web.Params(c.Req)[":id"]
			_, writeErr := c.Resp.Write([]byte(c.Req.URL.Path))
			require.NoError(t, writeErr)
		}
		appAccess := ac.Middleware(access)(ac.EvalPermission(
			pluginaccesscontrol.ActionAppAccess,
			pluginaccesscontrol.ScopeProvider.GetResourceScope(ac.Parameter(":id")),
		))
		pageGate := RoleAppPluginAuth(access, ps, logger)
		sc.m.Get("/a/:id/*", appAccess, ReqSignedIn, pageGate, index)
		sc.m.Get("/a/:id", appAccess, ReqSignedIn, pageGate, index)

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				reached = false
				servedPath = ""
				servedPluginID = ""
				access.permissions = tt.perms
				sc.withIdentity(&authn.Identity{
					ID:    "user-1",
					Type:  "user",
					OrgID: 0,
					OrgRoles: map[int64]org.RoleType{
						0: tt.role,
					},
				})
				sc.fakeReq(http.MethodGet, tt.path).exec()

				assert.Equal(t, tt.wantCode, sc.resp.Code, "body: %s", sc.resp.Body.String())
				assert.Equal(t, tt.wantReached, reached)
				if tt.wantReached {
					requestPath := sc.req.URL.Path
					assert.Equal(t, requestPath, servedPath)
					assert.Equal(t, requestPath, sc.resp.Body.String())
					assert.Equal(t, tt.wantPluginID, servedPluginID)
				} else {
					assert.Empty(t, servedPath)
					assert.Empty(t, servedPluginID)
					assert.Equal(t, "/", sc.resp.Header().Get("Location"))
				}
			})
		}
	})
}
