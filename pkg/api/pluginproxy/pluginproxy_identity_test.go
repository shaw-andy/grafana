package pluginproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web"
)

// TestPluginProxyDoesNotForwardCallerIdentityToRouteHost checks the app plugin
// reverse proxy that /api/plugin-proxy and the app-plugin connect proxy both
// use. A route with no identity opt-in must not receive the caller's identity.
// The route host is a local server standing in for the plugin route URL.
func TestPluginProxyDoesNotForwardCallerIdentityToRouteHost(t *testing.T) {
	const (
		email            = "caller@example.com"
		login            = "caller-login"
		name             = "Caller Name"
		authID           = "external-auth-id-placeholder"
		accessToken      = "access-token-placeholder"
		permissionAction = "secret-permission-sentinel"
		teamUID          = "team-uid-placeholder"
	)

	serverAdmin := &user.SignedInUser{
		UserID:          42,
		UserUID:         "user-uid-placeholder",
		OrgID:           1,
		OrgName:         "Example Org",
		OrgRole:         org.RoleAdmin,
		Login:           login,
		Name:            name,
		Email:           email,
		EmailVerified:   true,
		AuthID:          authID,
		AuthenticatedBy: "oauth",
		IsGrafanaAdmin:  true,
		TeamIDs:         []int64{11, 22},
		TeamUIDs:        []string{teamUID},
		Permissions:     map[int64]map[string][]string{1: {permissionAction: {"plugins:id:test-app"}}},
		AccessToken:     accessToken,
		FallbackType:    claims.TypeUser,
	}

	editor := &user.SignedInUser{
		UserID:          7,
		OrgID:           1,
		OrgRole:         org.RoleEditor,
		Login:           login,
		Name:            name,
		Email:           email,
		AuthID:          authID,
		AuthenticatedBy: "saml",
		IsGrafanaAdmin:  false,
		TeamIDs:         []int64{11, 22},
		TeamUIDs:        []string{teamUID},
		Permissions:     map[int64]map[string][]string{1: {"example.route:read": {}}},
		AccessToken:     accessToken,
		FallbackType:    claims.TypeUser,
	}

	// Concrete type the app-plugin apiserver stores for service and anonymous
	// callers. It has no json:"-" tags, so a marshal of the interface includes
	// the access token and the permission map.
	staticAdmin := &identity.StaticRequester{
		Type:           claims.TypeUser,
		UserID:         42,
		UserUID:        "user-uid-placeholder",
		OrgID:          1,
		OrgName:        "Example Org",
		OrgRole:        identity.RoleAdmin,
		Login:          login,
		Name:           name,
		Email:          email,
		AuthID:         authID,
		IsGrafanaAdmin: true,
		Permissions:    map[int64]map[string][]string{1: {permissionAction: {}}},
		AccessToken:    accessToken,
		Groups:         []string{teamUID},
	}

	tcs := []struct {
		name           string
		method         string
		proxyPath      string
		route          plugins.Route
		user           identity.Requester
		sendUserHeader bool
		jsonData       map[string]any
	}{
		{
			name:      "server admin on an unrestricted GET route",
			method:    http.MethodGet,
			proxyPath: "/resources/widgets",
			route: plugins.Route{
				Path: "resources/*",
				URL:  "{{.JsonData.upstream}}",
			},
			user:     serverAdmin,
			jsonData: map[string]any{},
		},
		{
			name:      "server admin on a role-gated POST route with send user header enabled",
			method:    http.MethodPost,
			proxyPath: "/settings",
			route: plugins.Route{
				Path:    "settings",
				Method:  http.MethodPost,
				ReqRole: org.RoleAdmin,
			},
			user:           serverAdmin,
			sendUserHeader: true,
		},
		{
			name:      "editor on an action-gated route",
			method:    http.MethodGet,
			proxyPath: "/projects",
			route: plugins.Route{
				Path:      "projects",
				Method:    http.MethodGet,
				ReqAction: "example.route:read",
			},
			user: editor,
		},
		{
			name:      "static requester on a method-unrestricted route",
			method:    http.MethodPut,
			proxyPath: "/resources/widgets",
			route: plugins.Route{
				Path: "resources/*",
			},
			user: staticAdmin,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var got http.Header
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Clone()
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(backend.Close)

			route := tc.route
			if route.URL == "" {
				route.URL = backend.URL
			}
			jsonData := tc.jsonData
			if strings.Contains(route.URL, ".JsonData.upstream") {
				jsonData = map[string]any{"upstream": backend.URL}
			}

			req := httptest.NewRequest(tc.method, tc.proxyPath, nil)
			responseWriter := web.NewResponseWriter(tc.method, httptest.NewRecorder())
			ps := &pluginsettings.DTO{
				PluginID: "test-app",
				JSONData: jsonData,
			}
			proxy, err := NewPluginProxy(
				ps,
				[]*plugins.Route{&route},
				req,
				responseWriter,
				tc.user,
				tc.proxyPath,
				false,
				tc.sendUserHeader,
				nil,
				tracing.InitializeTracerForTest(),
				&http.Transport{},
				acimpl.ProvideAccessControl(featuremgmt.WithFeatures()),
				featuremgmt.WithFeatures(),
			)
			require.NoError(t, err)

			proxy.HandleRequest()

			require.NotNil(t, got, "plugin route host was not called, status %d", responseWriter.Status())

			forwarded := got.Get("X-Grafana-Context")
			require.Empty(t, forwarded, "X-Grafana-Context = %s", forwarded)

			flat := headerValues(got)
			for _, secret := range []string{email, name, authID, accessToken, permissionAction, teamUID, `"IsGrafanaAdmin"`} {
				require.NotContains(t, flat, secret)
			}
			if !tc.sendUserHeader {
				require.NotContains(t, flat, login)
			}
			require.NotContains(t, flat, `"TeamIDs"`)
			require.NotContains(t, flat, `"OrgRole"`)
		})
	}
}

func headerValues(h http.Header) string {
	var b strings.Builder
	for name, values := range h {
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(strings.Join(values, ","))
		b.WriteString("\n")
	}
	return b.String()
}
