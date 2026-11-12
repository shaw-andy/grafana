package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web"
)

func TestOSSViewerCanPassDatasourceProxyRoute(t *testing.T) {
	// declareFixedRoles passes this flag through. OSS licensing reports every
	// feature, including dspermissions.enforcement, as disabled, and the
	// default of viewers_can_edit is false.
	enforced := (&licensing.OSSLicensingService{}).FeatureEnabled("dspermissions.enforcement")
	require.False(t, enforced)

	var reader accesscontrol.RoleRegistration
	found := false
	for _, reg := range FixedRoleRegistrations(false, enforced) {
		if reg.Role.Name == datasourcesReaderRoleName {
			reader = reg
			found = true
			break
		}
	}
	require.True(t, found)
	require.Equal(t, []string{string(org.RoleViewer)}, reader.Grants)

	perms := map[string][]string{}
	for _, perm := range reader.Role.Permissions {
		perms[perm.Action] = append(perms[perm.Action], perm.Scope)
	}
	require.Equal(t, []string{datasources.ScopeAll}, perms[datasources.ActionQuery])
	require.Equal(t, []string{datasources.ScopeAll}, perms[datasources.ActionRead])

	viewer := &user.SignedInUser{
		UserID:      1,
		OrgID:       1,
		OrgRole:     org.RoleViewer,
		Login:       "viewer",
		Permissions: map[int64]map[string][]string{1: perms},
	}
	allowed, err := acimpl.ProvideAccessControlTest().Evaluate(
		t.Context(),
		viewer,
		accesscontrol.EvalPermission(datasources.ActionQuery),
	)
	require.NoError(t, err)
	require.True(t, allowed, "the proxy route evaluator is datasources:query with no scope")

	editorOnly := &user.SignedInUser{
		UserID:  2,
		OrgID:   1,
		OrgRole: org.RoleViewer,
		Login:   "no-query",
		Permissions: map[int64]map[string][]string{
			1: {datasources.ActionRead: {datasources.ScopeAll}},
		},
	}
	allowed, err = acimpl.ProvideAccessControlTest().Evaluate(
		t.Context(),
		editorOnly,
		accesscontrol.EvalPermission(datasources.ActionQuery),
	)
	require.NoError(t, err)
	require.False(t, allowed)

	reached := false
	server := web.New()
	server.UseMiddleware(web.Renderer("../../public/views", "[[", "]]"))
	server.Use(func(c *web.Context) {
		reqCtx := &contextmodel.ReqContext{
			Context:      c,
			Logger:       log.NewNopLogger(),
			SignedInUser: viewer,
			IsSignedIn:   true,
		}
		c.Req = c.Req.WithContext(ctxkey.Set(c.Req.Context(), reqCtx))
	})
	server.Use(accesscontrol.Middleware(acimpl.ProvideAccessControlTest())(accesscontrol.EvalPermission(datasources.ActionQuery)))
	server.Any("/api/datasources/proxy/uid/:uid/*", func(c *contextmodel.ReqContext) {
		reached = true
		c.Resp.WriteHeader(http.StatusNoContent)
	})

	req, err := http.NewRequest(http.MethodGet, "http://grafana.example/api/datasources/proxy/uid/prom-a/api/v1/status/config", nil)
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.True(t, reached, "a Viewer with the OSS reader role reaches the proxy handler")
	require.Equal(t, http.StatusNoContent, rec.Code)
}
