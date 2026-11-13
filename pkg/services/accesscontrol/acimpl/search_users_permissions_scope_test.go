package acimpl

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/api"
	"github.com/grafana/grafana/pkg/services/accesscontrol/database"
	"github.com/grafana/grafana/pkg/services/accesscontrol/permreg"
	rs "github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/team/teamimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web/webtest"
)

const (
	allowedDashboardScope     = "dashboards:uid:allowed-board"
	victimDashboardScope      = "dashboards:uid:victim-board"
	victimDatasourceScope     = "datasources:uid:victim-datasource"
	saDashboardScope          = "dashboards:uid:sa-board"
	memberAdminDashboardScope = "dashboards:uid:member-admin-board"
)

// TestIntegrationSearchUsersPermissions_NamespacedIDScope is the spec for
// GET /api/access-control/users/permissions/search. A grant of
// users.permissions:read on a single users:id:<n> scope must not return any
// other account's actions or scopes, and a server admin who is not a member
// of the caller's organization must not be readable by id or by the unscoped
// search.
func TestIntegrationSearchUsersPermissions_NamespacedIDScope(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	ctx := context.Background()
	fx := newPermissionSearchFixture(t)
	// Keep an organization admin in place before any other role change. Removing
	// the last admin is rejected, and the first user is created as a viewer.
	memberAdmin := fx.createUser(t, "member-admin", true, org.RoleAdmin)
	allowed := fx.createUser(t, "allowed", false, org.RoleEditor)
	victim := fx.createUser(t, "victim", false, org.RoleEditor)
	caller := fx.createUser(t, "caller", false, org.RoleViewer)
	outsider := fx.createUser(t, "outsider-admin", true, "")
	sa := fx.createServiceAccount(t, "sa-scope")

	fx.grantDashboard(t, allowed.ID, "allowed-board")
	fx.grantDashboard(t, victim.ID, "victim-board")
	fx.grantDatasource(t, victim.ID, "victim-datasource")
	fx.grantDashboard(t, sa.ID, "sa-board")
	fx.grantDashboard(t, memberAdmin.ID, "member-admin-board")

	limited := signedInWithReadScope(caller.ID, fx.orgID, accesscontrol.Scope("users", "id", strconv.FormatInt(allowed.ID, 10)))
	broad := signedInWithReadScope(caller.ID, fx.orgID, accesscontrol.ScopeUsersAll)
	none := signedInWithReadScope(caller.ID, fx.orgID)

	// Cold path: nothing has been cached for these targets yet.
	t.Run("service cold hides another org member selected by id", func(t *testing.T) {
		fx.requireHidden(t, limited, victim.ID, dashboards.ActionDashboardsRead, victimDashboardScope)
	})
	t.Run("service cold hides another org member datasource scope", func(t *testing.T) {
		fx.requireHidden(t, limited, victim.ID, datasources.ActionRead, victimDatasourceScope)
	})
	t.Run("service cold hides another org member when an action prefix is set", func(t *testing.T) {
		fx.requireHiddenOpts(t, limited, accesscontrol.SearchOptions{UserID: victim.ID, ActionPrefix: "dashboards:"}, victim.ID, dashboards.ActionDashboardsRead, victimDashboardScope)
	})
	t.Run("service cold hides a service account selected by id", func(t *testing.T) {
		fx.requireHidden(t, limited, sa.ID, dashboards.ActionDashboardsRead, saDashboardScope)
	})
	t.Run("service cold hides another org member who is a server admin", func(t *testing.T) {
		fx.requireHidden(t, limited, memberAdmin.ID, dashboards.ActionDashboardsRead, memberAdminDashboardScope)
		fx.requireHidden(t, limited, memberAdmin.ID, accesscontrol.ActionLDAPUsersRead, "")
	})
	t.Run("service cold hides a server admin who is not an org member", func(t *testing.T) {
		fx.requireHidden(t, limited, outsider.ID, accesscontrol.ActionLDAPUsersRead, "")
	})
	t.Run("service cold users star hides a server admin who is not an org member", func(t *testing.T) {
		fx.requireHidden(t, broad, outsider.ID, accesscontrol.ActionLDAPUsersRead, "")
	})

	t.Run("service cold namespaced id still returns the granted account", func(t *testing.T) {
		fx.requireVisible(t, limited, allowed.ID, dashboards.ActionDashboardsRead, allowedDashboardScope)
		got, err := fx.svc.SearchUsersPermissions(ctx, limited, accesscontrol.SearchOptions{UserID: allowed.ID})
		require.NoError(t, err)
		require.False(t, permissionSet(got[allowed.ID])[permKey{dashboards.ActionDashboardsRead, victimDashboardScope}])
		require.False(t, permissionSet(got[allowed.ID])[permKey{accesscontrol.ActionLDAPUsersRead, ""}])
	})
	t.Run("service cold users star still returns an org member who is a server admin", func(t *testing.T) {
		fx.requireVisible(t, broad, memberAdmin.ID, accesscontrol.ActionLDAPUsersRead, "")
		fx.requireVisible(t, broad, memberAdmin.ID, dashboards.ActionDashboardsRead, memberAdminDashboardScope)
	})

	t.Run("service unscoped search keeps the single-user grant and org boundary", func(t *testing.T) {
		got, err := fx.svc.SearchUsersPermissions(ctx, limited, accesscontrol.SearchOptions{ActionPrefix: "dashboards:"})
		require.NoError(t, err)
		require.True(t, permissionSet(got[allowed.ID])[permKey{dashboards.ActionDashboardsRead, allowedDashboardScope}])
		require.NotContains(t, got, victim.ID)
		require.NotContains(t, got, sa.ID)
		require.NotContains(t, got, memberAdmin.ID)
		require.NotContains(t, got, outsider.ID)

		adminSearch, err := fx.svc.SearchUsersPermissions(ctx, broad, accesscontrol.SearchOptions{Action: accesscontrol.ActionLDAPUsersRead})
		require.NoError(t, err)
		require.Contains(t, adminSearch, memberAdmin.ID)
		require.True(t, permissionSet(adminSearch[memberAdmin.ID])[permKey{accesscontrol.ActionLDAPUsersRead, ""}])
		require.NotContains(t, adminSearch, outsider.ID)

		dashSearch, err := fx.svc.SearchUsersPermissions(ctx, broad, accesscontrol.SearchOptions{ActionPrefix: "dashboards:"})
		require.NoError(t, err)
		require.True(t, permissionSet(dashSearch[victim.ID])[permKey{dashboards.ActionDashboardsRead, victimDashboardScope}])
		require.True(t, permissionSet(dashSearch[allowed.ID])[permKey{dashboards.ActionDashboardsRead, allowedDashboardScope}])
		require.NotContains(t, dashSearch, outsider.ID)
	})

	t.Run("http denies a caller with no users.permissions:read grant", func(t *testing.T) {
		status, body := fx.search(t, none, "namespacedId=user:"+itoa(victim.ID))
		require.Equal(t, http.StatusForbidden, status)
		requireBodyOmits(t, body, victimDashboardScope, victimDatasourceScope)
	})
	t.Run("http hides another org member selected by numeric id", func(t *testing.T) {
		_, body := fx.search(t, limited, "namespacedId=user:"+itoa(victim.ID))
		requireBodyOmits(t, body, victimDashboardScope)
	})
	t.Run("http hides another org member datasource scope", func(t *testing.T) {
		_, body := fx.search(t, limited, "namespacedId=user:"+itoa(victim.ID))
		requireBodyOmits(t, body, victimDatasourceScope)
	})
	t.Run("http hides another org member selected by uid", func(t *testing.T) {
		_, body := fx.search(t, limited, "namespacedId=user:"+victim.UID)
		requireBodyOmits(t, body, victimDashboardScope, victimDatasourceScope)
	})
	t.Run("http hides another org member when an action prefix is set", func(t *testing.T) {
		_, body := fx.search(t, limited, "namespacedId=user:"+itoa(victim.ID)+"&actionPrefix=dashboards:")
		requireBodyOmits(t, body, victimDashboardScope)
	})
	t.Run("http hides a service account selected by numeric id", func(t *testing.T) {
		_, body := fx.search(t, limited, "namespacedId=service-account:"+itoa(sa.ID))
		requireBodyOmits(t, body, saDashboardScope)
	})
	t.Run("http hides a service account selected by uid", func(t *testing.T) {
		_, body := fx.search(t, limited, "namespacedId=service-account:"+sa.UID)
		requireBodyOmits(t, body, saDashboardScope)
	})
	t.Run("http hides another org member who is a server admin", func(t *testing.T) {
		_, body := fx.search(t, limited, "namespacedId=user:"+itoa(memberAdmin.ID))
		requireBodyOmits(t, body, memberAdminDashboardScope, accesscontrol.ActionLDAPUsersRead)
	})
	t.Run("http hides a server admin who is not an org member", func(t *testing.T) {
		_, body := fx.search(t, limited, "namespacedId=user:"+itoa(outsider.ID))
		requireBodyOmits(t, body, accesscontrol.ActionLDAPUsersRead)
	})
	t.Run("http returns the account the grant names", func(t *testing.T) {
		status, body := fx.search(t, limited, "namespacedId=user:"+itoa(allowed.ID))
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, allowedDashboardScope)
		requireBodyOmits(t, body, victimDashboardScope, saDashboardScope, memberAdminDashboardScope, accesscontrol.ActionLDAPUsersRead)

		status, body = fx.search(t, limited, "namespacedId=user:"+allowed.UID)
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, allowedDashboardScope)
		requireBodyOmits(t, body, victimDashboardScope)
	})
	t.Run("http users star hides a server admin who is not an org member", func(t *testing.T) {
		_, body := fx.search(t, broad, "namespacedId=user:"+itoa(outsider.ID))
		requireBodyOmits(t, body, accesscontrol.ActionLDAPUsersRead)
	})
	t.Run("http users star returns an org member who is a server admin", func(t *testing.T) {
		status, body := fx.search(t, broad, "namespacedId=user:"+itoa(memberAdmin.ID))
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, accesscontrol.ActionLDAPUsersRead)
		require.Contains(t, body, memberAdminDashboardScope)
	})
	t.Run("http unscoped search keeps the org boundary", func(t *testing.T) {
		status, body := fx.search(t, broad, "action="+accesscontrol.ActionLDAPUsersRead)
		require.Equal(t, http.StatusOK, status)
		ids := permissionUserIDs(t, body)
		require.Contains(t, ids, itoa(memberAdmin.ID))
		require.NotContains(t, ids, itoa(outsider.ID))

		status, body = fx.search(t, limited, "actionPrefix=dashboards:")
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, allowedDashboardScope)
		requireBodyOmits(t, body, victimDashboardScope, saDashboardScope, memberAdminDashboardScope)
	})

	// A broader caller fills the user-permission cache. The limited caller must
	// still be checked against the requested id on the way back out of that cache.
	broadPrime := signedInWithReadScope(memberAdmin.ID, fx.orgID, accesscontrol.ScopeUsersAll)
	for _, opts := range []accesscontrol.SearchOptions{
		{UserID: victim.ID},
		{UserID: victim.ID, ActionPrefix: "dashboards:"},
		{UserID: sa.ID},
		{UserID: memberAdmin.ID},
		{UserID: outsider.ID},
		{UserID: allowed.ID},
	} {
		_, err := fx.svc.SearchUsersPermissions(ctx, broadPrime, opts)
		require.NoError(t, err)
	}

	t.Run("service warm cache hides another org member", func(t *testing.T) {
		fx.requireHidden(t, limited, victim.ID, dashboards.ActionDashboardsRead, victimDashboardScope)
		fx.requireHiddenOpts(t, limited, accesscontrol.SearchOptions{UserID: victim.ID, ActionPrefix: "dashboards:"}, victim.ID, dashboards.ActionDashboardsRead, victimDashboardScope)
	})
	t.Run("service warm cache hides a service account", func(t *testing.T) {
		fx.requireHidden(t, limited, sa.ID, dashboards.ActionDashboardsRead, saDashboardScope)
	})
	t.Run("service warm cache hides server admins outside the grant", func(t *testing.T) {
		fx.requireHidden(t, limited, memberAdmin.ID, accesscontrol.ActionLDAPUsersRead, "")
		fx.requireHidden(t, limited, outsider.ID, accesscontrol.ActionLDAPUsersRead, "")
	})
	t.Run("service warm cache still returns the granted account", func(t *testing.T) {
		fx.requireVisible(t, limited, allowed.ID, dashboards.ActionDashboardsRead, allowedDashboardScope)
	})

	t.Run("http warm cache hides another org member", func(t *testing.T) {
		_, body := fx.search(t, limited, "namespacedId=user:"+itoa(victim.ID))
		requireBodyOmits(t, body, victimDashboardScope, victimDatasourceScope)
	})
	t.Run("http warm cache hides a uid lookup with an action prefix", func(t *testing.T) {
		_, body := fx.search(t, limited, "namespacedId=user:"+victim.UID+"&actionPrefix=dashboards:")
		requireBodyOmits(t, body, victimDashboardScope)
	})
	t.Run("http warm cache hides a service account", func(t *testing.T) {
		_, body := fx.search(t, limited, "namespacedId=service-account:"+itoa(sa.ID))
		requireBodyOmits(t, body, saDashboardScope)
	})
	t.Run("http warm cache hides a server admin who is not an org member", func(t *testing.T) {
		_, body := fx.search(t, limited, "namespacedId=user:"+itoa(outsider.ID))
		requireBodyOmits(t, body, accesscontrol.ActionLDAPUsersRead)
	})
	t.Run("http warm cache still returns the granted account", func(t *testing.T) {
		status, body := fx.search(t, limited, "namespacedId=user:"+itoa(allowed.ID))
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, allowedDashboardScope)
		requireBodyOmits(t, body, victimDashboardScope, victimDatasourceScope, saDashboardScope)
	})
}

type userResourceGranter interface {
	SetUserResourcePermission(ctx context.Context, orgID int64, usr accesscontrol.User, cmd rs.SetResourcePermissionCommand, hook rs.UserResourceHookFunc) (*accesscontrol.ResourcePermission, error)
}

type permissionSearchFixture struct {
	svc     *Service
	orgID   int64
	server  *webtest.Server
	userSvc user.Service
	orgSvc  org.Service
	perms   userResourceGranter
}

func newPermissionSearchFixture(t *testing.T) *permissionSearchFixture {
	t.Helper()
	ctx := context.Background()
	sql, cfg := db.InitTestDBWithCfg(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgRole = "Viewer"
	cfg.AutoAssignOrgId = 1

	orgService, err := orgimpl.ProvideService(legacysql.NewDatabaseProvider(sql), cfg, quotatest.New(false, nil))
	require.NoError(t, err)
	orgID, err := orgService.GetOrCreate(ctx, "test")
	require.NoError(t, err)
	require.Equal(t, int64(1), orgID)

	teamService, err := teamimpl.ProvideService(legacysql.NewDatabaseProvider(sql), cfg, tracing.InitializeTracerForTest(), nil)
	require.NoError(t, err)
	userService, err := userimpl.ProvideService(
		legacysql.NewDatabaseProvider(sql), orgService, cfg, teamService, localcache.ProvideService(), tracing.InitializeTracerForTest(),
		quotatest.New(false, nil), supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)

	svc := ProvideOSSService(
		cfg,
		database.ProvideService(sql),
		rs.NewActionSetService(),
		localcache.ProvideService(),
		featuremgmt.WithFeatures(),
		tracing.InitializeTracerForTest(),
		sql,
		permreg.ProvidePermissionRegistry(),
		nil,
	)
	require.NoError(t, accesscontrol.DeclareFixedRoles(svc))
	require.NoError(t, svc.RegisterFixedRoles(ctx))

	rr := routing.NewRouteRegister()
	api.NewAccessControlAPI(rr, ProvideAccessControlTest(), svc, userService).RegisterAPIEndpoints()

	return &permissionSearchFixture{
		svc:     svc,
		orgID:   orgID,
		server:  webtest.NewServer(t, rr),
		userSvc: userService,
		orgSvc:  orgService,
		perms:   rs.NewStore(cfg, sql, featuremgmt.WithFeatures()),
	}
}

func (f *permissionSearchFixture) createUser(t *testing.T, login string, serverAdmin bool, role org.RoleType) *user.User {
	t.Helper()
	created, err := f.userSvc.Create(context.Background(), &user.CreateUserCommand{
		Login:   login,
		OrgID:   f.orgID,
		IsAdmin: serverAdmin,
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)
	require.NotEmpty(t, created.UID)

	if role == "" {
		require.NoError(t, f.orgSvc.RemoveOrgUser(context.Background(), &org.RemoveOrgUserCommand{
			OrgID:  f.orgID,
			UserID: created.ID,
		}))
		return created
	}
	require.NoError(t, f.orgSvc.UpdateOrgUser(context.Background(), &org.UpdateOrgUserCommand{
		OrgID:  f.orgID,
		UserID: created.ID,
		Role:   role,
	}))
	return created
}

func (f *permissionSearchFixture) createServiceAccount(t *testing.T, login string) *user.User {
	t.Helper()
	created, err := f.userSvc.CreateServiceAccount(context.Background(), &user.CreateUserCommand{
		Login:          login,
		OrgID:          f.orgID,
		DefaultOrgRole: string(org.RoleEditor),
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)
	require.NotEmpty(t, created.UID)
	require.True(t, created.IsServiceAccount)
	return created
}

func (f *permissionSearchFixture) grantDashboard(t *testing.T, userID int64, uid string) {
	t.Helper()
	_, err := f.perms.SetUserResourcePermission(context.Background(), f.orgID, accesscontrol.User{ID: userID}, rs.SetResourcePermissionCommand{
		Actions:           []string{dashboards.ActionDashboardsRead},
		Resource:          "dashboards",
		ResourceAttribute: "uid",
		ResourceID:        uid,
	}, nil)
	require.NoError(t, err)
}

func (f *permissionSearchFixture) grantDatasource(t *testing.T, userID int64, uid string) {
	t.Helper()
	_, err := f.perms.SetUserResourcePermission(context.Background(), f.orgID, accesscontrol.User{ID: userID}, rs.SetResourcePermissionCommand{
		Actions:           []string{datasources.ActionRead},
		Resource:          "datasources",
		ResourceAttribute: "uid",
		ResourceID:        uid,
	}, nil)
	require.NoError(t, err)
}

func (f *permissionSearchFixture) requireHidden(t *testing.T, caller *user.SignedInUser, target int64, action, scope string) {
	t.Helper()
	f.requireHiddenOpts(t, caller, accesscontrol.SearchOptions{UserID: target}, target, action, scope)
}

func (f *permissionSearchFixture) requireHiddenOpts(t *testing.T, caller *user.SignedInUser, opts accesscontrol.SearchOptions, target int64, action, scope string) {
	t.Helper()
	got, err := f.svc.SearchUsersPermissions(context.Background(), caller, opts)
	if err != nil {
		if scope != "" {
			require.NotContains(t, err.Error(), scope)
		}
		require.NotContains(t, err.Error(), action)
		return
	}
	require.Falsef(t, permissionSet(got[target])[permKey{action, scope}], "disclosed user %d action %s scope %q", target, action, scope)
	for id, perms := range got {
		require.Falsef(t, permissionSet(perms)[permKey{action, scope}], "disclosed user %d while asking about %d action %s scope %q", id, target, action, scope)
	}
}

func (f *permissionSearchFixture) requireVisible(t *testing.T, caller *user.SignedInUser, target int64, action, scope string) {
	t.Helper()
	got, err := f.svc.SearchUsersPermissions(context.Background(), caller, accesscontrol.SearchOptions{UserID: target})
	require.NoError(t, err)
	require.Truef(t, permissionSet(got[target])[permKey{action, scope}], "missing user %d action %s scope %q", target, action, scope)
}

func (f *permissionSearchFixture) search(t *testing.T, caller *user.SignedInUser, rawQuery string) (int, string) {
	t.Helper()
	req := f.server.NewGetRequest("/api/access-control/users/permissions/search?" + rawQuery)
	webtest.RequestWithSignedInUser(req, caller)
	res, err := f.server.Send(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(body)
}

func signedInWithReadScope(userID, orgID int64, scopes ...string) *user.SignedInUser {
	perms := map[string][]string{}
	if len(scopes) > 0 {
		perms[accesscontrol.ActionUsersPermissionsRead] = scopes
	}
	return &user.SignedInUser{
		UserID:      userID,
		OrgID:       orgID,
		Permissions: map[int64]map[string][]string{orgID: perms},
	}
}

func permissionUserIDs(t *testing.T, body string) map[string]json.RawMessage {
	t.Helper()
	var decoded map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(body), &decoded))
	return decoded
}

func requireBodyOmits(t *testing.T, body string, markers ...string) {
	t.Helper()
	for _, marker := range markers {
		if marker != "" && strings.Contains(body, marker) {
			t.Fatalf("response disclosed %q", marker)
		}
	}
}

func permissionSet(perms []accesscontrol.Permission) map[permKey]bool {
	set := make(map[permKey]bool, len(perms))
	for _, p := range perms {
		set[permKey{p.Action, p.Scope}] = true
	}
	return set
}

func itoa(id int64) string {
	return strconv.FormatInt(id, 10)
}
