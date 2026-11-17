package resourcepermissions

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/licensing/licensingtest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/serviceaccounts"
	serviceaccountsretriever "github.com/grafana/grafana/pkg/services/serviceaccounts/retriever"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/team"
	"github.com/grafana/grafana/pkg/services/team/teamimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// TestIntegrationCrossOrgResourceAssignmentRejected covers every resource
// permission service that assigns a user through validateUser: dashboards,
// folders, service accounts, alerting receivers, and alerting routes. Team
// membership is covered by TestIntegrationCrossOrgTeamMembershipRejected.
// Datasource permission writes in OSS do not call this service.
func TestIntegrationCrossOrgResourceAssignmentRejected(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	env := setupCrossOrgAssignmentEnv(t)
	cases := []assignmentCase{
		{
			name:       "dashboards",
			resource:   dashboards.ScopeDashboardsRoot,
			attribute:  "uid",
			permission: "View",
			resourceID: "dash-in-caller-org",
			actions:    map[string][]string{"View": {dashboards.ActionDashboardsRead}},
		},
		{
			name:       "folders",
			resource:   folder.ScopeFoldersRoot,
			attribute:  "uid",
			permission: "View",
			resourceID: "folder-in-caller-org",
			actions:    map[string][]string{"View": {folder.ActionFoldersRead}},
		},
		{
			name:       "serviceaccounts",
			resource:   serviceaccounts.ScopeServiceAccountRoot,
			attribute:  "id",
			permission: "Edit",
			resourceID: "42",
			actions:    map[string][]string{"Edit": {serviceaccounts.ActionRead, serviceaccounts.ActionWrite}},
		},
		{
			name:       "receivers",
			resource:   "receivers",
			attribute:  "uid",
			permission: "View",
			resourceID: "receiver-in-caller-org",
			actions:    map[string][]string{"View": {accesscontrol.ActionAlertingReceiversRead}},
		},
		{
			name:            "routingtrees",
			resource:        accesscontrol.AlertingRoutesResource,
			attribute:       "uid",
			permission:      "View",
			resourceID:      "route-in-caller-org",
			actions:         map[string][]string{"View": {accesscontrol.ActionAlertingManagedRoutesRead}},
			apiGroup:        accesscontrol.AlertingNotificationsApiGroup,
			k8sActionFormat: true,
		},
	}

	services := make(map[string]*Service, len(cases))
	for _, tc := range cases {
		services[tc.name] = env.service(t, tc)
	}
	env.server = webtest.NewServer(t, env.router)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := services[tc.name]
			ctx := context.Background()
			scope := accesscontrol.Scope(tc.resource, tc.attribute, tc.resourceID)

			_, err := svc.SetUserPermission(ctx, env.callerOrgID, accesscontrol.User{ID: env.outsider.ID}, tc.resourceID, tc.permission)
			require.Error(t, err)
			require.ErrorIs(t, err, accesscontrol.ErrAssignmentEntityNotFound)
			require.Zero(t, env.permissionCount(t, env.outsider.ID, scope))

			batchID := tc.resourceID + "-batch"
			batchScope := accesscontrol.Scope(tc.resource, tc.attribute, batchID)
			_, err = svc.SetPermissions(ctx, env.callerOrgID, batchID,
				accesscontrol.SetResourcePermissionCommand{UserID: env.outsider.ID, Permission: tc.permission},
				accesscontrol.SetResourcePermissionCommand{UserID: env.insider.ID, Permission: tc.permission},
			)
			require.Error(t, err)
			require.ErrorIs(t, err, accesscontrol.ErrAssignmentEntityNotFound)
			require.Zero(t, env.permissionCount(t, env.outsider.ID, batchScope))
			require.Zero(t, env.permissionCount(t, env.insider.ID, batchScope))

			status, body := env.postUserPermission(t, tc, env.outsider.ID)
			require.NotEqual(t, http.StatusOK, status, body)
			require.NotContains(t, body, env.outsider.Login)
			require.NotContains(t, body, env.outsider.Email)
			require.Zero(t, env.permissionCount(t, env.outsider.ID, scope))

			assigned, err := svc.SetUserPermission(ctx, env.callerOrgID, accesscontrol.User{ID: env.insider.ID}, tc.resourceID, tc.permission)
			require.NoError(t, err)
			require.Equal(t, env.insider.ID, assigned.UserID)
			require.Positive(t, env.permissionCount(t, env.insider.ID, scope))
			require.Zero(t, env.permissionCount(t, env.outsider.ID, scope))

			listed, err := svc.GetPermissions(ctx, env.reader(), tc.resourceID)
			require.NoError(t, err)
			require.NotContains(t, permissionLogins(listed), env.outsider.Login)
			require.NotContains(t, permissionEmails(listed), env.outsider.Email)
			require.Contains(t, permissionLogins(listed), env.insider.Login)
		})
	}
}

type assignmentCase struct {
	name            string
	resource        string
	attribute       string
	permission      string
	resourceID      string
	actions         map[string][]string
	apiGroup        string
	k8sActionFormat bool
}

type crossOrgAssignmentEnv struct {
	sql         *sqlstore.SQLStore
	cfg         *setting.Cfg
	features    featuremgmt.FeatureToggles
	license     *licensingtest.FakeLicensing
	ac          accesscontrol.AccessControl
	roleSvc     *actest.FakeService
	teamSvc     team.Service
	userSvc     user.Service
	retriever   *serviceaccountsretriever.Service
	router      routing.RouteRegister
	server      *webtest.Server
	admin       *user.SignedInUser
	callerOrgID int64
	outsider    *user.User
	insider     *user.User
}

func setupCrossOrgAssignmentEnv(t *testing.T) *crossOrgAssignmentEnv {
	t.Helper()
	cfg := setting.NewCfg()
	cfg.AutoAssignOrg = false
	sqlStore := db.NewTestStore(t)
	tracer := tracing.InitializeTracerForTest()
	sqlProvider := legacysql.NewDatabaseProvider(sqlStore)

	teamSvc, err := teamimpl.ProvideService(sqlProvider, cfg, tracer, nil)
	require.NoError(t, err)
	orgSvc, err := orgimpl.ProvideService(sqlProvider, cfg, quotatest.New(false, nil))
	require.NoError(t, err)
	userSvc, err := userimpl.ProvideService(sqlProvider, orgSvc, cfg, teamSvc, nil, tracer, quotatest.New(false, nil), supportbundlestest.NewFakeBundleService(), nil)
	require.NoError(t, err)

	adminUser, err := userSvc.Create(context.Background(), &user.CreateUserCommand{Login: "resource-admin", Email: "resource-admin@example.test", Name: "Resource Admin"})
	require.NoError(t, err)
	outsider, err := userSvc.Create(context.Background(), &user.CreateUserCommand{Login: "resource-outsider", Email: "resource-outsider@example.test", Name: "Resource Outsider"})
	require.NoError(t, err)
	require.NotEqual(t, adminUser.OrgID, outsider.OrgID)

	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgRole = string(org.RoleEditor)
	insider, err := userSvc.Create(context.Background(), &user.CreateUserCommand{
		Login: "resource-insider",
		Email: "resource-insider@example.test",
		Name:  "Resource Insider",
		OrgID: adminUser.OrgID,
	})
	require.NoError(t, err)
	require.Equal(t, adminUser.OrgID, insider.OrgID)

	features := featuremgmt.WithFeatures()
	license := licensingtest.NewFakeLicensing()
	license.On("FeatureEnabled", "accesscontrol.enforcement").Return(true).Maybe()

	return &crossOrgAssignmentEnv{
		sql:         sqlStore,
		cfg:         cfg,
		features:    features,
		license:     license,
		ac:          acimpl.ProvideAccessControl(features),
		roleSvc:     &actest.FakeService{},
		teamSvc:     teamSvc,
		userSvc:     userSvc,
		retriever:   serviceaccountsretriever.ProvideService(sqlStore, nil, nil, userSvc, orgSvc),
		router:      routing.NewRouteRegister(),
		callerOrgID: adminUser.OrgID,
		outsider:    outsider,
		insider:     insider,
		admin: &user.SignedInUser{
			UserID:  adminUser.ID,
			OrgID:   adminUser.OrgID,
			OrgRole: org.RoleAdmin,
			Login:   adminUser.Login,
			Permissions: map[int64]map[string][]string{
				adminUser.OrgID: {},
			},
		},
	}
}

func (e *crossOrgAssignmentEnv) service(t *testing.T, tc assignmentCase) *Service {
	t.Helper()
	callerOrgID := e.callerOrgID
	allowed := map[string]struct{}{tc.resourceID: {}, tc.resourceID + "-batch": {}}
	// The production resource validator only checks that the resource belongs to
	// the caller's organization. It does not decide whether the assignee does.
	svc, err := New(e.cfg, Options{
		Resource:             tc.resource,
		ResourceAttribute:    tc.attribute,
		APIGroup:             tc.apiGroup,
		K8sActionFormat:      tc.k8sActionFormat,
		Assignments:          Assignments{Users: true},
		PermissionsToActions: tc.actions,
		ResourceValidator: func(_ context.Context, orgID int64, resourceID string) error {
			if orgID != callerOrgID {
				return fmt.Errorf("resource %s is not in organization %d", resourceID, orgID)
			}
			if _, ok := allowed[resourceID]; !ok {
				return fmt.Errorf("resource %s is not in organization %d", resourceID, orgID)
			}
			return nil
		},
	}, e.features, e.router, e.license, e.ac, e.roleSvc, e.sql, e.teamSvc, e.userSvc, e.retriever, NewActionSetService())
	require.NoError(t, err)
	e.grantWrite(tc)
	return svc
}

func (e *crossOrgAssignmentEnv) grantWrite(tc assignmentCase) {
	opts := Options{Resource: tc.resource, ResourceAttribute: tc.attribute, APIGroup: tc.apiGroup, K8sActionFormat: tc.k8sActionFormat}
	perms := e.admin.Permissions[e.callerOrgID]
	perms[opts.GetAction("write")] = append(perms[opts.GetAction("write")], opts.GetScope("*"))
	perms[opts.GetAction("read")] = append(perms[opts.GetAction("read")], opts.GetScope("*"))
	perms[accesscontrol.ActionOrgUsersRead] = []string{accesscontrol.ScopeUsersAll}
	e.admin.Permissions[e.callerOrgID] = perms
}

func (e *crossOrgAssignmentEnv) reader() *user.SignedInUser {
	return e.admin
}

func (e *crossOrgAssignmentEnv) postUserPermission(t *testing.T, tc assignmentCase, userID int64) (int, string) {
	t.Helper()
	body := fmt.Sprintf(`{"permission":%q}`, tc.permission)
	path := fmt.Sprintf("/api/access-control/%s/%s/users/%d", tc.resource, tc.resourceID, userID)
	req := webtest.RequestWithSignedInUser(e.server.NewRequest(http.MethodPost, path, strings.NewReader(body)), e.admin)
	res, err := e.server.SendJSON(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(raw)
}

func (e *crossOrgAssignmentEnv) permissionCount(t *testing.T, userID int64, scope string) int64 {
	t.Helper()
	return countPermissionRows(t, e.sql, e.callerOrgID, userID, scope)
}

func countPermissionRows(t *testing.T, sql *sqlstore.SQLStore, orgID, userID int64, scope string) int64 {
	t.Helper()
	var count int64
	err := sql.WithDbSession(context.Background(), func(sess *db.Session) error {
		_, err := sess.SQL(`
			SELECT COUNT(*) FROM permission p
			INNER JOIN user_role ur ON ur.role_id = p.role_id
			WHERE ur.org_id = ? AND ur.user_id = ? AND p.scope = ?
		`, orgID, userID, scope).Get(&count)
		return err
	})
	require.NoError(t, err)
	return count
}

func permissionLogins(perms []accesscontrol.ResourcePermission) []string {
	out := make([]string, 0, len(perms))
	for _, perm := range perms {
		if perm.UserLogin != "" {
			out = append(out, perm.UserLogin)
		}
	}
	return out
}

func permissionEmails(perms []accesscontrol.ResourcePermission) []string {
	out := make([]string, 0, len(perms))
	for _, perm := range perms {
		if perm.UserEmail != "" {
			out = append(out, perm.UserEmail)
		}
	}
	return out
}
