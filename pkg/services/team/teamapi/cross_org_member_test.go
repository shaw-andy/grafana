package teamapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/accesscontrol/ossaccesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/services/licensing/licensingtest"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/preference/preftest"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
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

const (
	crossOrgOutsiderLogin  = "outside-org-login"
	crossOrgOutsiderName   = "Outside Org Person"
	crossOrgOutsiderEmail  = "outside-org@example.test"
	crossOrgOutsiderModule = "oauth_generic_oauth"
	crossOrgInsiderLogin   = "inside-org-login"
	crossOrgInsiderEmail   = "inside-org@example.test"
	crossOrgAdminLogin     = "org-admin-login"
	crossOrgAdminEmail     = "org-admin@example.test"
)

// TestIntegrationCrossOrgTeamMembershipRejected is the spec for assigning team
// members. An organization administrator must not be able to attach an account
// that has no membership in the caller's organization, by user id or by email,
// and the team member list must not return that account's login, name, email,
// or authentication module. The same-organization member can still be added.
func TestIntegrationCrossOrgTeamMembershipRejected(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	env := setupCrossOrgTeamEnv(t)
	ctx := context.Background()

	t.Run("post user id does not add an account from another organization", func(t *testing.T) {
		target := env.createTeam(t, "id-assignment")
		before := env.permissionCount(t, env.outsider.ID, teamScope(target.ID))

		status, body := env.postMember(t, target.ID, env.outsider.ID)
		require.NotEqual(t, http.StatusOK, status)
		require.NotContains(t, body, "Member added to Team")
		require.NotContains(t, body, crossOrgOutsiderLogin)
		require.NotContains(t, body, crossOrgOutsiderEmail)
		require.NotContains(t, body, crossOrgOutsiderName)
		require.NotContains(t, body, crossOrgOutsiderModule)

		require.Zero(t, env.membershipCount(t, target.ID, env.outsider.ID))
		require.Equal(t, before, env.permissionCount(t, env.outsider.ID, teamScope(target.ID)))

		members := env.listMembers(t, target.ID)
		require.NotContains(t, memberLogins(members), crossOrgOutsiderLogin)
		require.NotContains(t, memberEmails(members), crossOrgOutsiderEmail)
		require.NotContains(t, memberNames(members), crossOrgOutsiderName)
		require.NotContains(t, memberAuthModules(members), crossOrgOutsiderModule)
	})

	t.Run("direct permission write returns assignment not found and writes nothing", func(t *testing.T) {
		target := env.createTeam(t, "direct-write")
		_, err := env.permissions.SetUserPermission(ctx, env.callerOrgID, accesscontrol.User{ID: env.outsider.ID}, fmt.Sprint(target.ID), team.PermissionTypeMember.String())
		require.Error(t, err)
		require.ErrorIs(t, err, accesscontrol.ErrAssignmentEntityNotFound)
		require.Zero(t, env.membershipCount(t, target.ID, env.outsider.ID))
		require.Zero(t, env.permissionCount(t, env.outsider.ID, teamScope(target.ID)))
	})

	t.Run("put email does not resolve an account from another organization", func(t *testing.T) {
		target := env.createTeam(t, "email-assignment")
		status, body := env.putMemberships(t, target.ID, []string{crossOrgOutsiderEmail}, nil)
		require.NotEqual(t, http.StatusOK, status)
		require.NotContains(t, body, crossOrgOutsiderLogin)
		require.NotContains(t, body, crossOrgOutsiderEmail)
		require.NotContains(t, body, crossOrgOutsiderName)
		require.NotContains(t, body, crossOrgOutsiderModule)
		require.Zero(t, env.membershipCount(t, target.ID, env.outsider.ID))
		require.Zero(t, env.permissionCount(t, env.outsider.ID, teamScope(target.ID)))
		require.NotContains(t, memberLogins(env.listMembers(t, target.ID)), crossOrgOutsiderLogin)
	})

	t.Run("put email batch does not write a membership before rejecting the outsider", func(t *testing.T) {
		target := env.createTeam(t, "email-batch")
		status, _ := env.putMemberships(t, target.ID, []string{crossOrgOutsiderEmail, crossOrgInsiderEmail}, []string{crossOrgOutsiderEmail})
		require.NotEqual(t, http.StatusOK, status)
		require.Zero(t, env.membershipCount(t, target.ID, env.outsider.ID))
		require.Zero(t, env.membershipCount(t, target.ID, env.insider.ID))
		require.Zero(t, env.permissionCount(t, env.outsider.ID, teamScope(target.ID)))
		require.Zero(t, env.permissionCount(t, env.insider.ID, teamScope(target.ID)))
	})

	t.Run("access control user assignment does not add an account from another organization", func(t *testing.T) {
		target := env.createTeam(t, "access-control")
		status, body := env.postAccessControlUser(t, target.ID, env.outsider.ID, team.PermissionTypeAdmin.String())
		require.NotEqual(t, http.StatusOK, status)
		require.NotContains(t, body, crossOrgOutsiderLogin)
		require.NotContains(t, body, crossOrgOutsiderEmail)
		require.Zero(t, env.membershipCount(t, target.ID, env.outsider.ID))
		require.Zero(t, env.permissionCount(t, env.outsider.ID, teamScope(target.ID)))
	})

	t.Run("bulk permission write rejects the outsider before writing either assignee", func(t *testing.T) {
		target := env.createTeam(t, "bulk-write")
		_, err := env.permissions.SetPermissions(ctx, env.callerOrgID, fmt.Sprint(target.ID),
			accesscontrol.SetResourcePermissionCommand{UserID: env.outsider.ID, Permission: team.PermissionTypeMember.String()},
			accesscontrol.SetResourcePermissionCommand{UserID: env.insider.ID, Permission: team.PermissionTypeAdmin.String()},
		)
		require.Error(t, err)
		require.ErrorIs(t, err, accesscontrol.ErrAssignmentEntityNotFound)
		require.Zero(t, env.membershipCount(t, target.ID, env.outsider.ID))
		require.Zero(t, env.membershipCount(t, target.ID, env.insider.ID))
		require.Zero(t, env.permissionCount(t, env.outsider.ID, teamScope(target.ID)))
		require.Zero(t, env.permissionCount(t, env.insider.ID, teamScope(target.ID)))
	})

	t.Run("a member of the caller organization can be added and listed", func(t *testing.T) {
		target := env.createTeam(t, "insider")
		status, body := env.postMember(t, target.ID, env.insider.ID)
		require.Equal(t, http.StatusOK, status, body)
		require.Equal(t, int64(1), env.membershipCount(t, target.ID, env.insider.ID))
		require.Zero(t, env.membershipCount(t, target.ID, env.outsider.ID))
		require.Positive(t, env.permissionCount(t, env.insider.ID, teamScope(target.ID)))
		require.Zero(t, env.permissionCount(t, env.outsider.ID, teamScope(target.ID)))

		members := env.listMembers(t, target.ID)
		require.Equal(t, []string{crossOrgInsiderLogin}, memberLogins(members))
		require.Equal(t, []string{crossOrgInsiderEmail}, memberEmails(members))
		require.NotContains(t, memberLogins(members), crossOrgOutsiderLogin)
	})

	t.Run("rejecting the outsider leaves no membership for a later organization add", func(t *testing.T) {
		target := env.createTeam(t, "later-add")
		status, _ := env.postMember(t, target.ID, env.outsider.ID)
		require.NotEqual(t, http.StatusOK, status)

		err := env.orgSvc.AddOrgUser(ctx, &org.AddOrgUserCommand{
			OrgID:  env.callerOrgID,
			UserID: env.outsider.ID,
			Role:   org.RoleViewer,
		})
		require.NoError(t, err)

		require.Zero(t, env.membershipCount(t, target.ID, env.outsider.ID))
		require.Zero(t, env.permissionCount(t, env.outsider.ID, teamScope(target.ID)))
		require.NotContains(t, memberLogins(env.listMembers(t, target.ID)), crossOrgOutsiderLogin)
	})
}

type crossOrgTeamEnv struct {
	sql         *sqlstore.SQLStore
	orgSvc      org.Service
	teamSvc     team.Service
	permissions *ossaccesscontrol.TeamPermissionsService
	server      *webtest.Server
	admin       *user.SignedInUser
	callerOrgID int64
	outsider    *user.User
	insider     *user.User
}

func setupCrossOrgTeamEnv(t *testing.T) *crossOrgTeamEnv {
	t.Helper()
	ctx := context.Background()

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

	adminUser := createCrossOrgUser(t, userSvc, crossOrgAdminLogin, crossOrgAdminEmail, "Org Admin", 0)
	outsider := createCrossOrgUser(t, userSvc, crossOrgOutsiderLogin, crossOrgOutsiderEmail, crossOrgOutsiderName, 0)
	require.NotEqual(t, adminUser.OrgID, outsider.OrgID)

	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgRole = string(org.RoleEditor)
	insider := createCrossOrgUser(t, userSvc, crossOrgInsiderLogin, crossOrgInsiderEmail, "Inside Org Person", adminUser.OrgID)
	require.Equal(t, adminUser.OrgID, insider.OrgID)

	require.NoError(t, sqlStore.WithDbSession(ctx, func(sess *db.Session) error {
		_, err := sess.Table("user_auth").Insert(&login.UserAuth{
			UserId:     outsider.ID,
			UserUID:    outsider.UID,
			AuthModule: crossOrgOutsiderModule,
			AuthId:     "external-subject",
			Created:    time.Now(),
		})
		return err
	}))

	features := featuremgmt.WithFeatures()
	license := licensingtest.NewFakeLicensing()
	license.On("FeatureEnabled", "accesscontrol.enforcement").Return(true).Maybe()
	retriever := serviceaccountsretriever.ProvideService(sqlStore, nil, nil, userSvc, orgSvc)
	router := routing.NewRouteRegister()
	permissions, err := ossaccesscontrol.ProvideTeamPermissions(
		cfg, features, router, sqlStore, acimpl.ProvideAccessControl(features), license, &actest.FakeService{},
		teamSvc, userSvc, retriever, resourcepermissions.NewActionSetService(), nil,
	)
	require.NoError(t, err)

	ProvideTeamAPI(
		router, teamSvc, &actest.FakeService{}, acimpl.ProvideAccessControl(features), permissions, userSvc,
		&licensing.OSSLicensingService{}, cfg, preftest.NewPreferenceServiceFake(), nil,
		dashboards.NewFakeDashboardService(t), features, nil, nil,
	)

	return &crossOrgTeamEnv{
		sql:         sqlStore,
		orgSvc:      orgSvc,
		teamSvc:     teamSvc,
		permissions: permissions,
		server:      webtest.NewServer(t, router),
		admin:       orgAdmin(adminUser),
		callerOrgID: adminUser.OrgID,
		outsider:    outsider,
		insider:     insider,
	}
}

func orgAdmin(admin *user.User) *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  admin.ID,
		OrgID:   admin.OrgID,
		OrgRole: org.RoleAdmin,
		Login:   admin.Login,
		Permissions: map[int64]map[string][]string{
			admin.OrgID: {
				accesscontrol.ActionTeamsPermissionsWrite: {accesscontrol.ScopeTeamsAll},
				accesscontrol.ActionTeamsPermissionsRead:  {accesscontrol.ScopeTeamsAll},
				accesscontrol.ActionOrgUsersRead:          {accesscontrol.ScopeUsersAll},
			},
		},
	}
}

func createCrossOrgUser(t *testing.T, userSvc user.Service, loginName, email, name string, orgID int64) *user.User {
	t.Helper()
	created, err := userSvc.Create(context.Background(), &user.CreateUserCommand{
		Login: loginName,
		Email: email,
		Name:  name,
		OrgID: orgID,
	})
	require.NoError(t, err)
	return created
}

func (e *crossOrgTeamEnv) createTeam(t *testing.T, name string) team.Team {
	t.Helper()
	created, err := e.teamSvc.CreateTeam(context.Background(), &team.CreateTeamCommand{
		Name:  name,
		Email: name + "@example.test",
		OrgID: e.callerOrgID,
	})
	require.NoError(t, err)
	return created
}

func (e *crossOrgTeamEnv) postMember(t *testing.T, teamID, userID int64) (int, string) {
	t.Helper()
	req := webtest.RequestWithSignedInUser(
		e.server.NewRequest(http.MethodPost, fmt.Sprintf("/api/teams/%d/members", teamID), strings.NewReader(fmt.Sprintf(`{"userId":%d}`, userID))),
		e.admin,
	)
	return e.send(t, req)
}

func (e *crossOrgTeamEnv) putMemberships(t *testing.T, teamID int64, members, admins []string) (int, string) {
	t.Helper()
	payload := map[string][]string{"members": members, "admins": admins}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	req := webtest.RequestWithSignedInUser(
		e.server.NewRequest(http.MethodPut, fmt.Sprintf("/api/teams/%d/members", teamID), strings.NewReader(string(raw))),
		e.admin,
	)
	return e.send(t, req)
}

func (e *crossOrgTeamEnv) postAccessControlUser(t *testing.T, teamID, userID int64, permission string) (int, string) {
	t.Helper()
	body := fmt.Sprintf(`{"permission":%q}`, permission)
	req := webtest.RequestWithSignedInUser(
		e.server.NewRequest(http.MethodPost, fmt.Sprintf("/api/access-control/teams/%d/users/%d", teamID, userID), strings.NewReader(body)),
		e.admin,
	)
	return e.send(t, req)
}

func (e *crossOrgTeamEnv) listMembers(t *testing.T, teamID int64) []team.TeamMemberDTO {
	t.Helper()
	req := webtest.RequestWithSignedInUser(e.server.NewGetRequest(fmt.Sprintf("/api/teams/%d/members", teamID)), e.admin)
	res, err := e.server.SendJSON(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode, string(raw))
	var members []team.TeamMemberDTO
	require.NoError(t, json.Unmarshal(raw, &members))
	return members
}

func (e *crossOrgTeamEnv) send(t *testing.T, req *http.Request) (int, string) {
	t.Helper()
	res, err := e.server.SendJSON(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(raw)
}

func (e *crossOrgTeamEnv) membershipCount(t *testing.T, teamID, userID int64) int64 {
	t.Helper()
	var count int64
	err := e.sql.WithDbSession(context.Background(), func(sess *db.Session) error {
		n, err := sess.Table("team_member").Where("org_id = ? AND team_id = ? AND user_id = ?", e.callerOrgID, teamID, userID).Count()
		count = n
		return err
	})
	require.NoError(t, err)
	return count
}

func (e *crossOrgTeamEnv) permissionCount(t *testing.T, userID int64, scope string) int64 {
	t.Helper()
	var count int64
	err := e.sql.WithDbSession(context.Background(), func(sess *db.Session) error {
		_, err := sess.SQL(`
			SELECT COUNT(*) FROM permission p
			INNER JOIN user_role ur ON ur.role_id = p.role_id
			WHERE ur.org_id = ? AND ur.user_id = ? AND p.scope = ?
		`, e.callerOrgID, userID, scope).Get(&count)
		return err
	})
	require.NoError(t, err)
	return count
}

func teamScope(teamID int64) string {
	return accesscontrol.Scope("teams", "id", fmt.Sprint(teamID))
}

func memberLogins(members []team.TeamMemberDTO) []string {
	return memberField(members, func(m team.TeamMemberDTO) string { return m.Login })
}

func memberEmails(members []team.TeamMemberDTO) []string {
	return memberField(members, func(m team.TeamMemberDTO) string { return m.Email })
}

func memberNames(members []team.TeamMemberDTO) []string {
	return memberField(members, func(m team.TeamMemberDTO) string { return m.Name })
}

func memberAuthModules(members []team.TeamMemberDTO) []string {
	return memberField(members, func(m team.TeamMemberDTO) string { return m.AuthModule })
}

func memberField(members []team.TeamMemberDTO, pick func(team.TeamMemberDTO) string) []string {
	out := make([]string, 0, len(members))
	for _, member := range members {
		out = append(out, pick(member))
	}
	return out
}
