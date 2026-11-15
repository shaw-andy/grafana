package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	tempuser "github.com/grafana/grafana/pkg/services/temp_user"
	"github.com/grafana/grafana/pkg/services/temp_user/tempusertest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

func TestOrgInvitesAPIEndpoint_RBAC(t *testing.T) {
	type testCase struct {
		desc         string
		body         string
		permissions  []accesscontrol.Permission
		expectedCode int
	}

	tests := []testCase{
		{
			desc: "should be able to invite user to org with correct permissions",
			body: `{"loginOrEmail": "new user", "role": "Viewer"}`,
			permissions: []accesscontrol.Permission{
				{Action: accesscontrol.ActionOrgUsersAdd, Scope: "users:id:1"},
			},
			expectedCode: http.StatusOK,
		},
		{
			desc:         "should not be able to invite user to org without correct permissions",
			body:         `{"loginOrEmail": "new user", "role": "Viewer"}`,
			permissions:  []accesscontrol.Permission{},
			expectedCode: http.StatusForbidden,
		},
		{
			desc: "should not be able to invite user to org with wrong scope",
			body: `{"loginOrEmail": "new user", "role": "Viewer"}`,
			permissions: []accesscontrol.Permission{
				{Action: accesscontrol.ActionOrgUsersAdd, Scope: "users:id:2"},
			},
			expectedCode: http.StatusForbidden,
		},
		{
			desc: "should not be able to invite user to org with higher role then requester",
			body: `{"loginOrEmail": "new user", "role": "Admin"}`,
			permissions: []accesscontrol.Permission{
				{Action: accesscontrol.ActionOrgUsersAdd, Scope: "users:id:1"},
			},
			expectedCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			server := SetupAPITestServer(t, func(hs *HTTPServer) {
				hs.Cfg = setting.NewCfg()
				hs.orgService = orgtest.NewOrgServiceFake()
				hs.userService = &usertest.FakeUserService{
					ExpectedUser: &user.User{ID: 1},
				}
			})

			req := webtest.RequestWithSignedInUser(server.NewPostRequest("/api/org/invites", strings.NewReader(tt.body)), userWithPermissions(1, tt.permissions))
			res, err := server.SendJSON(req)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedCode, res.StatusCode)
			require.NoError(t, res.Body.Close())
		})
	}
}

// TestAddOrgInvite_NewUserRequiresUsersWildcardScope covers POST /api/org/invites
// when the submitted login or email is not an existing user.
//
// A caller who holds org.users:add only for one user id may add that account and
// must not create a pending invite for any other address. Creating an invite for
// an address that is not a user requires org.users:add on users:*. The invite that
// is stored has to be for the submitted address, and a later lookup that returns
// a different account must not add that account.
//
// POST /api/org/users and POST /api/orgs/:orgId/users already require users:* on
// the route and are covered here so a change cannot move the missing check onto
// those handlers. GET /api/org/invites and PATCH /api/org/invites/:code/revoke use
// the same unscoped route permission but do not create a membership; they are not
// part of this spec.
func TestAddOrgInvite_NewUserRequiresUsersWildcardScope(t *testing.T) {
	const (
		orgID        = int64(1)
		callerID     = int64(99)
		scopedUserID = int64(1)
		otherUserID  = int64(2)
		scopedEmail  = "scoped-user@example.com"
		scopedLogin  = "scoped-user"
		otherEmail   = "other-user@example.com"
		otherLogin   = "other-user"
		unknownEmail = "stranger@example.com"
		unknownLogin = "stranger-login"
	)

	knownUsers := map[string]*user.User{
		scopedEmail: {ID: scopedUserID, Email: scopedEmail, Login: scopedLogin},
		scopedLogin: {ID: scopedUserID, Email: scopedEmail, Login: scopedLogin},
		otherEmail:  {ID: otherUserID, Email: otherEmail, Login: otherLogin},
		otherLogin:  {ID: otherUserID, Email: otherEmail, Login: otherLogin},
	}

	editor := func(permissions []accesscontrol.Permission) *user.SignedInUser {
		return &user.SignedInUser{
			UserID:  callerID,
			OrgID:   orgID,
			OrgRole: identity.RoleEditor,
			Permissions: map[int64]map[string][]string{
				orgID: accesscontrol.GroupScopesByActionContext(context.Background(), permissions),
			},
		}
	}
	scopedOnly := []accesscontrol.Permission{
		{Action: accesscontrol.ActionOrgUsersAdd, Scope: accesscontrol.Scope("users", "id", fmt.Sprintf("%d", scopedUserID))},
	}
	allUsers := []accesscontrol.Permission{
		{Action: accesscontrol.ActionOrgUsersAdd, Scope: accesscontrol.ScopeUsersAll},
	}

	type inviteResult struct {
		status  int
		invites []tempuser.CreateTempUserCommand
		added   []org.AddOrgUserCommand
		lookups []string
	}

	post := func(t *testing.T, path, body string, signedIn *user.SignedInUser) inviteResult {
		t.Helper()

		var mu sync.Mutex
		var invites []tempuser.CreateTempUserCommand
		var lookups []string
		unknownLookups := map[string]int{}
		orgSvc := &recordingOrgService{FakeOrgService: orgtest.NewOrgServiceFake()}

		// The first lookup of an unknown address is not found, matching both the
		// legacy SQL store and the Kubernetes user service. A later lookup of that
		// same address returns the other existing account. The authorization
		// decision and the account that is invited or added have to stay on the
		// address from the request.
		userSvc := &usertest.FakeUserService{
			GetByLoginFn: func(_ context.Context, query *user.GetUserByLoginQuery) (*user.User, error) {
				key := strings.ToLower(query.LoginOrEmail)
				mu.Lock()
				lookups = append(lookups, key)
				mu.Unlock()

				if found, ok := knownUsers[key]; ok {
					copied := *found
					return &copied, nil
				}

				mu.Lock()
				unknownLookups[key]++
				call := unknownLookups[key]
				mu.Unlock()
				if call == 1 {
					return nil, user.ErrUserNotFound
				}
				return &user.User{ID: otherUserID, Email: otherEmail, Login: otherLogin}, nil
			},
		}
		tempSvc := &tempusertest.FakeTempUserService{
			CreateTempUserFN: func(_ context.Context, cmd *tempuser.CreateTempUserCommand) (*tempuser.TempUser, error) {
				mu.Lock()
				invites = append(invites, *cmd)
				mu.Unlock()
				return &tempuser.TempUser{Email: cmd.Email, OrgID: cmd.OrgID, Code: cmd.Code, Role: cmd.Role, Status: cmd.Status}, nil
			},
		}

		cfg := setting.NewCfg()
		cfg.DisableLoginForm = false
		server := SetupAPITestServer(t, func(hs *HTTPServer) {
			hs.Cfg = cfg
			hs.orgService = orgSvc
			hs.userService = userSvc
			hs.tempUserService = tempSvc
		})

		req := webtest.RequestWithSignedInUser(server.NewPostRequest(path, strings.NewReader(body)), signedIn)
		res, err := server.SendJSON(req)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())

		mu.Lock()
		defer mu.Unlock()
		return inviteResult{status: res.StatusCode, invites: append([]tempuser.CreateTempUserCommand(nil), invites...), added: append([]org.AddOrgUserCommand(nil), orgSvc.added...), lookups: append([]string(nil), lookups...)}
	}

	inviteBody := func(loginOrEmail string, role identity.RoleType) string {
		return fmt.Sprintf(`{"loginOrEmail":%q,"role":%q,"name":"Outside","sendEmail":false}`, loginOrEmail, role)
	}

	t.Run("single user scope does not invite an unknown email", func(t *testing.T) {
		got := post(t, "/api/org/invites", inviteBody(unknownEmail, identity.RoleEditor), editor(scopedOnly))
		require.Equal(t, http.StatusForbidden, got.status)
		require.Empty(t, got.invites)
		require.Empty(t, got.added)
		require.NotEmpty(t, got.lookups)
		require.Equal(t, strings.ToLower(unknownEmail), got.lookups[0])
	})

	t.Run("single user scope does not invite an unknown login", func(t *testing.T) {
		got := post(t, "/api/org/invites", inviteBody(unknownLogin, identity.RoleViewer), editor(scopedOnly))
		require.Equal(t, http.StatusForbidden, got.status)
		require.Empty(t, got.invites)
		require.Empty(t, got.added)
		require.NotEmpty(t, got.lookups)
		require.Equal(t, strings.ToLower(unknownLogin), got.lookups[0])
	})

	t.Run("empty scope does not invite an unknown address", func(t *testing.T) {
		got := post(t, "/api/org/invites", inviteBody(unknownEmail, identity.RoleEditor), editor([]accesscontrol.Permission{
			{Action: accesscontrol.ActionOrgUsersAdd, Scope: ""},
		}))
		require.Equal(t, http.StatusForbidden, got.status)
		require.Empty(t, got.invites)
		require.Empty(t, got.added)
	})

	t.Run("users wildcard invites the submitted address and does not add a different account", func(t *testing.T) {
		got := post(t, "/api/org/invites", inviteBody(unknownEmail, identity.RoleEditor), editor(allUsers))
		require.Equal(t, http.StatusOK, got.status)
		require.Empty(t, got.added)
		require.Len(t, got.invites, 1)
		require.Equal(t, unknownEmail, got.invites[0].Email)
		require.Equal(t, "Outside", got.invites[0].Name)
		require.Equal(t, identity.RoleEditor, got.invites[0].Role)
		require.Equal(t, tempuser.TmpUserInvitePending, got.invites[0].Status)
		require.Equal(t, orgID, got.invites[0].OrgID)
		require.Equal(t, callerID, got.invites[0].InvitedByUserID)
		require.NotEmpty(t, got.invites[0].Code)
		require.NotEqual(t, otherEmail, got.invites[0].Email)
		require.NotEqual(t, otherUserID, got.invites[0].InvitedByUserID)
	})

	t.Run("users wildcard invites a submitted login at a role the caller holds", func(t *testing.T) {
		got := post(t, "/api/org/invites", inviteBody(unknownLogin, identity.RoleViewer), editor(allUsers))
		require.Equal(t, http.StatusOK, got.status)
		require.Empty(t, got.added)
		require.Len(t, got.invites, 1)
		require.Equal(t, unknownLogin, got.invites[0].Email)
		require.Equal(t, identity.RoleViewer, got.invites[0].Role)
		require.Equal(t, orgID, got.invites[0].OrgID)
	})

	t.Run("users wildcard cannot invite above the caller org role", func(t *testing.T) {
		got := post(t, "/api/org/invites", inviteBody(unknownEmail, identity.RoleAdmin), editor(allUsers))
		require.Equal(t, http.StatusForbidden, got.status)
		require.Empty(t, got.invites)
		require.Empty(t, got.added)
	})

	t.Run("single user scope still adds only that existing user", func(t *testing.T) {
		got := post(t, "/api/org/invites", inviteBody("Scoped-User@example.com", identity.RoleEditor), editor(scopedOnly))
		require.Equal(t, http.StatusOK, got.status)
		require.Empty(t, got.invites)
		require.Len(t, got.added, 1)
		require.Equal(t, scopedUserID, got.added[0].UserID)
		require.Equal(t, identity.RoleEditor, got.added[0].Role)
		require.Equal(t, orgID, got.added[0].OrgID)
		require.Equal(t, []string{scopedEmail}, got.lookups)
	})

	t.Run("single user scope does not add a different existing user", func(t *testing.T) {
		got := post(t, "/api/org/invites", inviteBody("Other-User@example.com", identity.RoleEditor), editor(scopedOnly))
		require.Equal(t, http.StatusForbidden, got.status)
		require.Empty(t, got.invites)
		require.Empty(t, got.added)
		require.Equal(t, []string{otherEmail}, got.lookups)
	})

	t.Run("missing org.users:add cannot invite", func(t *testing.T) {
		got := post(t, "/api/org/invites", inviteBody(unknownEmail, identity.RoleViewer), editor(nil))
		require.Equal(t, http.StatusForbidden, got.status)
		require.Empty(t, got.invites)
		require.Empty(t, got.added)
		require.Empty(t, got.lookups)
	})

	orgUserBody := fmt.Sprintf(`{"loginOrEmail":%q,"role":"Editor"}`, scopedEmail)
	t.Run("adding an existing user through the org users route still requires users:*", func(t *testing.T) {
		got := post(t, "/api/org/users", orgUserBody, editor(scopedOnly))
		require.Equal(t, http.StatusForbidden, got.status)
		require.Empty(t, got.invites)
		require.Empty(t, got.added)
		require.Empty(t, got.lookups)
	})

	t.Run("adding an existing user through the org id route still requires users:*", func(t *testing.T) {
		got := post(t, "/api/orgs/1/users", orgUserBody, editor(scopedOnly))
		require.Equal(t, http.StatusForbidden, got.status)
		require.Empty(t, got.invites)
		require.Empty(t, got.added)
		require.Empty(t, got.lookups)
	})
}

type recordingOrgService struct {
	*orgtest.FakeOrgService
	mu    sync.Mutex
	added []org.AddOrgUserCommand
}

func (r *recordingOrgService) AddOrgUser(ctx context.Context, cmd *org.AddOrgUserCommand) error {
	r.mu.Lock()
	r.added = append(r.added, *cmd)
	r.mu.Unlock()
	return r.FakeOrgService.AddOrgUser(ctx, cmd)
}
