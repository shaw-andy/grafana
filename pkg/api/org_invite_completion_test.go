package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	tempuser "github.com/grafana/grafana/pkg/services/temp_user"
	"github.com/grafana/grafana/pkg/services/temp_user/tempuserimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// placeholderPassword is an obvious placeholder, not a real credential.
const placeholderPassword = "placeholder-password"

// placeholderSession is an obvious placeholder, not a real session token.
const placeholderSession = "placeholder-session"

// TestInviteCompletionBindsAccountToInvitedLogin is the spec for invite completion.
// Cases that submit an identity other than the invited login fail while completion
// still creates that account. The email-invite cases record the behavior a fix must keep.
func TestInviteCompletionBindsAccountToInvitedLogin(t *testing.T) {
	cases := []struct {
		name              string
		verifyEmail       bool
		invitedLogin      string
		submittedEmail    string
		submittedUsername string
		// reject is false only for the supported email-invite completion, where the
		// submitted address is the invited address.
		reject bool
	}{
		{
			name:              "username invite completed as a different email and username",
			invitedLogin:      "invited-person",
			submittedEmail:    "other.person@example.com",
			submittedUsername: "other-person",
			reject:            true,
		},
		{
			name:              "username invite keeps the invited username but takes a caller supplied email",
			invitedLogin:      "invited-person",
			submittedEmail:    "other.person@example.com",
			submittedUsername: "invited-person",
			reject:            true,
		},
		{
			name:              "display name invite completed as a different email and username",
			invitedLogin:      "Invited Person",
			submittedEmail:    "other.person@example.com",
			submittedUsername: "other-person",
			reject:            true,
		},
		{
			name:              "username invite still unbound when email verification is enabled",
			verifyEmail:       true,
			invitedLogin:      "invited-person",
			submittedEmail:    "other.person@example.com",
			submittedUsername: "other-person",
			reject:            true,
		},
		{
			name:              "email invite rejects a different address",
			invitedLogin:      "invited.person@example.com",
			submittedEmail:    "other.person@example.com",
			submittedUsername: "other-person",
			reject:            true,
		},
		{
			name:              "email invite completes as the invited address",
			invitedLogin:      "invited.person@example.com",
			submittedEmail:    "invited.person@example.com",
			submittedUsername: "chosen-login",
			reject:            false,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			env := setupInviteCompletionEnv(t, tt.verifyEmail)
			code := env.invite(t, tt.invitedLogin, org.RoleEditor)

			status, body, cookies := env.completeUnauthenticated(t, code, tt.submittedEmail, tt.submittedUsername)
			created := env.users.createdSince(0)
			sessions := env.sessions.sessions

			if tt.reject {
				assert.GreaterOrEqual(t, status, 400, "body: %s", body)
				assert.Less(t, status, 500, "body: %s", body)
				assert.Empty(t, created, "completion persisted an account before refusing: %+v body: %s", created, body)
				assert.Empty(t, sessions, "completion signed in %+v", sessions)
				assert.NotContains(t, cookieNames(cookies), env.cfg.LoginCookieName)
				assert.False(t, accountExists(t, env, tt.submittedEmail), "submitted email was stored")
				if !strings.EqualFold(tt.submittedUsername, tt.invitedLogin) {
					assert.False(t, accountExists(t, env, tt.submittedUsername), "submitted username was stored")
				}
				for _, member := range env.orgMembers(t) {
					assert.NotEqual(t, strings.ToLower(tt.submittedEmail), strings.ToLower(member.Email))
					assert.NotEqual(t, strings.ToLower(tt.submittedUsername), strings.ToLower(member.Login))
					if strings.EqualFold(member.Email, tt.submittedEmail) || strings.EqualFold(member.Login, tt.submittedUsername) {
						t.Logf("org member email=%s login=%s role=%s", member.Email, member.Login, member.Role)
					}
				}
				invite, err := env.invites.GetTempUserByCode(context.Background(), &tempuser.GetTempUserByCodeQuery{Code: code})
				require.NoError(t, err)
				assert.Equal(t, tempuser.TmpUserInvitePending, invite.Status)
				return
			}

			require.Equal(t, http.StatusOK, status, "body: %s", body)
			require.Len(t, created, 1)
			require.Equal(t, tt.invitedLogin, created[0].Email)
			require.Equal(t, tt.submittedUsername, created[0].Login)
			require.False(t, created[0].EmailVerified)
			require.Len(t, sessions, 1)
			require.Equal(t, tt.invitedLogin, sessions[0].email)
			require.Contains(t, cookieNames(cookies), env.cfg.LoginCookieName)

			createdUser := env.requireUser(t, tt.submittedEmail)
			require.Equal(t, strings.ToLower(tt.submittedUsername), createdUser.Login)
			require.False(t, createdUser.EmailVerified)
			env.requireOrgRole(t, createdUser.ID, org.RoleEditor)
			env.requireInviteStatus(t, code, tempuser.TmpUserCompleted)
		})
	}
}

type recordedCreate struct {
	Email         string
	Login         string
	EmailVerified bool
}

type recordingUserService struct {
	user.Service
	created []recordedCreate
}

func (r *recordingUserService) Create(ctx context.Context, cmd *user.CreateUserCommand) (*user.User, error) {
	r.created = append(r.created, recordedCreate{
		Email:         cmd.Email,
		Login:         cmd.Login,
		EmailVerified: cmd.EmailVerified,
	})
	return r.Service.Create(ctx, cmd)
}

func (r *recordingUserService) createdSince(n int) []recordedCreate {
	if n > len(r.created) {
		return nil
	}
	return r.created[n:]
}

type recordedSession struct {
	email         string
	login         string
	emailVerified bool
}

type sessionRecorder struct {
	svc      *authtest.FakeUserAuthTokenService
	sessions []recordedSession
}

func newSessionRecorder() *sessionRecorder {
	r := &sessionRecorder{svc: authtest.NewFakeUserAuthTokenService()}
	r.svc.CreateTokenProvider = func(ctx context.Context, cmd *auth.CreateTokenCommand) (*auth.UserToken, error) {
		recorded := recordedSession{}
		userID := int64(0)
		if cmd != nil && cmd.User != nil {
			userID = cmd.User.ID
			recorded = recordedSession{email: cmd.User.Email, login: cmd.User.Login, emailVerified: cmd.User.EmailVerified}
		}
		r.sessions = append(r.sessions, recorded)
		return &auth.UserToken{UserId: userID, UnhashedToken: placeholderSession}, nil
	}
	return r
}

type inviteCompletionEnv struct {
	cfg      *setting.Cfg
	server   *webtest.Server
	users    *recordingUserService
	orgs     org.Service
	invites  tempuser.Service
	sessions *sessionRecorder
	admin    *user.SignedInUser
	orgID    int64
}

func setupInviteCompletionEnv(t *testing.T, verifyEmail bool) *inviteCompletionEnv {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.VerifyEmailEnabled = verifyEmail
	cfg.AutoAssignOrg = false
	cfg.BasicAuthStrongPasswordPolicy = false
	cfg.LoginCookieName = "grafana_session"

	sqlStore := db.NewTestStore(t, db.WithCfg(cfg))
	quotaSvc := quotatest.New(false, nil)
	orgSvc, err := orgimpl.ProvideService(legacysql.NewDatabaseProvider(sqlStore), cfg, quotaSvc)
	require.NoError(t, err)
	userSvc, err := userimpl.ProvideService(
		legacysql.NewDatabaseProvider(sqlStore), orgSvc, cfg, nil, nil, tracing.InitializeTracerForTest(),
		quotaSvc, supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)

	adminUser, err := userSvc.Create(context.Background(), &user.CreateUserCommand{
		Email:    "org-admin@example.com",
		Login:    "org-admin",
		Name:     "Org Admin",
		Password: placeholderPassword,
	})
	require.NoError(t, err)
	require.NotZero(t, adminUser.OrgID)

	recorder := &recordingUserService{Service: userSvc}
	sessions := newSessionRecorder()
	inviteSvc := tempuserimpl.ProvideService(sqlStore, cfg)

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.log = log.New("invite-completion-test")
		hs.bus = bus.ProvideBus(tracing.InitializeTracerForTest())
		hs.SQLStore = sqlStore
		hs.userService = recorder
		hs.tempUserService = inviteSvc
		hs.orgService = orgSvc
		hs.QuotaService = quotaSvc
		hs.AuthTokenService = sessions.svc
	})

	return &inviteCompletionEnv{
		cfg:      cfg,
		server:   server,
		users:    recorder,
		orgs:     orgSvc,
		invites:  inviteSvc,
		sessions: sessions,
		orgID:    adminUser.OrgID,
		admin: &user.SignedInUser{
			UserID:  adminUser.ID,
			OrgID:   adminUser.OrgID,
			OrgRole: org.RoleAdmin,
			Login:   adminUser.Login,
			Email:   adminUser.Email,
			Permissions: map[int64]map[string][]string{
				adminUser.OrgID: {accesscontrol.ActionOrgUsersAdd: {"users:id:*"}},
			},
		},
	}
}

func (e *inviteCompletionEnv) invite(t *testing.T, loginOrEmail string, role org.RoleType) string {
	t.Helper()

	body := dtos.AddInviteForm{LoginOrEmail: loginOrEmail, Name: loginOrEmail, Role: role, SendEmail: false}
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	req := webtest.RequestWithSignedInUser(e.server.NewPostRequest("/api/org/invites", strings.NewReader(string(payload))), e.admin)
	res, err := e.server.SendJSON(req)
	require.NoError(t, err)
	responseBody := readBody(t, res)
	require.Equal(t, http.StatusOK, res.StatusCode, "invite create failed: %s", responseBody)

	listReq := webtest.RequestWithSignedInUser(e.server.NewGetRequest("/api/org/invites"), e.admin)
	listRes, err := e.server.Send(listReq)
	require.NoError(t, err)
	listBody := readBody(t, listRes)
	require.Equal(t, http.StatusOK, listRes.StatusCode, "pending invites failed: %s", listBody)

	var pending []*tempuser.TempUserDTO
	require.NoError(t, json.Unmarshal([]byte(listBody), &pending))
	var invite *tempuser.TempUserDTO
	for _, candidate := range pending {
		if candidate.Email == loginOrEmail {
			invite = candidate
			break
		}
	}
	require.NotNil(t, invite, "pending invites: %s", listBody)

	prefix := setting.ToAbsUrl("invite/")
	require.True(t, strings.HasPrefix(invite.URL, prefix), "invite url %q", invite.URL)
	code := strings.TrimPrefix(invite.URL, prefix)
	require.NotEmpty(t, code)
	require.Equal(t, invite.Code, code)
	require.Equal(t, role, invite.Role)
	return code
}

func (e *inviteCompletionEnv) completeUnauthenticated(t *testing.T, code, email, username string) (int, string, []*http.Cookie) {
	t.Helper()

	before := len(e.users.created)
	body := dtos.CompleteInviteForm{
		InviteCode: code,
		Email:      email,
		Name:       "Submitted Name",
		Username:   username,
		Password:   placeholderPassword,
	}
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	// No signed-in user: the completion route does not require authentication.
	req := e.server.NewPostRequest("/api/user/invite/complete", strings.NewReader(string(payload)))
	res, err := e.server.SendJSON(req)
	require.NoError(t, err)
	responseBody := readBody(t, res)
	e.users.created = e.users.created[before:]
	return res.StatusCode, responseBody, res.Cookies()
}

func accountExists(t *testing.T, env *inviteCompletionEnv, loginOrEmail string) bool {
	t.Helper()
	usr, err := env.users.GetByLogin(context.Background(), &user.GetUserByLoginQuery{LoginOrEmail: loginOrEmail})
	if errors.Is(err, user.ErrUserNotFound) {
		return false
	}
	require.NoError(t, err)
	t.Logf("stored account email=%s login=%s emailVerified=%v", usr.Email, usr.Login, usr.EmailVerified)
	return true
}

func (e *inviteCompletionEnv) requireUser(t *testing.T, email string) *user.User {
	t.Helper()
	usr, err := e.users.GetByEmail(context.Background(), &user.GetUserByEmailQuery{Email: email})
	require.NoError(t, err)
	return usr
}

func (e *inviteCompletionEnv) requireOrgRole(t *testing.T, userID int64, role org.RoleType) {
	t.Helper()
	orgs, err := e.orgs.GetUserOrgList(context.Background(), &org.GetUserOrgListQuery{UserID: userID})
	require.NoError(t, err)
	require.NotEmpty(t, orgs)
	var matched bool
	for _, membership := range orgs {
		if membership.OrgID == e.orgID {
			require.Equal(t, role, membership.Role)
			matched = true
		}
	}
	require.True(t, matched, "user %d orgs: %+v", userID, orgs)
}

func (e *inviteCompletionEnv) requireInviteStatus(t *testing.T, code string, status tempuser.TempUserStatus) {
	t.Helper()
	invite, err := e.invites.GetTempUserByCode(context.Background(), &tempuser.GetTempUserByCodeQuery{Code: code})
	require.NoError(t, err)
	require.Equal(t, status, invite.Status)
}

func (e *inviteCompletionEnv) orgMembers(t *testing.T) []*org.OrgUserDTO {
	t.Helper()
	members, err := e.orgs.GetOrgUsers(context.Background(), &org.GetOrgUsersQuery{
		OrgID:                    e.orgID,
		DontEnforceAccessControl: true,
		Limit:                    50,
	})
	require.NoError(t, err)
	return members
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	payload, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return string(payload)
}

func cookieNames(cookies []*http.Cookie) []string {
	names := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		names = append(names, cookie.Name)
	}
	return names
}

func sessionEmails(sessions []recordedSession) []string {
	emails := make([]string, 0, len(sessions))
	for _, session := range sessions {
		emails = append(emails, session.email)
	}
	return emails
}
