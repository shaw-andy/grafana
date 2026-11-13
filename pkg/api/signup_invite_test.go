package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	tempuser "github.com/grafana/grafana/pkg/services/temp_user"
	"github.com/grafana/grafana/pkg/services/temp_user/tempuserimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// placeholderPassword is a non-secret stand-in that satisfies the length check
// applied when the strong password policy is off.
const placeholderPassword = "placeholder-password"

// signupInviteHarness exercises POST /api/user/signup/step2 against the real
// user, org, and temp-user stores. Session creation is stubbed after the
// invite decision; it does not decide which invites are applied.
type signupInviteHarness struct {
	server      *webtest.Server
	orgService  org.Service
	userService user.Service
	tempUsers   tempuser.Service
	autoOrgID   int64
}

func newSignupInviteHarness(t *testing.T, allowSignUp, verifyEmail bool) *signupInviteHarness {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.AllowUserSignUp = allowSignUp
	cfg.VerifyEmailEnabled = verifyEmail
	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgId = 1
	cfg.AutoAssignOrgRole = string(org.RoleViewer)
	cfg.LoginCookieName = "grafana_session"

	sqlStore := sqlstore.NewTestStore(t, sqlstore.WithCfg(cfg))
	// NewTestStore writes the database section into this same config object.
	// Repeat the signup settings so the handler and the user service share them.
	cfg.AllowUserSignUp = allowSignUp
	cfg.VerifyEmailEnabled = verifyEmail
	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgId = 1
	cfg.AutoAssignOrgRole = string(org.RoleViewer)

	quotaService := quotatest.New(false, nil)
	sql := legacysql.NewDatabaseProvider(sqlStore)
	orgService, err := orgimpl.ProvideService(sql, cfg, quotaService)
	require.NoError(t, err)
	userService, err := userimpl.ProvideService(
		sql, orgService, cfg, nil, nil, tracing.InitializeTracerForTest(),
		quotaService, supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)
	tempUsers := tempuserimpl.ProvideService(sqlStore, cfg)

	autoOrgID, err := orgService.GetOrCreate(context.Background(), "Main Org.")
	require.NoError(t, err)
	require.Equal(t, int64(cfg.AutoAssignOrgId), autoOrgID)

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.Features = featuremgmt.WithFeatures()
		hs.userService = userService
		hs.orgService = orgService
		hs.tempUserService = tempUsers
		hs.bus = bus.ProvideBus(tracing.InitializeTracerForTest())
		hs.log = log.New("signup-invite-test")
		hs.AuthTokenService = authtest.NewFakeUserAuthTokenService()
	})

	return &signupInviteHarness{
		server:      server,
		orgService:  orgService,
		userService: userService,
		tempUsers:   tempUsers,
		autoOrgID:   autoOrgID,
	}
}

func (h *signupInviteHarness) createOrg(t *testing.T, name string) int64 {
	t.Helper()
	created, err := h.orgService.CreateWithMember(context.Background(), &org.CreateOrgCommand{Name: name})
	require.NoError(t, err)
	return created.ID
}

func (h *signupInviteHarness) createInvite(t *testing.T, email string, orgID int64, role org.RoleType, code string) {
	t.Helper()
	_, err := h.tempUsers.CreateTempUser(context.Background(), &tempuser.CreateTempUserCommand{
		Email:  email,
		OrgID:  orgID,
		Role:   role,
		Code:   code,
		Status: tempuser.TmpUserInvitePending,
	})
	require.NoError(t, err)
}

func (h *signupInviteHarness) createSignupVerification(t *testing.T, email, code string) {
	t.Helper()
	_, err := h.tempUsers.CreateTempUser(context.Background(), &tempuser.CreateTempUserCommand{
		Email:  email,
		OrgID:  -1,
		Code:   code,
		Status: tempuser.TmpUserSignUpStarted,
	})
	require.NoError(t, err)
}

type signupStep2Body struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	Code     string `json:"code,omitempty"`
}

func (h *signupInviteHarness) postStep2(t *testing.T, body signupStep2Body) (int, string) {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := h.server.NewPostRequest("/api/user/signup/step2", strings.NewReader(string(payload)))
	res, err := h.server.SendJSON(req)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, res.Body.Close())
	}()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(raw)
}

func (h *signupInviteHarness) inviteStatus(t *testing.T, code string) tempuser.TempUserStatus {
	t.Helper()
	got, err := h.tempUsers.GetTempUserByCode(context.Background(), &tempuser.GetTempUserByCodeQuery{Code: code})
	require.NoError(t, err)
	return got.Status
}

func (h *signupInviteHarness) userByEmail(t *testing.T, email string) (*user.User, bool) {
	t.Helper()
	usr, err := h.userService.GetByLogin(context.Background(), &user.GetUserByLoginQuery{LoginOrEmail: email})
	if err != nil {
		require.ErrorIs(t, err, user.ErrUserNotFound)
		return nil, false
	}
	return usr, true
}

func (h *signupInviteHarness) roleInOrg(t *testing.T, userID, orgID int64) (org.RoleType, bool) {
	t.Helper()
	memberships, err := h.orgService.GetUserOrgList(context.Background(), &org.GetUserOrgListQuery{UserID: userID})
	require.NoError(t, err)
	for _, membership := range memberships {
		if membership.OrgID == orgID {
			return membership.Role, true
		}
	}
	return "", false
}

func assertInviteStillPending(t *testing.T, h *signupInviteHarness, code string) {
	t.Helper()
	require.Equal(t, tempuser.TmpUserInvitePending, h.inviteStatus(t, code))
}

func assertNotMember(t *testing.T, h *signupInviteHarness, userID, orgID int64) {
	t.Helper()
	_, member := h.roleInOrg(t, userID, orgID)
	require.False(t, member)
}

// TestIntegrationSignupStep2DoesNotConsumeInvitesWithoutCode is the unauthenticated
// signup completion the finding describes: allow_sign_up is on, verify_email is
// off, and the request omits the invite code.
func TestIntegrationSignupStep2DoesNotConsumeInvitesWithoutCode(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	h := newSignupInviteHarness(t, true, false)
	otherOrgID := h.createOrg(t, "Invited Org")
	const invitedEmail = "invited@example.com"
	const autoOrgInvite = "invite-code-auto-org"
	const otherOrgInvite = "invite-code-other-org"
	const unrelatedInvite = "invite-code-unrelated"

	h.createInvite(t, invitedEmail, h.autoOrgID, org.RoleAdmin, autoOrgInvite)
	h.createInvite(t, invitedEmail, otherOrgID, org.RoleAdmin, otherOrgInvite)
	h.createInvite(t, "someone-else@example.com", otherOrgID, org.RoleAdmin, unrelatedInvite)

	status, body := h.postStep2(t, signupStep2Body{
		Email:    invitedEmail,
		Name:     "Invited User",
		Username: "invited-user",
		Password: placeholderPassword,
	})
	require.NotEqualf(t, http.StatusInternalServerError, status, "signup handler failed before the invite decision: %s", body)
	require.NotContains(t, body, "User signup is disabled")

	assertInviteStillPending(t, h, autoOrgInvite)
	assertInviteStillPending(t, h, otherOrgInvite)
	assertInviteStillPending(t, h, unrelatedInvite)

	created, ok := h.userByEmail(t, invitedEmail)
	if !ok {
		return
	}
	role, member := h.roleInOrg(t, created.ID, h.autoOrgID)
	require.True(t, member)
	require.Equal(t, org.RoleViewer, role)
	assertNotMember(t, h, created.ID, otherOrgID)
}

func TestIntegrationSignupStep2DoesNotConsumeCaseVariantInviteWithoutCode(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	h := newSignupInviteHarness(t, true, false)
	otherOrgID := h.createOrg(t, "Case Org")
	const storedEmail = "Invited.User@Example.com"
	const submittedEmail = "invited.user@example.com"
	const inviteCode = "invite-code-case"

	h.createInvite(t, storedEmail, otherOrgID, org.RoleEditor, inviteCode)

	status, body := h.postStep2(t, signupStep2Body{
		Email:    submittedEmail,
		Name:     "Case User",
		Username: "case-user",
		Password: placeholderPassword,
	})
	require.NotEqualf(t, http.StatusInternalServerError, status, "signup handler failed before the invite decision: %s", body)
	require.NotContains(t, body, "User signup is disabled")

	assertInviteStillPending(t, h, inviteCode)
	created, ok := h.userByEmail(t, submittedEmail)
	if !ok {
		return
	}
	assertNotMember(t, h, created.ID, otherOrgID)
}

func TestIntegrationSignupStep2WrongCodeDoesNotConsumeInvites(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	h := newSignupInviteHarness(t, true, false)
	otherOrgID := h.createOrg(t, "Wrong Code Org")
	const invitedEmail = "wrong-code@example.com"
	const inviteCode = "invite-code-real"
	h.createInvite(t, invitedEmail, otherOrgID, org.RoleAdmin, inviteCode)

	status, body := h.postStep2(t, signupStep2Body{
		Email:    invitedEmail,
		Name:     "Wrong Code",
		Username: "wrong-code-user",
		Password: placeholderPassword,
		Code:     "not-the-invite-code",
	})
	require.NotEqualf(t, http.StatusInternalServerError, status, "signup handler failed before the invite decision: %s", body)
	require.NotContains(t, body, "User signup is disabled")

	assertInviteStillPending(t, h, inviteCode)
	created, ok := h.userByEmail(t, invitedEmail)
	if !ok {
		return
	}
	assertNotMember(t, h, created.ID, otherOrgID)
}

// TestIntegrationSignupStep2CodeAuthorizesOnlyTheMatchingInvite fails if a
// check of one invite code is then used to complete a different invite.
func TestIntegrationSignupStep2CodeAuthorizesOnlyTheMatchingInvite(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	h := newSignupInviteHarness(t, true, false)
	matchedOrgID := h.createOrg(t, "Matched Org")
	otherOrgID := h.createOrg(t, "Unmatched Org")
	const invitedEmail = "one-code@example.com"
	const matchedCode = "invite-code-matched"
	const otherCode = "invite-code-unmatched"
	h.createInvite(t, invitedEmail, matchedOrgID, org.RoleEditor, matchedCode)
	h.createInvite(t, invitedEmail, otherOrgID, org.RoleAdmin, otherCode)

	status, body := h.postStep2(t, signupStep2Body{
		Email:    invitedEmail,
		Name:     "One Code",
		Username: "one-code-user",
		Password: placeholderPassword,
		Code:     matchedCode,
	})
	require.NotEqualf(t, http.StatusInternalServerError, status, "signup handler failed before the invite decision: %s", body)
	require.NotContains(t, body, "User signup is disabled")

	assertInviteStillPending(t, h, otherCode)
	require.Equal(t, tempuser.TmpUserCompleted, h.inviteStatus(t, matchedCode))

	created, ok := h.userByEmail(t, invitedEmail)
	require.Truef(t, ok, "matching invite code should still create the account, body: %s", body)
	role, member := h.roleInOrg(t, created.ID, matchedOrgID)
	require.True(t, member)
	require.Equal(t, org.RoleEditor, role)
	assertNotMember(t, h, created.ID, otherOrgID)

	autoRole, autoMember := h.roleInOrg(t, created.ID, h.autoOrgID)
	require.True(t, autoMember)
	require.Equal(t, org.RoleViewer, autoRole)
}

// TestIntegrationSignupStep2MatchingCodeUpgradesExistingMembership covers an
// invite for the auto-assigned org. The code that was submitted is the only
// invite that may change that membership.
func TestIntegrationSignupStep2MatchingCodeUpgradesExistingMembership(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	h := newSignupInviteHarness(t, true, false)
	otherOrgID := h.createOrg(t, "Not This Org")
	const invitedEmail = "upgrade@example.com"
	const matchedCode = "invite-code-upgrade"
	const otherCode = "invite-code-leave-pending"
	h.createInvite(t, invitedEmail, h.autoOrgID, org.RoleAdmin, matchedCode)
	h.createInvite(t, invitedEmail, otherOrgID, org.RoleAdmin, otherCode)

	status, body := h.postStep2(t, signupStep2Body{
		Email:    invitedEmail,
		Name:     "Upgrade",
		Username: "upgrade-user",
		Password: placeholderPassword,
		Code:     matchedCode,
	})
	require.NotEqualf(t, http.StatusInternalServerError, status, "signup handler failed before the invite decision: %s", body)

	assertInviteStillPending(t, h, otherCode)
	require.Equal(t, tempuser.TmpUserCompleted, h.inviteStatus(t, matchedCode))

	created, ok := h.userByEmail(t, invitedEmail)
	require.Truef(t, ok, "matching invite code should still create the account, body: %s", body)
	role, member := h.roleInOrg(t, created.ID, h.autoOrgID)
	require.True(t, member)
	require.Equal(t, org.RoleAdmin, role)
	assertNotMember(t, h, created.ID, otherOrgID)
}

func TestIntegrationSignupStep2InviteCodeDoesNotAuthorizeOtherInvitesWhenVerificationEnabled(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	h := newSignupInviteHarness(t, true, true)
	matchedOrgID := h.createOrg(t, "Verified Match Org")
	otherOrgID := h.createOrg(t, "Verified Other Org")
	const invitedEmail = "verify-one@example.com"
	const matchedCode = "invite-code-verify-match"
	const otherCode = "invite-code-verify-other"
	h.createInvite(t, invitedEmail, matchedOrgID, org.RoleEditor, matchedCode)
	h.createInvite(t, invitedEmail, otherOrgID, org.RoleAdmin, otherCode)

	status, body := h.postStep2(t, signupStep2Body{
		Email:    invitedEmail,
		Name:     "Verify One",
		Username: "verify-one-user",
		Password: placeholderPassword,
		Code:     matchedCode,
	})
	require.NotEqualf(t, http.StatusInternalServerError, status, "signup handler failed before the invite decision: %s", body)

	assertInviteStillPending(t, h, otherCode)
	created, ok := h.userByEmail(t, invitedEmail)
	if !ok {
		assertInviteStillPending(t, h, matchedCode)
		return
	}
	assertNotMember(t, h, created.ID, otherOrgID)
	role, member := h.roleInOrg(t, created.ID, matchedOrgID)
	require.True(t, member)
	require.Equal(t, org.RoleEditor, role)
	require.Equal(t, tempuser.TmpUserCompleted, h.inviteStatus(t, matchedCode))
}

func TestIntegrationSignupStep2VerifiedEmailAppliesEveryInviteForThatAddress(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	h := newSignupInviteHarness(t, true, true)
	otherOrgID := h.createOrg(t, "Verified Email Org")
	const invitedEmail = "verified@example.com"
	const verificationCode = "signup-verification-code"
	const autoOrgInvite = "invite-code-verified-auto"
	const otherOrgInvite = "invite-code-verified-other"
	h.createSignupVerification(t, invitedEmail, verificationCode)
	h.createInvite(t, invitedEmail, h.autoOrgID, org.RoleAdmin, autoOrgInvite)
	h.createInvite(t, invitedEmail, otherOrgID, org.RoleEditor, otherOrgInvite)

	status, body := h.postStep2(t, signupStep2Body{
		Email:    invitedEmail,
		Name:     "Verified",
		Username: "verified-user",
		Password: placeholderPassword,
		Code:     verificationCode,
	})
	require.Equalf(t, http.StatusOK, status, "completed email verification should finish signup: %s", body)

	require.Equal(t, tempuser.TmpUserCompleted, h.inviteStatus(t, autoOrgInvite))
	require.Equal(t, tempuser.TmpUserCompleted, h.inviteStatus(t, otherOrgInvite))

	created, ok := h.userByEmail(t, invitedEmail)
	require.True(t, ok)
	autoRole, autoMember := h.roleInOrg(t, created.ID, h.autoOrgID)
	require.True(t, autoMember)
	require.Equal(t, org.RoleAdmin, autoRole)
	otherRole, otherMember := h.roleInOrg(t, created.ID, otherOrgID)
	require.True(t, otherMember)
	require.Equal(t, org.RoleEditor, otherRole)
}

func TestIntegrationSignupStep2VerificationFailureHasNoSideEffects(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	h := newSignupInviteHarness(t, true, true)
	otherOrgID := h.createOrg(t, "Rejected Org")
	const invitedEmail = "rejected@example.com"
	const inviteCode = "invite-code-rejected"
	h.createInvite(t, invitedEmail, otherOrgID, org.RoleAdmin, inviteCode)
	h.createSignupVerification(t, invitedEmail, "signup-verification-real")

	status, body := h.postStep2(t, signupStep2Body{
		Email:    invitedEmail,
		Name:     "Rejected",
		Username: "rejected-user",
		Password: placeholderPassword,
		Code:     "not-the-verification-code",
	})
	require.NotEqual(t, http.StatusOK, status, body)
	require.NotEqual(t, http.StatusInternalServerError, status, body)

	assertInviteStillPending(t, h, inviteCode)
	_, created := h.userByEmail(t, invitedEmail)
	require.False(t, created)
}

func TestIntegrationSignupDisabledDoesNotCreateAccountOrConsumeInvite(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	h := newSignupInviteHarness(t, false, false)
	otherOrgID := h.createOrg(t, "Disabled Signup Org")
	const invitedEmail = "disabled@example.com"
	const inviteCode = "invite-code-disabled"
	h.createInvite(t, invitedEmail, otherOrgID, org.RoleAdmin, inviteCode)

	status, body := h.postStep2(t, signupStep2Body{
		Email:    invitedEmail,
		Name:     "Disabled",
		Username: "disabled-user",
		Password: placeholderPassword,
	})
	require.Equal(t, http.StatusUnauthorized, status, body)
	require.Contains(t, body, "User signup is disabled")

	assertInviteStillPending(t, h, inviteCode)
	_, created := h.userByEmail(t, invitedEmail)
	require.False(t, created)
}
