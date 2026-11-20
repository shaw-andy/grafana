package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/serverlock"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/login/authinfotest"
	"github.com/grafana/grafana/pkg/services/loginattempt/loginattemptimpl"
	"github.com/grafana/grafana/pkg/services/notifications"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	tempuser "github.com/grafana/grafana/pkg/services/temp_user"
	"github.com/grafana/grafana/pkg/services/temp_user/tempusertest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web"
)

func TestIntegrationShortPasswordHandlers(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	ss, cfg := db.InitTestDBWithCfg(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	cfg.BasicAuthEnabled = true
	cfg.BasicAuthStrongPasswordPolicy = false
	cfg.DisableLogin = false
	cfg.DisableLoginForm = false
	cfg.DisableBruteForceLoginProtection = false
	cfg.BruteForceLoginProtectionMaxAttempts = 5
	cfg.DisableUsernameLoginProtection = false
	cfg.DisableIPAddressLoginProtection = true
	cfg.AutoAssignOrg = false
	cfg.AllowUserSignUp = false
	cfg.VerifyEmailEnabled = false
	cfg.SecretKey = "placeholder-signing-key"
	cfg.EmailCodeValidMinutes = 60
	cfg.LoginCookieName = "grafana_session"

	tracer := tracing.InitializeTracerForTest()
	orgSvc, err := orgimpl.ProvideService(legacysql.NewDatabaseProvider(ss), cfg, quotatest.New(false, nil))
	require.NoError(t, err)
	usrSvc, err := userimpl.ProvideService(
		legacysql.NewDatabaseProvider(ss), orgSvc, cfg, nil, nil, tracer,
		quotatest.New(false, nil), supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)
	attempts := loginattemptimpl.ProvideService(ss, cfg, serverlock.ProvideService(legacysql.NewDatabaseProvider(ss), tracer))
	passwords := clients.ProvidePassword(attempts, tracer, clients.ProvideGrafana(cfg, usrSvc, tracer))
	tokens := authtest.NewFakeUserAuthTokenService()
	tokens.RevokeAllUserTokensProvider = func(context.Context, int64) error { return nil }
	hs := &HTTPServer{
		log:                 log.New("test"),
		Cfg:                 cfg,
		bus:                 bus.ProvideBus(tracer),
		userService:         usrSvc,
		orgService:          orgSvc,
		authInfoService:     &authinfotest.FakeService{ExpectedError: user.ErrUserNotFound},
		loginAttemptService: attempts,
		AuthTokenService:    tokens,
		NotificationService: &notifications.NotificationService{Cfg: cfg},
		tempUserService:     &tempusertest.FakeTempUserService{},
	}
	ctx := context.Background()

	t.Run("signed-in password change", func(t *testing.T) {
		loginName := "handler-change"
		current := passwordOfLen(user.MinPasswordLength)
		created := mustCreateLocalUser(t, ctx, usrSvc, loginName, current)
		replacement := passwordOfLen(user.MinPasswordLength + 1)
		resp := hs.ChangeUserPassword(passwordChangeContext(t, created.ID, current, replacement))
		require.Equal(t, http.StatusOK, resp.Status())
		require.True(t, formLoginSucceeds(t, passwords, loginName, string(replacement)))

		short := passwordOfLen(4)
		resp = hs.ChangeUserPassword(passwordChangeContext(t, created.ID, replacement, short))
		require.NotEqual(t, http.StatusOK, resp.Status())
		require.False(t, formLoginSucceeds(t, passwords, loginName, string(short)))
		require.True(t, formLoginSucceeds(t, passwords, loginName, string(replacement)))
	})

	t.Run("administrator create", func(t *testing.T) {
		acceptedLogin := "handler-admin-create-ok"
		accepted := passwordOfLen(user.MinPasswordLength)
		resp := hs.AdminCreateUser(jsonContext(t, http.MethodPost, "/api/admin/users", dtos.AdminCreateUserForm{
			Login:    acceptedLogin,
			Email:    acceptedLogin + "@example.com",
			Password: accepted,
		}, nil))
		require.Equal(t, http.StatusOK, resp.Status())
		require.True(t, formLoginSucceeds(t, passwords, acceptedLogin, string(accepted)))

		rejectedLogin := "handler-admin-create-short"
		rejectedEmail := rejectedLogin + "@example.com"
		resp = hs.AdminCreateUser(jsonContext(t, http.MethodPost, "/api/admin/users", dtos.AdminCreateUserForm{
			Login:    rejectedLogin,
			Email:    rejectedEmail,
			Password: passwordOfLen(4),
		}, nil))
		require.NotEqual(t, http.StatusOK, resp.Status())
		requireUserMissing(t, ctx, usrSvc, rejectedLogin)
		_, orgErr := orgSvc.GetByName(ctx, &org.GetOrgByNameQuery{Name: rejectedEmail})
		require.Error(t, orgErr)
		require.False(t, formLoginSucceeds(t, passwords, rejectedLogin, string(passwordOfLen(4))))
	})

	t.Run("administrator password update", func(t *testing.T) {
		loginName := "handler-admin-set"
		otherName := "handler-admin-set-other"
		current := passwordOfLen(user.MinPasswordLength)
		otherPassword := passwordOfLen(user.MinPasswordLength + 2)
		created := mustCreateLocalUser(t, ctx, usrSvc, loginName, current)
		mustCreateLocalUser(t, ctx, usrSvc, otherName, otherPassword)
		replacement := passwordOfLen(user.MinPasswordLength + 1)

		resp := hs.AdminUpdateUserPassword(adminPasswordContext(t, created.ID, replacement))
		require.Equal(t, http.StatusOK, resp.Status())
		require.True(t, formLoginSucceeds(t, passwords, loginName, string(replacement)))
		require.True(t, formLoginSucceeds(t, passwords, otherName, string(otherPassword)))

		short := passwordOfLen(4)
		resp = hs.AdminUpdateUserPassword(adminPasswordContext(t, created.ID, short))
		require.NotEqual(t, http.StatusOK, resp.Status())
		require.False(t, formLoginSucceeds(t, passwords, loginName, string(short)))
		require.False(t, formLoginSucceeds(t, passwords, otherName, string(short)))
		require.True(t, formLoginSucceeds(t, passwords, loginName, string(replacement)))
		require.True(t, formLoginSucceeds(t, passwords, otherName, string(otherPassword)))
	})

	t.Run("password reset", func(t *testing.T) {
		loginName := "handler-reset"
		current := passwordOfLen(user.MinPasswordLength)
		created := mustCreateLocalUser(t, ctx, usrSvc, loginName, current)
		stored := mustStoredUser(t, ctx, usrSvc, loginName)
		replacement := passwordOfLen(user.MinPasswordLength + 1)

		resp := hs.ResetPassword(resetContext(t, emailResetCode(t, cfg, stored), replacement))
		require.Equal(t, http.StatusOK, resp.Status())
		require.True(t, formLoginSucceeds(t, passwords, loginName, string(replacement)))

		stored = mustStoredUser(t, ctx, usrSvc, loginName)
		short := passwordOfLen(4)
		resp = hs.ResetPassword(resetContext(t, emailResetCode(t, cfg, stored), short))
		require.NotEqual(t, http.StatusOK, resp.Status())
		require.False(t, formLoginSucceeds(t, passwords, loginName, string(short)))
		require.True(t, formLoginSucceeds(t, passwords, loginName, string(replacement)))
		require.Equal(t, created.ID, stored.ID)
	})

	t.Run("invite completion", func(t *testing.T) {
		anchor := mustCreateLocalUser(t, ctx, usrSvc, "handler-invite-anchor", passwordOfLen(user.MinPasswordLength))
		acceptedLogin := "handler-invite-ok"
		acceptedEmail := acceptedLogin + "@example.com"
		accepted := passwordOfLen(user.MinPasswordLength)
		hs.tempUserService = inviteService(anchor.OrgID, acceptedEmail)
		resp := hs.CompleteInvite(jsonContext(t, http.MethodPost, "/api/user/invite/complete", dtos.CompleteInviteForm{
			InviteCode:      "invite-ok",
			Email:           acceptedEmail,
			Username:        acceptedLogin,
			Password:        accepted,
			ConfirmPassword: accepted,
		}, nil))
		require.Equal(t, http.StatusOK, resp.Status())
		require.True(t, formLoginSucceeds(t, passwords, acceptedLogin, string(accepted)))

		rejectedLogin := "handler-invite-short"
		rejectedEmail := rejectedLogin + "@example.com"
		hs.tempUserService = inviteService(anchor.OrgID, rejectedEmail)
		resp = hs.CompleteInvite(jsonContext(t, http.MethodPost, "/api/user/invite/complete", dtos.CompleteInviteForm{
			InviteCode:      "invite-short",
			Email:           rejectedEmail,
			Username:        rejectedLogin,
			Password:        passwordOfLen(4),
			ConfirmPassword: passwordOfLen(4),
		}, nil))
		require.NotEqual(t, http.StatusOK, resp.Status())
		requireUserMissing(t, ctx, usrSvc, rejectedLogin)
		require.False(t, formLoginSucceeds(t, passwords, rejectedLogin, string(passwordOfLen(4))))
	})

	t.Run("signup completion when signup is enabled", func(t *testing.T) {
		cfg.AllowUserSignUp = true
		t.Cleanup(func() { cfg.AllowUserSignUp = false })

		acceptedLogin := "handler-signup-ok"
		accepted := passwordOfLen(user.MinPasswordLength)
		resp := hs.SignUpStep2(jsonContext(t, http.MethodPost, "/api/user/signup/step2", dtos.SignUpStep2Form{
			Email:    acceptedLogin + "@example.com",
			Username: acceptedLogin,
			Password: accepted,
		}, nil))
		require.Equal(t, http.StatusOK, resp.Status())
		require.True(t, formLoginSucceeds(t, passwords, acceptedLogin, string(accepted)))

		rejectedLogin := "handler-signup-short"
		rejectedEmail := rejectedLogin + "@example.com"
		resp = hs.SignUpStep2(jsonContext(t, http.MethodPost, "/api/user/signup/step2", dtos.SignUpStep2Form{
			Email:    rejectedEmail,
			Username: rejectedLogin,
			Password: passwordOfLen(4),
		}, nil))
		require.NotEqual(t, http.StatusOK, resp.Status())
		requireUserMissing(t, ctx, usrSvc, rejectedLogin)
		_, orgErr := orgSvc.GetByName(ctx, &org.GetOrgByNameQuery{Name: rejectedEmail})
		require.Error(t, orgErr)
	})
}

func mustCreateLocalUser(t *testing.T, ctx context.Context, svc user.Service, loginName string, password user.Password) *user.User {
	t.Helper()
	created, err := svc.Create(ctx, &user.CreateUserCommand{
		Login:    loginName,
		Email:    loginName + "@example.com",
		Password: password,
	})
	require.NoError(t, err)
	return created
}

func mustStoredUser(t *testing.T, ctx context.Context, svc user.Service, loginName string) *user.User {
	t.Helper()
	stored, err := svc.GetByLogin(ctx, &user.GetUserByLoginQuery{LoginOrEmail: loginName})
	require.NoError(t, err)
	require.NotEmpty(t, stored.Rands)
	require.NotEmpty(t, stored.Password)
	return stored
}

func requireUserMissing(t *testing.T, ctx context.Context, svc user.Service, loginName string) {
	t.Helper()
	_, err := svc.GetByLogin(ctx, &user.GetUserByLoginQuery{LoginOrEmail: loginName})
	require.ErrorIs(t, err, user.ErrUserNotFound)
}

func passwordOfLen(length int) user.Password {
	return user.Password(strings.Repeat("p", length))
}

func passwordChangeContext(t *testing.T, userID int64, oldPassword, newPassword user.Password) *contextmodel.ReqContext {
	t.Helper()
	return jsonContext(t, http.MethodPut, "/api/user/password", user.ChangeUserPasswordCommand{
		OldPassword: oldPassword,
		NewPassword: newPassword,
	}, &user.SignedInUser{UserID: userID, Login: "signed-in"})
}

func adminPasswordContext(t *testing.T, userID int64, password user.Password) *contextmodel.ReqContext {
	t.Helper()
	reqCtx := jsonContext(t, http.MethodPut, "/api/admin/users/"+strconv.FormatInt(userID, 10)+"/password", dtos.AdminUpdateUserPasswordForm{
		Password: password,
	}, nil)
	reqCtx.Req = web.SetURLParams(reqCtx.Req, map[string]string{":id": strconv.FormatInt(userID, 10)})
	return reqCtx
}

func resetContext(t *testing.T, code string, password user.Password) *contextmodel.ReqContext {
	t.Helper()
	return jsonContext(t, http.MethodPost, "/api/user/password/reset", dtos.ResetUserPasswordForm{
		Code:            code,
		NewPassword:     password,
		ConfirmPassword: password,
	}, nil)
}

func jsonContext(t *testing.T, method, target string, body any, signedIn *user.SignedInUser) *contextmodel.ReqContext {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(method, target, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.20:9"
	if signedIn == nil {
		signedIn = &user.SignedInUser{}
	}
	return &contextmodel.ReqContext{
		Context:      &web.Context{Req: req, Resp: web.NewResponseWriter(method, httptest.NewRecorder())},
		SignedInUser: signedIn,
		Logger:       log.New("test"),
	}
}

func inviteService(orgID int64, email string) *tempusertest.FakeTempUserService {
	invite := &tempuser.TempUserDTO{
		OrgID:  orgID,
		Email:  email,
		Status: tempuser.TmpUserInvitePending,
		Code:   "invite",
		Role:   org.RoleViewer,
	}
	return &tempusertest.FakeTempUserService{
		GetTempUserByCodeFN: func(context.Context, *tempuser.GetTempUserByCodeQuery) (*tempuser.TempUserDTO, error) {
			return invite, nil
		},
		UpdateTempUserStatusFN: func(context.Context, *tempuser.UpdateTempUserStatusCommand) error {
			return nil
		},
	}
}

// emailResetCode reproduces the code layout in pkg/services/notifications/codes.go
// so the real NotificationService.ValidateResetPasswordCode accepts it.
func emailResetCode(t *testing.T, cfg *setting.Cfg, usr *user.User) string {
	t.Helper()
	const minutes = 60
	start := time.Now()
	startStr := start.Format("200601021504")
	endStr := start.Add(time.Minute * minutes).Format("200601021504")
	payload := strconv.FormatInt(usr.ID, 10) + usr.Email + usr.Login + string(usr.Password) + usr.Rands
	mac := hmac.New(sha256.New, []byte(cfg.SecretKey))
	_, err := mac.Write([]byte(payload + startStr + endStr))
	require.NoError(t, err)
	code := fmt.Sprintf("%s%06d%s", startStr, minutes, hex.EncodeToString(mac.Sum(nil)))
	code += hex.EncodeToString([]byte(usr.Login))

	ns := &notifications.NotificationService{Cfg: cfg}
	got, err := ns.ValidateResetPasswordCode(context.Background(), &notifications.ValidateResetPasswordCodeQuery{Code: code}, func(_ context.Context, loginName string) (*user.User, error) {
		if loginName != usr.Login {
			return nil, user.ErrUserNotFound
		}
		return usr, nil
	})
	require.NoError(t, err)
	require.Equal(t, usr.ID, got.ID)
	return code
}

func formLoginSucceeds(t *testing.T, passwords authn.PasswordClient, username, password string) bool {
	t.Helper()
	body := strings.NewReader(`{"user":"` + username + `","password":"` + password + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.21:9"
	form := clients.ProvideForm(passwords)
	identity, err := form.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
	return err == nil && identity != nil
}
