package api

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

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
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

// placeholderPassword is not a credential. Signup completion requires a password
// field, and this value exists only so the handler can reach verification.
const placeholderPassword = "placeholder-password"

// TestIntegrationSignupVerificationCodeExpiry covers POST /api/user/signup/step2.
// A signup code must be rejected unless its temp-user row is still SignUpStarted
// and its created time is inside user_invite_max_lifetime_duration. The row is
// put in its final state before the request, so a second read of the same code
// sees the same status and age as the first. These cases fail while completion
// ignores status and created time.
func TestIntegrationSignupVerificationCodeExpiry(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	const inviteLifetime = 24 * time.Hour
	// Distinct from inviteLifetime so a check against verification_email_max_lifetime_duration
	// rejects a code that is still inside the invite lifetime.
	const verificationLifetime = time.Hour
	const insideLifetime = 2 * time.Hour
	const outsideLifetime = 48 * time.Hour

	cfg := setting.NewCfg()
	cfg.AllowUserSignUp = true
	cfg.VerifyEmailEnabled = true
	cfg.AutoAssignOrg = false
	cfg.UserInviteMaxLifetime = inviteLifetime
	cfg.VerificationEmailMaxLifetime = verificationLifetime
	cfg.LoginCookieName = "grafana_session"

	sqlStore := db.InitTestDB(t, sqlstore.InitTestDBOpt{Cfg: cfg}) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	tempUserSvc := tempuserimpl.ProvideService(sqlStore, cfg)
	orgSvc, err := orgimpl.ProvideService(legacysql.NewDatabaseProvider(sqlStore), cfg, quotatest.New(false, nil))
	require.NoError(t, err)
	userSvc, err := userimpl.ProvideService(
		legacysql.NewDatabaseProvider(sqlStore), orgSvc, cfg, nil, nil, tracing.InitializeTracerForTest(),
		quotatest.New(false, nil), supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.SQLStore = sqlStore
		hs.userService = userSvc
		hs.tempUserService = tempUserSvc
		hs.bus = bus.ProvideBus(tracing.InitializeTracerForTest())
		hs.AuthTokenService = authtest.NewFakeUserAuthTokenService()
		hs.log = log.New("signup-verification-expiry-test")
	})

	statusOf := func(status tempuser.TempUserStatus) *tempuser.TempUserStatus {
		return &status
	}

	tests := []struct {
		name          string
		age           time.Duration
		status        *tempuser.TempUserStatus
		runCleanup    bool
		overrideEmail bool
		accept        bool
	}{
		{
			name:   "fresh signup code",
			accept: true,
		},
		{
			name:   "signup code still inside invite lifetime",
			age:    insideLifetime,
			accept: true,
		},
		{
			name: "signup code older than invite lifetime before cleanup",
			age:  outsideLifetime,
		},
		{
			name:       "signup code marked expired by cleanup",
			age:        outsideLifetime,
			runCleanup: true,
		},
		{
			name:   "completed signup code",
			status: statusOf(tempuser.TmpUserCompleted),
		},
		{
			name:   "revoked code",
			status: statusOf(tempuser.TmpUserRevoked),
		},
		{
			name:   "pending invite code",
			status: statusOf(tempuser.TmpUserInvitePending),
		},
		{
			name:   "email update code",
			status: statusOf(tempuser.TmpUserEmailUpdateStarted),
		},
		{
			name:   "expired email update code",
			status: statusOf(tempuser.TmpUserEmailUpdateExpired),
		},
		{
			name:          "signup code for a different email",
			overrideEmail: true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := uniqueSignupEmail(i)
			code := startSignup(t, server, tempUserSvc, email)

			if tt.age > 0 {
				setTempUserCreated(t, sqlStore, code, time.Now().Add(-tt.age))
			}
			if tt.status != nil {
				require.NoError(t, tempUserSvc.UpdateTempUserStatus(context.Background(), &tempuser.UpdateTempUserStatusCommand{
					Code:   code,
					Status: *tt.status,
				}))
			}
			if tt.runCleanup {
				// Same cutoff as CleanUpService.expireOldUserInvites.
				cmd := tempuser.ExpireTempUsersCommand{OlderThan: time.Now().Add(-cfg.UserInviteMaxLifetime)}
				require.NoError(t, tempUserSvc.ExpireOldUserInvites(context.Background(), &cmd))
				require.GreaterOrEqual(t, cmd.NumExpired, int64(1))
			}

			loaded, err := tempUserSvc.GetTempUserByCode(context.Background(), &tempuser.GetTempUserByCodeQuery{Code: code})
			require.NoError(t, err)
			require.Equal(t, email, loaded.Email)
			if tt.runCleanup {
				require.Equal(t, tempuser.TmpUserExpired, loaded.Status)
			} else if tt.status != nil {
				require.Equal(t, *tt.status, loaded.Status)
			} else {
				require.Equal(t, tempuser.TmpUserSignUpStarted, loaded.Status)
			}
			if tt.age > cfg.UserInviteMaxLifetime {
				require.False(t, loaded.Created.IsZero(), "signup row created time was not returned with the code")
				require.True(t, loaded.Created.Before(time.Now().Add(-cfg.UserInviteMaxLifetime)), "stored created time is still inside the invite lifetime")
			}
			if tt.accept {
				require.False(t, loaded.Created.IsZero(), "signup row created time was not returned with the code")
				require.True(t, loaded.Created.After(time.Now().Add(-cfg.UserInviteMaxLifetime)), "stored created time is already outside the invite lifetime")
			}

			submittedEmail := email
			if tt.overrideEmail {
				submittedEmail = uniqueSignupEmail(100 + i)
			}
			status, body := postSignupStep2(t, server, submittedEmail, code)

			assertNoUser := func(addr string) {
				t.Helper()
				_, lookupErr := userSvc.GetByLogin(context.Background(), &user.GetUserByLoginQuery{LoginOrEmail: addr})
				require.ErrorIs(t, lookupErr, user.ErrUserNotFound, "status=%d body=%s", status, body)
			}

			if tt.accept {
				require.Equalf(t, http.StatusOK, status, "body=%s", body)
				created, lookupErr := userSvc.GetByLogin(context.Background(), &user.GetUserByLoginQuery{LoginOrEmail: email})
				require.NoError(t, lookupErr)
				require.True(t, created.EmailVerified)
				after, err := tempUserSvc.GetTempUserByCode(context.Background(), &tempuser.GetTempUserByCodeQuery{Code: code})
				require.NoError(t, err)
				require.Equal(t, tempuser.TmpUserCompleted, after.Status)
				return
			}

			require.GreaterOrEqualf(t, status, 400, "body=%s", body)
			require.Lessf(t, status, 500, "body=%s", body)
			assertNoUser(email)
			assertNoUser(submittedEmail)
			after, err := tempUserSvc.GetTempUserByCode(context.Background(), &tempuser.GetTempUserByCodeQuery{Code: code})
			require.NoError(t, err)
			require.NotEqual(t, tempuser.TmpUserCompleted, after.Status)
			require.Equal(t, loaded.Status, after.Status)
		})
	}
}

func uniqueSignupEmail(n int) string {
	return fmt.Sprintf("signup-%d-%d@example.test", time.Now().UnixNano(), n)
}

func startSignup(t *testing.T, server *webtest.Server, tempUserSvc tempuser.Service, email string) string {
	t.Helper()

	body := `{"email":"` + email + `"}`
	req := withUnauthenticatedRequester(server.NewPostRequest("/api/user/signup", strings.NewReader(body)))
	resp, err := server.SendJSON(req)
	require.NoError(t, err)
	responseBody := readResponseBody(t, resp)
	require.Equalf(t, http.StatusOK, resp.StatusCode, "body=%s", responseBody)

	// SignUp stores the code and the signup email copies that same value into the link.
	rows, err := tempUserSvc.GetTempUsersQuery(context.Background(), &tempuser.GetTempUsersQuery{
		Email:  email,
		Status: tempuser.TmpUserSignUpStarted,
	})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.NotEmpty(t, rows[0].Code)
	return rows[0].Code
}

func postSignupStep2(t *testing.T, server *webtest.Server, email string, code string) (int, string) {
	t.Helper()

	payload, err := json.Marshal(map[string]string{
		"email":    email,
		"code":     code,
		"username": email,
		"password": placeholderPassword,
		"name":     "Signup Test",
	})
	require.NoError(t, err)

	req := withUnauthenticatedRequester(server.NewPostRequest("/api/user/signup/step2", strings.NewReader(string(payload))))
	resp, err := server.SendJSON(req)
	require.NoError(t, err)
	body := readResponseBody(t, resp)
	return resp.StatusCode, body
}

// withUnauthenticatedRequester matches ContextHandler when authentication fails:
// the request still carries an empty signed-in user, and it is not signed in.
func withUnauthenticatedRequester(req *http.Request) *http.Request {
	return webtest.RequestWithWebContext(req, &contextmodel.ReqContext{
		SignedInUser: &user.SignedInUser{Permissions: map[int64]map[string][]string{}},
	})
}

func readResponseBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b)
}

func setTempUserCreated(t *testing.T, store *sqlstore.SQLStore, code string, created time.Time) {
	t.Helper()
	err := store.WithDbSession(context.Background(), func(sess *sqlstore.DBSession) error {
		_, err := sess.Exec("UPDATE temp_user SET created = ? WHERE code = ?", created.Unix(), code)
		return err
	})
	require.NoError(t, err)
}
