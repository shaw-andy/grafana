package userimpl

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/serverlock"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/loginattempt/loginattemptimpl"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/util/testutil"
)

func TestIntegrationShortPasswordFloor(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	shipped := setting.NewCfg()
	require.NoError(t, shipped.Load(setting.CommandLineArgs{
		HomePath: "../../../..",
		Config:   "../../../../conf/defaults.ini",
	}))
	require.True(t, shipped.BasicAuthEnabled)
	require.False(t, shipped.DisableLogin)
	require.False(t, shipped.DisableLoginForm)
	require.False(t, shipped.LDAPAuthEnabled)
	require.False(t, shipped.DisableBruteForceLoginProtection)
	require.False(t, shipped.DisableUsernameLoginProtection)
	require.Equal(t, int64(5), shipped.BruteForceLoginProtectionMaxAttempts)

	ss, cfg := db.InitTestDBWithCfg(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	cfg.BasicAuthEnabled = shipped.BasicAuthEnabled
	cfg.BasicAuthStrongPasswordPolicy = false
	cfg.DisableLogin = shipped.DisableLogin
	cfg.DisableLoginForm = shipped.DisableLoginForm
	cfg.LDAPAuthEnabled = shipped.LDAPAuthEnabled
	cfg.DisableBruteForceLoginProtection = shipped.DisableBruteForceLoginProtection
	cfg.BruteForceLoginProtectionMaxAttempts = shipped.BruteForceLoginProtectionMaxAttempts
	cfg.DisableUsernameLoginProtection = shipped.DisableUsernameLoginProtection
	cfg.DisableIPAddressLoginProtection = shipped.DisableIPAddressLoginProtection
	cfg.AutoAssignOrg = false

	orgSvc, usrSvc := createOrgAndUserSvc(t, ss, cfg)
	tracer := tracing.InitializeTracerForTest()
	attempts := loginattemptimpl.ProvideService(ss, cfg, serverlock.ProvideService(legacysql.NewDatabaseProvider(ss), tracer))
	grafanaClient := clients.ProvideGrafana(cfg, usrSvc, tracer)
	passwords := clients.ProvidePassword(attempts, tracer, disabledLDAP(cfg, usrSvc, tracer), grafanaClient)
	ctx := context.Background()

	t.Run("create rejects a short password before writing a user or org", func(t *testing.T) {
		loginName := "create-short"
		email := loginName + "@example.com"
		_, err := usrSvc.Create(ctx, &user.CreateUserCommand{
			Login:    loginName,
			Email:    email,
			Password: passwordOfLen(4),
		})
		require.Error(t, err)
		require.True(t, isPasswordPolicyError(err))
		requireUserMissing(t, ctx, usrSvc, loginName)
		_, orgErr := orgSvc.GetByName(ctx, &org.GetOrgByNameQuery{Name: email})
		require.Error(t, orgErr)
		require.False(t, formLoginSucceeds(t, passwords, loginName, string(passwordOfLen(4))))
	})

	t.Run("password change keeps the previous password", func(t *testing.T) {
		loginName := "change-short"
		current := passwordOfLen(user.MinPasswordLength)
		created := mustCreateUser(t, ctx, usrSvc, loginName, current)
		require.True(t, formLoginSucceeds(t, passwords, loginName, string(current)))

		err := usrSvc.Update(ctx, &user.UpdateUserCommand{
			UserID:      created.ID,
			OldPassword: &current,
			Password:    passwordOfLenPtr(4),
		})
		require.Error(t, err)
		require.True(t, isPasswordPolicyError(err))
		require.False(t, formLoginSucceeds(t, passwords, loginName, string(passwordOfLen(4))))
		require.True(t, formLoginSucceeds(t, passwords, loginName, string(current)))
		require.False(t, basicLoginSucceeds(t, passwords, loginName, string(passwordOfLen(4))))
	})

	t.Run("administrator password update keeps the previous password", func(t *testing.T) {
		loginName := "admin-set-short"
		current := passwordOfLen(user.MinPasswordLength)
		created := mustCreateUser(t, ctx, usrSvc, loginName, current)

		err := usrSvc.Update(ctx, &user.UpdateUserCommand{
			UserID:   created.ID,
			Password: passwordOfLenPtr(11),
		})
		require.Error(t, err)
		require.True(t, isPasswordPolicyError(err))
		require.False(t, formLoginSucceeds(t, passwords, loginName, string(passwordOfLen(11))))
		require.True(t, formLoginSucceeds(t, passwords, loginName, string(current)))
	})

	t.Run("twelve character password without character classes is accepted when the policy is off", func(t *testing.T) {
		loginName := "create-floor"
		current := passwordOfLen(user.MinPasswordLength)
		created := mustCreateUser(t, ctx, usrSvc, loginName, current)
		require.True(t, formLoginSucceeds(t, passwords, loginName, string(current)))

		replacement := passwordOfLen(user.MinPasswordLength + 1)
		require.NoError(t, usrSvc.Update(ctx, &user.UpdateUserCommand{
			UserID:   created.ID,
			Password: &replacement,
		}))
		require.True(t, formLoginSucceeds(t, passwords, loginName, string(replacement)))
		require.False(t, formLoginSucceeds(t, passwords, loginName, string(current)))
	})

	t.Run("username lockout blocks the attempt after the shipped maximum", func(t *testing.T) {
		loginName := "lockout-user"
		current := passwordOfLen(user.MinPasswordLength)
		mustCreateUser(t, ctx, usrSvc, loginName, current)
		wrong := passwordOfLen(user.MinPasswordLength + 3)

		for i := int64(0); i < cfg.BruteForceLoginProtectionMaxAttempts; i++ {
			err := formLogin(t, passwords, loginName, string(wrong))
			require.Error(t, err)
			require.NotContains(t, err.Error(), "temporarily blocked")
		}
		blocked := formLogin(t, passwords, loginName, string(current))
		require.Error(t, blocked)
		require.Contains(t, blocked.Error(), "temporarily blocked")
	})
}

func mustCreateUser(t *testing.T, ctx context.Context, svc user.Service, loginName string, password user.Password) *user.User {
	t.Helper()
	created, err := svc.Create(ctx, &user.CreateUserCommand{
		Login:    loginName,
		Email:    loginName + "@example.com",
		Password: password,
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)
	return created
}

func requireUserMissing(t *testing.T, ctx context.Context, svc user.Service, loginName string) {
	t.Helper()
	_, err := svc.GetByLogin(ctx, &user.GetUserByLoginQuery{LoginOrEmail: loginName})
	require.ErrorIs(t, err, user.ErrUserNotFound)
}

func passwordOfLen(length int) user.Password {
	return user.Password(strings.Repeat("p", length))
}

func passwordOfLenPtr(length int) *user.Password {
	password := passwordOfLen(length)
	return &password
}

func isPasswordPolicyError(err error) bool {
	return errors.Is(err, user.ErrPasswordTooShort) || errors.Is(err, user.ErrPasswordPolicyInfringe)
}

func formLoginSucceeds(t *testing.T, passwords authn.PasswordClient, username, password string) bool {
	t.Helper()
	identity, err := formLoginIdentity(t, passwords, username, password)
	return err == nil && identity != nil
}

func formLogin(t *testing.T, passwords authn.PasswordClient, username, password string) error {
	t.Helper()
	_, err := formLoginIdentity(t, passwords, username, password)
	return err
}

func formLoginIdentity(t *testing.T, passwords authn.PasswordClient, username, password string) (*authn.Identity, error) {
	t.Helper()
	body := strings.NewReader(`{"user":"` + username + `","password":"` + password + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.10:1234"
	form := clients.ProvideForm(passwords)
	return form.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
}

func basicLoginSucceeds(t *testing.T, passwords authn.PasswordClient, username, password string) bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/user", nil)
	req.SetBasicAuth(username, password)
	req.RemoteAddr = "203.0.113.11:1234"
	basic := clients.ProvideBasic(passwords)
	identity, err := basic.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
	return err == nil && identity != nil
}

type ldapDisabled struct{}

func (ldapDisabled) Login(*login.LoginUserQuery) (*login.ExternalUserInfo, error) {
	return nil, nil
}

func (ldapDisabled) User(string) (*login.ExternalUserInfo, error) {
	return nil, nil
}

func (ldapDisabled) Enabled() bool { return false }

func disabledLDAP(cfg *setting.Cfg, users user.Service, tracer tracing.Tracer) *clients.LDAP {
	return clients.ProvideLDAP(cfg, ldapDisabled{}, users, nil, tracer)
}
