package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/login/authinfoimpl"
	"github.com/grafana/grafana/pkg/services/notifications"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	secretsdb "github.com/grafana/grafana/pkg/services/secrets/database"
	secretsManager "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// TestUnauthenticatedResetEmailResponseIsIndependentOfAccount is the spec for
// the password-reset account oracle. An anonymous POST to
// /api/user/password/send-reset-email must return the same HTTP 200 body for
// every candidate, including when the account is an active local user and the
// shipped SMTP configuration cannot send mail.
func TestUnauthenticatedResetEmailResponseIsIndependentOfAccount(t *testing.T) {
	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: "../../",
		Config:   "../../conf/defaults.ini",
	}))
	require.False(t, cfg.DisableLogin, "shipped default leaves Grafana login enabled")
	require.False(t, cfg.DisableLoginForm, "shipped default leaves the login form enabled")
	require.False(t, cfg.Smtp.Enabled, "shipped default leaves SMTP disabled")
	require.False(t, cfg.LDAPAuthEnabled, "shipped default leaves LDAP disabled")
	require.NotEmpty(t, cfg.LoginCookieName)
	// registerRoutes touches the public-dashboard API when this flag is on.
	// The reset handler does not. The test server does not construct that API.
	cfg.PublicDashboardsEnabled = false

	sqlStore := sqlstore.NewTestStore(t)
	sqlstore.SeedDefaultOrgAndUser(t, sqlStore)
	// Login and email of the account SeedDefaultOrgAndUser creates when the test
	// config has no admin identity. These match conf/defaults.ini admin_user and admin_email.
	const seededAdminLogin = "admin"
	const seededAdminEmail = "admin@localhost"

	dbProvider := legacysql.NewDatabaseProvider(sqlStore)
	quotaSvc := quotatest.New(false, nil)
	orgSvc, err := orgimpl.ProvideService(dbProvider, cfg, quotaSvc)
	require.NoError(t, err)
	userSvc, err := userimpl.ProvideService(
		dbProvider, orgSvc, cfg, nil, nil, tracing.InitializeTracerForTest(),
		quotaSvc, supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)

	ctx := context.Background()
	admin, err := userSvc.GetByLogin(ctx, &user.GetUserByLoginQuery{LoginOrEmail: seededAdminLogin})
	require.NoError(t, err)
	require.False(t, admin.IsDisabled)
	require.False(t, admin.IsServiceAccount)
	require.Equal(t, seededAdminEmail, admin.Email)

	disabledUser, err := userSvc.Create(ctx, &user.CreateUserCommand{
		Login:      "reset-oracle-disabled",
		Email:      "reset-oracle-disabled@example.com",
		Name:       "Disabled",
		IsDisabled: true,
	})
	require.NoError(t, err)
	require.True(t, disabledUser.IsDisabled)

	localUser, err := userSvc.Create(ctx, &user.CreateUserCommand{
		Login: "reset-oracle-local",
		Email: "reset-oracle-local@example.com",
		Name:  "Local",
	})
	require.NoError(t, err)
	require.False(t, localUser.IsDisabled)
	require.False(t, localUser.IsServiceAccount)

	externalUser, err := userSvc.Create(ctx, &user.CreateUserCommand{
		Login: "reset-oracle-external",
		Email: "reset-oracle-external@example.com",
		Name:  "External",
	})
	require.NoError(t, err)

	secretsSvc := secretsManager.SetupTestService(t, secretsdb.ProvideSecretsStore(sqlStore))
	authInfoStore, err := authinfoimpl.ProvideStore(ctx, dbProvider, secretsSvc)
	require.NoError(t, err)
	authInfoSvc := authinfoimpl.ProvideService(authInfoStore, remotecache.NewFakeCacheStorage(), secretsSvc)
	require.NoError(t, authInfoSvc.SetAuthInfo(ctx, &login.SetAuthInfoCommand{
		AuthModule: login.LDAPAuthModule,
		AuthId:     "reset-oracle-external-id",
		UserId:     externalUser.ID,
		UserUID:    externalUser.UID,
	}))

	serviceAccount, err := userSvc.CreateServiceAccount(ctx, &user.CreateUserCommand{
		Login:          "reset-oracle-sa",
		Name:           "Reset Oracle SA",
		OrgID:          admin.OrgID,
		DefaultOrgRole: string(org.RoleViewer),
	})
	require.NoError(t, err)
	require.True(t, serviceAccount.IsServiceAccount)

	mailer, err := notifications.ProvideSmtpService(cfg)
	require.NoError(t, err)
	notifier, err := notifications.ProvideService(bus.ProvideBus(tracing.InitializeTracerForTest()), cfg, mailer, nil)
	require.NoError(t, err)

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.userService = userSvc
		hs.authInfoService = authInfoSvc
		hs.NotificationService = notifier
	})
	server.Mux.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())

	// Candidates that must be indistinguishable from a name that is not an account.
	// The built-in administrator is included by the login and email stored for the seeded admin.
	candidates := []string{
		"reset-oracle-missing",
		"reset-oracle-missing@example.com",
		seededAdminLogin,
		seededAdminEmail,
		localUser.Login,
		localUser.Email,
		disabledUser.Login,
		disabledUser.Email,
		serviceAccount.Login,
		externalUser.Login,
	}

	t.Run("smtp disabled", func(t *testing.T) {
		require.False(t, cfg.Smtp.Enabled)
		require.False(t, cfg.LDAPAuthEnabled)
		for _, candidate := range candidates {
			t.Run(candidate, func(t *testing.T) {
				status, message := postResetEmail(t, server, candidate)
				requireSameResetResponse(t, status, message)
			})
		}

		t.Run("external provider enabled", func(t *testing.T) {
			cfg.LDAPAuthEnabled = true
			t.Cleanup(func() { cfg.LDAPAuthEnabled = false })
			status, message := postResetEmail(t, server, externalUser.Login)
			requireSameResetResponse(t, status, message)
		})
	})

	t.Run("smtp enabled", func(t *testing.T) {
		cfg.Smtp.Enabled = true
		t.Cleanup(func() { cfg.Smtp.Enabled = false })
		for _, candidate := range []string{
			"reset-oracle-missing",
			seededAdminLogin,
			localUser.Email,
			externalUser.Login,
		} {
			t.Run(candidate, func(t *testing.T) {
				status, message := postResetEmail(t, server, candidate)
				requireSameResetResponse(t, status, message)
			})
		}
	})

	t.Run("login form disabled", func(t *testing.T) {
		cfg.DisableLoginForm = true
		t.Cleanup(func() { cfg.DisableLoginForm = false })
		missingStatus, missingMessage := postResetEmail(t, server, "reset-oracle-missing")
		adminStatus, adminMessage := postResetEmail(t, server, seededAdminLogin)
		require.Equal(t, missingStatus, adminStatus)
		require.Equal(t, missingMessage, adminMessage)
		require.Equal(t, http.StatusUnauthorized, missingStatus)
	})
}

func requireSameResetResponse(t *testing.T, status int, message string) {
	t.Helper()
	require.Equal(t, http.StatusOK, status, "status must not depend on whether the account exists (message %q)", message)
	require.Equal(t, "Email sent", message, "body must not depend on whether the account exists")
}

func postResetEmail(t *testing.T, server *webtest.Server, userOrEmail string) (int, string) {
	t.Helper()

	req := server.NewPostRequest("/api/user/password/send-reset-email", strings.NewReader(fmt.Sprintf(`{"userOrEmail":%q}`, userOrEmail)))
	req.Header.Del("Cookie")
	resp, err := server.SendJSON(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(raw, &payload), "body: %s", raw)
	message, _ := payload["message"].(string)
	return resp.StatusCode, message
}
