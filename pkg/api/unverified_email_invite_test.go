package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/auth/idtest"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/login/authinfoimpl"
	"github.com/grafana/grafana/pkg/services/ngalert"
	"github.com/grafana/grafana/pkg/services/notifications"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	secretstest "github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	tempuserimpl "github.com/grafana/grafana/pkg/services/temp_user/tempuserimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// These tests are the specification for the unverified-email invite bug.
// They fail while a signed-in local user can store an unused email or login
// without proving control of the mailbox and a later organization invite, or
// an add-by-email, attaches that account to the target organization.
// They pass once that account is not granted the invited membership.

func TestIntegrationUnverifiedEmailClaimDoesNotGrantOrgMembership(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	cfg := loadShippedDefaults(t)
	require.False(t, cfg.Smtp.Enabled, "shipped default [smtp] enabled")
	require.False(t, cfg.VerifyEmailEnabled, "shipped default verify_email_enabled")
	require.False(t, cfg.AuthProxy.Enabled, "shipped default auth proxy")
	require.True(t, cfg.AutoAssignOrg)
	require.Equal(t, 1, cfg.AutoAssignOrgId)
	require.Equal(t, string(identity.RoleViewer), cfg.AutoAssignOrgRole)
	// Route registration touches the public-dashboard API when this flag is on.
	// The email and invite handlers do not read it.
	cfg.PublicDashboardsEnabled = false

	publicDir, err := filepath.Abs(filepath.Join("..", "..", "public"))
	require.NoError(t, err)
	cfg.StaticRootPath = publicDir

	store := sqlstore.NewTestStore(t, sqlstore.WithCfg(cfg))
	sql := legacysql.NewDatabaseProvider(store)
	quotaSvc := quotatest.New(false, nil)
	orgSvc, err := orgimpl.ProvideService(sql, cfg, quotaSvc)
	require.NoError(t, err)
	userSvc, err := userimpl.ProvideService(
		sql, orgSvc, cfg, nil, nil, tracing.InitializeTracerForTest(),
		quotaSvc, supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)
	tempUsers := tempuserimpl.ProvideService(store, cfg)
	authStore, err := authinfoimpl.ProvideStore(context.Background(), sql, secretstest.NewFakeSecretsService())
	require.NoError(t, err)
	authInfo := authinfoimpl.ProvideService(authStore, remotecache.NewFakeCacheStorage(), secretstest.NewFakeSecretsService())
	mailer := notifications.NewFakeMailer()
	notifier, err := notifications.ProvideService(bus.ProvideBus(tracing.InitializeTracerForTest()), cfg, mailer, nil)
	require.NoError(t, err)
	verifier := userimpl.ProvideVerifier(cfg, userSvc, tempUsers, notifier, &idtest.FakeService{})

	ctx := context.Background()
	bootstrap, err := userSvc.Create(ctx, &user.CreateUserCommand{
		Email:        "bootstrap@home.example",
		Login:        "bootstrap",
		Name:         "Bootstrap",
		SkipOrgSetup: true,
	})
	require.NoError(t, err)
	_, err = orgSvc.CreateWithMember(ctx, &org.CreateOrgCommand{Name: "Main Org.", UserID: bootstrap.ID})
	require.NoError(t, err)

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.log = log.New("unverified-email-invite-test")
		hs.SQLStore = store
		hs.userService = userSvc
		hs.orgService = orgSvc
		hs.tempUserService = tempUsers
		hs.authInfoService = authInfo
		hs.userVerifier = verifier
		hs.AlertNG = &ngalert.AlertNG{NotificationService: notifier}
	})

	tests := []struct {
		name         string
		smtp         bool
		verify       bool
		claim        claimKind
		previously   bool
		grant        grantKind
		role         org.RoleType
		sendEmail    bool
		externalLDAP bool
	}{
		{
			name:  "default config stores a new email and an invite adds that account",
			claim: claimEmailKeepingLogin,
			grant: grantInvite,
			role:  org.RoleAdmin,
		},
		{
			name:      "default config stores an email-only profile update and an invite still adds that account",
			claim:     claimEmailOmittingLogin,
			grant:     grantInvite,
			role:      org.RoleEditor,
			sendEmail: true,
		},
		{
			name:  "default config stores a login that is an unused email and an invite adds that account",
			claim: claimLoginAsEmail,
			grant: grantInvite,
			role:  org.RoleViewer,
		},
		{
			name:       "a previously verified account keeps the flag and an invite still adds it after the email changes",
			claim:      claimEmailKeepingLogin,
			previously: true,
			grant:      grantInvite,
			role:       org.RoleAdmin,
		},
		{
			name:   "verify_email_enabled without SMTP still stores the email and an invite adds that account",
			verify: true,
			claim:  claimEmailKeepingLogin,
			grant:  grantInvite,
			role:   org.RoleEditor,
		},
		{
			name:  "SMTP without verify_email_enabled still stores the email and an invite adds that account",
			smtp:  true,
			claim: claimEmailKeepingLogin,
			grant: grantInvite,
			role:  org.RoleAdmin,
		},
		{
			name:  "an administrator profile update stores another user's email and an invite adds that account",
			claim: claimEmailAsAdmin,
			grant: grantInvite,
			role:  org.RoleEditor,
		},
		{
			name:  "adding an organization user by the claimed email adds that account",
			claim: claimEmailKeepingLogin,
			grant: grantAddCurrentOrg,
			role:  org.RoleEditor,
		},
		{
			name:  "adding an organization user by org id and the claimed email adds that account",
			claim: claimEmailKeepingLogin,
			grant: grantAddOrgByID,
			role:  org.RoleAdmin,
		},
		{
			name:   "SMTP and verification together do not attach an unconfirmed address",
			smtp:   true,
			verify: true,
			claim:  claimEmailKeepingLogin,
			grant:  grantInvite,
			role:   org.RoleAdmin,
		},
		{
			name:         "an account authenticated by an enabled external provider cannot claim the address",
			claim:        claimEmailKeepingLogin,
			grant:        grantInvite,
			role:         org.RoleAdmin,
			externalLDAP: true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.Smtp.Enabled = tt.smtp
			cfg.VerifyEmailEnabled = tt.verify
			cfg.LDAPAuthEnabled = tt.externalLDAP
			t.Cleanup(func() {
				cfg.Smtp.Enabled = false
				cfg.VerifyEmailEnabled = false
				cfg.LDAPAuthEnabled = false
			})

			attacker, err := userSvc.Create(ctx, &user.CreateUserCommand{
				Email: fmt.Sprintf("attacker-%d@home.example", i),
				Login: fmt.Sprintf("attacker-%d", i),
				Name:  "Attacker",
			})
			require.NoError(t, err)
			target, err := orgSvc.CreateWithMember(ctx, &org.CreateOrgCommand{
				Name:   fmt.Sprintf("Target %d", i),
				UserID: bootstrap.ID,
			})
			require.NoError(t, err)

			if tt.previously {
				verified := true
				require.NoError(t, userSvc.Update(ctx, &user.UpdateUserCommand{
					UserID:        attacker.ID,
					EmailVerified: &verified,
				}))
			}
			if tt.externalLDAP {
				require.NoError(t, authInfo.SetAuthInfo(ctx, &login.SetAuthInfoCommand{
					AuthModule: login.LDAPAuthModule,
					AuthId:     fmt.Sprintf("ldap-%d", i),
					UserId:     attacker.ID,
					UserUID:    attacker.UID,
				}))
			}

			_, memberBefore := membershipRole(t, orgSvc, attacker.ID, target.ID)
			require.False(t, memberBefore, "attacker must start outside the target organization")

			// Each case claims a different unused address. Reusing one address makes
			// later updates conflict with the first account, so the invite attaches
			// that earlier account instead of the user this case created.
			claimed := fmt.Sprintf("Invited-%d.Person@Other.Example", i)
			updateStatus, updateBody := claimAddress(t, server, tt.claim, attacker, bootstrap, target.ID, claimed)
			grantStatus, grantBody := grantAddress(t, server, tt.grant, bootstrap, target.ID, claimed, tt.role, tt.sendEmail)
			t.Logf("profile update %d %s; grant %d %s", updateStatus, updateBody, grantStatus, grantBody)

			role, member := membershipRole(t, orgSvc, attacker.ID, target.ID)
			if member {
				stored, err := userSvc.GetByID(ctx, &user.GetUserByIDQuery{ID: attacker.ID})
				require.NoError(t, err)
				t.Fatalf("attacker %d joined org %d as %s after an unconfirmed claim of %s (stored email %s login %s verified %t); profile update %d %s; grant %d %s",
					attacker.ID, target.ID, role, claimed, stored.Email, stored.Login, stored.EmailVerified,
					updateStatus, updateBody, grantStatus, grantBody)
			}
		})
	}
}

type claimKind int

const (
	claimEmailKeepingLogin claimKind = iota
	claimEmailOmittingLogin
	claimLoginAsEmail
	claimEmailAsAdmin
)

type grantKind int

const (
	grantInvite grantKind = iota
	grantAddCurrentOrg
	grantAddOrgByID
)

func claimAddress(t *testing.T, server *webtest.Server, kind claimKind, attacker, admin *user.User, adminOrgID int64, claimed string) (int, string) {
	t.Helper()

	var (
		body    string
		method  = http.MethodPut
		path    = "/api/user"
		signer  = attacker
		orgID   = attacker.OrgID
		orgRole = identity.RoleViewer
		perms   map[int64]map[string][]string
	)
	switch kind {
	case claimEmailKeepingLogin:
		body = fmt.Sprintf(`{"email":%q,"login":%q,"name":"Attacker"}`, claimed, attacker.Login)
	case claimEmailOmittingLogin:
		body = fmt.Sprintf(`{"email":%q,"name":"Attacker"}`, claimed)
	case claimLoginAsEmail:
		body = fmt.Sprintf(`{"email":%q,"login":%q,"name":"Attacker"}`, attacker.Email, claimed)
	case claimEmailAsAdmin:
		body = fmt.Sprintf(`{"email":%q,"login":%q,"name":"Attacker"}`, claimed, attacker.Login)
		path = fmt.Sprintf("/api/users/%d", attacker.ID)
		signer = admin
		orgID = adminOrgID
		orgRole = identity.RoleAdmin
		perms = map[int64]map[string][]string{
			adminOrgID: {
				accesscontrol.ActionUsersWrite: {accesscontrol.ScopeGlobalUsersAll},
			},
		}
	default:
		t.Fatalf("unknown claim %d", kind)
	}

	return sendSignedIn(t, server, method, path, body, signer, orgID, orgRole, perms)
}

func grantAddress(t *testing.T, server *webtest.Server, kind grantKind, admin *user.User, orgID int64, claimed string, role org.RoleType, sendEmail bool) (int, string) {
	t.Helper()

	body := fmt.Sprintf(`{"loginOrEmail":%q,"role":%q,"sendEmail":%t,"name":"Invited Person"}`, claimed, role, sendEmail)
	path := "/api/org/invites"
	if kind == grantAddCurrentOrg || kind == grantAddOrgByID {
		body = fmt.Sprintf(`{"loginOrEmail":%q,"role":%q}`, claimed, role)
		path = "/api/org/users"
		if kind == grantAddOrgByID {
			path = fmt.Sprintf("/api/orgs/%d/users", orgID)
		}
	}
	return sendSignedIn(t, server, http.MethodPost, path, body, admin, orgID, identity.RoleAdmin, map[int64]map[string][]string{
		orgID: {
			accesscontrol.ActionOrgUsersAdd: {accesscontrol.ScopeUsersAll},
		},
	})
}

func sendSignedIn(t *testing.T, server *webtest.Server, method, path, body string, signer *user.User, orgID int64, orgRole identity.RoleType, perms map[int64]map[string][]string) (int, string) {
	t.Helper()

	req := webtest.RequestWithSignedInUser(server.NewRequest(method, path, strings.NewReader(body)), &user.SignedInUser{
		UserID:      signer.ID,
		UserUID:     signer.UID,
		OrgID:       orgID,
		OrgRole:     orgRole,
		Login:       signer.Login,
		Email:       signer.Email,
		Name:        signer.Name,
		Permissions: perms,
	})
	res, err := server.SendJSON(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	payload, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, strings.TrimSpace(string(payload))
}

func membershipRole(t *testing.T, orgSvc org.Service, userID, orgID int64) (org.RoleType, bool) {
	t.Helper()

	list, err := orgSvc.GetUserOrgList(context.Background(), &org.GetUserOrgListQuery{UserID: userID})
	require.NoError(t, err)
	for _, membership := range list {
		if membership.OrgID == orgID {
			return membership.Role, true
		}
	}
	return "", false
}

func loadShippedDefaults(t *testing.T) *setting.Cfg {
	t.Helper()

	path, err := filepath.Abs(filepath.Join("..", "..", "conf", "defaults.ini"))
	require.NoError(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	cfg, err := setting.NewCfgFromBytes(raw)
	require.NoError(t, err)
	return cfg
}
