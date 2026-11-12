package authnimpl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api"
	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	acdb "github.com/grafana/grafana/pkg/services/accesscontrol/database"
	"github.com/grafana/grafana/pkg/services/accesscontrol/permreg"
	"github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl/sync"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/ldap/service"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/login/authinfoimpl"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginaccesscontrol"
	"github.com/grafana/grafana/pkg/services/quota"
	"github.com/grafana/grafana/pkg/services/quota/quotaimpl"
	secretsdb "github.com/grafana/grafana/pkg/services/secrets/database"
	secretsmanager "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/ssosettings/ssosettingstests"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/team/teamimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/tests/testsuite"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

const (
	trustedProxyAddr  = "198.51.100.20:8443"
	attackerProxyAddr = "203.0.113.50:40000"
	newProxyLogin     = "proxy-created-user"
)

func TestShippedAuthProxyConfigLeavesWhitelistEmpty(t *testing.T) {
	cfg := loadShippedConfig(t)

	require.False(t, cfg.AuthProxy.Enabled)
	require.Empty(t, cfg.AuthProxy.Whitelist)
	require.True(t, cfg.AuthProxy.AutoSignUp)
	require.Equal(t, "X-WEBAUTH-USER", cfg.AuthProxy.HeaderName)
	require.Equal(t, "username", cfg.AuthProxy.HeaderProperty)
	require.False(t, cfg.LDAPAuthEnabled)
	require.NotEmpty(t, cfg.AdminUser)
}

func TestAuthProxyEmptyWhitelistDoesNotImpersonateServerAdmin(t *testing.T) {
	env := newAuthProxyEnv(t, "")
	admin := env.createServerAdmin(t)
	if env.proxy == nil {
		return
	}

	identity, err := env.authenticate(t, env.proxy, attackerProxyAddr, admin.Login)
	requireNotImpersonated(t, identity, err)

	_, authErr := env.authInfo.GetAuthInfo(context.Background(), &login.GetAuthInfoQuery{
		UserId:     admin.ID,
		AuthModule: login.AuthProxyAuthModule,
	})
	require.ErrorIs(t, authErr, user.ErrUserNotFound)
}

func TestAuthProxyWhitespaceWhitelistDoesNotImpersonateServerAdmin(t *testing.T) {
	env := newAuthProxyEnv(t, " \t\n ")
	admin := env.createServerAdmin(t)
	if env.proxy == nil {
		return
	}

	identity, err := env.authenticate(t, env.proxy, attackerProxyAddr, admin.Login)
	requireNotImpersonated(t, identity, err)
}

func TestAuthProxyEmptyWhitelistDoesNotSignUpNewLogin(t *testing.T) {
	env := newAuthProxyEnv(t, "")
	if env.proxy == nil {
		_, lookupErr := env.users.GetByLogin(context.Background(), &user.GetUserByLoginQuery{LoginOrEmail: newProxyLogin})
		require.ErrorIs(t, lookupErr, user.ErrUserNotFound)
		return
	}

	identity, err := env.authenticate(t, env.proxy, attackerProxyAddr, newProxyLogin)
	requireNotImpersonated(t, identity, err)

	_, lookupErr := env.users.GetByLogin(context.Background(), &user.GetUserByLoginQuery{LoginOrEmail: newProxyLogin})
	require.ErrorIs(t, lookupErr, user.ErrUserNotFound)
}

func TestAuthProxyEmptyWhitelistLoginDoesNotCreateSession(t *testing.T) {
	env := newAuthProxyEnv(t, "")
	admin := env.createServerAdmin(t)
	if env.proxy == nil {
		return
	}

	var sessionFor int64
	env.sessions.CreateTokenProvider = func(_ context.Context, cmd *auth.CreateTokenCommand) (*auth.UserToken, error) {
		sessionFor = cmd.User.ID
		return &auth.UserToken{UserId: cmd.User.ID}, nil
	}

	req := proxyRequest(env.cfg.AuthProxy.HeaderName, admin.Login, attackerProxyAddr)
	identity, err := env.svc.Login(context.Background(), authn.ClientProxy, req)
	requireNotImpersonated(t, identity, err)
	require.Zero(t, sessionFor)
}

func TestAuthProxyEmptyWhitelistReusesCachedIdentity(t *testing.T) {
	env := newAuthProxyEnv(t, trustedProxyIP())
	require.NotNil(t, env.proxy)
	admin := env.createServerAdmin(t)

	trusted, err := env.authenticate(t, env.proxy, trustedProxyAddr, admin.Login)
	require.NoError(t, err)
	requireAdminIdentity(t, trusted, admin)

	// A second proxy built from the shipped empty whitelist shares the cache
	// written by the trusted proxy. The cached user id must not authenticate
	// a different source address.
	env.cfg.AuthProxy.Whitelist = ""
	openProxy, err := env.newProxy()
	if err != nil {
		_, lookupErr := env.users.GetByLogin(context.Background(), &user.GetUserByLoginQuery{LoginOrEmail: admin.Login})
		require.NoError(t, lookupErr)
		return
	}

	identity, err := env.authenticate(t, openProxy, attackerProxyAddr, admin.Login)
	requireNotImpersonated(t, identity, err)
}

func TestAuthProxyTrustedAddressCanAuthenticateListedUser(t *testing.T) {
	env := newAuthProxyEnv(t, trustedProxyIP())
	require.NotNil(t, env.proxy)
	admin := env.createServerAdmin(t)

	identity, err := env.authenticate(t, env.proxy, trustedProxyAddr, admin.Login)
	require.NoError(t, err)
	requireAdminIdentity(t, identity, admin)
}

func TestAuthProxyUnlistedAddressIsRejectedWhenWhitelistIsSet(t *testing.T) {
	env := newAuthProxyEnv(t, trustedProxyIP())
	require.NotNil(t, env.proxy)
	admin := env.createServerAdmin(t)

	identity, err := env.authenticate(t, env.proxy, attackerProxyAddr, admin.Login)
	requireNotImpersonated(t, identity, err)

	_, authErr := env.authInfo.GetAuthInfo(context.Background(), &login.GetAuthInfoQuery{
		UserId:     admin.ID,
		AuthModule: login.AuthProxyAuthModule,
	})
	require.ErrorIs(t, authErr, user.ErrUserNotFound)
}

func TestAuthProxyRegistrationRefusesEmptyWhitelist(t *testing.T) {
	cfg := loadShippedConfig(t)
	cfg.AuthProxy.Enabled = true
	require.Empty(t, cfg.AuthProxy.Whitelist)

	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)

	svc := ProvideService(cfg, tracing.InitializeTracerForTest(), authtest.NewFakeUserAuthTokenService(), &usagestats.NoopUsageStats{}, prometheus.NewRegistry(), nil)
	_, err = ProvideRegistration(
		context.Background(),
		cfgProvider,
		svc,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		authinfoimpl.ProvideOSSUserProtectionService(),
		nil,
		nil,
		nil,
		nil,
		featuremgmt.WithFeatures(),
		nil,
		oauthProvidersNone{},
		&remotecache.RemoteCache{},
		nil,
		nil,
		tracing.InitializeTracerForTest(),
		nil,
		nil,
	)
	require.NoError(t, err)
	require.False(t, svc.IsClientEnabled(context.Background(), authn.ClientProxy))
}

type oauthProvidersNone struct{}

func (oauthProvidersNone) GetOAuthProviders(context.Context) (map[string]bool, error) {
	return map[string]bool{}, nil
}

func (oauthProvidersNone) GetOAuthHttpClient(context.Context, string) (*http.Client, error) {
	return nil, http.ErrNotSupported
}

func (oauthProvidersNone) GetConnector(context.Context, string) (social.SocialConnector, error) {
	return nil, http.ErrNotSupported
}

func (oauthProvidersNone) GetOAuthInfoProvider(context.Context, string) (*social.OAuthInfo, error) {
	return nil, http.ErrNotSupported
}

func (oauthProvidersNone) GetOAuthInfoProviders(context.Context) (map[string]*social.OAuthInfo, error) {
	return map[string]*social.OAuthInfo{}, nil
}

type authProxyEnv struct {
	cfg      *setting.Cfg
	sql      db.DB
	users    user.Service
	authInfo login.AuthInfoService
	sessions *authtest.FakeUserAuthTokenService
	cache    remotecache.FakeCacheStorage
	ac       *acimpl.Service
	svc      *Service
	proxy    *clients.Proxy
}

func newAuthProxyEnv(t *testing.T, whitelist string) *authProxyEnv {
	t.Helper()

	cfg := loadShippedConfig(t)
	cfg.AuthProxy.Enabled = true
	cfg.AuthProxy.Whitelist = whitelist

	sqlStore := db.InitTestDB(t)
	dbProvider := legacysql.NewDatabaseProvider(sqlStore)
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)

	quotaSvc := quotaimpl.ProvideService(context.Background(), dbProvider, cfgProvider)
	orgSvc, err := orgimpl.ProvideService(dbProvider, cfg, quotaSvc)
	require.NoError(t, err)
	// Shipped auto_assign_org_id points at the main org. Create it the same way
	// startup does when that org is missing, so user lookup and auto sign-up
	// can run.
	orgID, err := orgSvc.GetOrCreate(context.Background(), orgimpl.MainOrgName)
	require.NoError(t, err)
	require.Equal(t, int64(cfg.AutoAssignOrgId), orgID)

	secretsSvc := secretsmanager.SetupTestService(t, secretsdb.ProvideSecretsStore(sqlStore))
	authStore, err := authinfoimpl.ProvideStore(context.Background(), dbProvider, secretsSvc)
	require.NoError(t, err)
	authInfo := authinfoimpl.ProvideService(authStore, remotecache.NewFakeCacheStorage(), secretsSvc)

	tracer := tracing.InitializeTracerForTest()
	teamSvc, err := teamimpl.ProvideService(dbProvider, cfg, tracer, nil)
	require.NoError(t, err)
	userSvc, err := userimpl.ProvideService(
		dbProvider,
		orgSvc,
		cfg,
		teamSvc,
		localcache.ProvideService(),
		tracer,
		quotaSvc,
		supportbundlestest.NewFakeBundleService(),
		nil,
	)
	require.NoError(t, err)

	features := featuremgmt.WithFeatures()
	sso := ssosettingstests.NewFakeService()
	sso.ExpectedSSOSetting = &models.SSOSettings{Settings: map[string]any{"enabled": false}}
	ldapSvc := service.ProvideService(cfg, features, sso)
	require.False(t, ldapSvc.Enabled())

	permRegistry := permreg.ProvidePermissionRegistry()
	ac := acimpl.ProvideOSSService(
		cfg,
		acdb.ProvideService(sqlStore),
		resourcepermissions.NewActionSetService(),
		localcache.ProvideService(),
		features,
		tracer,
		sqlStore,
		permRegistry,
		nil,
	)
	require.NoError(t, pluginaccesscontrol.DeclareRBACRoles(ac, cfg))
	require.NoError(t, accesscontrol.DeclareFixedRoles(ac))
	lic := &licensing.OSSLicensingService{}
	require.NoError(t, ac.DeclareFixedRoles(api.FixedRoleRegistrations(cfg.ViewersCanEdit, lic.FeatureEnabled("dspermissions.enforcement"))...))
	require.NoError(t, ac.RegisterFixedRoles(context.Background()))

	sessions := authtest.NewFakeUserAuthTokenService()
	svc := ProvideService(cfg, tracer, sessions, &usagestats.NoopUsageStats{}, prometheus.NewRegistry(), authInfo)
	registerProxyHooks(svc, cfg, userSvc, orgSvc, ac, authInfo, quotaSvc, features, tracer, permRegistry)

	env := &authProxyEnv{
		cfg:      cfg,
		sql:      sqlStore,
		users:    userSvc,
		authInfo: authInfo,
		sessions: sessions,
		cache:    remotecache.NewFakeCacheStorage(),
		ac:       ac,
		svc:      svc,
	}

	env.proxy, err = env.newProxy()
	if err != nil {
		env.proxy = nil
		return env
	}
	svc.RegisterClient(env.proxy)
	return env
}

func (e *authProxyEnv) newProxy() (*clients.Proxy, error) {
	tracer := tracing.InitializeTracerForTest()
	ldapClient := clients.ProvideLDAP(e.cfg, disabledLDAP(), e.users, e.authInfo, tracer)
	grafanaClient := clients.ProvideGrafana(e.cfg, e.users, tracer)
	return clients.ProvideProxy(e.cfg, e.cache, tracer, ldapClient, grafanaClient)
}

func (e *authProxyEnv) createServerAdmin(t *testing.T) *user.User {
	t.Helper()
	created, err := e.users.Create(context.Background(), &user.CreateUserCommand{
		Login: e.cfg.AdminUser,
		Email: e.cfg.AdminEmail,
		Name:  "Server Admin",
		// IsAdmin keeps the org role at Admin. The auth proxy lookup uses the login.
		IsAdmin: true,
	})
	require.NoError(t, err)
	require.True(t, created.IsAdmin)
	require.Equal(t, e.cfg.AdminUser, created.Login)
	return created
}

func (e *authProxyEnv) authenticate(t *testing.T, proxy *clients.Proxy, remoteAddr, loginName string) (*authn.Identity, error) {
	t.Helper()
	e.svc.RegisterClient(proxy)
	return e.svc.Authenticate(context.Background(), proxyRequest(e.cfg.AuthProxy.HeaderName, loginName, remoteAddr))
}

func registerProxyHooks(
	svc *Service,
	cfg *setting.Cfg,
	userSvc user.Service,
	orgSvc org.Service,
	ac accesscontrol.Service,
	authInfo login.AuthInfoService,
	quotaSvc quota.Service,
	features featuremgmt.FeatureToggles,
	tracer tracing.Tracer,
	permRegistry permreg.PermissionRegistry,
) {
	userSync := sync.ProvideUserSync(userSvc, authinfoimpl.ProvideOSSUserProtectionService(), authInfo, quotaSvc, tracer, features, cfg, nil)
	orgSync := sync.ProvideOrgSync(userSvc, orgSvc, ac, cfg, tracer)
	rbacSync := sync.ProvideRBACSync(cfg, ac, tracer, permRegistry)

	svc.RegisterPostAuthHook(userSync.SyncUserHook, 10)
	svc.RegisterPostAuthHook(userSync.EnableUserHook, 20)
	svc.RegisterPostAuthHook(orgSync.SyncOrgRolesHook, 40)
	svc.RegisterPostAuthHook(userSync.FetchSyncedUserHook, 100)
	svc.RegisterPostAuthHook(rbacSync.SyncCloudRoles, 110)
	svc.RegisterPostAuthHook(sync.ProvideGroupsClaimSync(cfg).SyncGroupsClaimHook, 115)
	svc.RegisterPostAuthHook(rbacSync.SyncPermissionsHook, 120)
	svc.RegisterPostAuthHook(userSync.SyncLastSeenHook, 130)
	svc.RegisterPostAuthHook(sync.ProvideNamespaceSync(cfg).SyncNamespace, 150)
	svc.RegisterPostAuthHook(sync.AccessClaimsHook, 160)
	svc.RegisterPostLoginHook(orgSync.SetDefaultOrgHook, 140)
	svc.RegisterPostLoginHook(userSync.CatalogLoginHook, 145)
	svc.RegisterPostLoginHook(rbacSync.ClearUserPermissionCacheHook, 170)
}

func loadShippedConfig(t *testing.T) *setting.Cfg {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	cfg := setting.NewCfg()
	err := cfg.Load(setting.CommandLineArgs{
		HomePath: root,
		Config:   filepath.Join(root, "conf", "defaults.ini"),
	})
	require.NoError(t, err)
	return cfg
}

func proxyRequest(headerName, loginName, remoteAddr string) *authn.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/user", nil)
	req.Header.Set(headerName, loginName)
	req.RemoteAddr = remoteAddr
	return &authn.Request{HTTPRequest: req}
}

func requireNotImpersonated(t *testing.T, identity *authn.Identity, err error) {
	t.Helper()
	if err == nil {
		require.Failf(t, "auth proxy accepted an unlisted client",
			"login=%q id=%s grafanaAdmin=%v orgRole=%s permissions=%v",
			identity.Login, identity.ID, identity.GetIsGrafanaAdmin(), identity.GetOrgRole(), permissionActions(identity))
	}
	require.Nil(t, identity)
}

func requireAdminIdentity(t *testing.T, identity *authn.Identity, admin *user.User) {
	t.Helper()
	require.NotNil(t, identity)
	require.Equal(t, admin.Login, identity.Login)
	require.Equal(t, admin.ID, mustInternalID(t, identity))
	require.True(t, identity.GetIsGrafanaAdmin())
	require.Equal(t, org.RoleAdmin, identity.GetOrgRole())
	require.True(t, identity.HasRole(org.RoleAdmin))
	actions := permissionActions(identity)
	require.Contains(t, actions, dashboards.ActionDashboardsWrite)
	require.Contains(t, actions, datasources.ActionWrite)
	require.Contains(t, actions, accesscontrol.ActionUsersRead)
}

func permissionActions(identity *authn.Identity) []string {
	if identity == nil || identity.Permissions == nil {
		return nil
	}
	actions := make([]string, 0, len(identity.Permissions[identity.OrgID]))
	for action := range identity.Permissions[identity.OrgID] {
		actions = append(actions, action)
	}
	return actions
}

func mustInternalID(t *testing.T, identity *authn.Identity) int64 {
	t.Helper()
	id, err := identity.GetInternalID()
	require.NoError(t, err)
	return id
}

func trustedProxyIP() string {
	return "198.51.100.20"
}

// disabledLDAP is the real LDAP service after loading a disabled provider
// setting, matching auth.ldap enabled=false.
func disabledLDAP() *service.LDAPImpl {
	sso := ssosettingstests.NewFakeService()
	sso.ExpectedSSOSetting = &models.SSOSettings{Settings: map[string]any{"enabled": false}}
	return service.ProvideService(setting.NewCfg(), featuremgmt.WithFeatures(), sso)
}
