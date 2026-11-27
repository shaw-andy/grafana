package authz

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/fullstorydev/grpchan/inprocgrpc"
	grpcAuth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/api/validate/content"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/endpoints/request"

	authnlib "github.com/grafana/authlib/authn"
	authzlib "github.com/grafana/authlib/authz"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	authlibcache "github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/types"

	iamv0 "github.com/grafana/grafana/apps/iam/pkg/apis/iam/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/components/satokengen"
	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/registry/apis/iam/legacy"
	"github.com/grafana/grafana/pkg/registry/apis/iam/serviceaccount"
	iamuser "github.com/grafana/grafana/pkg/registry/apis/iam/user"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/database"
	"github.com/grafana/grafana/pkg/services/accesscontrol/permreg"
	"github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/apikey"
	"github.com/grafana/grafana/pkg/services/apikey/apikeyimpl"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl/sync"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/authz/rbac"
	"github.com/grafana/grafana/pkg/services/authz/rbac/store"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotaimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/team/teamimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// TestNumericSubjectUIDIsNotResolvedAsInternalUserID covers the in-process
// app-platform authorizer. A caller-chosen service account or user name is
// stored as the account UID. When that UID is all digits, authorization must
// still use that account, not the user whose internal id equals those digits.
//
// These tests fail while that lookup is in place. They pass once a numeric UID
// is no longer resolved as an internal id, and once the IAM create handlers
// refuse to persist a purely numeric name.
func TestIntegrationNumericSubjectUIDIsNotResolvedAsInternalUserID(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	env := newNumericUIDEnv(t)
	require.Empty(t, content.IsPathSegmentName(env.adminID), "apiserver path-segment validation accepts a numeric object name")
	require.NotEqual(t, env.adminID, env.admin.UID)

	t.Run("service account create does not persist a numeric name", func(t *testing.T) {
		env.deleteUID(t, env.adminID)
		ctx := env.namespaceContext(env.orgAdmin)
		obj := env.serviceAccount(env.adminID, "Numeric SA", iamv0.ServiceAccountOrgRoleViewer)
		err := serviceaccount.ValidateOnCreate(ctx, obj)
		if err == nil {
			_, err = env.saStore.Create(ctx, obj, func(ctx context.Context, created runtime.Object) error {
				return serviceaccount.ValidateOnCreate(ctx, created.(*iamv0.ServiceAccount))
			}, nil)
		}
		require.Error(t, err)
		env.requireNoUID(t, env.adminID)
	})

	t.Run("user create does not persist a numeric name", func(t *testing.T) {
		env.deleteUID(t, env.adminID)
		ctx := env.namespaceContext(env.orgAdmin)
		obj := env.userObject(env.adminID, "numeric-user", "numeric-user@example.com")
		err := iamuser.ValidateOnCreate(ctx, emptyUserSearch{}, obj)
		if err == nil {
			_, err = env.userStore.Create(ctx, obj, func(ctx context.Context, created runtime.Object) error {
				return iamuser.ValidateOnCreate(ctx, emptyUserSearch{}, created.(*iamv0.User))
			}, nil)
		}
		require.Error(t, err)
		env.requireNoUID(t, env.adminID)
	})

	t.Run("built-in admin is allowed and a lesser org admin is denied", func(t *testing.T) {
		adminIdent := env.identityForStoredUser(t, env.admin.ID, types.TypeUser)
		require.True(t, adminIdent.GetIsGrafanaAdmin())
		env.requireServerAdminAllowed(t, adminIdent)

		orgAdminIdent := env.identityForStoredUser(t, env.orgAdmin.UserID, types.TypeUser)
		require.False(t, orgAdminIdent.GetIsGrafanaAdmin())
		env.requireServerAdminDenied(t, orgAdminIdent)

		ordinary := env.mustCreateServiceAccount(t, "viewer-sa", "Ordinary", string(org.RoleViewer))
		ordinaryIdent := env.authenticateServiceAccountToken(t, ordinary.ID)
		require.Equal(t, "service-account:viewer-sa", ordinaryIdent.GetUID())
		env.requireServerAdminDenied(t, ordinaryIdent)
	})

	t.Run("service account token is not granted the built-in admin", func(t *testing.T) {
		env.deleteUID(t, env.adminID)
		impersonated := env.mustCreateServiceAccount(t, env.adminID, "Impersonated", string(org.RoleViewer))
		require.NotEqual(t, env.admin.ID, impersonated.ID)
		require.Equal(t, env.adminID, impersonated.UID)

		ident := env.authenticateServiceAccountToken(t, impersonated.ID)
		require.Equal(t, types.TypeServiceAccount, ident.GetIdentityType())
		require.Equal(t, "service-account:"+env.adminID, ident.GetUID())
		require.NotEqual(t, ident.GetSubject(), ident.GetUID())
		require.False(t, ident.GetIsGrafanaAdmin())
		env.requireServerAdminDenied(t, ident)
	})

	t.Run("user identity is not granted the built-in admin", func(t *testing.T) {
		env.deleteUID(t, env.adminID)
		created := env.mustCreateUser(t, env.adminID, "numeric-login", "numeric-login@example.com", string(org.RoleViewer), false)
		require.NotEqual(t, env.admin.ID, created.ID)
		require.Equal(t, env.adminID, created.UID)

		ident := env.identityForStoredUser(t, created.ID, types.TypeUser)
		require.Equal(t, types.TypeUser, ident.GetIdentityType())
		require.Equal(t, "user:"+env.adminID, ident.GetUID())
		require.False(t, ident.GetIsGrafanaAdmin())
		env.requireServerAdminDenied(t, ident)
	})
}

type numericUIDEnv struct {
	cfg       *setting.Cfg
	sql       *sqlstore.SQLStore
	users     user.Service
	keys      apikey.Service
	client    types.AccessClient
	saStore   *serviceaccount.LegacyStore
	userStore *iamuser.LegacyStore
	identity  legacy.LegacyIdentityStore
	ns        types.NamespaceInfo
	admin     *user.User
	adminID   string
	orgAdmin  *user.SignedInUser
}

func newNumericUIDEnv(t *testing.T) *numericUIDEnv {
	t.Helper()
	ctx := context.Background()
	cfg := setting.NewCfg()
	sqlStore := sqlstore.NewTestStore(t, sqlstore.WithCfg(cfg))
	sqlstore.SeedDefaultOrgAndUser(t, sqlStore)

	dbProvider := legacysql.NewDatabaseProvider(sqlStore)
	tracer := tracing.InitializeTracerForTest()
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	quotaService := quotaimpl.ProvideService(ctx, dbProvider, cfgProvider)
	orgService, err := orgimpl.ProvideService(dbProvider, cfg, quotaService)
	require.NoError(t, err)
	teamService, err := teamimpl.ProvideService(dbProvider, cfg, tracer, nil)
	require.NoError(t, err)
	userService, err := userimpl.ProvideService(
		dbProvider, orgService, cfg, teamService, localcache.ProvideService(), tracer,
		quotaService, supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)

	admin, err := userService.GetByLogin(ctx, &user.GetUserByLoginQuery{LoginOrEmail: "admin"})
	require.NoError(t, err)
	require.True(t, admin.IsAdmin)
	require.Equal(t, int64(1), admin.ID)

	orgAdminUser, err := userService.Create(ctx, &user.CreateUserCommand{
		Login:          "org-admin",
		Email:          "org-admin@example.com",
		Name:           "Org Admin",
		OrgID:          1,
		IsAdmin:        false,
		DefaultOrgRole: string(org.RoleAdmin),
	})
	require.NoError(t, err)
	require.False(t, orgAdminUser.IsAdmin)

	acStore := database.ProvideService(sqlStore)
	actionSets := resourcepermissions.NewActionSetService()
	acSvc := acimpl.ProvideOSSService(
		cfg, acStore, actionSets, localcache.ProvideService(),
		featuremgmt.WithFeatures(), tracer, sqlStore, permreg.ProvidePermissionRegistry(), nil,
	)
	require.NoError(t, accesscontrol.DeclareFixedRoles(acSvc))
	require.NoError(t, acSvc.RegisterFixedRoles(ctx))

	reg := prometheus.NewRegistry()
	server := rbac.NewService(
		dbProvider,
		store.NewSQLFolderStore(dbProvider, tracer),
		legacy.NewLegacySQLStores(dbProvider),
		store.NewUnionPermissionStore(
			store.NewStaticPermissionStore(acSvc),
			store.NewSQLPermissionStore(dbProvider, tracer),
		),
		nil,
		nil,
		actionSets,
		log.New("authz-grpc-server"),
		tracer,
		reg,
		authlibcache.NewLocalCache(authlibcache.Config{Expiry: time.Minute, CleanupInterval: time.Minute}),
		rbac.Settings{CacheTTL: 0},
	)

	channel := &inprocgrpc.Channel{}
	authenticate := func(ctx context.Context) (context.Context, error) {
		ctx = types.WithAuthInfo(ctx, authnlib.NewAccessTokenAuthInfo(authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{
				Namespace:   "*",
				Permissions: []string{userPermissionsDelegatedGrant},
			},
		}))
		return ctx, nil
	}
	authInterceptor := grpcAuth.UnaryServerInterceptor(authenticate)
	channel.WithServerUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return authInterceptor(ctx, req, info, handler)
	})
	authzv1.RegisterAuthzServiceServer(channel, server)
	accessClient := authzlib.NewClient(channel, authzlib.WithCacheClientOption(&NoopCache{}), authzlib.WithTracerClientOption(tracer))

	apiKeys, err := apikeyimpl.ProvideService(dbProvider, cfg, &quotatest.FakeQuotaService{})
	require.NoError(t, err)

	identityStore := legacy.NewLegacySQLStores(dbProvider)
	ns, err := types.ParseNamespace("default")
	require.NoError(t, err)

	return &numericUIDEnv{
		cfg:       cfg,
		sql:       sqlStore,
		users:     userService,
		keys:      apiKeys,
		client:    accessClient,
		saStore:   serviceaccount.NewLegacyStore(identityStore, nil, tracer),
		userStore: iamuser.NewLegacyStore(identityStore, nil, tracer),
		identity:  identityStore,
		ns:        ns,
		admin:     admin,
		adminID:   strconv.FormatInt(admin.ID, 10),
		orgAdmin: &user.SignedInUser{
			UserID:         orgAdminUser.ID,
			UserUID:        orgAdminUser.UID,
			OrgID:          1,
			OrgRole:        org.RoleAdmin,
			Namespace:      "default",
			IsGrafanaAdmin: false,
		},
	}
}

func (e *numericUIDEnv) namespaceContext(requester identity.Requester) context.Context {
	ctx := request.WithNamespace(context.Background(), e.ns.Value)
	return identity.WithRequester(ctx, requester)
}

func (e *numericUIDEnv) serviceAccount(name, title string, role iamv0.ServiceAccountOrgRole) *iamv0.ServiceAccount {
	return &iamv0.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: e.ns.Value},
		Spec: iamv0.ServiceAccountSpec{
			Title: title,
			Role:  role,
		},
	}
}

func (e *numericUIDEnv) userObject(name, login, email string) *iamv0.User {
	return &iamv0.User{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: e.ns.Value},
		Spec: iamv0.UserSpec{
			Login: login,
			Email: email,
			Title: login,
			Role:  string(org.RoleViewer),
		},
	}
}

func (e *numericUIDEnv) deleteUID(t *testing.T, uid string) {
	t.Helper()
	err := e.sql.WithDbSession(context.Background(), func(sess *sqlstore.DBSession) error {
		var row user.User
		has, err := sess.Where("uid = ?", uid).Get(&row)
		if err != nil || !has {
			return err
		}
		if _, err = sess.Where("service_account_id = ?", row.ID).Delete(&apikey.APIKey{}); err != nil {
			return err
		}
		if _, err = sess.Where("user_id = ?", row.ID).Delete(&org.OrgUser{}); err != nil {
			return err
		}
		_, err = sess.ID(row.ID).Delete(&user.User{})
		return err
	})
	require.NoError(t, err)
}

func (e *numericUIDEnv) requireNoUID(t *testing.T, uid string) {
	t.Helper()
	_, err := e.users.GetByUID(context.Background(), &user.GetUserByUIDQuery{UID: uid})
	require.ErrorIs(t, err, user.ErrUserNotFound)
}

func (e *numericUIDEnv) mustCreateServiceAccount(t *testing.T, uid, title, role string) legacy.ServiceAccount {
	t.Helper()
	ctx := request.WithNamespace(context.Background(), e.ns.Value)
	login := "sa-" + title
	created, err := e.identity.CreateServiceAccount(ctx, e.ns, legacy.CreateServiceAccountCommand{
		UID:   uid,
		Name:  title,
		Login: login,
		Role:  role,
	})
	if err != nil {
		e.insertServiceAccountRow(t, uid, title, login, role)
		loaded, loadErr := e.users.GetByUID(ctx, &user.GetUserByUIDQuery{UID: uid})
		require.NoError(t, loadErr)
		return legacy.ServiceAccount{ID: loaded.ID, UID: loaded.UID, Name: loaded.Name, Role: role}
	}
	require.Equal(t, uid, created.ServiceAccount.UID)
	return created.ServiceAccount
}

func (e *numericUIDEnv) insertServiceAccountRow(t *testing.T, uid, title, login, role string) {
	t.Helper()
	err := e.sql.WithDbSession(context.Background(), func(sess *sqlstore.DBSession) error {
		sess.UseBool("is_admin", "is_service_account", "is_disabled", "email_verified", "is_provisioned")
		now := time.Now().UTC()
		row := &user.User{
			UID:              uid,
			Login:            login,
			Email:            login,
			Name:             title,
			OrgID:            e.ns.OrgID,
			IsServiceAccount: true,
			Created:          now,
			Updated:          now,
		}
		if _, err := sess.Insert(row); err != nil {
			return err
		}
		_, err := sess.Insert(&org.OrgUser{
			OrgID:   e.ns.OrgID,
			UserID:  row.ID,
			Role:    org.RoleType(role),
			Created: now,
			Updated: now,
		})
		return err
	})
	require.NoError(t, err)
}

func (e *numericUIDEnv) mustCreateUser(t *testing.T, uid, login, email, role string, grafanaAdmin bool) user.User {
	t.Helper()
	ctx := request.WithNamespace(context.Background(), e.ns.Value)
	created, err := e.identity.CreateUser(ctx, e.ns, legacy.CreateUserCommand{
		UID:     uid,
		Login:   login,
		Email:   email,
		Name:    login,
		IsAdmin: grafanaAdmin,
		Role:    role,
	})
	require.NoError(t, err)
	require.Equal(t, uid, created.User.UID)
	return created.User.User
}

func (e *numericUIDEnv) authenticateServiceAccountToken(t *testing.T, serviceAccountID int64) *user.SignedInUser {
	t.Helper()
	generated, err := satokengen.New("sa")
	require.NoError(t, err)
	_, err = e.keys.AddAPIKey(context.Background(), &apikey.AddCommand{
		Name:             "token-" + strconv.FormatInt(serviceAccountID, 10),
		Role:             org.RoleViewer,
		OrgID:            e.ns.OrgID,
		Key:              generated.HashedKey,
		ServiceAccountID: &serviceAccountID,
	})
	require.NoError(t, err)

	httpReq, err := http.NewRequest(http.MethodGet, "/apis/iam.grafana.app/v0alpha1/namespaces/default/users", nil)
	require.NoError(t, err)
	httpReq.Header.Set("Authorization", "Bearer "+generated.ClientSecret)

	apiKeyClient := clients.ProvideAPIKey(e.keys, tracing.InitializeTracerForTest())
	ident, err := apiKeyClient.Authenticate(context.Background(), &authn.Request{HTTPRequest: httpReq, OrgID: e.ns.OrgID})
	require.NoError(t, err)
	return e.finishIdentity(t, ident)
}

func (e *numericUIDEnv) identityForStoredUser(t *testing.T, userID int64, identityType types.IdentityType) *user.SignedInUser {
	t.Helper()
	ident := &authn.Identity{
		ID:           strconv.FormatInt(userID, 10),
		Type:         identityType,
		OrgID:        e.ns.OrgID,
		ClientParams: authn.ClientParams{FetchSyncedUser: true, SyncPermissions: true},
	}
	return e.finishIdentity(t, ident)
}

func (e *numericUIDEnv) finishIdentity(t *testing.T, ident *authn.Identity) *user.SignedInUser {
	t.Helper()
	ctx := context.Background()
	tracer := tracing.InitializeTracerForTest()
	userSync := sync.ProvideUserSync(e.users, nil, nil, nil, tracer, featuremgmt.WithFeatures(), e.cfg, nil)
	req := &authn.Request{OrgID: e.ns.OrgID}
	require.NoError(t, userSync.FetchSyncedUserHook(ctx, ident, req))
	require.NoError(t, sync.ProvideNamespaceSync(e.cfg).SyncNamespace(ctx, ident, req))
	require.NoError(t, sync.AccessClaimsHook(ctx, ident, req))
	signedIn := ident.SignedInUser()
	require.Equal(t, "default", signedIn.GetNamespace())
	return signedIn
}

func (e *numericUIDEnv) requireServerAdminDenied(t *testing.T, ident *user.SignedInUser) {
	t.Helper()
	usersAllowed := e.allow(t, ident, utils.VerbCreate, "iam.grafana.app", "users", "new-user")
	settingsAllowed := e.allow(t, ident, utils.VerbUpdate, "setting.grafana.app", "settings", "auth.saml")
	require.Falsef(t, usersAllowed, "users:create; settings auth.saml allowed=%v", settingsAllowed)
	require.False(t, settingsAllowed, "settings:write auth.saml")
	batch := e.batch(t, ident)
	require.False(t, batch["users"].Allowed)
	require.False(t, batch["settings"].Allowed)
	require.NoError(t, batch["users"].Error)
	require.NoError(t, batch["settings"].Error)
	checker, _, err := e.client.Compile(context.Background(), ident, types.ListRequest{
		Group: "iam.grafana.app", Resource: "users", Verb: utils.VerbCreate, Namespace: "default",
	})
	require.NoError(t, err)
	require.NotNil(t, checker)
	require.False(t, checker("new-user", ""))
}

func (e *numericUIDEnv) requireServerAdminAllowed(t *testing.T, ident *user.SignedInUser) {
	t.Helper()
	require.True(t, e.allow(t, ident, utils.VerbCreate, "iam.grafana.app", "users", "new-user"))
	require.True(t, e.allow(t, ident, utils.VerbUpdate, "setting.grafana.app", "settings", "auth.saml"))
}

func (e *numericUIDEnv) allow(t *testing.T, ident *user.SignedInUser, verb, group, resource, name string) bool {
	t.Helper()
	res, err := e.client.Check(context.Background(), ident, types.CheckRequest{
		Verb: verb, Group: group, Resource: resource, Namespace: "default", Name: name,
	}, "")
	require.NoError(t, err)
	return res.Allowed
}

func (e *numericUIDEnv) batch(t *testing.T, ident *user.SignedInUser) map[string]types.BatchCheckResult {
	t.Helper()
	res, err := e.client.BatchCheck(context.Background(), ident, types.BatchCheckRequest{
		Namespace: "default",
		Checks: []types.BatchCheckItem{
			{CorrelationID: "users", Verb: utils.VerbCreate, Group: "iam.grafana.app", Resource: "users", Name: "new-user"},
			{CorrelationID: "settings", Verb: utils.VerbUpdate, Group: "setting.grafana.app", Resource: "settings", Name: "auth.saml"},
		},
	})
	require.NoError(t, err)
	return res.Results
}

type emptyUserSearch struct{}

func (emptyUserSearch) Search(context.Context, *resourcepb.ResourceSearchRequest, ...grpc.CallOption) (*resourcepb.ResourceSearchResponse, error) {
	return &resourcepb.ResourceSearchResponse{}, nil
}

func (emptyUserSearch) GetStats(context.Context, *resourcepb.ResourceStatsRequest, ...grpc.CallOption) (*resourcepb.ResourceStatsResponse, error) {
	return nil, nil
}

func (emptyUserSearch) RebuildIndexes(context.Context, *resourcepb.RebuildIndexesRequest, ...grpc.CallOption) (*resourcepb.RebuildIndexesResponse, error) {
	return nil, nil
}

func (emptyUserSearch) VectorSearch(context.Context, *resourcepb.VectorSearchRequest, ...grpc.CallOption) (*resourcepb.VectorSearchResponse, error) {
	return nil, nil
}

func (emptyUserSearch) HybridSearch(context.Context, *resourcepb.HybridSearchRequest, ...grpc.CallOption) (*resourcepb.HybridSearchResponse, error) {
	return nil, nil
}
