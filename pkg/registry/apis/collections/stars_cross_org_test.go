package collections

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authn "github.com/grafana/authlib/authn"
	authlib "github.com/grafana/authlib/types"
	appsdkapiserver "github.com/grafana/grafana-app-sdk/k8s/apiserver"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sauthorizer "k8s.io/apiserver/pkg/authorization/authorizer"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	registryrest "k8s.io/apiserver/pkg/registry/rest"

	collectionsapi "github.com/grafana/grafana/apps/collections/pkg/apis/collections/v1alpha1"
	dashboardsV1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	grafanarest "github.com/grafana/grafana/pkg/apiserver/rest"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/registry/apis/collections/legacy"
	grafanaauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/apiserver/builder"
	"github.com/grafana/grafana/pkg/services/apiserver/endpoints/request"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/star"
	"github.com/grafana/grafana/pkg/services/star/starimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/storage/legacysql/dualwrite"
)

const (
	orgA int64 = 1
	orgB int64 = 2
)

// sqlUserLookup reads users with the real user SQL store. GetByUID is the only
// method the stars writer calls; the remaining service methods are unused.
type sqlUserLookup struct {
	*usertest.FakeUserService
	byUID func(context.Context, string) (*user.User, error)
}

func (s *sqlUserLookup) GetByUID(ctx context.Context, query *user.GetUserByUIDQuery) (*user.User, error) {
	return s.byUID(ctx, query.UID)
}

var _ user.Service = (*sqlUserLookup)(nil)

type nopRegistrar struct{}

func (nopRegistrar) RegisterAPI(builder.APIGroupBuilder) {}

func (nopRegistrar) RegisterAppInstaller(appsdkapiserver.AppInstaller) {}

var _ builder.APIRegistrar = nopRegistrar{}

type statusResponder struct {
	code int
	err  error
}

func (s *statusResponder) Object(code int, _ runtime.Object) {
	s.code = code
}

func (s *statusResponder) Error(err error) {
	s.err = err
}

type starsFixture struct {
	t         *testing.T
	database  db.DB
	stars     star.Service
	storage   grafanarest.Storage
	authz     k8sauthorizer.Authorizer
	namespace string
	victimID  int64
	otherID   int64
}

func newStarsFixture(t *testing.T) *starsFixture {
	t.Helper()

	sqlStore := db.NewTestStore(t)
	cfg := setting.NewCfg()
	provider := legacysql.NewDatabaseProvider(sqlStore)
	userStore := userimpl.ProvideStore(provider, cfg)
	users := &sqlUserLookup{
		FakeUserService: usertest.NewUserServiceFake(),
		byUID:           userStore.GetByUID,
	}
	starService := starimpl.ProvideService(sqlStore)
	namespacer := request.GetNamespaceMapper(cfg)
	legacyStorage := legacy.NewDashboardStarsStorage(starService, users, namespacer, legacy.NewLegacySQL(provider))

	// No unified-storage config: stars stay on the legacy writer (mode 0).
	served, err := dualwrite.ProvideServiceForTests(cfg).NewStorage(
		collectionsapi.StarsResourceInfo.GroupResource(),
		legacyStorage,
		nil,
	)
	require.NoError(t, err)
	require.IsType(t, &legacy.DashboardStarsStorage{}, served)

	api := RegisterAPIService(cfg, featuremgmt.WithFeatures(), sqlStore, starService, users, nopRegistrar{})
	chain := grafanaauthorizer.NewGrafanaBuiltInSTAuthorizer()
	chain.Register(collectionsapi.GroupVersion, api.GetAuthorizer())

	now := time.Now()
	victimID, err := userStore.Insert(context.Background(), &user.User{
		UID:     "victim",
		Email:   "victim@example.com",
		Login:   "victim",
		Name:    "Victim",
		OrgID:   orgA,
		Created: now,
		Updated: now,
	})
	require.NoError(t, err)
	otherID, err := userStore.Insert(context.Background(), &user.User{
		UID:     "other",
		Email:   "other@example.com",
		Login:   "other",
		Name:    "Other",
		OrgID:   orgB,
		Created: now,
		Updated: now,
	})
	require.NoError(t, err)

	return &starsFixture{
		t:         t,
		database:  sqlStore,
		stars:     starService,
		storage:   served,
		authz:     chain,
		namespace: namespacer(orgA),
		victimID:  victimID,
		otherID:   otherID,
	}
}

func (f *starsFixture) addStar(userID, orgID int64, dashboardUID string) {
	f.t.Helper()
	err := f.stars.Add(context.Background(), &star.StarDashboardCommand{
		UserID:       userID,
		OrgID:        orgID,
		DashboardUID: dashboardUID,
		Updated:      time.Now(),
	})
	require.NoError(f.t, err)
}

func (f *starsFixture) requireStar(userID, orgID int64, dashboardUID string, present bool) {
	f.t.Helper()
	var count int64
	err := f.database.WithDbSession(context.Background(), func(sess *db.Session) error {
		var err error
		count, err = sess.Where(
			"user_id = ? AND org_id = ? AND dashboard_uid = ?",
			userID, orgID, dashboardUID,
		).Count(&star.Star{})
		return err
	})
	require.NoError(f.t, err)
	if present {
		require.Equal(f.t, int64(1), count, "star user=%d org=%d dashboard=%s should remain", userID, orgID, dashboardUID)
		return
	}
	require.Equal(f.t, int64(0), count, "star user=%d org=%d dashboard=%s should be removed", userID, orgID, dashboardUID)
}

func (f *starsFixture) ctxFor(uid string, orgID int64, role identity.RoleType) context.Context {
	f.t.Helper()
	ns := request.GetNamespaceMapper(setting.NewCfg())(orgID)
	requester := &identity.StaticRequester{
		Type:      authlib.TypeUser,
		UserUID:   uid,
		OrgID:     orgID,
		OrgRole:   role,
		Namespace: ns,
		// Session logins have no access token. The auth hook fills delegated
		// permissions from the service identity list, which includes this API.
		AccessTokenClaims: &authn.Claims[authn.AccessTokenClaims]{
			Rest: authn.AccessTokenClaims{
				DelegatedPermissions: identity.ServiceIdentityClaims.Rest.DelegatedPermissions,
			},
		},
	}
	ctx := identity.WithRequester(context.Background(), requester)
	return k8srequest.WithNamespace(ctx, ns)
}

func (f *starsFixture) allow(ctx context.Context, verb, name, subresource string) {
	f.t.Helper()
	ns, ok := k8srequest.NamespaceFrom(ctx)
	require.True(f.t, ok)
	decision, reason, err := f.authz.Authorize(ctx, k8sauthorizer.AttributesRecord{
		Verb:            verb,
		Namespace:       ns,
		APIGroup:        collectionsapi.APIGroup,
		APIVersion:      collectionsapi.APIVersion,
		Resource:        "stars",
		Subresource:     subresource,
		Name:            name,
		ResourceRequest: true,
	})
	require.NoError(f.t, err)
	require.Equal(f.t, k8sauthorizer.DecisionAllow, decision, reason)
}

func (f *starsFixture) orgAContext() context.Context {
	return k8srequest.WithNamespace(context.Background(), f.namespace)
}

func emptyStars(namespace, name string) *collectionsapi.Stars {
	return &collectionsapi.Stars{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}

func TestStarsEmptyListKeepsOtherOrganizations(t *testing.T) {
	const victim = "user-victim"

	t.Run("org admin delete of the stars object clears only the requested organization", func(t *testing.T) {
		f := newStarsFixture(t)
		f.addStar(f.victimID, orgA, "dash-a")
		f.addStar(f.victimID, orgB, "dash-b")
		f.addStar(f.otherID, orgB, "dash-other")

		ctx := f.ctxFor("admin", orgA, identity.RoleAdmin)
		f.allow(ctx, "delete", victim, "")

		_, _, err := f.storage.Delete(f.orgAContext(), victim, registryrest.ValidateAllObjectFunc, &metav1.DeleteOptions{})
		require.NoError(t, err)

		f.requireStar(f.victimID, orgA, "dash-a", false)
		f.requireStar(f.victimID, orgB, "dash-b", true)
		f.requireStar(f.otherID, orgB, "dash-other", true)
	})

	t.Run("update that clears the list removes only the requested organization", func(t *testing.T) {
		f := newStarsFixture(t)
		f.addStar(f.victimID, orgA, "dash-a")
		f.addStar(f.victimID, orgB, "dash-b")
		f.addStar(f.otherID, orgA, "dash-other")

		ctx := f.ctxFor("victim", orgA, identity.RoleViewer)
		f.allow(ctx, "update", victim, "")

		_, _, err := f.storage.Update(
			f.orgAContext(),
			victim,
			registryrest.DefaultUpdatedObjectInfo(emptyStars(f.namespace, victim)),
			registryrest.ValidateAllObjectFunc,
			registryrest.ValidateAllObjectUpdateFunc,
			false,
			&metav1.UpdateOptions{},
		)
		require.NoError(t, err)

		f.requireStar(f.victimID, orgA, "dash-a", false)
		f.requireStar(f.victimID, orgB, "dash-b", true)
		f.requireStar(f.otherID, orgA, "dash-other", true)
	})

	t.Run("create of an empty stars object removes only the requested organization", func(t *testing.T) {
		f := newStarsFixture(t)
		f.addStar(f.victimID, orgA, "dash-a")
		f.addStar(f.victimID, orgB, "dash-b")
		f.addStar(f.otherID, orgB, "dash-other")

		ctx := f.ctxFor("victim", orgA, identity.RoleEditor)
		f.allow(ctx, "create", victim, "")

		_, err := f.storage.Create(
			f.orgAContext(),
			emptyStars(f.namespace, victim),
			registryrest.ValidateAllObjectFunc,
			&metav1.CreateOptions{},
		)
		require.NoError(t, err)

		f.requireStar(f.victimID, orgA, "dash-a", false)
		f.requireStar(f.victimID, orgB, "dash-b", true)
		f.requireStar(f.otherID, orgB, "dash-other", true)
	})

	t.Run("removing the last starred dashboard clears only the requested organization", func(t *testing.T) {
		f := newStarsFixture(t)
		f.addStar(f.victimID, orgA, "dash-a")
		f.addStar(f.victimID, orgB, "dash-b")
		f.addStar(f.otherID, orgB, "dash-other")

		ctx := f.ctxFor("victim", orgA, identity.RoleViewer)
		f.allow(ctx, "delete", victim, "update")

		responder := &statusResponder{}
		handler, err := (&starsREST{store: f.storage}).Connect(f.orgAContext(), victim, nil, responder)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodDelete, "/stars/"+victim+"/update/"+dashboardsV1.APIGroup+"/Dashboard/dash-a", nil)
		handler.ServeHTTP(httptest.NewRecorder(), req)
		require.NoError(t, responder.err)

		f.requireStar(f.victimID, orgA, "dash-a", false)
		f.requireStar(f.victimID, orgB, "dash-b", true)
		f.requireStar(f.otherID, orgB, "dash-other", true)
	})

	t.Run("org admin removing another user's last star clears only the requested organization", func(t *testing.T) {
		f := newStarsFixture(t)
		f.addStar(f.victimID, orgA, "dash-a")
		f.addStar(f.victimID, orgB, "dash-b")

		ctx := f.ctxFor("admin", orgA, identity.RoleAdmin)
		f.allow(ctx, "delete", victim, "update")

		responder := &statusResponder{}
		handler, err := (&starsREST{store: f.storage}).Connect(f.orgAContext(), victim, nil, responder)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodDelete, "/stars/"+victim+"/update/"+dashboardsV1.APIGroup+"/Dashboard/dash-a", nil)
		handler.ServeHTTP(httptest.NewRecorder(), req)
		require.NoError(t, responder.err)

		f.requireStar(f.victimID, orgA, "dash-a", false)
		f.requireStar(f.victimID, orgB, "dash-b", true)
	})

	t.Run("removing one of several stars does not touch other organizations", func(t *testing.T) {
		f := newStarsFixture(t)
		f.addStar(f.victimID, orgA, "dash-a")
		f.addStar(f.victimID, orgA, "dash-a2")
		f.addStar(f.victimID, orgB, "dash-b")

		ctx := f.ctxFor("victim", orgA, identity.RoleViewer)
		f.allow(ctx, "delete", victim, "update")

		responder := &statusResponder{}
		handler, err := (&starsREST{store: f.storage}).Connect(f.orgAContext(), victim, nil, responder)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodDelete, "/stars/"+victim+"/update/"+dashboardsV1.APIGroup+"/Dashboard/dash-a", nil)
		handler.ServeHTTP(httptest.NewRecorder(), req)
		require.NoError(t, responder.err)

		f.requireStar(f.victimID, orgA, "dash-a", false)
		f.requireStar(f.victimID, orgA, "dash-a2", true)
		f.requireStar(f.victimID, orgB, "dash-b", true)
	})
}

func TestUserWideStarDeleteStillRemovesEveryOrganization(t *testing.T) {
	f := newStarsFixture(t)
	f.addStar(f.victimID, orgA, "dash-a")
	f.addStar(f.victimID, orgB, "dash-b")
	f.addStar(f.otherID, orgB, "dash-other")

	require.NoError(t, f.stars.DeleteByUser(context.Background(), f.victimID))

	f.requireStar(f.victimID, orgA, "dash-a", false)
	f.requireStar(f.victimID, orgB, "dash-b", false)
	f.requireStar(f.otherID, orgB, "dash-other", true)
}
