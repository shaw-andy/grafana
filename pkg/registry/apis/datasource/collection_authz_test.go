package datasource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fullstorydev/grpchan/inprocgrpc"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	authnlib "github.com/grafana/authlib/authn"
	authzlib "github.com/grafana/authlib/authz"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	authlib "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	datasourceV0 "github.com/grafana/grafana/pkg/apis/datasource/v0alpha1"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/registry/apis/datasource/converter"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	acmock "github.com/grafana/grafana/pkg/services/accesscontrol/mock"
	grafanaauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	grafanarequest "github.com/grafana/grafana/pkg/services/apiserver/endpoints/request"
	"github.com/grafana/grafana/pkg/services/authz"
	"github.com/grafana/grafana/pkg/services/authz/rbac"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/datasources/guardian"
	dsservice "github.com/grafana/grafana/pkg/services/datasources/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	secretskvs "github.com/grafana/grafana/pkg/services/secrets/kvstore"
	secretsmng "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql/dualwrite"
)

const (
	lokiGroup  = "loki.datasource.grafana.app"
	lokiPlugin = "loki"

	uidEdit   = "lokiedit"
	uidQuery  = "lokiquery"
	uidSecret = "lokisecret"

	orgNamespace = "default"
	orgID        = int64(1)
)

// TestDatasourceCollectionAuthorization runs the datasource collection routes
// an ordinary user can send once datasource.useNewCRUDAPIs is enabled.
//
// Each case parses the HTTP path with the apiserver request parser, authorizes
// it through the datasource authorizer and the in-process RBAC service, and
// only then calls the legacy store selected for the default storage mode.
// Datasources the caller cannot delete must still be present afterwards, and
// a list must not include a datasource the caller cannot read.
func TestDatasourceCollectionAuthorization(t *testing.T) {
	env := newCollectionEnv(t)

	t.Run("delete collection leaves datasources the caller cannot delete", func(t *testing.T) {
		env.seedLokiDatasources(t)
		grants := editorDatasourceGrants()
		caller := collectionUser("editor", grants)
		env.apply(t, caller, grants, http.MethodDelete, collectionPath())

		remaining := env.uids(t)
		require.Contains(t, remaining, uidQuery, "query permission must not delete the datasource")
		require.Contains(t, remaining, uidSecret, "a datasource the caller cannot read must not be deleted")
	})

	t.Run("list omits datasources the caller cannot read", func(t *testing.T) {
		env.seedLokiDatasources(t)
		grants := []accesscontrol.Permission{
			{Action: datasources.ActionRead, Scope: datasources.ScopeProvider.GetResourceScopeUID("grafana")},
			{Action: datasources.ActionQuery, Scope: datasources.ScopeProvider.GetResourceScopeUID("grafana")},
			{Action: datasources.ActionRead, Scope: datasources.ScopeProvider.GetResourceScopeUID(uidEdit)},
		}
		listed := env.list(t, collectionUser("viewer", grants), grants)
		require.Contains(t, listed, "http://loki-edit.example")
		require.NotContains(t, listed, "http://loki-query.example")
		require.NotContains(t, listed, "http://loki-secret.example")
	})

	t.Run("builtin read grant does not list other plugin datasources", func(t *testing.T) {
		env.seedLokiDatasources(t)
		grants := []accesscontrol.Permission{
			{Action: datasources.ActionRead, Scope: datasources.ScopeProvider.GetResourceScopeUID("grafana")},
			{Action: datasources.ActionQuery, Scope: datasources.ScopeProvider.GetResourceScopeUID("grafana")},
		}
		listed := env.list(t, collectionUser("viewer", grants), grants)
		require.NotContains(t, listed, "http://loki-edit.example")
		require.NotContains(t, listed, "http://loki-query.example")
		require.NotContains(t, listed, "http://loki-secret.example")
	})

	t.Run("wildcard delete still removes every datasource", func(t *testing.T) {
		env.seedLokiDatasources(t)
		grants := []accesscontrol.Permission{
			{Action: datasources.ActionDelete, Scope: datasources.ScopeAll},
			{Action: datasources.ActionRead, Scope: datasources.ScopeAll},
			{Action: datasources.ActionQuery, Scope: datasources.ScopeAll},
		}
		env.apply(t, collectionUser("admin", grants), grants, http.MethodDelete, collectionPath())
		require.Empty(t, env.uids(t))
	})

	t.Run("named delete does not remove a datasource the caller cannot delete", func(t *testing.T) {
		env.seedLokiDatasources(t)
		grants := editorDatasourceGrants()
		env.apply(t, collectionUser("editor", grants), grants, http.MethodDelete, collectionPath()+"/"+uidQuery)
		remaining := env.uids(t)
		require.Contains(t, remaining, uidQuery)
		require.Contains(t, remaining, uidSecret)
		require.Contains(t, remaining, uidEdit)
	})
}

func collectionPath() string {
	return "/apis/" + lokiGroup + "/v0alpha1/namespaces/" + orgNamespace + "/datasources"
}

// editorDatasourceGrants is an Editor with Edit on one Loki datasource and
// Query on another. Edit is stored as the datasources:edit action set plus
// the granular actions. Query is stored as read and query. The grafana scope
// is the built-in reader grant.
func editorDatasourceGrants() []accesscontrol.Permission {
	edit := datasources.ScopeProvider.GetResourceScopeUID(uidEdit)
	query := datasources.ScopeProvider.GetResourceScopeUID(uidQuery)
	builtin := datasources.ScopeProvider.GetResourceScopeUID("grafana")
	return []accesscontrol.Permission{
		{Action: "datasources:edit", Scope: edit},
		{Action: datasources.ActionRead, Scope: edit},
		{Action: datasources.ActionQuery, Scope: edit},
		{Action: datasources.ActionWrite, Scope: edit},
		{Action: datasources.ActionDelete, Scope: edit},
		{Action: datasources.ActionRead, Scope: query},
		{Action: datasources.ActionQuery, Scope: query},
		{Action: datasources.ActionRead, Scope: builtin},
		{Action: datasources.ActionQuery, Scope: builtin},
	}
}

func collectionUser(uid string, grants []accesscontrol.Permission) *user.SignedInUser {
	byAction := map[string][]string{}
	for _, grant := range grants {
		// Action-set tokens are expanded onto the signed-in user. The
		// permission rows passed to RBAC keep the token.
		if grant.Action == "datasources:edit" || grant.Action == "datasources:admin" {
			continue
		}
		byAction[grant.Action] = append(byAction[grant.Action], grant.Scope)
	}
	return &user.SignedInUser{
		UserID:    7,
		UserUID:   uid,
		OrgID:     orgID,
		Namespace: orgNamespace,
		OrgRole:   identity.RoleEditor,
		Permissions: map[int64]map[string][]string{
			orgID: byAction,
		},
		AccessTokenClaims: &authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{
				DelegatedPermissions: identity.ServiceIdentityClaims.Rest.DelegatedPermissions,
			},
		},
	}
}

type collectionEnv struct {
	sql db.DB
	ds  *dsservice.Service
}

func newCollectionEnv(t *testing.T) *collectionEnv {
	t.Helper()
	sqlStore := db.NewTestStore(t)
	features := featuremgmt.WithFeatures()
	secretsService := secretsmng.SetupTestService(t, fakes.NewFakeSecretsStore())
	secretsStore := secretskvs.NewSQLSecretsKVStore(sqlStore, secretsService, log.New("test"))
	perms := acmock.NewMockedPermissionsService()
	perms.On("SetPermissions", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return([]accesscontrol.ResourcePermission{}, nil)
	perms.On("DeleteResourcePermissions", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	ds, err := dsservice.ProvideService(
		sqlStore,
		secretsService,
		secretsStore,
		&setting.Cfg{},
		features,
		acimpl.ProvideAccessControlTest(),
		perms,
		quotatest.New(false, nil),
		&pluginstore.FakePluginStore{},
		nil,
		nil,
		dsservice.ProvideDataSourceRetriever(sqlStore, features),
	)
	require.NoError(t, err)
	return &collectionEnv{sql: sqlStore, ds: ds}
}

func (e *collectionEnv) seedLokiDatasources(t *testing.T) {
	t.Helper()
	existing, err := e.ds.GetDataSources(context.Background(), &datasources.GetDataSourcesQuery{OrgID: orgID})
	require.NoError(t, err)
	for _, row := range existing {
		require.NoError(t, e.ds.DeleteDataSource(context.Background(), &datasources.DeleteDataSourceCommand{
			UID:   row.UID,
			OrgID: row.OrgID,
		}))
	}
	seeds := []struct {
		uid, name, url, user, purpose string
	}{
		{uidEdit, "Loki editable", "http://loki-edit.example", "edit-user", "edit"},
		{uidQuery, "Loki query only", "http://loki-query.example", "query-user", "query"},
		{uidSecret, "Loki secret", "http://loki-secret.example", "secret-user", "secret"},
	}
	for _, seed := range seeds {
		_, err := e.ds.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
			OrgID:    orgID,
			UID:      seed.uid,
			Name:     seed.name,
			Type:     lokiPlugin,
			Access:   datasources.DS_ACCESS_PROXY,
			URL:      seed.url,
			User:     seed.user,
			JsonData: simplejson.NewFromAny(map[string]any{"purpose": seed.purpose}),
			UserID:   7,
		})
		require.NoError(t, err)
	}
}

func (e *collectionEnv) uids(t *testing.T) map[string]bool {
	t.Helper()
	rows, err := e.ds.GetDataSources(context.Background(), &datasources.GetDataSourcesQuery{OrgID: orgID})
	require.NoError(t, err)
	got := map[string]bool{}
	for _, row := range rows {
		if row.Type == lokiPlugin {
			got[row.UID] = true
		}
	}
	return got
}

// apply parses one HTTP request, authorizes it, and calls storage only when
// the authorizer allows the request. That is the apiserver's rule: a deny
// never reaches Delete or DeleteCollection.
func (e *collectionEnv) apply(t *testing.T, caller *user.SignedInUser, grants []accesscontrol.Permission, method, path string) {
	t.Helper()
	attrs := attributesFromRequest(t, method, path)
	ctx := callerContext(caller)
	decision, reason, err := e.authorizer(t, caller, grants).Authorize(ctx, attrs)
	require.NoError(t, err)
	t.Logf("%s %s verb=%s name=%q decision=%s reason=%q", method, path, attrs.GetVerb(), attrs.GetName(), decision, reason)
	if decision != authorizer.DecisionAllow {
		return
	}
	storage := e.legacyStorage(t)
	switch attrs.GetVerb() {
	case "deletecollection":
		_, err = storage.(rest.CollectionDeleter).DeleteCollection(ctx, nil, &metav1.DeleteOptions{}, &internalversion.ListOptions{})
	case "delete":
		_, _, err = storage.(rest.GracefulDeleter).Delete(ctx, attrs.GetName(), nil, &metav1.DeleteOptions{})
	default:
		t.Fatalf("unexpected verb %s", attrs.GetVerb())
	}
	require.NoError(t, err)
}

func (e *collectionEnv) list(t *testing.T, caller *user.SignedInUser, grants []accesscontrol.Permission) []string {
	t.Helper()
	path := collectionPath()
	attrs := attributesFromRequest(t, http.MethodGet, path)
	require.Empty(t, attrs.GetName())
	require.Equal(t, "list", attrs.GetVerb())
	ctx := callerContext(caller)
	decision, reason, err := e.authorizer(t, caller, grants).Authorize(ctx, attrs)
	require.NoError(t, err)
	t.Logf("GET %s decision=%s reason=%q", path, decision, reason)
	if decision != authorizer.DecisionAllow {
		return nil
	}
	obj, err := e.legacyStorage(t).(rest.Lister).List(ctx, &internalversion.ListOptions{})
	require.NoError(t, err)
	list, ok := obj.(*datasourceV0.DataSourceList)
	require.True(t, ok)
	urls := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		urls = append(urls, item.Spec.URL())
	}
	return urls
}

func (e *collectionEnv) legacyStorage(t *testing.T) rest.Storage {
	t.Helper()
	plugin := plugins.JSONData{ID: lokiPlugin, AliasIDs: []string{}}
	cache := dsservice.ProvideCacheService(localcache.New(time.Minute, time.Minute), e.sql, guardian.ProvideGuardian())
	provider := &scopedDatasourceProvider{
		plugin:    plugin,
		dsService: e.ds,
		dsCache:   cache,
		converter: converter.NewConverter(grafanarequest.GetNamespaceMapper(&setting.Cfg{}), lokiGroup, lokiPlugin, nil),
	}
	legacy := &legacyStorage{datasources: provider}
	// Empty unified-storage config is DualWriter mode 0: the apiserver serves
	// the legacy store directly.
	stored, err := dualwrite.ProvideServiceForTests(dualwrite.NewFakeConfig()).NewStorage(
		schema.GroupResource{Group: lokiGroup, Resource: "datasources"},
		legacy,
		nil,
	)
	require.NoError(t, err)
	return stored
}

func (e *collectionEnv) authorizer(t *testing.T, caller *user.SignedInUser, grants []accesscontrol.Permission) authorizer.Authorizer {
	t.Helper()
	info := datasourceV0.DataSourceResourceInfo.WithGroupAndShortName(lokiGroup, lokiPlugin)
	builder := &DataSourceAPIBuilder{
		datasourceResourceInfo: info,
		pluginJSON:             plugins.JSONData{ID: lokiPlugin},
		accessClient:           newInProcAccessClient(t, caller.UserUID, grants),
	}
	chain := grafanaauthorizer.NewGrafanaBuiltInSTAuthorizer()
	chain.Register(info.GroupVersion(), builder.GetAuthorizer())
	return chain
}

func callerContext(caller *user.SignedInUser) context.Context {
	return k8srequest.WithNamespace(identity.WithRequester(context.Background(), caller), orgNamespace)
}

func attributesFromRequest(t *testing.T, method, path string) authorizer.Attributes {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	info, err := (&k8srequest.RequestInfoFactory{
		APIPrefixes:          sets.NewString("apis"),
		GrouplessAPIPrefixes: sets.NewString("api"),
	}).NewRequestInfo(req)
	require.NoError(t, err)
	require.True(t, info.IsResourceRequest)
	return authorizer.AttributesRecord{
		ResourceRequest: info.IsResourceRequest,
		Path:            info.Path,
		Verb:            info.Verb,
		APIGroup:        info.APIGroup,
		APIVersion:      info.APIVersion,
		Resource:        info.Resource,
		Subresource:     info.Subresource,
		Namespace:       info.Namespace,
		Name:            info.Name,
	}
}

// newInProcAccessClient is the in-process client ProvideAuthZClients builds:
// authlib's client over an in-process server that runs the RBAC service.
func newInProcAccessClient(t *testing.T, userUID string, grants []accesscontrol.Permission) authlib.AccessClient {
	t.Helper()
	server := rbac.NewTestService(userUID, grants, nil)
	channel := &inprocgrpc.Channel{}
	channel.WithServerUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Same service identity the in-process authz server attaches before
		// the RBAC service reads the caller namespace.
		ctx = authlib.WithAuthInfo(ctx, authnlib.NewAccessTokenAuthInfo(authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{
				Namespace: "*",
			},
		}))
		return handler(ctx, req)
	})
	authzv1.RegisterAuthzServiceServer(channel, server)
	return authzlib.NewClient(channel, authzlib.WithCacheClientOption(&authz.NoopCache{}))
}
