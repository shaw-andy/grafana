package datasource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/api/pluginproxy"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	datasourceV0 "github.com/grafana/grafana/pkg/apis/datasource/v0alpha1"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/registry/apis/datasource/converter"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	acmock "github.com/grafana/grafana/pkg/services/accesscontrol/mock"
	grafanarequest "github.com/grafana/grafana/pkg/services/apiserver/endpoints/request"
	"github.com/grafana/grafana/pkg/services/authz/rbac"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/datasources/guardian"
	dsservice "github.com/grafana/grafana/pkg/services/datasources/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/oauthtoken/oauthtokentest"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/plugincontext"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	secretskvs "github.com/grafana/grafana/pkg/services/secrets/kvstore"
	secretsmng "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tests/testsuite"
	"github.com/grafana/grafana/pkg/util/testutil"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

// placeholderBasicAuthSecret is an obvious placeholder for the credential a
// provisioned datasource stores. It is not a real secret.
const placeholderBasicAuthSecret = "placeholder"

const readonlyPluginID = "testds"

func TestReadOnlyDatasourceKubernetesAuthzAllowsEditors(t *testing.T) {
	const namespace = "default"
	const uid = "lockedds"
	ctx := types.WithAuthInfo(context.Background(), authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{
		Claims: jwt.Claims{
			Subject:  types.NewTypeID(types.TypeAccessPolicy, "grafana"),
			Audience: []string{"authzservice"},
		},
		Rest: authn.AccessTokenClaims{Namespace: namespace},
	}))

	// Organization admins hold datasources:write on every datasource. The edit
	// action set grants the same Kubernetes update, patch, delete and
	// deletecollection verbs. Neither check consults the stored read-only flag.
	cases := []struct {
		name        string
		verb        string
		permissions []accesscontrol.Permission
		allowed     bool
	}{
		{
			name: "write on all datasources allows update",
			verb: "update",
			permissions: []accesscontrol.Permission{{
				Action: datasources.ActionWrite,
				Scope:  datasources.ScopeAll,
			}},
			allowed: true,
		},
		{
			name: "delete on all datasources allows delete",
			verb: "delete",
			permissions: []accesscontrol.Permission{{
				Action: datasources.ActionDelete,
				Scope:  datasources.ScopeAll,
			}},
			allowed: true,
		},
		{
			name: "delete on all datasources allows deletecollection",
			verb: "deletecollection",
			permissions: []accesscontrol.Permission{{
				Action: datasources.ActionDelete,
				Scope:  datasources.ScopeAll,
			}},
			allowed: true,
		},
		{
			name: "edit action set scoped to the datasource allows update",
			verb: "update",
			permissions: []accesscontrol.Permission{{
				Action: "datasources:edit",
				Scope:  datasources.ScopeProvider.GetResourceScopeUID(uid),
			}},
			allowed: true,
		},
		{
			name: "query permission does not allow update",
			verb: "update",
			permissions: []accesscontrol.Permission{{
				Action: datasources.ActionQuery,
				Scope:  datasources.ScopeAll,
			}},
			allowed: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := uid
			if tc.verb == "deletecollection" {
				name = ""
			}
			svc := rbac.NewTestService("admin-uid", tc.permissions, nil)
			resp, err := svc.Check(ctx, &authzv1.CheckRequest{
				Namespace: namespace,
				Subject:   "user:admin-uid",
				Group:     readonlyPluginID + ".datasource.grafana.app",
				Resource:  "datasources",
				Verb:      tc.verb,
				Name:      name,
			})
			require.NoError(t, err)
			require.Equal(t, tc.allowed, resp.Allowed)
		})
	}
}

func TestIntegrationReadOnlyDatasourceKubernetesStorage(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	t.Run("update cannot retarget or unlock a provisioned datasource", func(t *testing.T) {
		h := newReadonlyHarness(t)
		operator := newAuthCapture(t)
		attacker := newAuthCapture(t)
		defer operator.Close()
		defer attacker.Close()

		uid := h.provision(t, "Locked", "lockedds", operator.URL, true)
		otherURL := "http://other.example"
		otherUID := h.provision(t, "Other", "otherds", otherURL, false)

		decision, _, err := h.authorizer.Authorize(h.ctx, authorizer.AttributesRecord{
			ResourceRequest: true,
			Verb:            "update",
			Namespace:       h.namespace,
			Name:            uid,
		})
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision)
		require.Equal(t, uid, h.access.lastName, "authorization must name the datasource that is updated")

		current := h.kubernetesObject(t, uid)
		updated := current.DeepCopy()
		updated.Spec.SetURL(attacker.URL)
		updated.Spec.SetReadOnly(false)

		_, _, err = h.store.Update(h.ctx, uid, rest.DefaultUpdatedObjectInfo(updated), nil, nil, false, &metav1.UpdateOptions{})
		requireForbidden(t, err)

		stored := h.stored(t, uid)
		require.Equal(t, operator.URL, stored.URL)
		require.True(t, stored.ReadOnly)
		require.Equal(t, placeholderBasicAuthSecret, h.basicAuthPassword(t, stored))
		require.Equal(t, otherURL, h.stored(t, otherUID).URL)

		h.proxy(t, uid)
		require.Zero(t, attacker.requests(), "stored credential must not be sent to the requested host")
		require.NotZero(t, operator.requests())
		require.True(t, operator.sawPlaceholder(), "the next proxy call still uses the stored credential against the original host")
	})

	t.Run("update authorized for one datasource does not modify another", func(t *testing.T) {
		h := newReadonlyHarness(t)
		lockedURL := "http://locked.example"
		otherURL := "http://other.example"
		lockedUID := h.provision(t, "Locked", "lockedds", lockedURL, true)
		otherUID := h.provision(t, "Other", "otherds", otherURL, false)

		decision, _, err := h.authorizer.Authorize(h.ctx, authorizer.AttributesRecord{
			ResourceRequest: true,
			Verb:            "update",
			Namespace:       h.namespace,
			Name:            lockedUID,
		})
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision)

		// The body names a different datasource than the authorized URL name and
		// carries that datasource's resource version, so a version check cannot
		// hide a write to the wrong object. Secure names are omitted because
		// those are checked against the URL name before the write.
		body := h.kubernetesObject(t, otherUID)
		body.Secure = nil
		body.Spec.SetURL("http://attacker.example")
		body.Spec.SetReadOnly(false)

		_, _, err = h.store.Update(h.ctx, lockedUID, rest.DefaultUpdatedObjectInfo(body), nil, nil, false, &metav1.UpdateOptions{})
		requireForbidden(t, err)
		require.Equal(t, lockedURL, h.stored(t, lockedUID).URL)
		require.True(t, h.stored(t, lockedUID).ReadOnly)
		require.Equal(t, otherURL, h.stored(t, otherUID).URL)
		require.Equal(t, placeholderBasicAuthSecret, h.basicAuthPassword(t, h.stored(t, otherUID)))
	})

	t.Run("delete leaves a provisioned datasource and its credential in place", func(t *testing.T) {
		h := newReadonlyHarness(t)
		url := "http://locked.example"
		uid := h.provision(t, "Locked", "lockedds", url, true)

		decision, _, err := h.authorizer.Authorize(h.ctx, authorizer.AttributesRecord{
			ResourceRequest: true,
			Verb:            "delete",
			Namespace:       h.namespace,
			Name:            uid,
		})
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision)
		require.Equal(t, uid, h.access.lastName)

		_, _, err = h.store.Delete(h.ctx, uid, nil, &metav1.DeleteOptions{})
		requireForbidden(t, err)

		stored := h.stored(t, uid)
		require.Equal(t, url, stored.URL)
		require.True(t, stored.ReadOnly)
		require.Equal(t, placeholderBasicAuthSecret, h.basicAuthPassword(t, stored))
	})

	t.Run("deletecollection does not remove a provisioned datasource", func(t *testing.T) {
		h := newReadonlyHarness(t)
		lockedURL := "http://locked.example"
		writableURL := "http://writable.example"
		lockedUID := h.provision(t, "Locked", "lockedds", lockedURL, true)
		writableUID := h.provision(t, "Writable", "writeds", writableURL, false)
		require.Equal(t, writableURL, h.stored(t, writableUID).URL)

		decision, _, err := h.authorizer.Authorize(h.ctx, authorizer.AttributesRecord{
			ResourceRequest: true,
			Verb:            "deletecollection",
			Namespace:       h.namespace,
		})
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision)

		_, err = h.store.DeleteCollection(h.ctx, nil, &metav1.DeleteOptions{}, &internalversion.ListOptions{})
		requireForbidden(t, err)

		stored := h.stored(t, lockedUID)
		require.Equal(t, lockedURL, stored.URL)
		require.True(t, stored.ReadOnly)
		require.Equal(t, placeholderBasicAuthSecret, h.basicAuthPassword(t, stored))
	})

	t.Run("a writable datasource can still be updated", func(t *testing.T) {
		h := newReadonlyHarness(t)
		uid := h.provision(t, "Writable", "writeds", "http://original.example", false)
		current := h.kubernetesObject(t, uid)
		updated := current.DeepCopy()
		updated.Spec.SetURL("http://updated.example")

		_, _, err := h.store.Update(h.ctx, uid, rest.DefaultUpdatedObjectInfo(updated), nil, nil, false, &metav1.UpdateOptions{})
		require.NoError(t, err)

		stored := h.stored(t, uid)
		require.Equal(t, "http://updated.example", stored.URL)
		require.False(t, stored.ReadOnly)
		require.Equal(t, placeholderBasicAuthSecret, h.basicAuthPassword(t, stored))
	})
}

func requireForbidden(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	require.Truef(t, errors.IsForbidden(err), "expected a forbidden error, got %v", err)
}

type readonlyHarness struct {
	t          *testing.T
	cfg        *setting.Cfg
	sql        db.DB
	svc        *dsservice.Service
	plugin     plugins.JSONData
	pluginList pluginstore.Store
	namespace  string
	ctx        context.Context
	store      *legacyStorage
	authorizer authorizer.Authorizer
	access     *nameBoundAccessClient
}

func newReadonlyHarness(t *testing.T) *readonlyHarness {
	t.Helper()
	cfg := &setting.Cfg{}
	sqlStore := db.InitTestDB(t)
	secretsService := secretsmng.SetupTestService(t, fakes.NewFakeSecretsStore())
	secretsStore := secretskvs.NewSQLSecretsKVStore(sqlStore, secretsService, log.New("test.logger"))
	permissions := acmock.NewMockedPermissionsService()
	permissions.On("SetPermissions", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]accesscontrol.ResourcePermission{}, nil)
	permissions.On("DeleteResourcePermissions", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	plugin := plugins.JSONData{ID: readonlyPluginID, Type: plugins.TypeDataSource, Name: "Test datasource"}
	pluginStore := &pluginstore.FakePluginStore{PluginList: []pluginstore.Plugin{{JSONData: plugin}}}
	features := featuremgmt.WithFeatures()
	dsService, err := dsservice.ProvideService(
		sqlStore,
		secretsService,
		secretsStore,
		cfg,
		features,
		actest.FakeAccessControl{},
		permissions,
		quotatest.New(false, nil),
		pluginStore,
		&pluginfakes.FakePluginClient{},
		plugincontext.ProvideBaseService(cfg, pluginconfig.NewFakePluginRequestConfigProvider()),
		dsservice.ProvideDataSourceRetriever(sqlStore, features),
	)
	require.NoError(t, err)

	namespace := types.OrgNamespaceFormatter(1)
	ctx := identity.WithRequester(context.Background(), &user.SignedInUser{
		UserID:  1,
		OrgID:   1,
		OrgRole: identity.RoleAdmin,
		Login:   "admin",
	})
	ctx = k8srequest.WithNamespace(ctx, namespace)

	info := datasourceV0.DataSourceResourceInfo.WithGroupAndShortName(readonlyPluginID+".datasource.grafana.app", readonlyPluginID)
	access := &nameBoundAccessClient{allowedNames: map[string]bool{}}
	builder := &DataSourceAPIBuilder{
		datasourceResourceInfo: info,
		pluginJSON:             plugin,
		accessClient:           access,
	}

	h := &readonlyHarness{
		t:          t,
		cfg:        cfg,
		sql:        sqlStore,
		svc:        dsService,
		plugin:     plugin,
		pluginList: pluginStore,
		namespace:  namespace,
		ctx:        ctx,
		authorizer: builder.GetAuthorizer(),
		access:     access,
	}
	h.store = &legacyStorage{
		datasources:  h.provider(localcache.ProvideService()),
		resourceInfo: &info,
	}
	return h
}

func (h *readonlyHarness) provider(cacheSvc *localcache.CacheService) PluginDatasourceProvider {
	dsCache := dsservice.ProvideCacheService(cacheSvc, h.sql, guardian.ProvideGuardian())
	pctx := plugincontext.ProvideService(
		h.cfg,
		cacheSvc,
		h.pluginList,
		dsCache,
		h.svc,
		nil,
		pluginconfig.NewFakePluginRequestConfigProvider(),
	)
	return (&cachingDatasourceProvider{
		dsService:       h.svc,
		dsCache:         dsCache,
		contextProvider: pctx,
		converter:       converter.NewConverter(grafanarequest.GetNamespaceMapper(h.cfg), "", "", nil),
	}).GetDatasourceProvider(h.plugin)
}

func (h *readonlyHarness) provision(t *testing.T, title, uid, url string, readOnly bool) string {
	t.Helper()
	ds, err := h.svc.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
		OrgID:          1,
		Name:           title,
		UID:            uid,
		Type:           readonlyPluginID,
		Access:         datasources.DsAccess("proxy"),
		URL:            url,
		BasicAuth:      true,
		BasicAuthUser:  "operator",
		ReadOnly:       readOnly,
		JsonData:       simplejson.New(),
		SecureJsonData: map[string]string{"basicAuthPassword": placeholderBasicAuthSecret},
	})
	require.NoError(t, err)
	h.access.allowedNames[ds.UID] = true
	return ds.UID
}

func (h *readonlyHarness) kubernetesObject(t *testing.T, uid string) *datasourceV0.DataSource {
	t.Helper()
	obj, err := h.store.Get(h.ctx, uid, &metav1.GetOptions{})
	require.NoError(t, err)
	ds, ok := obj.(*datasourceV0.DataSource)
	require.True(t, ok)
	return ds
}

func (h *readonlyHarness) stored(t *testing.T, uid string) *datasources.DataSource {
	t.Helper()
	ds, err := h.svc.GetDataSource(context.Background(), &datasources.GetDataSourceQuery{UID: uid, OrgID: 1})
	require.NoError(t, err)
	return ds
}

func (h *readonlyHarness) basicAuthPassword(t *testing.T, ds *datasources.DataSource) string {
	t.Helper()
	value, err := h.svc.DecryptedBasicAuthPassword(context.Background(), ds)
	require.NoError(t, err)
	return value
}

func (h *readonlyHarness) proxy(t *testing.T, uid string) {
	t.Helper()
	// A new cache reads the database rather than the object loaded before the update.
	loader := newDatasourceLoader(h.provider(localcache.ProvideService()), uid, h.plugin.ID)
	req := httptest.NewRequest(http.MethodGet, "/apis/"+readonlyPluginID+".datasource.grafana.app/v0alpha1/namespaces/"+h.namespace+"/datasources/"+uid+"/proxy/health", nil)
	req = req.WithContext(h.ctx)
	recorder := httptest.NewRecorder()
	proxy, err := pluginproxy.NewDataSourceProxy(
		loader,
		nil,
		pluginproxy.HTTPContext{Req: req, Resp: recorder},
		"health",
		pluginproxy.NewDataSourceProxySettings(h.cfg),
		httpclient.NewProvider(),
		oauthtokentest.ProvideService(),
		tracing.NewNoopTracerService(),
		featuremgmt.WithFeatures(),
	)
	require.NoError(t, err)
	proxy.HandleRequest()
}

// nameBoundAccessClient allows Kubernetes datasource verbs only for names the
// test authorized. deletecollection has no name. The client does not look at
// the stored read-only flag; the RBAC service test covers that decision.
type nameBoundAccessClient struct {
	allowedNames map[string]bool
	lastName     string
	lastVerb     string
}

func (c *nameBoundAccessClient) Check(_ context.Context, _ types.AuthInfo, req types.CheckRequest, _ string) (types.CheckResponse, error) {
	c.lastName = req.Name
	c.lastVerb = req.Verb
	if req.Verb == "deletecollection" && req.Name == "" {
		return types.CheckResponse{Allowed: true}, nil
	}
	return types.CheckResponse{Allowed: c.allowedNames[req.Name]}, nil
}

func (c *nameBoundAccessClient) Compile(context.Context, types.AuthInfo, types.ListRequest) (types.ItemChecker, types.Zookie, error) {
	return nil, nil, nil
}

func (c *nameBoundAccessClient) BatchCheck(context.Context, types.AuthInfo, types.BatchCheckRequest) (types.BatchCheckResponse, error) {
	return types.BatchCheckResponse{}, nil
}

type authCapture struct {
	*httptest.Server
	mu    sync.Mutex
	count int
	saw   bool
}

func newAuthCapture(t *testing.T) *authCapture {
	t.Helper()
	c := &authCapture{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		c.mu.Lock()
		c.count++
		if ok && user == "operator" && password == placeholderBasicAuthSecret {
			c.saw = true
		}
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	return c
}

func (c *authCapture) requests() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

func (c *authCapture) sawPlaceholder() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saw
}
