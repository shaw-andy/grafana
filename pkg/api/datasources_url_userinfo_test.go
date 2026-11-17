package api

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	gokitlog "github.com/go-kit/log"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/accesscontrol/database"
	acmock "github.com/grafana/grafana/pkg/services/accesscontrol/mock"
	"github.com/grafana/grafana/pkg/services/accesscontrol/permreg"
	"github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/datasources/guardian"
	datasourceservice "github.com/grafana/grafana/pkg/services/datasources/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/services/live"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/plugincontext"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	secretskvs "github.com/grafana/grafana/pkg/services/secrets/kvstore"
	secretsmng "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web"
)

const (
	// Obvious placeholders. These are not credentials.
	datasourceURLUser          = "placeholder-user"
	datasourceURLSecret        = "placeholder-secret"
	datasourceSecureFieldValue = "placeholder-secure-field"
	datasourceURLHost          = "backend.example.test"
)

func datasourceURLWithUserinfo() string {
	return "http://" + datasourceURLUser + ":" + datasourceURLSecret + "@" + datasourceURLHost + ":9090"
}

func datasourceURLWithoutUserinfo() string {
	return "http://" + datasourceURLHost + ":9090"
}

type datasourceURLFixture struct {
	t       *testing.T
	hs      *HTTPServer
	service *datasourceservice.Service
	sc      *scenarioContext
	actor   *user.SignedInUser
	admin   *user.SignedInUser
	viewer  *user.SignedInUser
}

func (f *datasourceURLFixture) as(actor *user.SignedInUser) {
	f.t.Helper()
	f.actor = actor
}

func (f *datasourceURLFixture) request(method, path string, body any) *http.Response {
	f.t.Helper()
	f.sc.fakeReq(method, path)
	if body != nil {
		f.sc.req.Body = mockRequestBody(body)
		f.sc.req.ContentLength = -1
	}
	f.sc.exec()
	return f.sc.resp.Result()
}

func (f *datasourceURLFixture) body(method, path string, payload any) (int, []byte) {
	f.t.Helper()
	resp := f.request(method, path, payload)
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(resp.Body)
	require.NoError(f.t, err)
	return resp.StatusCode, buf.Bytes()
}

func newDatasourceURLFixture(t *testing.T) *datasourceURLFixture {
	t.Helper()
	testutil.SkipIntegrationTestInShortMode(t)

	sqlStore := db.InitTestDB(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	features := featuremgmt.WithFeatures()
	acService := acimpl.ProvideOSSService(
		setting.NewCfg(),
		database.ProvideService(sqlStore),
		resourcepermissions.NewActionSetService(),
		localcache.ProvideService(),
		features,
		tracing.InitializeTracerForTest(),
		sqlStore,
		permreg.ProvidePermissionRegistry(),
		nil,
	)
	require.NoError(t, acService.DeclareFixedRoles(FixedRoleRegistrations(false, false)...))
	require.NoError(t, acService.RegisterFixedRoles(context.Background()))

	adminPerms := permissionsFor(t, acService, 1, identity.RoleAdmin)
	viewerPerms := permissionsFor(t, acService, 2, identity.RoleViewer)
	requireScope(t, viewerPerms, datasources.ActionRead, datasources.ScopeAll)
	requireNoAction(t, viewerPerms, datasources.ActionCreate)
	requireAction(t, adminPerms, datasources.ActionCreate)
	requireAction(t, adminPerms, datasources.ActionWrite)

	enforced := acimpl.ProvideOSSService(
		setting.NewCfg(),
		database.ProvideService(sqlStore),
		resourcepermissions.NewActionSetService(),
		localcache.ProvideService(),
		features,
		tracing.InitializeTracerForTest(),
		sqlStore,
		permreg.ProvidePermissionRegistry(),
		nil,
	)
	require.NoError(t, enforced.DeclareFixedRoles(FixedRoleRegistrations(false, true)...))
	require.NoError(t, enforced.RegisterFixedRoles(context.Background()))
	enforcedViewer := permissionsFor(t, enforced, 2, identity.RoleViewer)
	requireNoScope(t, enforcedViewer, datasources.ActionRead, datasources.ScopeAll)

	secretsService := secretsmng.SetupTestService(t, fakes.NewFakeSecretsStore())
	secretsStore := secretskvs.NewSQLSecretsKVStore(sqlStore, secretsService, log.New("test.logger"))
	dsCfg := &setting.Cfg{}
	dsService, err := datasourceservice.ProvideService(
		sqlStore,
		secretsService,
		secretsStore,
		dsCfg,
		features,
		acimpl.ProvideAccessControl(features),
		acmock.NewMockedPermissionsService(),
		quotatest.New(false, nil),
		&pluginstore.FakePluginStore{},
		&pluginfakes.FakePluginClient{},
		plugincontext.ProvideBaseService(dsCfg, pluginconfig.NewFakePluginRequestConfigProvider()),
		datasourceservice.ProvideDataSourceRetriever(sqlStore, features),
	)
	require.NoError(t, err)

	hs := &HTTPServer{
		Cfg:                  dsCfg,
		Features:             features,
		License:              &licensing.OSSLicensingService{},
		Live:                 &live.GrafanaLive{},
		AccessControl:        acimpl.ProvideAccessControl(features),
		accesscontrolService: actest.FakeService{},
		DataSourcesService:   dsService,
		dsGuardian:           guardian.ProvideGuardian(),
		pluginStore:          &pluginstore.FakePluginStore{},
		pluginAssets:         newPluginAssets()(),
		tracer:               tracing.InitializeTracerForTest(),
	}
	hs.promRegister, hs.dsConfigHandlerRequestsDuration, hs.dsEndpointRedirects = setupDsConfigHandlerMetrics()

	f := &datasourceURLFixture{
		t:       t,
		hs:      hs,
		service: dsService,
		admin:   userWithPermissions(testOrgID, adminPerms),
		viewer:  userWithPermissions(testOrgID, viewerPerms),
	}
	f.admin.UserID = 1
	f.admin.OrgRole = identity.RoleAdmin
	f.viewer.UserID = 2
	f.viewer.OrgRole = identity.RoleViewer

	f.sc = setupScenarioContext(t, "/api/datasources/")
	f.sc.m.Use(func(c *web.Context) {
		rc := contexthandler.FromContext(c.Req.Context())
		if rc == nil || f.actor == nil {
			return
		}
		rc.SignedInUser = f.actor
		rc.IsSignedIn = true
		rc.LookupTokenErr = nil
	})

	authorize := accesscontrol.Middleware(hs.AccessControl)
	uidScope := datasources.ScopeProvider.GetResourceScopeUID(accesscontrol.Parameter(":uid"))
	nameScope := datasources.ScopeProvider.GetResourceScopeName(accesscontrol.Parameter(":name"))
	idScope := datasources.ScopeProvider.GetResourceScope(accesscontrol.Parameter(":id"))
	f.sc.m.Post("/api/datasources/", authorize(accesscontrol.EvalPermission(datasources.ActionCreate)), routing.Wrap(hs.AddDataSource))
	f.sc.m.Put("/api/datasources/uid/:uid", authorize(accesscontrol.EvalPermission(datasources.ActionWrite, uidScope)), routing.Wrap(hs.UpdateDataSourceByUID))
	f.sc.m.Put("/api/datasources/:id", authorize(accesscontrol.EvalPermission(datasources.ActionWrite, idScope)), routing.Wrap(hs.UpdateDataSourceByID))
	f.sc.m.Get("/api/datasources/", authorize(accesscontrol.EvalPermission(datasources.ActionRead)), routing.Wrap(hs.GetDataSources))
	f.sc.m.Get("/api/datasources/uid/:uid", authorize(accesscontrol.EvalPermission(datasources.ActionRead, uidScope)), hs.getK8sDataSourceByUIDHandler())
	f.sc.m.Get("/api/datasources/name/:name", authorize(accesscontrol.EvalPermission(datasources.ActionRead, nameScope)), routing.Wrap(hs.GetDataSourceByName))
	f.sc.m.Get("/api/datasources/:id", authorize(accesscontrol.EvalPermission(datasources.ActionRead, idScope)), routing.Wrap(hs.GetDataSourceById))
	f.sc.m.Get("/api/frontend/settings/datasources", authorize(accesscontrol.EvalPermission(datasources.ActionRead)), func(c *web.Context) {
		rc := contexthandler.FromContext(c.Req.Context())
		out, err := hs.getFSDataSources(rc, AvailablePlugins{
			plugins.TypeDataSource: {
				datasources.DS_PROMETHEUS: {
					Plugin: pluginstore.Plugin{
						JSONData: plugins.JSONData{
							ID:   datasources.DS_PROMETHEUS,
							Type: plugins.TypeDataSource,
							Name: "Prometheus",
						},
					},
				},
			},
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}
		c.JSON(http.StatusOK, out)
	})
	return f
}

func permissionsFor(t *testing.T, svc *acimpl.Service, userID int64, role identity.RoleType) []accesscontrol.Permission {
	t.Helper()
	perms, err := svc.GetUserPermissions(context.Background(), &user.SignedInUser{
		UserID:  userID,
		OrgID:   testOrgID,
		OrgRole: role,
	}, accesscontrol.Options{})
	require.NoError(t, err)
	return perms
}

func requireAction(t *testing.T, perms []accesscontrol.Permission, action string) {
	t.Helper()
	for _, perm := range perms {
		if perm.Action == action {
			return
		}
	}
	t.Fatalf("expected permission %s", action)
}

func requireNoAction(t *testing.T, perms []accesscontrol.Permission, action string) {
	t.Helper()
	for _, perm := range perms {
		if perm.Action == action {
			t.Fatalf("did not expect permission %s", action)
		}
	}
}

func requireScope(t *testing.T, perms []accesscontrol.Permission, action, scope string) {
	t.Helper()
	for _, perm := range perms {
		if perm.Action == action && perm.Scope == scope {
			return
		}
	}
	t.Fatalf("expected %s on %s", action, scope)
}

func requireNoScope(t *testing.T, perms []accesscontrol.Permission, action, scope string) {
	t.Helper()
	for _, perm := range perms {
		if perm.Action == action && perm.Scope == scope {
			t.Fatalf("did not expect %s on %s", action, scope)
		}
	}
}

func requireResponseHidesDatasourceCredentials(t *testing.T, body []byte) {
	t.Helper()
	text := string(body)
	require.NotContains(t, text, datasourceURLSecret)
	require.NotContains(t, text, datasourceURLUser)
	require.NotContains(t, text, datasourceSecureFieldValue)
}

func requireStoredURLWithoutUserinfo(t *testing.T, raw string) {
	t.Helper()
	require.NotContains(t, raw, datasourceURLSecret)
	require.NotContains(t, raw, datasourceURLUser)
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	require.Nil(t, parsed.User)
	require.Contains(t, parsed.Host, datasourceURLHost)
}

func (f *datasourceURLFixture) storedByName(name string) (*datasources.DataSource, error) {
	f.t.Helper()
	return f.service.GetDataSource(context.Background(), &datasources.GetDataSourceQuery{
		OrgID: testOrgID,
		Name:  name,
	})
}

func TestIntegrationDatasourceURLUserinfo(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)
	require.False(t, (&licensing.OSSLicensingService{}).FeatureEnabled("dspermissions.enforcement"))

	f := newDatasourceURLFixture(t)

	t.Run("viewer is denied without datasources read", func(t *testing.T) {
		f.as(userWithPermissions(testOrgID, nil))
		status, body := f.body(http.MethodGet, "/api/datasources/", nil)
		require.Equal(t, http.StatusForbidden, status)
		requireResponseHidesDatasourceCredentials(t, body)
	})

	t.Run("create does not keep userinfo", func(t *testing.T) {
		const name = "created-with-userinfo"
		f.as(f.admin)
		status, body := f.body(http.MethodPost, "/api/datasources/", datasources.AddDataSourceCommand{
			Name:   name,
			Type:   datasources.DS_PROMETHEUS,
			Access: datasources.DS_ACCESS_PROXY,
			URL:    datasourceURLWithUserinfo(),
			UID:    "createdds1",
			SecureJsonData: map[string]string{
				"password": datasourceSecureFieldValue,
			},
		})
		requireResponseHidesDatasourceCredentials(t, body)
		stored, err := f.storedByName(name)
		if status == http.StatusOK {
			require.NoError(t, err)
			requireStoredURLWithoutUserinfo(t, stored.URL)
			require.Equal(t, "createdds1", stored.UID)
		} else {
			require.Equal(t, http.StatusBadRequest, status)
			require.ErrorIs(t, err, datasources.ErrDataSourceNotFound)
		}

		f.as(f.viewer)
		status, body = f.body(http.MethodGet, "/api/datasources/", nil)
		require.Equal(t, http.StatusOK, status)
		requireResponseHidesDatasourceCredentials(t, body)
		status, body = f.body(http.MethodGet, "/api/datasources/uid/createdds1", nil)
		requireResponseHidesDatasourceCredentials(t, body)
		if status == http.StatusOK {
			require.Contains(t, string(body), datasourceURLHost)
			require.Contains(t, string(body), `"uid":"createdds1"`)
		} else {
			require.Equal(t, http.StatusNotFound, status)
		}
	})

	t.Run("update by uid does not keep userinfo", func(t *testing.T) {
		const name = "clean-then-update"
		created, err := f.service.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
			OrgID:  testOrgID,
			Name:   name,
			Type:   datasources.DS_PROMETHEUS,
			Access: datasources.DS_ACCESS_PROXY,
			URL:    datasourceURLWithoutUserinfo(),
			UID:    "updateds01",
		})
		require.NoError(t, err)

		f.as(f.admin)
		status, body := f.body(http.MethodPut, "/api/datasources/uid/"+created.UID, datasources.UpdateDataSourceCommand{
			Name:    name,
			Type:    datasources.DS_PROMETHEUS,
			Access:  datasources.DS_ACCESS_PROXY,
			URL:     datasourceURLWithUserinfo(),
			UID:     created.UID,
			Version: created.Version,
		})
		requireResponseHidesDatasourceCredentials(t, body)
		stored, err := f.storedByName(name)
		require.NoError(t, err)
		require.Equal(t, created.UID, stored.UID)
		if status == http.StatusOK {
			requireStoredURLWithoutUserinfo(t, stored.URL)
		} else {
			require.Equal(t, http.StatusBadRequest, status)
			require.Equal(t, datasourceURLWithoutUserinfo(), stored.URL)
		}

		f.as(f.viewer)
		status, body = f.body(http.MethodGet, "/api/datasources/uid/"+created.UID, nil)
		require.Equal(t, http.StatusOK, status)
		requireResponseHidesDatasourceCredentials(t, body)
		require.Contains(t, string(body), `"uid":"`+created.UID+`"`)
		require.Contains(t, string(body), datasourceURLHost)
	})

	t.Run("update by id does not keep userinfo", func(t *testing.T) {
		const name = "clean-then-update-id"
		created, err := f.service.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
			OrgID:  testOrgID,
			Name:   name,
			Type:   datasources.DS_PROMETHEUS,
			Access: datasources.DS_ACCESS_PROXY,
			URL:    datasourceURLWithoutUserinfo(),
			UID:    "updateid01",
		})
		require.NoError(t, err)

		f.as(f.admin)
		status, body := f.body(http.MethodPut, "/api/datasources/"+strconv.FormatInt(created.ID, 10), datasources.UpdateDataSourceCommand{
			Name:    name,
			Type:    datasources.DS_PROMETHEUS,
			Access:  datasources.DS_ACCESS_DIRECT,
			URL:     datasourceURLWithUserinfo(),
			Version: created.Version,
		})
		requireResponseHidesDatasourceCredentials(t, body)
		stored, err := f.storedByName(name)
		require.NoError(t, err)
		require.Equal(t, created.ID, stored.ID)
		if status == http.StatusOK {
			requireStoredURLWithoutUserinfo(t, stored.URL)
		} else {
			require.Equal(t, http.StatusBadRequest, status)
			require.Equal(t, datasourceURLWithoutUserinfo(), stored.URL)
		}

		f.as(f.viewer)
		status, body = f.body(http.MethodGet, "/api/datasources/"+strconv.FormatInt(created.ID, 10), nil)
		require.Equal(t, http.StatusOK, status)
		requireResponseHidesDatasourceCredentials(t, body)
		require.Contains(t, string(body), datasourceURLHost)
	})

	t.Run("previously stored userinfo is redacted on read", func(t *testing.T) {
		created, err := f.service.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
			OrgID:  testOrgID,
			Name:   "provisioned-with-userinfo",
			Type:   datasources.DS_PROMETHEUS,
			Access: datasources.DS_ACCESS_PROXY,
			URL:    datasourceURLWithUserinfo(),
			UID:    "seededds01",
			SecureJsonData: map[string]string{
				"password": datasourceSecureFieldValue,
			},
		})
		require.NoError(t, err)
		require.Contains(t, created.URL, datasourceURLSecret)

		f.as(f.viewer)
		reads := []struct {
			name string
			path string
		}{
			{name: "list", path: "/api/datasources/"},
			{name: "uid", path: "/api/datasources/uid/" + created.UID},
			{name: "name", path: "/api/datasources/name/" + created.Name},
			{name: "id", path: "/api/datasources/" + strconv.FormatInt(created.ID, 10)},
		}
		for _, read := range reads {
			t.Run(read.name, func(t *testing.T) {
				status, body := f.body(http.MethodGet, read.path, nil)
				require.Equal(t, http.StatusOK, status)
				requireResponseHidesDatasourceCredentials(t, body)
				require.Contains(t, string(body), datasourceURLHost)
				if read.name == "uid" {
					require.Contains(t, string(body), `"uid":"`+created.UID+`"`)
				}
			})
		}
	})

	t.Run("boot data redacts direct urls and proxy urls", func(t *testing.T) {
		direct, err := f.service.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
			OrgID:  testOrgID,
			Name:   "boot-direct",
			Type:   datasources.DS_PROMETHEUS,
			Access: datasources.DS_ACCESS_DIRECT,
			URL:    datasourceURLWithUserinfo(),
			UID:    "bootdirect",
			SecureJsonData: map[string]string{
				"password": datasourceSecureFieldValue,
			},
		})
		require.NoError(t, err)
		proxy, err := f.service.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
			OrgID:  testOrgID,
			Name:   "boot-proxy",
			Type:   datasources.DS_PROMETHEUS,
			Access: datasources.DS_ACCESS_PROXY,
			URL:    datasourceURLWithUserinfo(),
			UID:    "bootproxy1",
		})
		require.NoError(t, err)

		f.as(f.viewer)
		status, body := f.body(http.MethodGet, "/api/frontend/settings/datasources", nil)
		require.Equal(t, http.StatusOK, status)
		requireResponseHidesDatasourceCredentials(t, body)
		text := string(body)
		require.Contains(t, text, direct.Name)
		require.Contains(t, text, proxy.Name)
		require.Contains(t, text, datasourceURLHost)
		require.Contains(t, text, "/api/datasources/proxy/uid/"+proxy.UID)
	})
}

func TestDatasourceURLValidationFailureDoesNotLogUserinfo(t *testing.T) {
	var buf bytes.Buffer
	replacement := log.New("datasources-test")
	replacement.Swap(gokitlog.NewLogfmtLogger(&buf))
	previous := datasourcesLogger
	datasourcesLogger = replacement
	t.Cleanup(func() {
		datasourcesLogger = previous
	})

	hs := &HTTPServer{
		DataSourcesService: &dataSourcesServiceMock{},
		Cfg:                setting.NewCfg(),
	}
	hs.promRegister, hs.dsConfigHandlerRequestsDuration, hs.dsEndpointRedirects = setupDsConfigHandlerMetrics()
	sc := setupScenarioContext(t, "/api/datasources")
	sc.m.Post(sc.url, routing.Wrap(func(c *contextmodel.ReqContext) response.Response {
		c.Req.Body = mockRequestBody(datasources.AddDataSourceCommand{
			Name:   "invalid-url",
			Type:   datasources.DS_PROMETHEUS,
			Access: datasources.DS_ACCESS_PROXY,
			URL:    "http://" + datasourceURLUser + ":" + datasourceURLSecret + "@" + datasourceURLHost + ":notaport",
		})
		c.SignedInUser = authedUserWithPermissions(1, 1, nil)
		return hs.AddDataSource(c)
	}))
	sc.fakeReqWithParams("POST", sc.url, map[string]string{}).exec()

	require.Equal(t, http.StatusBadRequest, sc.resp.Code)
	requireResponseHidesDatasourceCredentials(t, sc.resp.Body.Bytes())
	require.NotContains(t, buf.String(), datasourceURLSecret)
	require.NotContains(t, buf.String(), datasourceURLUser)
}
