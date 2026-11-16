package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/grafana/grafana-azure-sdk-go/v2/azsettings"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins/manager/client"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/caching"
	datasources "github.com/grafana/grafana/pkg/services/datasources"
	dsfakes "github.com/grafana/grafana/pkg/services/datasources/fakes"
	"github.com/grafana/grafana/pkg/services/datasources/guardian"
	dsservice "github.com/grafana/grafana/pkg/services/datasources/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/oauthtoken/oauthtokentest"
	"github.com/grafana/grafana/pkg/services/pluginsintegration"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/coreplugin"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginaccesscontrol"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/plugincontext"
	pluginSettings "github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings/service"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	fakeSecrets "github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch"
	testdatasource "github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// TestData resource routes must not panic. The built-in TestData plugin's boom
// route currently panics on every method, and the HTTP recovery middleware turns
// that into a 500. These tests fail until that route is removed or the handler
// returns a normal response instead of panicking.
func TestTestDataBoomResourceDoesNotPanic(t *testing.T) {
	srv, ds := setupTestDataResourceServer(t)

	viewer := testDataQueryUser()
	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodHead,
		http.MethodOptions,
	}

	t.Run("scenarios resource still responds", func(t *testing.T) {
		rec := serveResource(t, srv, http.MethodGet, "/api/datasources/uid/"+ds.UID+"/resources/scenarios", viewer)
		require.Equal(t, http.StatusOK, rec.Code)
		require.NotContains(t, rec.Body.String(), "Internal Server Error")
	})

	targets := []struct {
		name string
		path string
		user *user.SignedInUser
	}{
		{
			name: "datasource uid resource",
			path: "/api/datasources/uid/" + ds.UID + "/resources/boom",
			user: viewer,
		},
		{
			name: "datasource id resource",
			path: "/api/datasources/" + strconv.Itoa(int(ds.ID)) + "/resources/boom",
			user: viewer,
		},
		{
			name: "plugin resource",
			path: "/api/plugins/grafana-testdata-datasource/resources/boom",
			user: testDataPluginAccessUser(),
		},
	}

	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			for _, method := range methods {
				t.Run(method, func(t *testing.T) {
					rec := serveResource(t, srv, method, target.path, target.user)
					require.NotEqual(t, http.StatusInternalServerError, rec.Code, "body: %s", rec.Body.String())
					require.NotContains(t, rec.Body.String(), "Internal Server Error")
				})
			}
		})
	}
}

func TestTestDataBoomResourceDeniesCallersWithoutPermission(t *testing.T) {
	srv, ds := setupTestDataResourceServer(t)

	unsigned := &user.SignedInUser{UserID: 2, OrgID: 1, OrgRole: "Viewer"}
	cases := []struct {
		name string
		path string
		user *user.SignedInUser
	}{
		{
			name: "datasource resource without datasources:query",
			path: "/api/datasources/uid/" + ds.UID + "/resources/boom",
			user: unsigned,
		},
		{
			name: "plugin resource without plugins.app:access",
			path: "/api/plugins/grafana-testdata-datasource/resources/boom",
			user: unsigned,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveResource(t, srv, http.MethodGet, tc.path, tc.user)
			require.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
		})
	}
}

func setupTestDataResourceServer(t *testing.T) (*webtest.Server, *datasources.DataSource) {
	t.Helper()

	staticRootPath, err := filepath.Abs("../../public/")
	require.NoError(t, err)

	cfg := setting.NewCfg()
	cfg.StaticRootPath = staticRootPath
	cfg.Azure = &azsettings.AzureSettings{}

	sqlStore := db.InitTestDB(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	ds := &datasources.DataSource{
		OrgID:     1,
		Name:      "TestData",
		Type:      datasources.DS_TESTDATA,
		Access:    datasources.DS_ACCESS_PROXY,
		UID:       "testdata",
		JsonData:  simplejson.New(),
		Version:   1,
		Created:   time.Now(),
		Updated:   time.Now(),
		IsDefault: true,
	}
	require.NoError(t, sqlStore.WithDbSession(context.Background(), func(sess *db.Session) error {
		_, err := sess.Insert(ds)
		return err
	}))
	require.NotZero(t, ds.ID)

	coreRegistry := coreplugin.ProvideCoreRegistry(tracing.InitializeTracerForTest(), nil, &cloudwatch.Service{}, nil,
		testdatasource.ProvideService(), nil)
	testCtx := pluginsintegration.CreateIntegrationTestCtx(t, cfg, coreRegistry)

	baseClient := client.ProvideService(testCtx.PluginRegistry)
	middlewares := pluginsintegration.CreateMiddlewares(cfg, &oauthtokentest.Service{}, tracing.InitializeTracerForTest(),
		caching.ProvideCachingServiceClient(&caching.OSSCachingService{}, nil), featuremgmt.WithFeatures(),
		prometheus.NewRegistry(), testCtx.PluginRegistry)
	pluginClient, err := backend.HandlerFromMiddlewares(baseClient, middlewares...)
	require.NoError(t, err)

	pcp := plugincontext.ProvideService(cfg, localcache.ProvideService(), testCtx.PluginStore, &dsfakes.FakeCacheService{},
		&dsfakes.FakeDataSourceService{}, pluginSettings.ProvideService(sqlStore, fakeSecrets.NewFakeSecretsService()), pluginconfig.NewFakePluginRequestConfigProvider()) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore

	cache := dsservice.ProvideCacheService(localcache.ProvideService(), sqlStore, guardian.ProvideGuardian())

	srv := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.Features = featuremgmt.WithFeatures(featuremgmt.FlagDatasourceLegacyIdApi)
		hs.pluginContextProvider = pcp
		hs.QuotaService = quotatest.New(false, nil)
		hs.pluginStore = testCtx.PluginStore
		hs.pluginClient = pluginClient
		hs.DataSourceCache = cache
		hs.DataSourceRequestValidator = validations.ProvideValidator()
		hs.log = log.New("test")
		hs.promRegister, hs.dsConfigHandlerRequestsDuration, hs.dsEndpointRedirects = setupDsConfigHandlerMetrics()
	})

	return srv, ds
}

func serveResource(t *testing.T, srv *webtest.Server, method, path string, usr *user.SignedInUser) *httptest.ResponseRecorder {
	t.Helper()

	req := srv.NewRequest(method, path, nil)
	webtest.RequestWithSignedInUser(req, usr)

	rec := httptest.NewRecorder()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("%s %s panicked: %v", method, path, recovered)
		}
	}()
	srv.Mux.ServeHTTP(rec, req)
	return rec
}

func testDataQueryUser() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  1,
		OrgID:   1,
		OrgRole: "Viewer",
		Permissions: map[int64]map[string][]string{
			1: {
				datasources.ActionQuery: {datasources.ScopeAll},
			},
		},
	}
}

func testDataPluginAccessUser() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  1,
		OrgID:   1,
		OrgRole: "Viewer",
		Permissions: map[int64]map[string][]string{
			1: accesscontrol.GroupScopesByActionContext(context.Background(), []accesscontrol.Permission{
				{Action: pluginaccesscontrol.ActionAppAccess, Scope: pluginaccesscontrol.ScopeProvider.GetResourceAllScope()},
			}),
		},
	}
}
