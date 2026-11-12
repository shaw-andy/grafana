package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	preferences "github.com/grafana/grafana/apps/preferences/pkg/apis/preferences/v1"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	acmock "github.com/grafana/grafana/pkg/services/accesscontrol/mock"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/datasources"
	dsservice "github.com/grafana/grafana/pkg/services/datasources/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/hooks"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/plugincontext"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/preference/prefapi"
	"github.com/grafana/grafana/pkg/services/publicdashboards"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	secretskvs "github.com/grafana/grafana/pkg/services/secrets/kvstore"
	secretsmng "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web"
)

// Placeholders stand in for datasource secrets. The public dashboard response must not contain them.
const (
	publicDashInfluxSecret   = "placeholder-influx-secret"
	publicDashInflux08Secret = "placeholder-influx08-secret"
	publicDashBasicSecret    = "placeholder-basic-secret"
	publicDashProxySecret    = "placeholder-proxy-secret"
	publicDashOtherOrgSecret = "placeholder-other-org-secret"

	publicDashBasicUser  = "placeholder-basic-user"
	publicDashInfluxUser = "placeholder-influx-user"

	publicDashAccessToken = "00000000-0000-4000-8000-000000000001"
	publicDashOrgID       = int64(42)
)

func TestIntegrationPublicDashboardBootDataOmitsDirectAccessSecrets(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	defaults, err := ini.Load(filepath.Join("..", "..", "conf", "defaults.ini"))
	require.NoError(t, err)
	require.True(t, defaults.Section("public_dashboards").Key("enabled").MustBool(false),
		"public dashboards are enabled in the shipped defaults")

	influxUID := "pdinflux1"
	influx08UID := "pdinfl08a"
	basicUID := "pdbasica1"
	proxyUID := "pdproxy01"
	otherOrgUID := "pdother01"

	cfg := setting.NewCfg()
	cfg.Env = setting.Dev
	cfg.StaticRootPath = filepath.Join("webassets", "testdata")
	cfg.DefaultTheme = "dark"
	cfg.PublicDashboardsEnabled = true

	pluginStore := pluginstore.NewFakePluginStore(
		publicDashTestPlugin(datasources.DS_INFLUXDB),
		publicDashTestPlugin(datasources.DS_INFLUXDB_08),
		publicDashTestPlugin(datasources.DS_PROMETHEUS),
	)
	features := featuremgmt.WithFeatures()
	_, hs := setupTestEnvironment(t, cfg, features, pluginStore, nil, nil)

	secretsService := secretsmng.SetupTestService(t, fakes.NewFakeSecretsStore())
	secretsStore := secretskvs.NewSQLSecretsKVStore(hs.SQLStore, secretsService, hs.Cfg.Logger)
	dsService, err := dsservice.ProvideService(
		hs.SQLStore,
		secretsService,
		secretsStore,
		cfg,
		features,
		acmock.New(),
		acmock.NewMockedPermissionsService(),
		quotatest.New(false, nil),
		pluginStore,
		&pluginfakes.FakePluginClient{},
		plugincontext.ProvideBaseService(cfg, pluginconfig.NewFakePluginRequestConfigProvider()),
		dsservice.ProvideDataSourceRetriever(hs.SQLStore, features),
	)
	require.NoError(t, err)
	hs.DataSourcesService = dsService

	ctx := context.Background()
	_, err = dsService.AddDataSource(ctx, &datasources.AddDataSourceCommand{
		OrgID:         publicDashOrgID,
		UID:           influxUID,
		Name:          "Public Influx",
		Type:          datasources.DS_INFLUXDB,
		Access:        datasources.DS_ACCESS_DIRECT,
		URL:           "http://influx.example.test:8086",
		User:          publicDashInfluxUser,
		Database:      "metrics",
		BasicAuth:     true,
		BasicAuthUser: publicDashBasicUser,
		JsonData:      simplejson.New(),
		SecureJsonData: map[string]string{
			"password":          publicDashInfluxSecret,
			"basicAuthPassword": publicDashBasicSecret,
		},
	})
	require.NoError(t, err)

	_, err = dsService.AddDataSource(ctx, &datasources.AddDataSourceCommand{
		OrgID:    publicDashOrgID,
		UID:      influx08UID,
		Name:     "Public Influx 0.8",
		Type:     datasources.DS_INFLUXDB_08,
		Access:   datasources.DS_ACCESS_DIRECT,
		URL:      "http://influx08.example.test:8086",
		User:     publicDashInfluxUser,
		Database: "legacy",
		JsonData: simplejson.New(),
		SecureJsonData: map[string]string{
			"password": publicDashInflux08Secret,
		},
	})
	require.NoError(t, err)

	_, err = dsService.AddDataSource(ctx, &datasources.AddDataSourceCommand{
		OrgID:         publicDashOrgID,
		UID:           basicUID,
		Name:          "Public Prometheus",
		Type:          datasources.DS_PROMETHEUS,
		Access:        datasources.DS_ACCESS_DIRECT,
		URL:           "http://prom.example.test:9090",
		BasicAuth:     true,
		BasicAuthUser: publicDashBasicUser,
		JsonData:      simplejson.New(),
		SecureJsonData: map[string]string{
			"basicAuthPassword": publicDashBasicSecret,
		},
	})
	require.NoError(t, err)

	_, err = dsService.AddDataSource(ctx, &datasources.AddDataSourceCommand{
		OrgID:    publicDashOrgID,
		UID:      proxyUID,
		Name:     "Proxied Influx",
		Type:     datasources.DS_INFLUXDB,
		Access:   datasources.DS_ACCESS_PROXY,
		URL:      "http://influx-proxy.example.test:8086",
		User:     publicDashInfluxUser,
		Database: "metrics",
		JsonData: simplejson.New(),
		SecureJsonData: map[string]string{
			"password": publicDashProxySecret,
		},
	})
	require.NoError(t, err)

	_, err = dsService.AddDataSource(ctx, &datasources.AddDataSourceCommand{
		OrgID:    publicDashOrgID + 1,
		UID:      otherOrgUID,
		Name:     "Other Org Influx",
		Type:     datasources.DS_INFLUXDB,
		Access:   datasources.DS_ACCESS_DIRECT,
		URL:      "http://other-org.example.test:8086",
		User:     publicDashInfluxUser,
		Database: "metrics",
		JsonData: simplejson.New(),
		SecureJsonData: map[string]string{
			"password": publicDashOtherOrgSecret,
		},
	})
	require.NoError(t, err)

	stored, err := dsService.GetDataSources(ctx, &datasources.GetDataSourcesQuery{OrgID: publicDashOrgID})
	require.NoError(t, err)
	byUID := map[string]*datasources.DataSource{}
	for _, ds := range stored {
		byUID[ds.UID] = ds
		require.Empty(t, ds.Password)
		require.Empty(t, ds.BasicAuthPassword)
		require.NotContains(t, string(ds.SecureJsonData["password"]), publicDashInfluxSecret)
		require.NotContains(t, string(ds.SecureJsonData["basicAuthPassword"]), publicDashBasicSecret)
	}
	decryptedInflux, err := dsService.DecryptedPassword(ctx, byUID[influxUID])
	require.NoError(t, err)
	require.Equal(t, publicDashInfluxSecret, decryptedInflux)
	decryptedBasic, err := dsService.DecryptedBasicAuthPassword(ctx, byUID[influxUID])
	require.NoError(t, err)
	require.Equal(t, publicDashBasicSecret, decryptedBasic)
	decrypted08, err := dsService.DecryptedPassword(ctx, byUID[influx08UID])
	require.NoError(t, err)
	require.Equal(t, publicDashInflux08Secret, decrypted08)
	decryptedProm, err := dsService.DecryptedBasicAuthPassword(ctx, byUID[basicUID])
	require.NoError(t, err)
	require.Equal(t, publicDashBasicSecret, decryptedProm)

	dash := dashboards.NewDashboard("public")
	dash.OrgID = publicDashOrgID
	dash.Data.Set("panels", []any{
		map[string]any{"id": 1, "datasource": map[string]any{"type": datasources.DS_INFLUXDB, "uid": influxUID}},
		map[string]any{"id": 2, "datasource": map[string]any{"type": datasources.DS_INFLUXDB_08, "uid": influx08UID}},
		map[string]any{"id": 3, "datasource": map[string]any{"type": datasources.DS_PROMETHEUS, "uid": basicUID}},
		map[string]any{"id": 4, "datasource": map[string]any{"type": datasources.DS_INFLUXDB, "uid": proxyUID}},
	})

	pdService := publicdashboards.NewFakePublicDashboardService(t)
	pdService.On("GetOrgIdByAccessToken", mock.Anything, publicDashAccessToken).Return(publicDashOrgID, nil)
	pdService.On("FindPublicDashboardAndDashboardByAccessToken", mock.Anything, publicDashAccessToken).Return(nil, dash, nil)
	hs.publicDashboardsService = pdService

	_, htmlHandlerRequestsDuration := setupHTMLHandlerMetrics()
	hs.htmlHandlerRequestsDuration = htmlHandlerRequestsDuration
	hs.navTreeService = &fakeNavTreeService{}
	prefClient := prefapi.NewMockK8sClient(t)
	prefClient.EXPECT().GetMerged(mock.Anything).Return(&preferences.PreferencesSpec{}, nil)
	hs.preferenceK8sHandler = prefapi.NewK8sHandler(prefClient, dashboards.NewFakeDashboardService(t), preferences.PreferencesSpec{})
	hs.HooksService = hooks.ProvideService()
	hs.orgService = &orgtest.FakeOrgService{}
	hs.accesscontrolService = acmock.New()

	viewsPath, err := filepath.Abs(filepath.Join("..", "..", "public", "views"))
	require.NoError(t, err)
	m := web.New()
	m.Use(getContextHandler(t, cfg).Middleware)
	m.UseMiddleware(web.Renderer(viewsPath, "[[", "]]"))

	viewMiddleware := publicdashboards.MiddlewareImpl{}
	publicHandlers := []web.Handler{
		viewMiddleware.HandleView,
		publicdashboards.SetPublicDashboardAccessToken,
		publicdashboards.SetPublicDashboardOrgIdOnContext(pdService),
		publicdashboards.CountPublicDashboardRequest(),
	}
	m.Get("/public-dashboards/:accessToken", append(publicHandlers, hs.Index)...)
	m.Get("/bootdata/:accessToken", append(publicHandlers, hs.GetBootdata)...)

	basicHeader := util.GetBasicAuthHeader(publicDashBasicUser, publicDashBasicSecret)
	secrets := []string{
		publicDashInfluxSecret,
		publicDashInflux08Secret,
		publicDashBasicSecret,
		publicDashProxySecret,
		publicDashOtherOrgSecret,
		basicHeader,
	}

	assertOmitsSecrets := func(t *testing.T, body string) {
		t.Helper()
		for _, secret := range secrets {
			require.NotContains(t, body, secret)
		}
		require.Contains(t, body, influxUID)
		require.Contains(t, body, influx08UID)
		require.Contains(t, body, basicUID)
		require.Contains(t, body, proxyUID)
		require.NotContains(t, body, otherOrgUID)
		require.True(t, strings.Contains(body, `"isSignedIn":false`) || strings.Contains(body, `"isSignedIn": false`))
	}

	t.Run("bootdata json", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/bootdata/"+publicDashAccessToken, nil)
		m.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
		assertOmitsSecrets(t, recorder.Body.String())
	})

	t.Run("index html", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/public-dashboards/"+publicDashAccessToken, nil)
		m.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
		body := recorder.Body.String()
		require.Contains(t, body, "window.grafanaBootData")
		assertOmitsSecrets(t, body)
	})
}

func publicDashTestPlugin(id string) pluginstore.Plugin {
	return pluginstore.Plugin{
		JSONData: plugins.JSONData{
			ID:   id,
			Name: id,
			Type: plugins.TypeDataSource,
			Info: plugins.Info{Version: "1.0.0"},
		},
		FS:              &pluginfakes.FakePluginFS{},
		Module:          "/" + id + "/module.js",
		LoadingStrategy: plugins.LoadingStrategyScript,
	}
}
