package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	acmock "github.com/grafana/grafana/pkg/services/accesscontrol/mock"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	dsservice "github.com/grafana/grafana/pkg/services/datasources/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/live"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/plugincontext"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	secretskvs "github.com/grafana/grafana/pkg/services/secrets/kvstore"
	secretsmng "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// TestOrgAdminCannotSaveHostAWSCredentials checks the datasource create and
// update paths an organization admin can call. Shipped AWS settings must not
// accept an auth type that resolves to the host credential chain. The same
// service methods back the legacy HTTP API and the datasource API server.
func TestOrgAdminCannotSaveHostAWSCredentials(t *testing.T) {
	cfg := loadShippedGrafanaConfig(t)
	service := newDataSourceService(t, cfg)
	hs := &HTTPServer{
		Cfg:                  cfg,
		DataSourcesService:   service,
		accesscontrolService: acmock.New(),
		Features:             featuremgmt.WithFeatures(),
		Live:                 &live.GrafanaLive{},
	}
	hs.promRegister, hs.dsConfigHandlerRequestsDuration, hs.dsEndpointRedirects = setupDsConfigHandlerMetrics()

	allowed := []savedDataSource{
		{name: "keys-cloudwatch", payload: cloudWatchPayload("keys-cloudwatch", `"authType":"keys"`)},
		{name: "plain-prometheus", payload: `{"name":"plain-prometheus","type":"prometheus","access":"proxy","jsonData":{"httpMethod":"POST"}}`},
	}
	for _, ds := range allowed {
		resp := addDataSource(t, hs, ds.payload)
		require.Equalf(t, http.StatusOK, resp.Status(), "saving %s should stay allowed: %s", ds.name, resp.Body())
	}

	rejected := []savedDataSource{
		{name: "default-cloudwatch", payload: cloudWatchPayload("default-cloudwatch", `"authType":"default","assumeRoleArn":"arn:aws:iam::123456789012:role/tenant"`)},
		{name: "omitted-cloudwatch", payload: cloudWatchPayload("omitted-cloudwatch", `"defaultRegion":"us-east-1"`)},
		{name: "arn-cloudwatch", payload: cloudWatchPayload("arn-cloudwatch", `"authType":"arn","assumeRoleArn":"arn:aws:iam::123456789012:role/tenant"`)},
		{name: "profile-cloudwatch", payload: cloudWatchPayload("profile-cloudwatch", `"authType":"credentials","profile":"tenant"`)},
		{name: "ec2-cloudwatch", payload: cloudWatchPayload("ec2-cloudwatch", `"authType":"ec2_iam_role"`)},
		{name: "sigv4-prometheus", payload: `{"name":"sigv4-prometheus","type":"prometheus","access":"proxy","jsonData":{"sigV4Auth":true,"sigV4AuthType":"default","sigV4Region":"us-east-1"}}`},
		{name: "sigv4-profile", payload: `{"name":"sigv4-profile","type":"elasticsearch","access":"proxy","jsonData":{"sigV4Auth":true,"sigV4AuthType":"credentials","sigV4Profile":"tenant","sigV4Region":"us-east-1"}}`},
	}
	for _, ds := range rejected {
		t.Run("add "+ds.name, func(t *testing.T) {
			resp := addDataSource(t, hs, ds.payload)
			require.GreaterOrEqualf(t, resp.Status(), 400, "org admin save of %s returned %d: %s", ds.name, resp.Status(), resp.Body())
			requireDatasourceAbsent(t, service, ds.name)
		})
	}

	// Direct service calls are what the datasource API server and provisioning use.
	for _, ds := range rejected {
		t.Run("service add "+ds.name, func(t *testing.T) {
			name := "svc-" + ds.name
			payload := strings.Replace(ds.payload, `"name":"`+ds.name+`"`, `"name":"`+name+`"`, 1)
			cmd := &datasources.AddDataSourceCommand{}
			require.NoError(t, web.Bind(jsonRequest(t, http.MethodPost, "/api/datasources", payload), cmd))
			cmd.OrgID = 2
			_, err := service.AddDataSource(context.Background(), cmd)
			require.Error(t, err)
			requireDatasourceAbsent(t, service, name)
		})
	}

	keys := mustGetDataSource(t, service, "keys-cloudwatch")
	updates := []string{
		cloudWatchPayload("keys-cloudwatch", `"authType":"default"`),
		cloudWatchPayload("keys-cloudwatch", `"authType":"credentials","profile":"tenant"`),
		cloudWatchPayload("keys-cloudwatch", `"authType":"ec2_iam_role"`),
		cloudWatchPayload("keys-cloudwatch", `"authType":"arn","assumeRoleArn":"arn:aws:iam::123456789012:role/tenant"`),
	}
	for _, payload := range updates {
		t.Run("update uid "+payload, func(t *testing.T) {
			resp := updateDataSourceByUID(t, hs, keys.UID, payload)
			require.GreaterOrEqual(t, resp.Status(), 400, resp.Body())
			require.Equal(t, "keys", mustGetDataSource(t, service, "keys-cloudwatch").JsonData.Get("authType").MustString())
		})
		t.Run("update id "+payload, func(t *testing.T) {
			resp := updateDataSourceByID(t, hs, keys.ID, payload)
			require.GreaterOrEqual(t, resp.Status(), 400, resp.Body())
			require.Equal(t, "keys", mustGetDataSource(t, service, "keys-cloudwatch").JsonData.Get("authType").MustString())
		})
		t.Run("service update "+payload, func(t *testing.T) {
			cmd := &datasources.UpdateDataSourceCommand{}
			require.NoError(t, web.Bind(jsonRequest(t, http.MethodPut, "/api/datasources/uid/"+keys.UID, payload), cmd))
			cmd.OrgID = 2
			cmd.ID = keys.ID
			cmd.UID = keys.UID
			_, err := service.UpdateDataSource(context.Background(), cmd)
			require.Error(t, err)
			require.Equal(t, "keys", mustGetDataSource(t, service, "keys-cloudwatch").JsonData.Get("authType").MustString())
		})
	}
}

type savedDataSource struct {
	name    string
	payload string
}

func cloudWatchPayload(name, jsonFields string) string {
	return `{"name":"` + name + `","type":"cloudwatch","access":"proxy","jsonData":{` + jsonFields + `}}`
}

func newDataSourceService(t *testing.T, cfg *setting.Cfg) *dsservice.Service {
	t.Helper()
	sqlStore := sqlstore.NewTestStore(t)
	features := featuremgmt.WithFeatures()
	secretsService := secretsmng.SetupTestService(t, fakes.NewFakeSecretsStore())
	secretsStore := secretskvs.NewSQLSecretsKVStore(sqlStore, secretsService, log.New("test"))
	permissions := acmock.NewMockedPermissionsService()
	permissions.On("SetPermissions", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return([]accesscontrol.ResourcePermission{}, nil)
	svc, err := dsservice.ProvideService(
		sqlStore,
		secretsService,
		secretsStore,
		cfg,
		features,
		acmock.New(),
		permissions,
		quotatest.New(false, nil),
		&pluginstore.FakePluginStore{},
		&pluginfakes.FakePluginClient{},
		plugincontext.ProvideBaseService(cfg, pluginconfig.NewFakePluginRequestConfigProvider()),
		dsservice.ProvideDataSourceRetriever(sqlStore, features),
	)
	require.NoError(t, err)
	return svc
}

func loadShippedGrafanaConfig(t *testing.T) *setting.Cfg {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: root,
		Config:   filepath.Join(root, "conf", "defaults.ini"),
	}))
	return cfg
}

func orgAdminContext(req *http.Request) *contextmodel.ReqContext {
	return &contextmodel.ReqContext{
		Context: &web.Context{Req: req},
		SignedInUser: &user.SignedInUser{
			UserID:         3,
			OrgID:          2,
			OrgRole:        org.RoleAdmin,
			IsGrafanaAdmin: false,
			Login:          "tenant-admin",
		},
		IsSignedIn: true,
	}
}

func jsonRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func addDataSource(t *testing.T, hs *HTTPServer, body string) response.Response {
	t.Helper()
	return hs.AddDataSource(orgAdminContext(jsonRequest(t, http.MethodPost, "/api/datasources", body)))
}

func updateDataSourceByUID(t *testing.T, hs *HTTPServer, uid, body string) response.Response {
	t.Helper()
	req := jsonRequest(t, http.MethodPut, "/api/datasources/uid/"+uid, body)
	req = web.SetURLParams(req, map[string]string{":uid": uid})
	return hs.UpdateDataSourceByUID(orgAdminContext(req))
}

func updateDataSourceByID(t *testing.T, hs *HTTPServer, id int64, body string) response.Response {
	t.Helper()
	idText := strconv.FormatInt(id, 10)
	req := web.SetURLParams(jsonRequest(t, http.MethodPut, "/api/datasources/"+idText, body), map[string]string{":id": idText})
	return hs.UpdateDataSourceByID(orgAdminContext(req))
}

func requireDatasourceAbsent(t *testing.T, service *dsservice.Service, name string) {
	t.Helper()
	_, err := service.GetDataSource(context.Background(), &datasources.GetDataSourceQuery{OrgID: 2, Name: name})
	require.ErrorIs(t, err, datasources.ErrDataSourceNotFound)
}

func mustGetDataSource(t *testing.T, service *dsservice.Service, name string) *datasources.DataSource {
	t.Helper()
	ds, err := service.GetDataSource(context.Background(), &datasources.GetDataSourceQuery{OrgID: 2, Name: name})
	require.NoError(t, err)
	require.NotNil(t, ds.JsonData)
	return ds
}
