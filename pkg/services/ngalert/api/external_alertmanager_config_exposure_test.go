package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/db/dbtest"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasourceproxy"
	"github.com/grafana/grafana/pkg/services/datasources"
	datasourceservice "github.com/grafana/grafana/pkg/services/datasources/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/ngalert/accesscontrol"
	"github.com/grafana/grafana/pkg/services/oauthtoken"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/plugincontext"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	secretskvs "github.com/grafana/grafana/pkg/services/secrets/kvstore"
	secretsmng "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// receiverSecret is an obvious placeholder. It stands in for every receiver
// credential the upstream Alertmanager config carries (Slack and webhook URLs,
// PagerDuty routing key, OpsGenie and VictorOps API keys, SMTP auth password,
// and basic-auth or bearer credentials).
const receiverSecret = "placeholder-receiver-secret"

// upstreamAlertmanagerConfig is the YAML document Mimir and Cortex return from
// GET /api/v1/alerts: template_files plus alertmanager_config as a string.
// Field names match the types Grafana decodes into (definitions.ExternalAlertmanagerConfig
// and prometheus/alertmanager config.Config).
const upstreamAlertmanagerConfig = `
template_files: {}
alertmanager_config: |
  global:
    smtp_smarthost: smtp.example.invalid:587
    smtp_from: alerts@example.invalid
    smtp_auth_password: placeholder-receiver-secret
  route:
    receiver: team-receiver
  receivers:
    - name: team-receiver
      slack_configs:
        - api_url: http://hooks.example.invalid/placeholder-receiver-secret
          channel: "#alerts"
      pagerduty_configs:
        - routing_key: placeholder-receiver-secret
      email_configs:
        - to: oncall@example.invalid
          from: alerts@example.invalid
          smarthost: smtp.example.invalid:587
          auth_password: placeholder-receiver-secret
      webhook_configs:
        - url: http://hooks.example.invalid/hook/placeholder-receiver-secret
          http_config:
            basic_auth:
              username: notifier
              password: placeholder-receiver-secret
        - url: http://hooks.example.invalid/bearer/placeholder-receiver-secret
          http_config:
            bearer_token: placeholder-receiver-secret
      opsgenie_configs:
        - api_key: placeholder-receiver-secret
      victorops_configs:
        - api_key: placeholder-receiver-secret
          routing_key: oncall-route
`

func TestExternalAlertmanagerConfig_ViewerCannotReadReceiverSecrets(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/alerts" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, upstreamAlertmanagerConfig)
	}))
	t.Cleanup(upstream.Close)

	routes := alertmanagerPluginRoutes(t)
	cache := &uidDatasourceCache{items: map[string]*datasources.DataSource{}}
	proxy := newAlertingDataProxy(t, cache, routes)
	acService := acimpl.ProvideAccessControlTest()
	viewer := viewerUser(1)

	for _, tc := range []struct {
		name           string
		uid            string
		implementation string
	}{
		{name: "mimir", uid: "mimiruid", implementation: "mimir"},
		{name: "cortex", uid: "cortexuid", implementation: "cortex"},
		{name: "default implementation", uid: "defaultuid", implementation: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache.items[tc.uid] = alertmanagerDatasource(t, tc.uid, upstream.URL, tc.implementation)

			t.Run("grafana config api", func(t *testing.T) {
				status, body := getExternalAlertingConfig(t, acService, proxy, cache, viewer, tc.uid)
				requireNoReceiverSecret(t, status, body)
			})

			t.Run("datasource proxy", func(t *testing.T) {
				status, body := proxyExternalAlertingConfig(t, acService, proxy, viewer, tc.uid)
				requireNoReceiverSecret(t, status, body)
			})
		})
	}

	t.Run("permission on one datasource does not disclose another", func(t *testing.T) {
		const allowedUID = "alloweduid"
		const otherUID = "otheruid"
		cache.items[allowedUID] = alertmanagerDatasource(t, allowedUID, upstream.URL, "mimir")
		cache.items[otherUID] = alertmanagerDatasource(t, otherUID, upstream.URL, "mimir")
		user := viewerScopedToDatasource(1, allowedUID)

		t.Run("grafana config api", func(t *testing.T) {
			status, body := getExternalAlertingConfig(t, acService, proxy, cache, user, otherUID)
			requireNoReceiverSecret(t, status, body)
		})

		t.Run("datasource proxy", func(t *testing.T) {
			status, body := proxyExternalAlertingConfig(t, acService, proxy, user, otherUID)
			requireNoReceiverSecret(t, status, body)
		})
	})
}

func requireNoReceiverSecret(t *testing.T, status int, body []byte) {
	t.Helper()
	switch status {
	case http.StatusOK, http.StatusForbidden, http.StatusUnauthorized:
	default:
		t.Fatalf("status %d, body %s", status, body)
	}
	require.NotContains(t, string(body), receiverSecret)
}

func getExternalAlertingConfig(t *testing.T, acService ac.AccessControl, proxy *datasourceproxy.DataSourceProxyService, cache datasources.CacheService, user *user.SignedInUser, uid string) (int, []byte) {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/alertmanager/"+uid+"/config/api/v1/alerts", nil)
	req = web.SetURLParams(req, map[string]string{":DatasourceUID": uid})
	req = req.WithContext(identity.WithRequester(req.Context(), user))
	ctx := &contextmodel.ReqContext{
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(http.MethodGet, rec),
		},
		SignedInUser: user,
		Logger:       log.NewNopLogger(),
		IsSignedIn:   true,
	}

	api := &API{AccessControl: acService}
	authorize := api.authorize(http.MethodGet, "/api/alertmanager/{DatasourceUID}/config/api/v1/alerts")
	authorize.(func(*contextmodel.ReqContext))(ctx)
	if rec.Body.Len() > 0 {
		return rec.Code, rec.Body.Bytes()
	}

	handler := NewForkingAM(cache, NewLotexAM(&AlertingProxy{DataProxy: proxy}, log.NewNopLogger()), nil)
	resp := handler.RouteGetAlertingConfig(ctx)
	return resp.Status(), resp.Body()
}

func proxyExternalAlertingConfig(t *testing.T, acService ac.AccessControl, proxy *datasourceproxy.DataSourceProxyService, user *user.SignedInUser, uid string) (int, []byte) {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/datasources/proxy/uid/"+uid+"/api/v1/alerts", nil)
	req = web.SetURLParams(req, map[string]string{":uid": uid})
	req = req.WithContext(identity.WithRequester(req.Context(), user))
	ctx := &contextmodel.ReqContext{
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(http.MethodGet, rec),
		},
		SignedInUser: user,
		Logger:       log.NewNopLogger(),
		IsSignedIn:   true,
	}

	// Same gate as GET /api/datasources/proxy/uid/:uid/*.
	authorize := ac.Middleware(acService)(ac.EvalPermission(datasources.ActionQuery))
	authorize.(func(*contextmodel.ReqContext))(ctx)
	if rec.Body.Len() > 0 {
		return rec.Code, rec.Body.Bytes()
	}

	proxy.ProxyDatasourceRequestWithUID(ctx, uid)
	return rec.Code, rec.Body.Bytes()
}

func alertmanagerDatasource(t *testing.T, uid, url, implementation string) *datasources.DataSource {
	t.Helper()
	jsonData := map[string]any{}
	if implementation != "" {
		jsonData["implementation"] = implementation
	}
	return &datasources.DataSource{
		ID:       1,
		UID:      uid,
		OrgID:    1,
		Type:     datasources.DS_ALERTMANAGER,
		URL:      url,
		Name:     uid,
		Access:   datasources.DS_ACCESS_PROXY,
		JsonData: simplejson.NewFromAny(jsonData),
	}
}

func viewerUser(orgID int64) *user.SignedInUser {
	return &user.SignedInUser{
		UserID:      7,
		OrgID:       orgID,
		OrgRole:     org.RoleViewer,
		Permissions: map[int64]map[string][]string{orgID: viewerPermissionMap()},
	}
}

func viewerScopedToDatasource(orgID int64, uid string) *user.SignedInUser {
	perms := viewerPermissionMap()
	perms[ac.ActionAlertingNotificationsExternalRead] = []string{datasources.ScopeProvider.GetResourceScopeUID(uid)}
	return &user.SignedInUser{
		UserID:      7,
		OrgID:       orgID,
		OrgRole:     org.RoleViewer,
		Permissions: map[int64]map[string][]string{orgID: perms},
	}
}

// viewerPermissionMap is the fixed-role grant a Viewer receives for external
// notifications, plus the OSS datasources reader grant (datasources:query and
// datasources:read on all datasources) that applies when datasource permission
// enforcement is off.
func viewerPermissionMap() map[string][]string {
	perms := map[string][]string{}
	for _, reg := range accesscontrol.FixedRoleRegistrations() {
		granted := false
		for _, role := range reg.Grants {
			if role == string(org.RoleViewer) {
				granted = true
				break
			}
		}
		if !granted {
			continue
		}
		for _, perm := range reg.Role.Permissions {
			if perm.Scope == "" {
				perms[perm.Action] = append(perms[perm.Action], "")
				continue
			}
			perms[perm.Action] = append(perms[perm.Action], perm.Scope)
		}
	}
	perms[datasources.ActionRead] = append(perms[datasources.ActionRead], datasources.ScopeAll)
	perms[datasources.ActionQuery] = append(perms[datasources.ActionQuery], datasources.ScopeAll)
	return perms
}

func alertmanagerPluginRoutes(t *testing.T) []*plugins.Route {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	path := filepath.Join(filepath.Dir(thisFile), "../../../../public/app/plugins/datasource/alertmanager/plugin.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var meta plugins.JSONData
	require.NoError(t, json.Unmarshal(raw, &meta))
	require.NotEmpty(t, meta.Routes)
	return meta.Routes
}

func newAlertingDataProxy(t *testing.T, cache datasources.CacheService, routes []*plugins.Route) *datasourceproxy.DataSourceProxyService {
	t.Helper()
	cfg := setting.NewCfg()
	secretsService := secretsmng.SetupTestService(t, fakes.NewFakeSecretsStore())
	secretsStore := secretskvs.NewSQLSecretsKVStore(dbtest.NewFakeDB(), secretsService, log.NewNopLogger())
	features := featuremgmt.WithFeatures()
	var sqlStore db.DB
	dsRetriever := datasourceservice.ProvideDataSourceRetriever(sqlStore, features)
	dsService, err := datasourceservice.ProvideService(
		sqlStore,
		secretsService,
		secretsStore,
		cfg,
		features,
		acimpl.ProvideAccessControl(features),
		&actest.FakePermissionsService{},
		quotatest.New(false, nil),
		&pluginstore.FakePluginStore{},
		&pluginfakes.FakePluginClient{},
		plugincontext.ProvideBaseService(cfg, pluginconfig.NewFakePluginRequestConfigProvider()),
		dsRetriever,
	)
	require.NoError(t, err)

	return datasourceproxy.ProvideService(
		cache,
		validations.ProvideValidator(),
		pluginstore.NewFakePluginStore(pluginstore.Plugin{
			JSONData: plugins.JSONData{
				ID:     datasources.DS_ALERTMANAGER,
				Type:   plugins.TypeDataSource,
				Routes: routes,
			},
		}),
		cfg,
		httpclient.NewProvider(),
		&oauthtoken.Service{},
		dsService,
		tracing.InitializeTracerForTest(),
		secretsService,
		features,
	)
}

type uidDatasourceCache struct {
	items map[string]*datasources.DataSource
}

func (c *uidDatasourceCache) GetDatasource(context.Context, int64, identity.Requester, bool) (*datasources.DataSource, error) {
	return nil, datasources.ErrDataSourceNotFound
}

func (c *uidDatasourceCache) GetDatasourceByUID(_ context.Context, uid string, _ identity.Requester, _ bool) (*datasources.DataSource, error) {
	ds, ok := c.items[uid]
	if !ok {
		return nil, datasources.ErrDataSourceNotFound
	}
	return ds, nil
}
