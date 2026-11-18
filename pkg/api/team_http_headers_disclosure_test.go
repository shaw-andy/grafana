package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/datasources"
	datafakes "github.com/grafana/grafana/pkg/services/datasources/fakes"
	"github.com/grafana/grafana/pkg/services/datasources/guardian"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/publicdashboards"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web"
)

const (
	teamHTTPHeaderName = "X-Prom-Label-Policy"
	// Label selectors an administrator stored for two different teams.
	// A viewer who belongs only to the first team must not receive either rule.
	teamARule     = `tenant-a:{namespace="payments"}`
	teamBRule     = `tenant-b:{namespace="billing"}`
	benignJSONKey = "timeInterval"
	benignJSONVal = "1m"
	promUID       = "prom-uid"
	promName      = "Prom"
)

func lbacJSONData() *simplejson.Json {
	return simplejson.NewFromAny(map[string]any{
		benignJSONKey: benignJSONVal,
		"teamHttpHeaders": map[string]any{
			"headers": map[string]any{
				"101": []any{map[string]any{"header": teamHTTPHeaderName, "value": teamARule}},
				"202": []any{map[string]any{"header": teamHTTPHeaderName, "value": teamBRule}},
			},
		},
	})
}

func promWithLBACRules() *datasources.DataSource {
	return &datasources.DataSource{
		ID:       7,
		UID:      promUID,
		Name:     promName,
		Type:     datasources.DS_PROMETHEUS,
		OrgID:    1,
		URL:      "http://prometheus.internal:9090",
		Access:   datasources.DS_ACCESS_PROXY,
		JsonData: lbacJSONData(),
	}
}

func assertStoredRulesRemain(t *testing.T, ds *datasources.DataSource) {
	t.Helper()
	stored, err := datasources.GetTeamHTTPHeaders(ds.JsonData)
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.Contains(t, stored.Headers, "101")
	require.Contains(t, stored.Headers, "202")
	require.Equal(t, teamARule, stored.Headers["101"][0].LBACRule)
	require.Equal(t, teamBRule, stored.Headers["202"][0].LBACRule)
}

func assertJSONDataOmitsTeamHTTPHeaders(t *testing.T, raw []byte, jsonData any) {
	t.Helper()
	require.NotContains(t, string(raw), teamARule)
	require.NotContains(t, string(raw), teamBRule)
	require.NotContains(t, string(raw), "teamHttpHeaders")

	encoded, err := json.Marshal(jsonData)
	require.NoError(t, err)
	var asMap map[string]any
	require.NoError(t, json.Unmarshal(encoded, &asMap))
	_, leaked := asMap["teamHttpHeaders"]
	require.False(t, leaked, "jsonData still contains teamHttpHeaders: %s", encoded)
	require.Equal(t, benignJSONVal, asMap[benignJSONKey])
}

func prometheusPluginStore() *pluginstore.FakePluginStore {
	return &pluginstore.FakePluginStore{PluginList: []pluginstore.Plugin{{
		Module:          "/prometheus/module.js",
		JSONData:        plugins.JSONData{ID: datasources.DS_PROMETHEUS, Name: "Prometheus", Type: plugins.TypeDataSource, Info: plugins.Info{Version: "1.0.0"}},
		FS:              &pluginfakes.FakePluginFS{},
		LoadingStrategy: plugins.LoadingStrategyScript,
	}}}
}

func viewer() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:   2,
		OrgID:    1,
		OrgRole:  org.RoleViewer,
		Login:    "viewer",
		TeamIDs:  []int64{101},
		TeamUIDs: []string{"team-a"},
	}
}

func requestContext(req *http.Request, signedIn *user.SignedInUser, publicToken string) *contextmodel.ReqContext {
	return &contextmodel.ReqContext{
		Context:                    &web.Context{Req: req},
		SignedInUser:               signedIn,
		IsSignedIn:                 signedIn != nil && !signedIn.IsAnonymous,
		PublicDashboardAccessToken: publicToken,
	}
}

func TestOSSViewerCanReadAllDatasources(t *testing.T) {
	// Datasource permissions are not enforced in the open-source build, so the
	// reader role that includes datasources:read on every datasource is granted
	// to Viewer. GET /api/datasources is therefore reachable by a Viewer.
	require.False(t, (&licensing.OSSLicensingService{}).FeatureEnabled("dspermissions.enforcement"))

	var reader accesscontrol.RoleRegistration
	found := false
	for _, reg := range FixedRoleRegistrations(false, false) {
		if reg.Role.Name == datasourcesReaderRoleName {
			reader = reg
			found = true
			break
		}
	}
	require.True(t, found)
	require.Contains(t, reader.Grants, string(org.RoleViewer))
	require.Contains(t, reader.Role.Permissions, accesscontrol.Permission{
		Action: datasources.ActionRead,
		Scope:  datasources.ScopeAll,
	})
}

func TestTeamHTTPHeadersNotDisclosedByDatasourceAPI(t *testing.T) {
	ds := promWithLBACRules()
	hs := &HTTPServer{
		Cfg:         setting.NewCfg(),
		pluginStore: prometheusPluginStore(),
		DataSourcesService: &datafakes.FakeDataSourceService{
			DataSources: []*datasources.DataSource{ds},
		},
		dsGuardian: guardian.ProvideGuardian(),
	}
	hs.promRegister, hs.dsConfigHandlerRequestsDuration, hs.dsEndpointRedirects = setupDsConfigHandlerMetrics()

	cases := []struct {
		name   string
		params map[string]string
		call   func(c *contextmodel.ReqContext) response.Response
		list   bool
	}{
		{
			name: "GET /api/datasources",
			call: func(c *contextmodel.ReqContext) response.Response { return hs.GetDataSources(c) },
			list: true,
		},
		{
			name:   "GET /api/datasources/uid/{uid}",
			params: map[string]string{":uid": promUID},
			call:   func(c *contextmodel.ReqContext) response.Response { return hs.GetDataSourceByUID(c) },
		},
		{
			name:   "GET /api/datasources/{id}",
			params: map[string]string{":id": "7"},
			call:   func(c *contextmodel.ReqContext) response.Response { return hs.GetDataSourceById(c) },
		},
		{
			name:   "GET /api/datasources/name/{name}",
			params: map[string]string{":name": promName},
			call:   func(c *contextmodel.ReqContext) response.Response { return hs.GetDataSourceByName(c) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/datasources", nil)
			if tc.params != nil {
				req = web.SetURLParams(req, tc.params)
			}
			resp := tc.call(requestContext(req, viewer(), ""))
			require.Equal(t, http.StatusOK, resp.Status())
			var jsonData any
			if tc.list {
				items := decodeListJSONData(t, resp.Body())
				require.Len(t, items, 1)
				jsonData = items[0]
			} else {
				jsonData = decodeObjectJSONData(t, resp.Body())
			}
			assertJSONDataOmitsTeamHTTPHeaders(t, resp.Body(), jsonData)
			assertStoredRulesRemain(t, ds)
		})
	}
}

func decodeListJSONData(t *testing.T, raw []byte) []any {
	t.Helper()
	var items []map[string]any
	require.NoError(t, json.Unmarshal(raw, &items))
	require.NotEmpty(t, items)
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, item["jsonData"])
	}
	return out
}

func decodeObjectJSONData(t *testing.T, raw []byte) any {
	t.Helper()
	var item map[string]any
	require.NoError(t, json.Unmarshal(raw, &item))
	return item["jsonData"]
}

func TestIntegrationTeamHTTPHeadersNotDisclosedByFrontendSettings(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	ds := promWithLBACRules()
	other := &datasources.DataSource{
		ID: 8, UID: "loki-uid", Name: "Loki", Type: datasources.DS_LOKI, OrgID: 1,
		JsonData: simplejson.NewFromAny(map[string]any{"timeout": "10"}),
	}

	cfg := setting.NewCfg()
	pluginStore := &pluginstore.FakePluginStore{PluginList: []pluginstore.Plugin{
		{
			Module:          "/prometheus/module.js",
			JSONData:        plugins.JSONData{ID: datasources.DS_PROMETHEUS, Name: "Prometheus", Type: plugins.TypeDataSource, Info: plugins.Info{Version: "1.0.0"}},
			FS:              &pluginfakes.FakePluginFS{},
			LoadingStrategy: plugins.LoadingStrategyScript,
		},
		{
			Module:          "/loki/module.js",
			JSONData:        plugins.JSONData{ID: datasources.DS_LOKI, Name: "Loki", Type: plugins.TypeDataSource, Info: plugins.Info{Version: "1.0.0"}},
			FS:              &pluginfakes.FakePluginFS{},
			LoadingStrategy: plugins.LoadingStrategyScript,
		},
	}}
	pluginSettings := &pluginsettings.FakePluginSettings{Plugins: map[string]*pluginsettings.DTO{
		datasources.DS_PROMETHEUS: {ID: 1, OrgID: 1, PluginID: datasources.DS_PROMETHEUS, PluginVersion: "1.0.0", Enabled: true},
		datasources.DS_LOKI:       {ID: 2, OrgID: 1, PluginID: datasources.DS_LOKI, PluginVersion: "1.0.0", Enabled: true},
	}}

	serve := func(t *testing.T, signedIn *user.SignedInUser, publicToken string) (*httptest.ResponseRecorder, *HTTPServer) {
		t.Helper()
		m, hs := setupTestEnvironment(t, cfg, featuremgmt.WithFeatures(), pluginStore, pluginSettings, nil)
		hs.DataSourcesService = &datafakes.FakeDataSourceService{
			DataSources: []*datasources.DataSource{ds, other},
		}
		if publicToken != "" {
			dashJSON := simplejson.NewFromAny(map[string]any{
				"title": "Shared",
				"uid":   "dash",
				"panels": []any{
					map[string]any{"id": 1, "datasource": map[string]any{"uid": promUID}},
				},
			})
			dash := dashboards.NewDashboardFromJson(dashJSON)
			dash.OrgID = 1
			pub := &publicdashboards.FakePublicDashboardService{}
			pub.On("FindPublicDashboardAndDashboardByAccessToken", mock.Anything, publicToken).Return(nil, dash, nil)
			hs.publicDashboardsService = pub
		}
		m.UseMiddleware(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()
				reqCtx := &contextmodel.ReqContext{
					Context:                    web.FromContext(ctx),
					SignedInUser:               signedIn,
					IsSignedIn:                 signedIn != nil && !signedIn.IsAnonymous,
					PublicDashboardAccessToken: publicToken,
				}
				ctx = context.WithValue(ctx, ctxkey.Key{}, reqCtx)
				*reqCtx.Req = *reqCtx.Req.WithContext(ctx)
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		})
		req := httptest.NewRequest(http.MethodGet, "/api/frontend/settings", nil)
		rec := httptest.NewRecorder()
		m.ServeHTTP(rec, req)
		return rec, hs
	}

	t.Run("signed-in viewer", func(t *testing.T) {
		rec, _ := serve(t, viewer(), "")
		require.Equal(t, http.StatusOK, rec.Code)
		settings := decodeSettings(t, rec.Body.Bytes())
		prom, ok := settings.Datasources[promName]
		require.True(t, ok, "viewer settings omitted the prometheus datasource")
		_, lokiOK := settings.Datasources["Loki"]
		require.True(t, lokiOK, "viewer settings omitted a datasource that has no label rules")
		assertJSONDataOmitsTeamHTTPHeaders(t, rec.Body.Bytes(), prom.JSONData)
		assertStoredRulesRemain(t, ds)
	})

	t.Run("public dashboard visitor", func(t *testing.T) {
		anon := &user.SignedInUser{OrgID: 1, IsAnonymous: true}
		rec, _ := serve(t, anon, "public-token")
		require.Equal(t, http.StatusOK, rec.Code)
		settings := decodeSettings(t, rec.Body.Bytes())
		prom, ok := settings.Datasources[promName]
		require.True(t, ok, "public dashboard settings omitted the datasource the dashboard uses")
		_, lokiOK := settings.Datasources["Loki"]
		require.False(t, lokiOK, "public dashboard settings included a datasource the dashboard does not use")
		assertJSONDataOmitsTeamHTTPHeaders(t, rec.Body.Bytes(), prom.JSONData)
		assertStoredRulesRemain(t, ds)
	})
}

func decodeSettings(t *testing.T, raw []byte) dtos.FrontendSettingsDTO {
	t.Helper()
	var settings dtos.FrontendSettingsDTO
	require.NoError(t, json.Unmarshal(raw, &settings))
	return settings
}
