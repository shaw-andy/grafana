package datasourceproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/pluginproxy"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/datasources/guardian"
	datasourceservice "github.com/grafana/grafana/pkg/services/datasources/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/oauthtoken"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/plugincontext"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/secrets"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	secretskvs "github.com/grafana/grafana/pkg/services/secrets/kvstore"
	secretsmng "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
	"github.com/grafana/grafana/pkg/web"
)

// Placeholders stand in for the datasource's stored basic-auth secret and
// password. They are not real credentials.
const (
	placeholderUser        = "placeholder-user"
	placeholderSecret      = "placeholder-secret"
	placeholderOtherSecret = "placeholder-other-secret"
)

// Routes below are the proxy routes published by the datasource plugins.
// Prometheus and Amazon Prometheus are the routes in plugin.json at tags
// v13.2.6 and v3.3.5 (the same paths are in prometheus v13.1.9). Loki is
// grafana-loki-datasource v13.2.5. InfluxDB v13.1.10, Tempo v13.4.2, Jaeger
// v13.0.8, OpenTSDB v13.0.8, and Zipkin v12.4.13 publish no routes. Graphite's
// plugin.json in this repository publishes no routes.
func prometheusProxyRoutes() []*plugins.Route {
	return []*plugins.Route{
		{Method: http.MethodPost, Path: "api/v1/query", ReqRole: identity.RoleViewer, ReqAction: datasources.ActionQuery},
		{Method: http.MethodPost, Path: "api/v1/query_range", ReqRole: identity.RoleViewer, ReqAction: datasources.ActionQuery},
		{Method: http.MethodPost, Path: "api/v1/series", ReqRole: identity.RoleViewer, ReqAction: datasources.ActionQuery},
		{Method: http.MethodPost, Path: "api/v1/labels", ReqRole: identity.RoleViewer, ReqAction: datasources.ActionQuery},
		{Method: http.MethodPost, Path: "api/v1/query_exemplars", ReqRole: identity.RoleViewer, ReqAction: datasources.ActionQuery},
		{Method: http.MethodGet, Path: "/rules", ReqRole: identity.RoleViewer, ReqAction: "alert.rules.external:read"},
		{Method: http.MethodPost, Path: "/rules", ReqRole: identity.RoleEditor, ReqAction: "alert.rules.external:write"},
		{Method: http.MethodDelete, Path: "/rules", ReqRole: identity.RoleEditor, ReqAction: "alert.rules.external:write"},
		{Method: http.MethodDelete, Path: "/config/v1/rules", ReqRole: identity.RoleEditor, ReqAction: "alert.rules.external:write"},
		{Method: http.MethodPost, Path: "/config/v1/rules", ReqRole: identity.RoleEditor, ReqAction: "alert.rules.external:write"},
	}
}

func lokiProxyRoutes() []*plugins.Route {
	viewerQuery := func(method, path string) *plugins.Route {
		return &plugins.Route{Method: method, Path: path, ReqRole: identity.RoleViewer, ReqAction: datasources.ActionQuery}
	}
	editorWrite := func(method, path string) *plugins.Route {
		return &plugins.Route{Method: method, Path: path, ReqRole: identity.RoleEditor, ReqAction: "alert.rules.external:write"}
	}
	viewerRules := func(path string) *plugins.Route {
		return &plugins.Route{Method: http.MethodGet, Path: path, ReqRole: identity.RoleViewer, ReqAction: "alert.rules.external:read"}
	}
	return []*plugins.Route{
		viewerQuery(http.MethodGet, "/api/v1/query"),
		viewerQuery(http.MethodGet, "/api/v1/query_range"),
		viewerQuery(http.MethodPost, "/api/v1/query_range"),
		viewerQuery(http.MethodGet, "/api/v1/labels"),
		viewerQuery(http.MethodGet, "/api/v1/label"),
		viewerQuery(http.MethodGet, "/api/v1/series"),
		viewerQuery(http.MethodPost, "/api/v1/series"),
		viewerQuery(http.MethodGet, "/api/v1/index/stats"),
		viewerQuery(http.MethodGet, "/api/v1/index/volume"),
		viewerQuery(http.MethodGet, "/api/v1/index/volume_range"),
		viewerQuery(http.MethodGet, "/api/v1/patterns"),
		viewerQuery(http.MethodGet, "/api/v1/tail"),
		viewerQuery(http.MethodGet, "/api/v1/status/buildinfo"),
		viewerQuery(http.MethodGet, "/api/v1/format_query"),
		viewerQuery(http.MethodPost, "/api/v1/format_query"),
		viewerRules("/api/v1/rules"),
		editorWrite(http.MethodPost, "/api/v1/rules"),
		editorWrite(http.MethodDelete, "/api/v1/rules"),
		viewerRules("/prometheus/api/v1/rules"),
		viewerRules("/prometheus/api/v1/alerts"),
		viewerRules("/loki/api/v1/rules"),
		editorWrite(http.MethodPost, "/loki/api/v1/rules"),
		editorWrite(http.MethodDelete, "/loki/api/v1/rules"),
		viewerRules("/rules"),
		editorWrite(http.MethodPost, "/rules"),
		editorWrite(http.MethodDelete, "/rules"),
		viewerRules("/api/prom/rules"),
		editorWrite(http.MethodPost, "/api/prom/rules"),
		editorWrite(http.MethodDelete, "/api/prom/rules"),
	}
}

type capturedUpstream struct {
	method      string
	path        string
	body        string
	thisSecret  bool
	otherSecret bool
}

// TestViewerDatasourceProxyRejectsPrivilegedUpstreamCalls drives the mounted
// legacy proxy route as a Viewer who holds only the OSS datasource reader
// permissions, then requires privileged upstream calls to be rejected before
// the datasource is contacted.
func TestViewerDatasourceProxyRejectsPrivilegedUpstreamCalls(t *testing.T) {
	var mu sync.Mutex
	var got []capturedUpstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		mu.Lock()
		got = append(got, capturedUpstream{
			method:      r.Method,
			path:        r.URL.Path,
			body:        string(body),
			thisSecret:  requestCarriesSecret(r, placeholderSecret),
			otherSecret: requestCarriesSecret(r, placeholderOtherSecret),
		})
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream-marker")
	}))
	t.Cleanup(upstream.Close)

	clearUpstream := func() {
		mu.Lock()
		got = nil
		mu.Unlock()
	}
	upstreamCalls := func() []capturedUpstream {
		mu.Lock()
		defer mu.Unlock()
		out := make([]capturedUpstream, len(got))
		copy(out, got)
		return out
	}

	viewer := viewerWithDatasourceReaderRole(t, 1)
	svc, byUID := newProxyService(t, upstream.URL, viewer.OrgID)

	var current *user.SignedInUser
	server := web.New()
	server.UseMiddleware(web.Renderer("../../../public/views", "[[", "]]"))
	server.Use(proxyTestContext(func(c *contextmodel.ReqContext) {
		c.SignedInUser = current
		c.IsSignedIn = true
	}))
	// Same evaluator the route in pkg/api/api.go registers for
	// /api/datasources/proxy/uid/:uid and /api/datasources/proxy/uid/:uid/*.
	server.Use(accesscontrol.Middleware(acimpl.ProvideAccessControlTest())(accesscontrol.EvalPermission(datasources.ActionQuery)))
	server.Any("/api/datasources/proxy/uid/:uid/*", func(c *contextmodel.ReqContext) {
		svc.ProxyDatasourceRequestWithUID(c, "")
	})

	do := func(t *testing.T, user *user.SignedInUser, method, uid, subpath, body string) (int, string) {
		t.Helper()
		clearUpstream()
		current = user
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, "http://grafana.example/api/datasources/proxy/uid/"+uid+"/"+subpath, reader)
		require.NoError(t, err)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		resp := rec.Result()
		defer resp.Body.Close()
		payload, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, string(payload)
	}

	t.Run("viewer without datasources query permission never reaches the upstream", func(t *testing.T) {
		noQuery := &user.SignedInUser{
			UserID:  2,
			OrgID:   viewer.OrgID,
			OrgRole: org.RoleViewer,
			Login:   "no-query",
			Permissions: map[int64]map[string][]string{
				viewer.OrgID: {datasources.ActionRead: {datasources.ScopeAll}},
			},
		}
		status, body := do(t, noQuery, http.MethodGet, "prom-a", "api/v1/status/config", "")
		require.Equal(t, http.StatusForbidden, status, "body: %s", body)
		require.Empty(t, upstreamCalls())
		require.NotContains(t, body, "upstream-marker")
	})

	t.Run("prometheus query route is still proxied with that datasource secret", func(t *testing.T) {
		status, body := do(t, viewer, http.MethodPost, "prom-a", "api/v1/query", "query=up")
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		require.Contains(t, body, "upstream-marker")
		calls := upstreamCalls()
		require.Len(t, calls, 1)
		require.Equal(t, http.MethodPost, calls[0].method)
		require.Equal(t, "/api/v1/query", calls[0].path)
		require.Equal(t, "query=up", calls[0].body)
		require.True(t, calls[0].thisSecret, "the requested datasource secret must be attached")
		require.False(t, calls[0].otherSecret, "another datasource secret must not be attached")
	})

	t.Run("loki query route is still proxied", func(t *testing.T) {
		status, body := do(t, viewer, http.MethodGet, "loki-a", "api/v1/query?query=%7Bjob%3D%22app%22%7D", "")
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		calls := upstreamCalls()
		require.Len(t, calls, 1)
		require.Equal(t, "/api/v1/query", calls[0].path)
		require.True(t, calls[0].thisSecret)
	})

	t.Run("graphite query endpoints the plugin uses are still proxied", func(t *testing.T) {
		for _, sub := range []string{"render", "metrics/find"} {
			status, body := do(t, viewer, http.MethodPost, "graphite-a", sub, "query=placeholder")
			require.Equal(t, http.StatusOK, status, "path %s body %s", sub, body)
			calls := upstreamCalls()
			require.Len(t, calls, 1)
			require.Equal(t, "/"+sub, calls[0].path)
			require.True(t, calls[0].thisSecret)
		}
	})

	privileged := []struct {
		name   string
		uid    string
		method string
		path   string
		body   string
	}{
		{name: "prometheus status config", uid: "prom-a", method: http.MethodGet, path: "api/v1/status/config"},
		{name: "prometheus status flags", uid: "prom-a", method: http.MethodGet, path: "api/v1/status/flags"},
		{name: "prometheus targets", uid: "prom-a", method: http.MethodGet, path: "api/v1/targets"},
		{name: "amazon prometheus status config", uid: "amp-a", method: http.MethodGet, path: "api/v1/status/config"},
		{name: "loki server config", uid: "loki-a", method: http.MethodGet, path: "config"},
		{name: "influx write", uid: "influx-a", method: http.MethodPost, path: "write", body: "cpu value=1"},
		{name: "influx delete", uid: "influx-a", method: http.MethodPost, path: "api/v2/delete", body: "{}"},
		{name: "influx delete bucket", uid: "influx-a", method: http.MethodDelete, path: "api/v2/buckets/example"},
		{name: "influx 0.8 write", uid: "influx08-a", method: http.MethodPost, path: "write", body: "cpu value=1"},
		{name: "graphite delete series", uid: "graphite-a", method: http.MethodPost, path: "tags/delSeries", body: "path=servers.cpu"},
		{name: "graphite delete", uid: "graphite-a", method: http.MethodDelete, path: "metrics"},
		{name: "tempo post", uid: "tempo-a", method: http.MethodPost, path: "api/v2/traces", body: "{}"},
		{name: "tempo delete", uid: "tempo-a", method: http.MethodDelete, path: "api/v2/traces/example"},
		{name: "jaeger post", uid: "jaeger-a", method: http.MethodPost, path: "api/traces", body: "{}"},
		{name: "jaeger delete", uid: "jaeger-a", method: http.MethodDelete, path: "api/traces/example"},
		{name: "opentsdb post", uid: "opentsdb-a", method: http.MethodPost, path: "api/put", body: "{}"},
		{name: "opentsdb delete", uid: "opentsdb-a", method: http.MethodDelete, path: "api/put"},
		{name: "zipkin post", uid: "zipkin-a", method: http.MethodPost, path: "api/v2/spans", body: "[]"},
		{name: "zipkin delete", uid: "zipkin-a", method: http.MethodDelete, path: "api/v2/spans"},
	}

	for _, tc := range privileged {
		t.Run(tc.name+" is rejected before the datasource is contacted", func(t *testing.T) {
			status, body := do(t, viewer, tc.method, tc.uid, tc.path, tc.body)
			calls := upstreamCalls()
			require.Emptyf(t, calls, "upstream was contacted: %v credential=%v", redact(calls), credentialOnAny(calls))
			require.Equalf(t, http.StatusForbidden, status, "body: %s", body)
			require.NotContains(t, body, "upstream-marker")
		})
	}

	t.Run("prometheus admin delete stays rejected", func(t *testing.T) {
		status, body := do(t, viewer, http.MethodPost, "prom-a", "api/v1/admin/tsdb/delete_series", "match[]=up")
		require.Equal(t, http.StatusForbidden, status, "body: %s", body)
		require.Empty(t, upstreamCalls())
		require.NotContains(t, body, "upstream-marker")
	})

	t.Run("legacy id handler shares the same proxy", func(t *testing.T) {
		clearUpstream()
		current = viewer
		req, err := http.NewRequest(http.MethodGet, "http://grafana.example/api/datasources/proxy/1/api/v1/status/config", nil)
		require.NoError(t, err)
		req = req.WithContext(identity.WithRequester(req.Context(), viewer))
		rec := httptest.NewRecorder()
		c := &contextmodel.ReqContext{
			Context: &web.Context{
				Req:  req,
				Resp: web.NewResponseWriter(http.MethodGet, rec),
			},
			SignedInUser: viewer,
			Logger:       log.NewNopLogger(),
		}
		svc.ProxyDatasourceRequestWithID(c, byUID["prom-a"].ID)
		resp := rec.Result()
		defer resp.Body.Close()
		payload, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Empty(t, upstreamCalls())
		require.Equal(t, http.StatusForbidden, resp.StatusCode, "body: %s", payload)
		require.NotContains(t, string(payload), "upstream-marker")
	})
}

func viewerWithDatasourceReaderRole(t *testing.T, orgID int64) *user.SignedInUser {
	t.Helper()
	// OSS fixed:datasources:reader grants these two actions on every datasource
	// to Viewer when datasource permission enforcement is disabled.
	return &user.SignedInUser{
		UserID:  1,
		OrgID:   orgID,
		OrgRole: org.RoleViewer,
		Login:   "viewer",
		Permissions: map[int64]map[string][]string{
			orgID: {
				datasources.ActionRead:  {datasources.ScopeAll},
				datasources.ActionQuery: {datasources.ScopeAll},
			},
		},
	}
}

func newProxyService(t *testing.T, upstreamURL string, orgID int64) (*DataSourceProxyService, map[string]*datasources.DataSource) {
	t.Helper()
	cfg := setting.NewCfg()
	secretsService := secretsmng.SetupTestService(t, fakes.NewFakeSecretsStore())
	// The SQL secrets store needs a database session. The service falls through
	// to decryptLegacySecrets when the store has no value, which is the same
	// Decrypt the SQL store uses on the way back out.
	secretsStore := secretskvs.NewFakeSecretsKVStore()
	features := featuremgmt.WithFeatures()
	dsService, err := datasourceservice.ProvideService(
		nil, secretsService, secretsStore, cfg, features,
		acimpl.ProvideAccessControl(features), &actest.FakePermissionsService{},
		quotatest.New(false, nil), &pluginstore.FakePluginStore{}, &pluginfakes.FakePluginClient{},
		plugincontext.ProvideBaseService(cfg, pluginconfig.NewFakePluginRequestConfigProvider()),
		datasourceservice.ProvideDataSourceRetriever(nil, features),
	)
	require.NoError(t, err)

	type spec struct {
		uid      string
		id       int64
		name     string
		dsType   string
		basic    bool
		secret   string
		database string
		routes   []*plugins.Route
	}
	specs := []spec{
		{uid: "prom-a", id: 1, name: "prom-a", dsType: datasources.DS_PROMETHEUS, basic: true, secret: placeholderSecret, routes: prometheusProxyRoutes()},
		{uid: "prom-b", id: 2, name: "prom-b", dsType: datasources.DS_PROMETHEUS, basic: true, secret: placeholderOtherSecret, routes: prometheusProxyRoutes()},
		{uid: "amp-a", id: 3, name: "amp-a", dsType: datasources.DS_AMAZON_PROMETHEUS, basic: true, secret: placeholderSecret, routes: prometheusProxyRoutes()},
		{uid: "loki-a", id: 4, name: "loki-a", dsType: datasources.DS_LOKI, basic: true, secret: placeholderSecret, routes: lokiProxyRoutes()},
		{uid: "influx-a", id: 5, name: "influx-a", dsType: datasources.DS_INFLUXDB, basic: false, secret: placeholderSecret, database: "metrics"},
		{uid: "influx08-a", id: 6, name: "influx08-a", dsType: datasources.DS_INFLUXDB_08, basic: false, secret: placeholderSecret, database: "metrics"},
		{uid: "graphite-a", id: 7, name: "graphite-a", dsType: datasources.DS_GRAPHITE, basic: true, secret: placeholderSecret},
		{uid: "tempo-a", id: 8, name: "tempo-a", dsType: datasources.DS_TEMPO, basic: true, secret: placeholderSecret},
		{uid: "jaeger-a", id: 9, name: "jaeger-a", dsType: datasources.DS_JAEGER, basic: true, secret: placeholderSecret},
		{uid: "opentsdb-a", id: 10, name: "opentsdb-a", dsType: datasources.DS_OPENTSDB, basic: true, secret: placeholderSecret},
		{uid: "zipkin-a", id: 11, name: "zipkin-a", dsType: datasources.DS_ZIPKIN, basic: true, secret: placeholderSecret},
	}

	byUID := map[string]*datasources.DataSource{}
	pluginsByType := map[string][]*plugins.Route{}
	for _, s := range specs {
		ds := &datasources.DataSource{
			ID:        s.id,
			OrgID:     orgID,
			Name:      s.name,
			UID:       s.uid,
			Type:      s.dsType,
			Access:    datasources.DS_ACCESS_PROXY,
			URL:       upstreamURL,
			Database:  s.database,
			JsonData:  simplejson.New(),
			User:      placeholderUser,
			BasicAuth: s.basic,
		}
		if s.basic {
			ds.BasicAuthUser = placeholderUser
		}
		key := "password"
		if s.basic {
			key = "basicAuthPassword"
		}
		encrypted, err := secretsService.EncryptJsonData(t.Context(), map[string]string{key: s.secret}, secrets.WithoutScope())
		require.NoError(t, err)
		ds.SecureJsonData = encrypted
		byUID[s.uid] = ds
		if _, ok := pluginsByType[s.dsType]; !ok {
			pluginsByType[s.dsType] = s.routes
		}
	}

	var pluginList []pluginstore.Plugin
	for dsType, routes := range pluginsByType {
		pluginList = append(pluginList, pluginstore.Plugin{
			JSONData: plugins.JSONData{ID: dsType, Routes: routes},
		})
	}

	return &DataSourceProxyService{
		DataSourceCache:            &ossGuardingCache{byUID: byUID, guardian: guardian.ProvideGuardian()},
		DataSourceRequestValidator: validations.ProvideValidator(),
		pluginStore:                &pluginstore.FakePluginStore{PluginList: pluginList},
		proxyCfg:                   pluginproxy.NewDataSourceProxySettings(cfg),
		HTTPClientProvider:         httpclient.NewProvider(),
		OAuthTokenService:          &oauthtoken.Service{},
		DataSourcesService:         dsService,
		tracer:                     tracing.InitializeTracerForTest(),
		secretsService:             secretsService,
		features:                   features,
	}, byUID
}

type ossGuardingCache struct {
	byUID    map[string]*datasources.DataSource
	guardian guardian.DatasourceGuardianProvider
}

func (c *ossGuardingCache) GetDatasource(ctx context.Context, datasourceID int64, user identity.Requester, skipCache bool) (*datasources.DataSource, error) {
	for _, ds := range c.byUID {
		if ds.ID == datasourceID {
			return c.allow(user, ds)
		}
	}
	return nil, datasources.ErrDataSourceNotFound
}

func (c *ossGuardingCache) GetDatasourceByUID(ctx context.Context, datasourceUID string, user identity.Requester, skipCache bool) (*datasources.DataSource, error) {
	if datasourceUID == "" {
		return nil, datasources.ErrDataSourceNotFound
	}
	if user.GetOrgID() == 0 {
		return nil, datasources.ErrDataSourceAccessDenied
	}
	ds, ok := c.byUID[datasourceUID]
	if !ok || ds.OrgID != user.GetOrgID() {
		return nil, datasources.ErrDataSourceNotFound
	}
	return c.allow(user, ds)
}

func (c *ossGuardingCache) allow(user identity.Requester, ds *datasources.DataSource) (*datasources.DataSource, error) {
	g := c.guardian.New(user.GetOrgID(), user, *ds)
	canQuery, err := g.CanQuery(ds.ID)
	if err != nil {
		return nil, err
	}
	if !canQuery {
		return nil, datasources.ErrDataSourceAccessDenied
	}
	return ds, nil
}

func proxyTestContext(modifiers ...func(*contextmodel.ReqContext)) web.Handler {
	return func(c *web.Context) {
		reqCtx := &contextmodel.ReqContext{
			Context:      c,
			Logger:       log.NewNopLogger(),
			SignedInUser: &user.SignedInUser{},
			IsSignedIn:   true,
		}
		for _, modifier := range modifiers {
			modifier(reqCtx)
		}
		c.Req = c.Req.WithContext(ctxkey.Set(c.Req.Context(), reqCtx))
		c.Req = c.Req.WithContext(identity.WithRequester(c.Req.Context(), reqCtx.SignedInUser))
	}
}

func requestCarriesSecret(r *http.Request, secret string) bool {
	if r.Header.Get("Authorization") == util.GetBasicAuthHeader(placeholderUser, secret) {
		return true
	}
	values := r.URL.Query()
	return values.Get("u") == placeholderUser && values.Get("p") == secret
}

func credentialOnAny(calls []capturedUpstream) bool {
	for _, call := range calls {
		if call.thisSecret || call.otherSecret {
			return true
		}
	}
	return false
}

func redact(calls []capturedUpstream) []string {
	out := make([]string, 0, len(calls))
	for _, call := range calls {
		out = append(out, call.method+" "+call.path)
	}
	return out
}
