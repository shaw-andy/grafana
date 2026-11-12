package datasource

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	authlib "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/api/pluginproxy"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	datasourceV0 "github.com/grafana/grafana/pkg/apis/datasource/v0alpha1"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/oauthtoken"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
)

type proxyMockDatasourceProvider struct {
	resourceMockDatasourceProvider
	ds    *datasourceV0.DataSource
	dsErr error
}

func (m *proxyMockDatasourceProvider) GetDataSource(ctx context.Context, uid string) (*datasourceV0.DataSource, error) {
	return m.ds, m.dsErr
}

type allowAllValidator struct{}

func (allowAllValidator) Validate(_ string, _ map[string]any, _ *http.Request) error { return nil }

func newProxyTestBuilder(provider PluginDatasourceProvider) *DataSourceAPIBuilder {
	return &DataSourceAPIBuilder{
		datasourceResourceInfo:     datasourceV0.DataSourceResourceInfo.WithGroupAndShortName("test.datasource.grafana.app", "test"),
		pluginJSON:                 plugins.JSONData{ID: "test"},
		datasources:                provider,
		dataSourceRequestValidator: allowAllValidator{},
		proxyDeps: &ProxyDependencies{
			ProxyCfg:           pluginproxy.NewDataSourceProxySettings(setting.NewCfg()),
			HTTPClientProvider: httpclient.NewProvider(),
			OAuthTokenService:  &oauthtoken.Service{},
			Tracer:             tracing.InitializeTracerForTest(),
			Features:           featuremgmt.WithFeatures(),
		},
	}
}

func proxyTestContext() context.Context {
	return identity.WithRequester(context.Background(), &user.SignedInUser{UserID: 1, OrgID: 1, Login: "admin"})
}

func TestSubProxyREST_Connect(t *testing.T) {
	t.Run("responds NotFound when the datasource does not exist", func(t *testing.T) {
		provider := &proxyMockDatasourceProvider{dsErr: datasources.ErrDataSourceNotFound}
		r := &subProxyREST{builder: newProxyTestBuilder(provider)}

		responder := &resourceMockResponder{}
		handler, err := r.Connect(proxyTestContext(), "missing", nil, responder)
		require.NoError(t, err)
		require.NotNil(t, handler)

		req := httptest.NewRequest(http.MethodGet, "/namespaces/default/datasources/missing/proxy/x", nil)
		handler.ServeHTTP(httptest.NewRecorder(), req)
		require.True(t, apierrors.IsNotFound(responder.lastErr))
	})

	t.Run("returns an error when proxy dependencies are not configured", func(t *testing.T) {
		builder := newProxyTestBuilder(&proxyMockDatasourceProvider{})
		builder.proxyDeps = nil
		r := &subProxyREST{builder: builder}

		handler, err := r.Connect(proxyTestContext(), "test-ds", nil, &resourceMockResponder{})
		require.Nil(t, handler)
		require.Error(t, err)
	})

	t.Run("proxies the request to the datasource backend", func(t *testing.T) {
		var gotPath string
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			gotPath = req.URL.Path
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "pong")
		}))
		defer target.Close()

		ds := &datasourceV0.DataSource{}
		ds.Spec.SetURL(target.URL)

		provider := &proxyMockDatasourceProvider{ds: ds}
		provider.instanceSettings = &backend.DataSourceInstanceSettings{
			UID:      "test-ds",
			Type:     "test",
			URL:      target.URL,
			JSONData: []byte("{}"),
		}
		r := &subProxyREST{builder: newProxyTestBuilder(provider)}

		ctx := proxyTestContext()
		handler, err := r.Connect(ctx, "test-ds", nil, &resourceMockResponder{})
		require.NoError(t, err)
		require.NotNil(t, handler)

		req := httptest.NewRequest(http.MethodGet,
			"/apis/test.datasource.grafana.app/v0alpha1/namespaces/default/datasources/test-ds/proxy/api/v1/query", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, "pong", rec.Body.String())
		require.Equal(t, "/api/v1/query", gotPath)
	})
}

func TestSubProxyREST_PrometheusConfigIsRejectedBeforeUpstream(t *testing.T) {
	const (
		name   = "prom-a"
		other  = "prom-b"
		user   = "placeholder-user"
		secret = "placeholder-secret"
		otherS = "placeholder-other-secret"
	)

	var mu sync.Mutex
	var gotPath string
	var hits int
	var credential bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		hits++
		gotPath = req.URL.Path
		credential = req.Header.Get("Authorization") == util.GetBasicAuthHeader(user, secret)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream-marker")
	}))
	t.Cleanup(target.Close)

	dsFor := func(dsName string) *datasourceV0.DataSource {
		ds := &datasourceV0.DataSource{}
		ds.Name = dsName
		ds.Spec.SetURL(target.URL)
		ds.Spec.SetBasicAuth(true)
		ds.Spec.SetBasicAuthUser(user)
		return ds
	}
	settingsFor := func(dsName, dsSecret string) *backend.DataSourceInstanceSettings {
		return &backend.DataSourceInstanceSettings{
			UID:                     dsName,
			Type:                    datasources.DS_PROMETHEUS,
			URL:                     target.URL,
			JSONData:                []byte("{}"),
			BasicAuthEnabled:        true,
			BasicAuthUser:           user,
			DecryptedSecureJSONData: map[string]string{"basicAuthPassword": dsSecret},
		}
	}

	named := &namedProxyProvider{
		proxyMockDatasourceProvider: proxyMockDatasourceProvider{},
		byName: map[string]*datasourceV0.DataSource{
			name:  dsFor(name),
			other: dsFor(other),
		},
		settings: map[string]*backend.DataSourceInstanceSettings{
			name:  settingsFor(name, secret),
			other: settingsFor(other, otherS),
		},
	}

	builder := newProxyTestBuilder(named)
	builder.pluginJSON = plugins.JSONData{ID: datasources.DS_PROMETHEUS, Routes: prometheusStyleRoutes()}
	builder.datasourceResourceInfo = datasourceV0.DataSourceResourceInfo.WithGroupAndShortName("prometheus.datasource.grafana.app", "prometheus")
	builder.dataSourceRequestValidator = validations.ProvideValidator()
	builder.accessClient = &recordingAccessClient{resp: authlib.CheckResponse{Allowed: true}}

	decision, _, err := builder.GetAuthorizer().Authorize(proxyTestContext(), authorizer.AttributesRecord{
		ResourceRequest: true,
		Verb:            "get",
		Resource:        "datasources",
		Subresource:     "proxy",
		Namespace:       "default",
		Name:            name,
	})
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision, "query permission is the proxy subresource gate")

	methods := (&subProxyREST{builder: builder}).ConnectMethods()
	require.Contains(t, methods, http.MethodGet)

	empty := newProxyTestBuilder(&proxyMockDatasourceProvider{})
	empty.pluginJSON = plugins.JSONData{ID: datasources.DS_INFLUXDB}
	require.Empty(t, (&subProxyREST{builder: empty}).ConnectMethods(), "a plugin with no routes registers no apiserver proxy methods")

	r := &subProxyREST{builder: builder}
	handler, err := r.Connect(proxyTestContext(), name, nil, &resourceMockResponder{})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet,
		"/apis/prometheus.datasource.grafana.app/v0alpha1/namespaces/default/datasources/"+name+"/proxy/api/v1/status/config", nil)
	req = req.WithContext(proxyTestContext())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	mu.Lock()
	defer mu.Unlock()
	require.Zerof(t, hits, "upstream path %s was contacted, stored credential attached=%v", gotPath, credential)
	require.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
	require.NotContains(t, rec.Body.String(), "upstream-marker")
}

type namedProxyProvider struct {
	proxyMockDatasourceProvider
	byName   map[string]*datasourceV0.DataSource
	settings map[string]*backend.DataSourceInstanceSettings
}

func (m *namedProxyProvider) GetDataSource(_ context.Context, uid string) (*datasourceV0.DataSource, error) {
	ds, ok := m.byName[uid]
	if !ok {
		return nil, datasources.ErrDataSourceNotFound
	}
	return ds, nil
}

func (m *namedProxyProvider) GetInstanceSettings(_ context.Context, uid string) (*backend.DataSourceInstanceSettings, error) {
	settings, ok := m.settings[uid]
	if !ok {
		return nil, datasources.ErrDataSourceNotFound
	}
	return settings, nil
}

func prometheusStyleRoutes() []*plugins.Route {
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

func TestProxyPathFromRequest(t *testing.T) {
	tests := []struct {
		path string
		name string
		want string
	}{
		{"/namespaces/default/datasources/x/proxy/api/v1/query", "x", "api/v1/query"},
		{"/namespaces/default/datasources/x/proxy", "x", ""},
		{"/namespaces/default/datasources/x/proxy/", "x", ""},
		// the forwarded path itself contains "/proxy": must keep it intact.
		{"/namespaces/default/datasources/x/proxy/admin/proxy/settings", "x", "admin/proxy/settings"},
		// the namespace happens to match the datasource name.
		{"/namespaces/proxy/datasources/proxy/proxy/api", "proxy", "api"},
		{"/no/match/here", "x", ""},
	}
	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		require.Equal(t, tc.want, proxyPathFromRequest(req, tc.name), "path %q", tc.path)
	}
}
