package api

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	preferences "github.com/grafana/grafana/apps/preferences/pkg/apis/preferences/v1"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	accesscontrolmock "github.com/grafana/grafana/pkg/services/accesscontrol/mock"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/datasources"
	datafakes "github.com/grafana/grafana/pkg/services/datasources/fakes"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/hooks"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/preference/prefapi"
	"github.com/grafana/grafana/pkg/services/publicdashboards"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web"
)

const (
	// Obvious placeholders. These stand in for a username, a password, and a
	// query credential an administrator embedded in a proxy-mode server URL.
	placeholderUser        = "PLACEHOLDER_USER"
	placeholderSecret      = "PLACEHOLDER_SECRET"
	placeholderQuerySecret = "PLACEHOLDER_QUERY_SECRET"

	otherOrgBackendHost = "other-org-prom.internal.example"
	lokiBackendHost     = "loki-backend.internal.example"
)

// proxyPromKinds are every datasource type getFSDataSources copies a server URL onto.
var proxyPromKinds = []struct {
	name string
	typ  string
	uid  string
	host string
}{
	{name: "Prom", typ: datasources.DS_PROMETHEUS, uid: "prom-uid", host: "prom-backend.internal.example"},
	{name: "AmazonProm", typ: datasources.DS_AMAZON_PROMETHEUS, uid: "amp-uid", host: "amp-backend.internal.example"},
	{name: "AzureProm", typ: datasources.DS_AZURE_PROMETHEUS, uid: "azp-uid", host: "azp-backend.internal.example"},
}

func proxyServerURL(host string) string {
	server := &url.URL{
		Scheme: "http",
		User:   url.UserPassword(placeholderUser, placeholderSecret),
		Host:   host + ":9090",
		Path:   "/prom",
	}
	query := server.Query()
	query.Set("timeout", "30s")
	query.Set("access_token", placeholderQuerySecret)
	server.RawQuery = query.Encode()
	return server.String()
}

func newJSONData() *simplejson.Json {
	return simplejson.NewFromAny(map[string]any{"httpMethod": "POST"})
}

func newProxyDatasources() []*datasources.DataSource {
	list := make([]*datasources.DataSource, 0, len(proxyPromKinds)+2)
	for _, kind := range proxyPromKinds {
		list = append(list, &datasources.DataSource{
			ID:       1,
			OrgID:    1,
			UID:      kind.uid,
			Name:     kind.name,
			Type:     kind.typ,
			Access:   datasources.DS_ACCESS_PROXY,
			URL:      proxyServerURL(kind.host),
			JsonData: newJSONData(),
		})
	}
	list = append(list,
		&datasources.DataSource{
			ID:       4,
			OrgID:    1,
			UID:      "loki-uid",
			Name:     "Loki",
			Type:     datasources.DS_LOKI,
			Access:   datasources.DS_ACCESS_PROXY,
			URL:      proxyServerURL(lokiBackendHost),
			JsonData: newJSONData(),
		},
		&datasources.DataSource{
			ID:       5,
			OrgID:    2,
			UID:      "other-org-prom",
			Name:     "OtherOrgProm",
			Type:     datasources.DS_PROMETHEUS,
			Access:   datasources.DS_ACCESS_PROXY,
			URL:      proxyServerURL(otherOrgBackendHost),
			JsonData: newJSONData(),
		},
	)
	return list
}

func proxyPath(uid string) string {
	return "/api/datasources/proxy/uid/" + uid
}

func viewerUser() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  20,
		OrgID:   1,
		OrgRole: org.RoleViewer,
		Login:   "viewer",
		Permissions: map[int64]map[string][]string{
			1: {datasources.ActionQuery: {datasources.ScopeAll}},
		},
	}
}

// configUser can open the datasource configuration UI. That permission is
// datasources.ConfigurationPageAccess: read, plus write or delete. The org
// role stays Viewer so a fix cannot treat the role name as the check.
func configUser() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  21,
		OrgID:   1,
		OrgRole: org.RoleViewer,
		Login:   "datasource-editor",
		Permissions: map[int64]map[string][]string{
			1: {
				datasources.ActionRead:  {datasources.ScopeAll},
				datasources.ActionWrite: {datasources.ScopeAll},
			},
		},
	}
}

// adminWithoutConfigPermission has the Admin org role and no datasource
// configuration permission. The configuration page checks the permission.
func adminWithoutConfigPermission() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  22,
		OrgID:   1,
		OrgRole: org.RoleAdmin,
		Login:   "org-admin",
		Permissions: map[int64]map[string][]string{
			1: {datasources.ActionQuery: {datasources.ScopeAll}},
		},
	}
}

// configPermissionInAnotherOrg grants datasource configuration only in org 2.
// The request is for org 1, so those permissions do not cover this org's datasources.
func configPermissionInAnotherOrg() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  23,
		OrgID:   1,
		OrgRole: org.RoleViewer,
		Login:   "other-org-editor",
		Permissions: map[int64]map[string][]string{
			2: {
				datasources.ActionRead:  {datasources.ScopeAll},
				datasources.ActionWrite: {datasources.ScopeAll},
			},
		},
	}
}

func publicDashboardVisitor() *user.SignedInUser {
	return &user.SignedInUser{
		OrgID:       1,
		OrgRole:     org.RoleViewer,
		IsAnonymous: true,
		Login:       "anonymous",
	}
}

type proxyURLHarness struct {
	t       *testing.T
	mux     *web.Mux
	hs      *HTTPServer
	sources *datafakes.FakeDataSourceService
	reqUser **user.SignedInUser
	token   *string
}

func newProxyURLHarness(t *testing.T) *proxyURLHarness {
	t.Helper()

	pluginsInUse := append([]string{}, datasources.DS_PROMETHEUS, datasources.DS_AMAZON_PROMETHEUS, datasources.DS_AZURE_PROMETHEUS, datasources.DS_LOKI)
	pluginList := make([]pluginstore.Plugin, len(pluginsInUse))
	for i, id := range pluginsInUse {
		pluginList[i] = pluginstore.Plugin{
			JSONData:        plugins.JSONData{ID: id, Info: plugins.Info{Version: "1.0.0"}, Type: plugins.TypeDataSource},
			Module:          "/" + id + "/module.js",
			FS:              &pluginfakes.FakePluginFS{},
			LoadingStrategy: plugins.LoadingStrategyScript,
		}
	}

	cfg := setting.NewCfg()
	cfg.Env = setting.Dev
	cfg.DefaultTheme = "dark"
	cfg.StaticRootPath = "webassets/testdata"

	mux, hs := setupTestEnvironment(t, cfg, featuremgmt.WithFeatures(), &pluginstore.FakePluginStore{PluginList: pluginList}, &pluginsettings.FakePluginSettings{}, nil)
	sources := &datafakes.FakeDataSourceService{DataSources: newProxyDatasources()}
	hs.DataSourcesService = sources

	navService := &fakeNavTreeService{}
	hs.navTreeService = navService
	prefClient := prefapi.NewMockK8sClient(t)
	prefClient.EXPECT().GetMerged(mock.Anything).Return(&preferences.PreferencesSpec{}, nil).Maybe()
	hs.preferenceK8sHandler = prefapi.NewK8sHandler(prefClient, dashboards.NewFakeDashboardService(t), preferences.PreferencesSpec{})
	hs.HooksService = hooks.ProvideService()
	hs.orgService = &orgtest.FakeOrgService{}
	hs.accesscontrolService = accesscontrolmock.New()

	var reqUser *user.SignedInUser
	token := ""
	userPtr := &reqUser
	tokenPtr := &token
	mux.UseMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			requester := *userPtr
			reqContext := &contextmodel.ReqContext{
				Context:                    web.FromContext(ctx),
				SignedInUser:               requester,
				IsSignedIn:                 requester != nil && requester.UserID > 0 && !requester.IsAnonymous,
				Logger:                     log.New("proxy-url-test"),
				PublicDashboardAccessToken: *tokenPtr,
			}
			ctx = context.WithValue(ctx, ctxkey.Key{}, reqContext)
			*reqContext.Req = *reqContext.Req.WithContext(ctx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	mux.Get("/bootdata", hs.GetBootdata)

	return &proxyURLHarness{t: t, mux: mux, hs: hs, sources: sources, reqUser: userPtr, token: tokenPtr}
}

func (h *proxyURLHarness) resetDatasources() []*datasources.DataSource {
	h.t.Helper()
	fresh := newProxyDatasources()
	h.sources.DataSources = fresh
	return fresh
}

func (h *proxyURLHarness) get(path string, requester *user.SignedInUser, publicToken string) *httptest.ResponseRecorder {
	h.t.Helper()
	*h.reqUser = requester
	*h.token = publicToken
	recorder := httptest.NewRecorder()
	h.mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder
}

type datasourceSettings struct {
	URL       string         `json:"url"`
	JSONData  map[string]any `json:"jsonData"`
	DirectURL string         `json:"directUrl"`
}

type settingsPayload struct {
	Datasources map[string]datasourceSettings `json:"datasources"`
}

type bootPayload struct {
	Settings settingsPayload `json:"settings"`
}

func decodeSettings(t *testing.T, recorder *httptest.ResponseRecorder) settingsPayload {
	t.Helper()
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var got settingsPayload
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &got))
	return got
}

func decodeBootSettings(t *testing.T, recorder *httptest.ResponseRecorder) settingsPayload {
	t.Helper()
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var got bootPayload
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &got))
	return got.Settings
}

func assertNoCredentialMaterial(t *testing.T, body string) {
	t.Helper()
	require.NotContains(t, body, placeholderUser)
	require.NotContains(t, body, placeholderSecret)
	require.NotContains(t, body, placeholderQuerySecret)
	require.NotContains(t, body, "access_token")
}

func assertProxyURL(t *testing.T, got datasourceSettings, uid string) {
	t.Helper()
	require.Equal(t, proxyPath(uid), got.URL)
}

func assertBackendHidden(t *testing.T, body string) {
	t.Helper()
	assertNoCredentialMaterial(t, body)
	for _, kind := range proxyPromKinds {
		require.NotContainsf(t, body, kind.host, "proxy-mode %s published its backend address", kind.typ)
	}
	require.NotContains(t, body, lokiBackendHost)
	require.NotContains(t, body, otherOrgBackendHost)
}

func assertStoredJSONUntouched(t *testing.T, stored []*datasources.DataSource) {
	t.Helper()
	for _, ds := range stored {
		encoded, err := ds.JsonData.Encode()
		require.NoError(t, err)
		require.NotContainsf(t, string(encoded), "directUrl", "datasource %s jsonData was mutated while building boot data", ds.UID)
		require.Equal(t, "POST", ds.JsonData.Get("httpMethod").MustString())
		_, present := ds.JsonData.CheckGet("directUrl")
		require.False(t, present)
	}
}

func assertHiddenFromCaller(t *testing.T, body string, settings settingsPayload, stored []*datasources.DataSource) {
	t.Helper()
	for _, kind := range proxyPromKinds {
		got, ok := settings.Datasources[kind.name]
		require.Truef(t, ok, "missing datasource %s", kind.name)
		assertProxyURL(t, got, kind.uid)
		_, leaked := got.JSONData["directUrl"]
		require.Falsef(t, leaked, "jsonData.directUrl leaked for %s", kind.name)
		require.Empty(t, got.DirectURL)
	}
	loki, ok := settings.Datasources["Loki"]
	require.True(t, ok)
	assertProxyURL(t, loki, "loki-uid")
	_, lokiDirect := loki.JSONData["directUrl"]
	require.False(t, lokiDirect)
	_, otherOrg := settings.Datasources["OtherOrgProm"]
	require.False(t, otherOrg)
	assertBackendHidden(t, body)
	assertStoredJSONUntouched(t, stored)
}

func assertSanitizedDirectURL(t *testing.T, body string, raw string, host string) {
	t.Helper()
	require.NotEmpty(t, raw)
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	require.Nil(t, parsed.User)
	require.Equal(t, host+":9090", parsed.Host)
	require.Equal(t, "/prom", parsed.Path)
	require.Empty(t, parsed.Query().Get("access_token"))
	require.NotContains(t, raw, placeholderUser)
	require.NotContains(t, raw, placeholderSecret)
	require.NotContains(t, raw, placeholderQuerySecret)
	if timeout := parsed.Query().Get("timeout"); timeout != "" {
		require.Equal(t, "30s", timeout)
	}
	remainder := strings.ReplaceAll(body, raw, "")
	require.NotContainsf(t, remainder, host, "backend address appeared outside the sanitized directUrl")
}

func exposedDirectURL(t *testing.T, got datasourceSettings) string {
	t.Helper()
	fromJSON, _ := got.JSONData["directUrl"].(string)
	require.NotEmptyf(t, fromJSON, "configuration users still need jsonData.directUrl, without credentials")
	if got.DirectURL != "" {
		require.Equal(t, fromJSON, got.DirectURL)
	}
	return fromJSON
}

func TestIntegrationProxyPrometheusURLHiddenFromViewer(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	h := newProxyURLHarness(t)
	viewer := viewerUser()

	t.Run("frontend settings", func(t *testing.T) {
		stored := h.resetDatasources()
		recorder := h.get("/api/frontend/settings", viewer, "")
		settings := decodeSettings(t, recorder)
		assertHiddenFromCaller(t, recorder.Body.String(), settings, stored)
	})

	t.Run("bootdata", func(t *testing.T) {
		stored := h.resetDatasources()
		recorder := h.get("/bootdata", viewer, "")
		settings := decodeBootSettings(t, recorder)
		assertHiddenFromCaller(t, recorder.Body.String(), settings, stored)
	})

	t.Run("index html", func(t *testing.T) {
		stored := h.resetDatasources()
		body := h.renderIndex(viewer, "")
		assertNoCredentialMaterial(t, body)
		for _, kind := range proxyPromKinds {
			require.NotContainsf(t, body, kind.host, "index html published the %s backend address", kind.typ)
			require.Contains(t, body, proxyPath(kind.uid))
		}
		require.NotContains(t, body, lokiBackendHost)
		require.NotContains(t, body, otherOrgBackendHost)
		assertStoredJSONUntouched(t, stored)
	})
}

func TestIntegrationProxyPrometheusURLHiddenWithoutConfigPermission(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	h := newProxyURLHarness(t)

	t.Run("org admin role without datasource write", func(t *testing.T) {
		stored := h.resetDatasources()
		recorder := h.get("/api/frontend/settings", adminWithoutConfigPermission(), "")
		settings := decodeSettings(t, recorder)
		assertHiddenFromCaller(t, recorder.Body.String(), settings, stored)
	})

	t.Run("configuration permission belongs to another org", func(t *testing.T) {
		stored := h.resetDatasources()
		recorder := h.get("/bootdata", configPermissionInAnotherOrg(), "")
		settings := decodeBootSettings(t, recorder)
		assertHiddenFromCaller(t, recorder.Body.String(), settings, stored)
	})
}

func TestIntegrationProxyPrometheusURLSanitizedForConfigurationUser(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	h := newProxyURLHarness(t)
	stored := h.resetDatasources()
	recorder := h.get("/api/frontend/settings", configUser(), "")
	body := recorder.Body.String()
	settings := decodeSettings(t, recorder)

	assertNoCredentialMaterial(t, body)
	require.NotContains(t, body, otherOrgBackendHost)
	require.NotContains(t, body, lokiBackendHost)
	for _, kind := range proxyPromKinds {
		got, ok := settings.Datasources[kind.name]
		require.True(t, ok)
		assertProxyURL(t, got, kind.uid)
		assertSanitizedDirectURL(t, body, exposedDirectURL(t, got), kind.host)
		require.Equal(t, "POST", got.JSONData["httpMethod"])
	}
	loki := settings.Datasources["Loki"]
	assertProxyURL(t, loki, "loki-uid")
	_, lokiDirect := loki.JSONData["directUrl"]
	require.False(t, lokiDirect)
	assertStoredJSONUntouched(t, stored)

	boot := h.resetDatasources()
	bootRecorder := h.get("/bootdata", configUser(), "")
	bootBody := bootRecorder.Body.String()
	bootSettings := decodeBootSettings(t, bootRecorder)
	assertNoCredentialMaterial(t, bootBody)
	for _, kind := range proxyPromKinds {
		got := bootSettings.Datasources[kind.name]
		assertProxyURL(t, got, kind.uid)
		assertSanitizedDirectURL(t, bootBody, exposedDirectURL(t, got), kind.host)
	}
	assertStoredJSONUntouched(t, boot)
}

func TestIntegrationProxyPrometheusURLOmittedFromPublicDashboard(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	const accessToken = "11111111-1111-1111-1111-111111111111"

	h := newProxyURLHarness(t)
	dashboardJSON := simplejson.New()
	dashboardJSON.Set("title", "Public")
	dashboardJSON.Set("uid", "public-dash")
	dashboardJSON.Set("panels", []any{
		map[string]any{"id": 1, "datasource": map[string]any{"type": datasources.DS_PROMETHEUS, "uid": "prom-uid"}},
	})
	dash := dashboards.NewDashboardFromJson(dashboardJSON)
	dash.OrgID = 1

	pub := &publicdashboards.FakePublicDashboardService{}
	pub.On("FindPublicDashboardAndDashboardByAccessToken", mock.Anything, accessToken).Return(nil, dash, nil)
	h.hs.publicDashboardsService = pub

	assertPublic := func(t *testing.T, body string, settings settingsPayload, stored []*datasources.DataSource) {
		t.Helper()
		prom, ok := settings.Datasources["Prom"]
		require.True(t, ok)
		assertProxyURL(t, prom, "prom-uid")
		_, leaked := prom.JSONData["directUrl"]
		require.False(t, leaked, "public dashboard boot data included jsonData.directUrl")
		require.Empty(t, prom.DirectURL)
		for _, name := range []string{"AmazonProm", "AzureProm", "Loki", "OtherOrgProm"} {
			_, present := settings.Datasources[name]
			require.Falsef(t, present, "public dashboard boot data included %s", name)
		}
		assertBackendHidden(t, body)
		assertStoredJSONUntouched(t, stored)
	}

	t.Run("frontend settings", func(t *testing.T) {
		stored := h.resetDatasources()
		recorder := h.get("/api/frontend/settings", publicDashboardVisitor(), accessToken)
		assertPublic(t, recorder.Body.String(), decodeSettings(t, recorder), stored)
	})

	t.Run("bootdata", func(t *testing.T) {
		stored := h.resetDatasources()
		recorder := h.get("/bootdata", publicDashboardVisitor(), accessToken)
		assertPublic(t, recorder.Body.String(), decodeBootSettings(t, recorder), stored)
	})

	t.Run("index html", func(t *testing.T) {
		stored := h.resetDatasources()
		body := h.renderIndex(publicDashboardVisitor(), accessToken)
		require.Contains(t, body, proxyPath("prom-uid"))
		require.NotContains(t, body, proxyPath("amp-uid"))
		assertNoCredentialMaterial(t, body)
		for _, kind := range proxyPromKinds {
			require.NotContains(t, body, kind.host)
		}
		assertStoredJSONUntouched(t, stored)
	})
}

func (h *proxyURLHarness) renderIndex(requester *user.SignedInUser, publicToken string) string {
	h.t.Helper()
	*h.reqUser = requester
	*h.token = publicToken

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	reqContext := &contextmodel.ReqContext{
		Context:                    &web.Context{Req: req},
		SignedInUser:               requester,
		IsSignedIn:                 requester != nil && requester.UserID > 0 && !requester.IsAnonymous,
		Logger:                     log.New("proxy-url-test"),
		PublicDashboardAccessToken: publicToken,
	}
	ctx := context.WithValue(req.Context(), ctxkey.Key{}, reqContext)
	reqContext.Req = req.WithContext(ctx)

	data, err := h.hs.setIndexViewData(reqContext)
	require.NoError(h.t, err)

	viewPath := filepath.Join("..", "..", "public", "views", "index.html")
	source, err := os.ReadFile(viewPath)
	require.NoError(h.t, err)
	tpl, err := template.New("index").Delims("[[", "]]").Parse(string(source))
	require.NoError(h.t, err)

	var rendered strings.Builder
	require.NoError(h.t, tpl.Execute(&rendered, data))
	return rendered.String()
}
