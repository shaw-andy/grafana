package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	kitlog "github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/api/v2"
	amconfig "github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/dispatch"
	"github.com/prometheus/alertmanager/provider/mem"
	"github.com/prometheus/alertmanager/types"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasourceproxy"
	"github.com/grafana/grafana/pkg/services/datasources"
	dsfakes "github.com/grafana/grafana/pkg/services/datasources/fakes"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

const externalDSUID = "amdsuid1"

// upstreamRequest is one request the Grafana datasource proxy made to Alertmanager.
type upstreamRequest struct {
	method      string
	path        string
	contentType string
	body        string
}

// externalAlertmanager runs the Alertmanager API Grafana is built against.
type externalAlertmanager struct {
	server   *httptest.Server
	requests []upstreamRequest
}

func startExternalAlertmanager(t *testing.T) *externalAlertmanager {
	t.Helper()

	reg := prometheus.NewRegistry()
	marker := types.NewMarker(reg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	store, err := mem.NewAlerts(ctx, marker, time.Hour, nil, kitlog.NewNopLogger(), reg)
	require.NoError(t, err)
	t.Cleanup(store.Close)

	cfg, err := amconfig.Load(`
route:
  receiver: empty
receivers:
- name: empty
`)
	require.NoError(t, err)

	// GroupFunc is injected by Alertmanager's dispatcher. The dispatcher does not
	// rewrite GeneratorURL; this callback returns the alerts the API stored.
	groupFn := func(_ func(*dispatch.Route) bool, alertFilter func(*types.Alert, time.Time) bool) (dispatch.AlertGroups, map[model.Fingerprint][]string) {
		iter := store.GetPending()
		defer iter.Close()
		now := time.Now()
		var alerts types.AlertSlice
		receivers := map[model.Fingerprint][]string{}
		for alert := range iter.Next() {
			if iter.Err() != nil {
				break
			}
			if alertFilter != nil && !alertFilter(alert, now) {
				continue
			}
			alerts = append(alerts, alert)
			receivers[alert.Fingerprint()] = []string{"empty"}
		}
		if len(alerts) == 0 {
			return nil, receivers
		}
		return dispatch.AlertGroups{{
			Alerts:   alerts,
			Labels:   model.LabelSet{"alertname": "group"},
			Receiver: "empty",
		}}, receivers
	}

	amAPI, err := v2.NewAPI(
		store,
		groupFn,
		func(model.Fingerprint) types.AlertStatus {
			return types.AlertStatus{State: types.AlertStateActive}
		},
		nil,
		nil,
		kitlog.NewNopLogger(),
		reg,
	)
	require.NoError(t, err)
	amAPI.Update(cfg, func(model.LabelSet) {})

	ext := &externalAlertmanager{}
	ext.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		require.NoError(t, readErr)
		_ = r.Body.Close()
		ext.requests = append(ext.requests, upstreamRequest{
			method:      r.Method,
			path:        r.URL.RequestURI(),
			contentType: r.Header.Get("Content-Type"),
			body:        string(body),
		})
		r.Body = io.NopCloser(bytes.NewReader(body))
		amAPI.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ext.server.Close)
	return ext
}

func editorUser() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  7,
		OrgID:   1,
		OrgRole: identity.RoleEditor,
		Login:   "editor",
		Permissions: map[int64]map[string][]string{
			1: {
				accesscontrol.ActionAlertingInstancesExternalWrite: {datasources.ScopeAll},
				accesscontrol.ActionAlertingInstancesExternalRead:  {datasources.ScopeAll},
			},
		},
	}
}

func (ext *externalAlertmanager) grafana(t *testing.T) (*LotexAM, *datasourceproxy.DataSourceProxyService) {
	t.Helper()
	jsonData := simplejson.New()
	jsonData.Set("implementation", "prometheus")
	ds := &datasources.DataSource{
		UID:      externalDSUID,
		Name:     externalDSUID,
		Type:     datasources.DS_ALERTMANAGER,
		URL:      ext.server.URL,
		JsonData: jsonData,
		Access:   datasources.DS_ACCESS_PROXY,
	}
	plugin := pluginstore.Plugin{
		JSONData: plugins.JSONData{
			ID:   datasources.DS_ALERTMANAGER,
			Type: plugins.TypeDataSource,
			Routes: []*plugins.Route{
				{Path: "api/v2/alerts/groups", Method: http.MethodGet, ReqRole: identity.RoleViewer, ReqAction: accesscontrol.ActionAlertingInstancesExternalRead},
				{Path: "api/v2/alerts", Method: http.MethodGet, ReqRole: identity.RoleViewer, ReqAction: accesscontrol.ActionAlertingInstancesExternalRead},
				{Path: "api/v2/alerts", Method: http.MethodPost, ReqRole: identity.RoleEditor, ReqAction: accesscontrol.ActionAlertingInstancesExternalWrite},
			},
		},
	}
	proxy := datasourceproxy.ProvideService(
		fakeCacheService{datasource: ds},
		&validations.OSSDataSourceRequestValidator{},
		pluginstore.NewFakePluginStore(plugin),
		setting.NewCfg(),
		httpclient.NewProvider(),
		nil,
		&dsfakes.FakeDataSourceService{},
		tracing.InitializeTracerForTest(),
		nil,
		featuremgmt.WithFeatures(),
	)
	return &LotexAM{AlertingProxy: &AlertingProxy{DataProxy: proxy}, log: log.NewNopLogger()}, proxy
}

func requestContext(t *testing.T, method, rawURL string, body io.Reader, params map[string]string) *contextmodel.ReqContext {
	t.Helper()
	editor := editorUser()
	req := httptest.NewRequest(method, rawURL, body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(identity.WithRequester(req.Context(), editor))
	if params != nil {
		req = web.SetURLParams(req, params)
	}
	return &contextmodel.ReqContext{
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(method, httptest.NewRecorder()),
		},
		SignedInUser: editor,
		Logger:       log.NewNopLogger(),
		IsSignedIn:   true,
	}
}

func responseBody(t *testing.T, resp response.Response) (int, []byte) {
	t.Helper()
	normal, ok := resp.(*response.NormalResponse)
	require.True(t, ok, "response type %T", resp)
	return normal.Status(), normal.Body()
}

func generatorURLs(t *testing.T, body []byte) []string {
	t.Helper()
	var urls []string
	var decoded any
	require.NoError(t, json.Unmarshal(body, &decoded))
	var walk func(any)
	walk = func(v any) {
		switch n := v.(type) {
		case map[string]any:
			if raw, ok := n["generatorURL"].(string); ok && raw != "" {
				urls = append(urls, raw)
			}
			for _, child := range n {
				walk(child)
			}
		case []any:
			for _, child := range n {
				walk(child)
			}
		}
	}
	walk(decoded)
	return urls
}

func TestExternalAlertGeneratorURLIsLimitedToTheAlertmanagerHost(t *testing.T) {
	ext := startExternalAlertmanager(t)
	am, proxy := ext.grafana(t)
	amURL, err := url.Parse(ext.server.URL)
	require.NoError(t, err)

	allowed := ext.server.URL + "/#/alerts"
	sameOriginLogout := "http://grafana.example/logout"
	sameOriginOrgSwitch := "http://grafana.example/profile/switch-org/2"
	relativeLogout := "/logout"
	protocolRelative := "//grafana.example/logout"
	foreign := "https://evil.example/phish"

	cases := []struct {
		name         string
		generatorURL string
		allowed      bool
	}{
		{name: "alertmanager host", generatorURL: allowed, allowed: true},
		{name: "grafana logout", generatorURL: sameOriginLogout},
		{name: "grafana org switch", generatorURL: sameOriginOrgSwitch},
		{name: "relative logout", generatorURL: relativeLogout},
		{name: "protocol relative logout", generatorURL: protocolRelative},
		{name: "foreign host", generatorURL: foreign},
	}

	// Rejecting a post is a valid fix. Accepting it is also fine when the URL is
	// not returned to viewers. A rejection that still stores the alert is not.
	planted := map[string]bool{}
	for _, tc := range cases {
		t.Run("post "+tc.name, func(t *testing.T) {
			status, body := postThroughDatasourceProxy(t, proxy, "alert"+strings.ReplaceAll(tc.name, " ", ""), tc.generatorURL)
			if tc.allowed {
				require.Equalf(t, http.StatusOK, status, "the alertmanager host must still be accepted: %s\nupstream %#v", body, ext.requests)
				planted[tc.generatorURL] = true
				return
			}
			if status == http.StatusOK {
				planted[tc.generatorURL] = true
				return
			}
			require.GreaterOrEqualf(t, status, 400, "unexpected proxy status %d body %s", status, body)
		})
	}

	viewerGets := []struct {
		name string
		call func(*contextmodel.ReqContext) response.Response
		path string
	}{
		{name: "alerts", call: am.RouteGetAMAlerts, path: "/api/v2/alerts"},
		{name: "groups", call: am.RouteGetAMAlertGroups, path: "/api/v2/alerts/groups"},
	}
	for _, get := range viewerGets {
		t.Run("viewer "+get.name, func(t *testing.T) {
			ctx := requestContext(
				t,
				http.MethodGet,
				"http://grafana.example/api/alertmanager/"+externalDSUID+get.path,
				nil,
				map[string]string{":DatasourceUID": externalDSUID},
			)
			status, body := responseBody(t, get.call(ctx))
			require.Equalf(t, http.StatusOK, status, "body %s upstream %#v", body, ext.requests)
			got := generatorURLs(t, body)
			require.Contains(t, got, allowed, "a generator URL on the configured alertmanager must still be returned")
			for _, raw := range got {
				parsed, parseErr := url.Parse(raw)
				require.NoError(t, parseErr)
				require.Equalf(t, amURL.Host, parsed.Host, "generator URL %q is not the alertmanager at %s", raw, amURL.Host)
			}
			for raw, wasPlanted := range planted {
				if raw == allowed || !wasPlanted {
					continue
				}
				require.NotContainsf(t, got, raw, "accepted generator URL %q was returned to the viewer", raw)
			}
		})
	}
}

func postThroughDatasourceProxy(t *testing.T, proxy *datasourceproxy.DataSourceProxyService, alertName, generatorURL string) (int, string) {
	t.Helper()
	payload := []byte(`[{"labels":{"alertname":"` + alertName + `"},"generatorURL":"` + generatorURL + `"}]`)
	editor := editorUser()
	req := httptest.NewRequest(
		http.MethodPost,
		"http://grafana.example/api/datasources/proxy/uid/"+externalDSUID+"/api/v2/alerts",
		bytes.NewReader(payload),
	)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(identity.WithRequester(req.Context(), editor))
	req = web.SetURLParams(req, map[string]string{":uid": externalDSUID})
	recorder := httptest.NewRecorder()
	ctx := &contextmodel.ReqContext{
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(http.MethodPost, recorder),
		},
		SignedInUser: editor,
		Logger:       log.NewNopLogger(),
		IsSignedIn:   true,
	}
	proxy.ProxyDatasourceRequestWithUID(ctx, externalDSUID)
	return recorder.Code, recorder.Body.String()
}
