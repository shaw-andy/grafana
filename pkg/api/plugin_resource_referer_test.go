package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

func TestPluginResourceDoesNotForwardDashboardPageQuery(t *testing.T) {
	const dashboardPageReferer = "https://grafana.example/d/abc/overview?orgId=1&var-region=page-query-value"
	const pageQueryValue = "page-query-value"

	pluginClient := &fakePluginClient{}
	hs := HTTPServer{
		Cfg:          setting.NewCfg(),
		log:          log.New("test"),
		pluginClient: pluginClient,
	}

	// Same request CallResource and callPluginResourceWithDataSource hand to
	// pluginResourceRequest: the resource query is limit=1, and the dashboard
	// query string arrives only in Referer.
	req := httptest.NewRequest(http.MethodGet, "http://grafana.example/api/plugins/example/resources/labels?limit=1", nil)
	req.Header.Set("Referer", dashboardPageReferer)
	req = web.SetURLParams(req, map[string]string{"*": "labels"})
	reqCtx := &contextmodel.ReqContext{Context: &web.Context{Req: req}}

	resourceReq, err := hs.pluginResourceRequest(reqCtx)
	require.NoError(t, err)

	err = hs.makePluginResourceRequest(httptest.NewRecorder(), resourceReq, backend.PluginContext{})
	require.NoError(t, err)

	sent := pluginClient.req
	require.NotNil(t, sent)
	require.Equal(t, "limit=1", sentURLQuery(t, sent.URL))
	require.NotContains(t, sent.URL, pageQueryValue)
	require.NotContains(t, string(sent.Body), pageQueryValue)

	for name, values := range sent.Headers {
		for _, value := range values {
			if strings.Contains(value, pageQueryValue) {
				t.Fatalf("plugin resource header %s contains the dashboard page query", name)
			}
		}
	}

	forwarded := http.Header(sent.Headers).Get("X-Grafana-Referer")
	if forwarded == "" {
		return
	}
	parsed, err := url.Parse(forwarded)
	require.NoError(t, err)
	require.Empty(t, parsed.RawQuery)
	require.NotContains(t, forwarded, "?")
}

func sentURLQuery(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	return parsed.RawQuery
}
