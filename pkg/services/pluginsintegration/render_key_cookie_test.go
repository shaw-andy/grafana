package pluginsintegration

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/registry"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// Cookie names the production auth code uses. Values are placeholders, not credentials.
const (
	renderKeyCookieName = "renderKey"
	loginCookieName     = "grafana_session"
	keptCookieName      = "ds_session"

	renderKeyPlaceholder = "render-key-placeholder"
	loginPlaceholder     = "login-cookie-placeholder"
	keptPlaceholder      = "kept-cookie-placeholder"
)

// TestRenderKeyCookieIsNotForwardedToDatasource checks the plugin client chain
// that backend datasources use for queries, chunked queries, resource calls,
// and health checks. A datasource keepCookies list is attacker-controlled and
// must not be able to forward the render auth cookie, or the login cookie, to
// the datasource host. A non-auth cookie that keepCookies names is still forwarded.
func TestRenderKeyCookieIsNotForwardedToDatasource(t *testing.T) {
	keepLists := []struct {
		name string
		keep []string
		// keptForwarded is true when the keep list matches ds_session.
		keptForwarded bool
	}{
		{name: "match all", keep: []string{"[]"}, keptForwarded: true},
		{name: "exact render key", keep: []string{renderKeyCookieName}, keptForwarded: false},
		{name: "render key prefix", keep: []string{"render[]"}, keptForwarded: false},
		{name: "kept cookie and render key", keep: []string{keptCookieName, renderKeyCookieName}, keptForwarded: true},
	}

	operations := []string{"QueryData", "QueryChunkedData", "CallResource", "CheckHealth"}

	for _, keep := range keepLists {
		for _, operation := range operations {
			t.Run(keep.name+"/"+operation, func(t *testing.T) {
				var outgoingCookies map[string]string
				outgoing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					outgoingCookies = map[string]string{}
					for _, c := range r.Cookies() {
						outgoingCookies[c.Name] = c.Value
					}
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(outgoing.Close)

				pluginCookie := callPluginOperation(t, operation, outgoing.URL, keep.keep)
				pluginCookies := cookiesFromHeader(t, pluginCookie)
				require.NotContains(t, pluginCookies, renderKeyCookieName)
				require.NotContains(t, pluginCookies, loginCookieName)
				if keep.keptForwarded {
					require.Equal(t, keptPlaceholder, pluginCookies[keptCookieName])
				} else {
					require.NotContains(t, pluginCookies, keptCookieName)
				}

				require.NotNil(t, outgoingCookies)
				require.NotContains(t, outgoingCookies, renderKeyCookieName)
				require.NotContains(t, outgoingCookies, loginCookieName)
				if keep.keptForwarded {
					require.Equal(t, keptPlaceholder, outgoingCookies[keptCookieName])
				} else {
					require.NotContains(t, outgoingCookies, keptCookieName)
				}
			})
		}
	}
}

func callPluginOperation(t *testing.T, operation, datasourceURL string, keepCookies []string) string {
	t.Helper()

	reg := registry.NewInMemory()
	require.NoError(t, reg.Add(context.Background(), &plugins.Plugin{
		JSONData: plugins.JSONData{ID: "graphite", Backend: true},
	}))

	cfg := &setting.Cfg{LoginCookieName: loginCookieName}
	middlewares := CreateMiddlewares(
		cfg,
		nil,
		tracing.NewNoopTracerService(),
		nil,
		featuremgmt.WithFeatures(),
		prometheus.NewRegistry(),
		reg,
	)

	handler := &datasourceHTTPHandler{url: datasourceURL}
	mw, err := backend.HandlerFromMiddlewares(handler, middlewares...)
	require.NoError(t, err)

	req := incomingRenderRequest()
	ctx := req.Context()
	pluginCtx := backend.PluginContext{
		PluginID: "graphite",
		DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{
			JSONData: []byte(`{"keepCookies":` + jsonStringArray(keepCookies) + `}`),
		},
	}

	switch operation {
	case "QueryData":
		_, err = mw.QueryData(ctx, &backend.QueryDataRequest{
			PluginContext: pluginCtx,
			Headers:       map[string]string{},
		})
	case "QueryChunkedData":
		err = mw.QueryChunkedData(ctx, &backend.QueryChunkedDataRequest{
			PluginContext: pluginCtx,
			Headers:       map[string]string{},
		}, nopChunkedWriter{})
	case "CallResource":
		err = mw.CallResource(ctx, &backend.CallResourceRequest{
			PluginContext: pluginCtx,
			Headers:       map[string][]string{},
		}, backend.CallResourceResponseSenderFunc(func(*backend.CallResourceResponse) error { return nil }))
	case "CheckHealth":
		_, err = mw.CheckHealth(ctx, &backend.CheckHealthRequest{
			PluginContext: pluginCtx,
			Headers:       map[string]string{},
		})
	default:
		t.Fatalf("unknown operation %s", operation)
	}
	require.NoError(t, err)
	return handler.pluginCookie
}

// datasourceHTTPHandler stands in for an in-process backend datasource. It issues
// its HTTP call with the SDK client the same way Grafana core datasources do:
// the provider supplies the default middleware chain, and the request uses the
// plugin context so contextual middleware runs.
type datasourceHTTPHandler struct {
	backend.BaseHandler
	url          string
	pluginCookie string
}

func (h *datasourceHTTPHandler) QueryData(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	h.pluginCookie = req.GetHTTPHeader("Cookie")
	if err := h.queryDatasource(ctx); err != nil {
		return nil, err
	}
	return &backend.QueryDataResponse{}, nil
}

func (h *datasourceHTTPHandler) QueryChunkedData(ctx context.Context, req *backend.QueryChunkedDataRequest, _ backend.ChunkedDataWriter) error {
	h.pluginCookie = req.GetHTTPHeader("Cookie")
	return h.queryDatasource(ctx)
}

func (h *datasourceHTTPHandler) CallResource(ctx context.Context, req *backend.CallResourceRequest, _ backend.CallResourceResponseSender) error {
	h.pluginCookie = req.GetHTTPHeader("Cookie")
	return h.queryDatasource(ctx)
}

func (h *datasourceHTTPHandler) CheckHealth(ctx context.Context, req *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	h.pluginCookie = req.GetHTTPHeader("Cookie")
	if err := h.queryDatasource(ctx); err != nil {
		return nil, err
	}
	return &backend.CheckHealthResult{Status: backend.HealthStatusOk}, nil
}

func (h *datasourceHTTPHandler) queryDatasource(ctx context.Context) error {
	client, err := httpclient.NewProvider().New()
	if err != nil {
		return err
	}
	out, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(out)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}

func incomingRenderRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://grafana.example/api/ds/query", nil)
	req.AddCookie(&http.Cookie{Name: keptCookieName, Value: keptPlaceholder})
	req.AddCookie(&http.Cookie{Name: loginCookieName, Value: loginPlaceholder})
	req.AddCookie(&http.Cookie{Name: renderKeyCookieName, Value: renderKeyPlaceholder})

	reqCtx := &contextmodel.ReqContext{
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(req.Method, httptest.NewRecorder()),
		},
		SignedInUser: &user.SignedInUser{},
	}
	ctx := ctxkey.Set(req.Context(), reqCtx)
	return req.WithContext(ctx)
}

func cookiesFromHeader(t *testing.T, header string) map[string]string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://grafana.example", nil)
	if header != "" {
		req.Header.Set("Cookie", header)
	}
	out := map[string]string{}
	for _, c := range req.Cookies() {
		out[c.Name] = c.Value
	}
	return out
}

func jsonStringArray(values []string) string {
	buf := []byte{'['}
	for i, v := range values {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, '"')
		buf = append(buf, v...)
		buf = append(buf, '"')
	}
	buf = append(buf, ']')
	return string(buf)
}

type nopChunkedWriter struct{}

func (nopChunkedWriter) WriteFrame(context.Context, string, string, *data.Frame) error {
	return nil
}

func (nopChunkedWriter) WriteError(context.Context, string, backend.Status, error) error {
	return nil
}
