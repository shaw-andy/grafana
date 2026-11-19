package diagnostics

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	sdkhar "github.com/grafana/grafana-plugin-sdk-go/backend/harcapture"
	sdkhttpclient "github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/httpclient/harcapture"
	"github.com/grafana/grafana/pkg/infra/httpclient/httpclientprovider"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/clientmiddleware"
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tsdb/graphite"
)

// Placeholders stand in for datasource secrets. They are not credentials.
const (
	placeholderBasicAuth      = "placeholder-basic-auth"
	placeholderBearer         = "placeholder-bearer"
	placeholderAPIToken       = "placeholder-api-token"
	placeholderProxyAuth      = "placeholder-proxy-auth"
	placeholderCookie         = "placeholder-cookie"
	placeholderHeaderPassword = "placeholder-header-password"
	placeholderHeaderSecret   = "placeholder-header-secret"
	placeholderHeaderKey      = "placeholder-header-key"
	placeholderUserinfo       = "placeholder-userinfo"
	placeholderQueryPassword  = "placeholder-query-password"
	placeholderSetCookie      = "placeholder-set-cookie"
	placeholderResponseToken  = "placeholder-response-token"
	placeholderBasicUser      = "ds-basic-user"
	placeholderUserinfoUser   = "ds-userinfo-user"
	keptVisibleHeader         = "kept-visible-label"
)

func TestDiagnosticsArchiveOmitsLiveDatasourceCredentials(t *testing.T) {
	prevTimeouts := sdkhttpclient.DefaultTimeoutOptions
	t.Cleanup(func() { sdkhttpclient.DefaultTimeoutOptions = prevTimeouts })

	var seen secretAttachment
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.observe(r)
		w.Header().Set("X-Token", placeholderResponseToken)
		http.SetCookie(w, &http.Cookie{Name: "diag_session", Value: placeholderSetCookie})
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "render failed")
	}))
	t.Cleanup(srv.Close)

	provider := httpclientprovider.New(testProxyCfg(), &validations.OSSDataSourceRequestURLValidator{}, tracing.InitializeTracerForTest())
	svc := graphite.ProvideService(provider, tracing.InitializeTracerForTest())
	plugin := &capturePlugin{graphite: svc, provider: provider}
	handler, err := backend.HandlerFromMiddlewares(plugin, clientmiddleware.NewHTTPCaptureMiddleware())
	require.NoError(t, err)

	ctx, buf := harcapture.WithCapture(context.Background())
	basic := basicAuthSettings(srv.URL)
	bearer := bearerSettings(srv.URL)
	withUserinfo := userinfoSettings(3, srv.URL)
	refused := userinfoSettings(4, "http://127.0.0.1:1")

	responses := []*backend.QueryDataResponse{}
	for _, settings := range []*backend.DataSourceInstanceSettings{basic, bearer, withUserinfo, refused} {
		resp, err := handler.QueryData(ctx, graphiteQuery(settings))
		require.NoError(t, err)
		responses = append(responses, resp)
	}
	require.NoError(t, handler.QueryChunkedData(ctx, &backend.QueryChunkedDataRequest{
		PluginContext: pluginContext(basic),
	}, nopChunkWriter{}))

	require.Greater(t, buf.Len(), 0, "in-process capture recorded no datasource calls")
	require.True(t, seen.basicAuth, "basic-auth middleware did not attach the stored password")
	require.True(t, seen.bearer, "secure Authorization header was not attached")
	require.True(t, seen.apiToken, "secure custom header was not attached")
	require.True(t, seen.proxyAuth, "Proxy-Authorization was not attached")
	require.True(t, seen.cookie, "Cookie was not attached")
	require.True(t, seen.headerPassword, "password header was not attached")
	require.True(t, seen.headerSecret, "secret header was not attached")
	require.True(t, seen.headerKey, "key header was not attached")
	require.True(t, seen.userinfo, "URL userinfo was not sent on the datasource request")

	var queryErr error
	for _, resp := range responses {
		queryErr = errors.Join(queryErr, ResponseError(resp))
	}
	require.Error(t, queryErr)

	panel, err := NewBundler(nil).Build(nil, buf, nil, nil, nil, nil, queryErr)
	require.NoError(t, err)
	assertArchiveOmitsSecrets(t, panel)
	panelFiles := readTarGz(t, panel)
	require.Contains(t, panelFiles, "traffic.har")
	require.Contains(t, string(panelFiles["traffic.har"]), "127.0.0.1", "captured URL host should survive redaction")
	require.Contains(t, panelFiles, "query-error.txt")

	dashboard, err := NewBundler(nil).BuildDashboard(nil, []DashboardPanel{{
		ID:        1,
		Title:     "CPU",
		HARBuffer: buf,
		QueryErr:  queryErr,
		Resp:      responses[0],
	}})
	require.NoError(t, err)
	assertArchiveOmitsSecrets(t, dashboard)
	dashFiles := readTarGz(t, dashboard)
	require.Contains(t, dashFiles, "panels/1-cpu/traffic.har")
	require.Contains(t, dashFiles, "panels/1-cpu/query-error.txt")
	require.Contains(t, string(dashFiles["manifest.json"]), "panels/1-cpu")
}

func TestMergedExternalHAROmitsLiveDatasourceCredentials(t *testing.T) {
	// The plugin SDK capture middleware records the request with Buffer.AddEntry and returns that
	// document in a __har__ frame. Grafana then merges the frame into traffic.har.
	u := &url.URL{
		Scheme:   "http",
		User:     url.UserPassword(placeholderUserinfoUser, placeholderUserinfo),
		Host:     "datasource.example",
		Path:     "/query",
		RawQuery: "password=" + url.QueryEscape(placeholderQueryPassword),
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+placeholderBearer)
	req.Header.Set("Proxy-Authorization", placeholderProxyAuth)
	req.Header.Set("Cookie", "session="+placeholderCookie)
	req.Header.Set("X-Api-Token", placeholderAPIToken)
	req.Header.Set("X-Password", placeholderHeaderPassword)
	req.Header.Set("X-Secret-Id", placeholderHeaderSecret)
	req.Header.Set("X-Api-Key", placeholderHeaderKey)
	req.Header.Set("X-Unrelated", keptVisibleHeader)

	resp := &http.Response{
		StatusCode: http.StatusUnauthorized,
		Status:     "401 Unauthorized",
		Proto:      "HTTP/1.1",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("denied")),
	}
	resp.Header.Set("X-Token", placeholderResponseToken)
	resp.Header.Set("Set-Cookie", (&http.Cookie{Name: "diag_session", Value: placeholderSetCookie}).String())

	sdkBuf := sdkhar.NewBuffer()
	sdkBuf.AddEntry(req, nil, false, resp, nil, time.Now(), time.Millisecond)
	harStr, err := sdkBuf.ToHARString()
	require.NoError(t, err)

	// Same string the SDK stores on the capture frame when the plugin call fails.
	client := &http.Client{Timeout: time.Second}
	refusedURL := &url.URL{
		Scheme: "http",
		User:   url.UserPassword(placeholderUserinfoUser, placeholderUserinfo),
		Host:   "127.0.0.1:1",
		Path:   "/query",
	}
	refusedReq, err := http.NewRequest(http.MethodGet, refusedURL.String(), nil)
	require.NoError(t, err)
	_, dialErr := client.Do(refusedReq)
	require.Error(t, dialErr)

	externalResp := func() *backend.QueryDataResponse {
		frame := data.NewFrame("__har__P123")
		frame.Meta = &data.FrameMeta{Custom: map[string]interface{}{
			"har":        harStr,
			"queryError": dialErr.Error(),
		}}
		queryResp := backend.NewQueryDataResponse()
		queryResp.Responses["__har__P123"] = backend.DataResponse{Frames: data.Frames{frame}}
		return queryResp
	}

	panelResp := externalResp()
	bundle, err := NewBundler(nil).Build(panelResp, nil, nil, nil, nil, nil, PluginCaptureError(panelResp))
	require.NoError(t, err)
	assertArchiveOmitsSecrets(t, bundle)
	files := readTarGz(t, bundle)
	require.Contains(t, files, "traffic.har")
	require.Contains(t, string(files["traffic.har"]), "datasource.example")
	require.Contains(t, string(files["traffic.har"]), keptVisibleHeader, "non-secret headers stay in the capture")
	require.Contains(t, files, "query-error.txt")

	dashResp := externalResp()
	dashboard, err := NewBundler(nil).BuildDashboard(nil, []DashboardPanel{{
		ID:       2,
		Title:    "External",
		Resp:     dashResp,
		QueryErr: PluginCaptureError(dashResp),
	}})
	require.NoError(t, err)
	assertArchiveOmitsSecrets(t, dashboard)
}

type secretAttachment struct {
	basicAuth      bool
	bearer         bool
	apiToken       bool
	proxyAuth      bool
	cookie         bool
	headerPassword bool
	headerSecret   bool
	headerKey      bool
	userinfo       bool
}

func (s *secretAttachment) observe(r *http.Request) {
	if user, pass, ok := r.BasicAuth(); ok {
		if user == placeholderBasicUser && pass == placeholderBasicAuth {
			s.basicAuth = true
		}
		if user == placeholderUserinfoUser && pass == placeholderUserinfo {
			s.userinfo = true
		}
	}
	if r.Header.Get("Authorization") == "Bearer "+placeholderBearer {
		s.bearer = true
	}
	if r.Header.Get("X-Api-Token") == placeholderAPIToken {
		s.apiToken = true
	}
	if r.Header.Get("Proxy-Authorization") == placeholderProxyAuth {
		s.proxyAuth = true
	}
	if strings.Contains(r.Header.Get("Cookie"), placeholderCookie) {
		s.cookie = true
	}
	if r.Header.Get("X-Password") == placeholderHeaderPassword {
		s.headerPassword = true
	}
	if r.Header.Get("X-Secret-Id") == placeholderHeaderSecret {
		s.headerSecret = true
	}
	if r.Header.Get("X-Api-Key") == placeholderHeaderKey {
		s.headerKey = true
	}
}

func assertArchiveOmitsSecrets(t *testing.T, archive []byte) {
	t.Helper()
	// The bundle is gzip-compressed, so search the unpacked files. A match against the
	// compressed bytes would miss secrets that only exist after gunzip.
	files := readTarGz(t, archive)
	var text strings.Builder
	for name, body := range files {
		text.WriteString(name)
		text.WriteByte('\n')
		text.Write(body)
		text.WriteByte('\n')
	}
	unpacked := text.String()
	secrets := []string{
		placeholderBasicAuth,
		placeholderBearer,
		placeholderAPIToken,
		placeholderProxyAuth,
		placeholderCookie,
		placeholderHeaderPassword,
		placeholderHeaderSecret,
		placeholderHeaderKey,
		placeholderUserinfo,
		placeholderQueryPassword,
		placeholderSetCookie,
		placeholderResponseToken,
	}
	for _, secret := range secrets {
		if strings.Contains(unpacked, secret) {
			t.Errorf("diagnostics archive contains datasource secret %q", secret)
		}
	}
	for _, pair := range []struct{ user, pass string }{
		{placeholderBasicUser, placeholderBasicAuth},
		{placeholderUserinfoUser, placeholderUserinfo},
	} {
		encoded := base64.StdEncoding.EncodeToString([]byte(pair.user + ":" + pair.pass))
		if strings.Contains(unpacked, encoded) {
			t.Errorf("diagnostics archive contains basic-auth material for user %s", pair.user)
		}
	}
}

func basicAuthSettings(rawURL string) *backend.DataSourceInstanceSettings {
	return &backend.DataSourceInstanceSettings{
		ID:               1,
		UID:              "basic",
		Type:             "graphite",
		Name:             "basic",
		URL:              rawURL,
		BasicAuthEnabled: true,
		BasicAuthUser:    placeholderBasicUser,
		JSONData: mustJSON(map[string]any{
			"httpHeaderName1": "X-Api-Token",
			"httpHeaderName2": "Proxy-Authorization",
			"httpHeaderName3": "Cookie",
			"httpHeaderName4": "X-Password",
			"httpHeaderName5": "X-Secret-Id",
			"httpHeaderName6": "X-Api-Key",
		}),
		DecryptedSecureJSONData: map[string]string{
			"basicAuthPassword": placeholderBasicAuth,
			"httpHeaderValue1":  placeholderAPIToken,
			"httpHeaderValue2":  placeholderProxyAuth,
			"httpHeaderValue3":  "session=" + placeholderCookie,
			"httpHeaderValue4":  placeholderHeaderPassword,
			"httpHeaderValue5":  placeholderHeaderSecret,
			"httpHeaderValue6":  placeholderHeaderKey,
		},
		Updated: time.Now(),
	}
}

func bearerSettings(rawURL string) *backend.DataSourceInstanceSettings {
	return &backend.DataSourceInstanceSettings{
		ID:   2,
		UID:  "bearer",
		Type: "graphite",
		Name: "bearer",
		URL:  rawURL,
		JSONData: mustJSON(map[string]any{
			"httpHeaderName1": "Authorization",
		}),
		DecryptedSecureJSONData: map[string]string{
			"httpHeaderValue1": "Bearer " + placeholderBearer,
		},
		Updated: time.Now(),
	}
}

func userinfoSettings(id int64, rawURL string) *backend.DataSourceInstanceSettings {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	u.User = url.UserPassword(placeholderUserinfoUser, placeholderUserinfo)
	q := u.Query()
	q.Set("password", placeholderQueryPassword)
	u.RawQuery = q.Encode()
	return &backend.DataSourceInstanceSettings{
		ID:      id,
		UID:     "userinfo",
		Type:    "graphite",
		Name:    "userinfo",
		URL:     u.String(),
		Updated: time.Now(),
	}
}

func graphiteQuery(settings *backend.DataSourceInstanceSettings) *backend.QueryDataRequest {
	return &backend.QueryDataRequest{
		PluginContext: pluginContext(settings),
		Queries: []backend.DataQuery{{
			RefID: "A",
			JSON:  []byte(`{"target":"metric"}`),
			TimeRange: backend.TimeRange{
				From: time.Now().Add(-time.Hour),
				To:   time.Now(),
			},
		}},
	}
}

func pluginContext(settings *backend.DataSourceInstanceSettings) backend.PluginContext {
	return backend.PluginContext{
		OrgID:                      1,
		PluginID:                   "graphite",
		DataSourceInstanceSettings: settings,
		GrafanaConfig:              backend.NewGrafanaCfg(map[string]string{}),
	}
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func testProxyCfg() *setting.Cfg {
	return &setting.Cfg{
		DataProxyTimeout:               30,
		DataProxyDialTimeout:           5,
		DataProxyKeepAlive:             30,
		DataProxyTLSHandshakeTimeout:   5,
		DataProxyExpectContinueTimeout: 1,
		DataProxyMaxConnsPerHost:       10,
		DataProxyMaxIdleConns:          10,
		DataProxyIdleConnTimeout:       30,
		DataProxyUserAgent:             "grafana-diagnostics-test",
	}
}

// capturePlugin is the in-process plugin handler the capture middleware wraps.
// QueryData is graphite. QueryChunkedData uses the same instance HTTP client
// graphite builds (DataSourceInstanceSettings.HTTPClientOptions + the provider).
type capturePlugin struct {
	backend.BaseHandler
	graphite *graphite.Service
	provider *sdkhttpclient.Provider
}

func (p *capturePlugin) QueryData(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	return p.graphite.QueryData(ctx, req)
}

func (p *capturePlugin) QueryChunkedData(ctx context.Context, req *backend.QueryChunkedDataRequest, _ backend.ChunkedDataWriter) error {
	settings := req.PluginContext.DataSourceInstanceSettings
	opts, err := settings.HTTPClientOptions(ctx)
	if err != nil {
		return err
	}
	client, err := p.provider.New(opts)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, settings.URL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

type nopChunkWriter struct{}

func (nopChunkWriter) WriteFrame(context.Context, string, string, *data.Frame) error { return nil }
func (nopChunkWriter) WriteError(context.Context, string, backend.Status, error) error {
	return nil
}
