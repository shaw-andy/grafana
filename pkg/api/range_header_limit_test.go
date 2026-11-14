package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	httpstatic "github.com/grafana/grafana/pkg/api/static"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/config"
	"github.com/grafana/grafana/pkg/plugins/pluginscdn"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/rendering"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// Go 1.26.9 net/http.parseRange ignores Range headers with more specs than
// defaultMaxContentRanges. A smaller list is still a normal partial response.
const maxHonoredRanges = 200

func TestRangeHeaderStaticOverLimit(t *testing.T) {
	payload := rangeTestPayload()
	srv := newStaticRangeServer(t, payload)
	header := byteRanges(maxHonoredRanges + 1)
	require.Less(t, len(header), http.DefaultMaxHeaderBytes)

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			resp := rangeRequest(t, srv, method, "/public/app.js", header)
			assertFullContent(t, resp, method, payload)
		})
	}
}

func TestRangeHeaderPluginAssetOverLimit(t *testing.T) {
	payload := rangeTestPayload()
	srv := newPluginRangeServer(t, payload)
	header := byteRanges(maxHonoredRanges + 1)
	require.Less(t, len(header), http.DefaultMaxHeaderBytes)

	resp := rangeRequest(t, srv, http.MethodGet, "/public/plugins/sample/module.js", header)
	assertFullContent(t, resp, http.MethodGet, payload)
}

func TestRangeHeaderRenderedFileOverLimit(t *testing.T) {
	payload := rangeTestPayload()
	srv := newRenderRangeServer(t, payload, true)
	header := byteRanges(maxHonoredRanges + 1)
	require.Less(t, len(header), http.DefaultMaxHeaderBytes)

	resp := rangeRequest(t, srv, http.MethodGet, "/render/d-solo/abc.png", header)
	assertFullContent(t, resp, http.MethodGet, payload)
}

func TestRangeHeaderWithinLimitStillPartial(t *testing.T) {
	payload := rangeTestPayload()
	header := byteRanges(maxHonoredRanges)
	require.Less(t, len(header), http.DefaultMaxHeaderBytes)

	t.Run("static", func(t *testing.T) {
		srv := newStaticRangeServer(t, payload)
		resp := rangeRequest(t, srv, http.MethodGet, "/public/app.js", header)
		assertPartial(t, resp)
	})
	t.Run("plugin asset", func(t *testing.T) {
		srv := newPluginRangeServer(t, payload)
		resp := rangeRequest(t, srv, http.MethodGet, "/public/plugins/sample/module.js", header)
		assertPartial(t, resp)
	})
	t.Run("rendered file", func(t *testing.T) {
		srv := newRenderRangeServer(t, payload, true)
		resp := rangeRequest(t, srv, http.MethodGet, "/render/d-solo/abc.png", header)
		assertPartial(t, resp)
	})
}

func TestRangeHeaderSingleRangeStillPartial(t *testing.T) {
	payload := rangeTestPayload()
	srv := newStaticRangeServer(t, payload)
	resp := rangeRequest(t, srv, http.MethodGet, "/public/app.js", "bytes=0-3")
	t.Cleanup(func() { _ = resp.Body.Close() })
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusPartialContent, resp.StatusCode)
	require.Equal(t, payload[:4], body)
	require.Equal(t, "bytes 0-3/"+strconv.Itoa(len(payload)), resp.Header.Get("Content-Range"))
}

func TestRangeHeaderRenderedFileRequiresSignIn(t *testing.T) {
	payload := rangeTestPayload()
	srv := newRenderRangeServer(t, payload, false)
	resp := rangeRequest(t, srv, http.MethodGet, "/render/d-solo/abc.png", byteRanges(maxHonoredRanges+1))
	t.Cleanup(func() { _ = resp.Body.Close() })
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Contains(t, resp.Header.Get("Location"), "/login")
	require.NotContains(t, string(body), string(payload[:24]))
}

func rangeTestPayload() []byte {
	return bytes.Repeat([]byte("grafana-range-limit-payload-"), 160)
}

func byteRanges(n int) string {
	var b strings.Builder
	b.WriteString("bytes=")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(i))
		b.WriteByte('-')
		b.WriteString(strconv.Itoa(i))
	}
	return b.String()
}

func newStaticRangeServer(t *testing.T, payload []byte) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.js"), payload, 0o644))

	cfg := setting.NewCfg()
	cfg.LoginCookieName = "grafana_session"

	m := web.New()
	m.UseMiddleware(middleware.Gziper())
	m.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	m.Use(httpstatic.Static(dir, httpstatic.StaticOptions{
		Prefix:      "public",
		SkipLogging: true,
	}))
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return srv
}

func newPluginRangeServer(t *testing.T, payload []byte) *httptest.Server {
	t.Helper()
	hs := &HTTPServer{
		Cfg: setting.NewCfg(),
		log: log.NewNopLogger(),
		pluginStore: rangePluginStore{plugin: pluginstore.Plugin{JSONData: plugins.JSONData{
			ID:   "sample",
			Info: plugins.Info{Version: "1.0.0"},
		}}},
		pluginFileStore:   rangePluginFiles{content: payload},
		pluginsCDNService: pluginscdn.ProvideService(&config.PluginManagementCfg{}),
	}
	return newFilteredServer(t, func(w http.ResponseWriter, r *http.Request) {
		r = web.SetURLParams(r, map[string]string{
			":pluginId": "sample",
			"*":         "module.js",
		})
		hs.getPluginAssets(newRangeReqContext(w, r, false))
	})
}

func newRenderRangeServer(t *testing.T, payload []byte, signedIn bool) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	filePath := filepath.Join(dir, "render.png")
	require.NoError(t, os.WriteFile(filePath, payload, 0o644))

	hs := &HTTPServer{
		Cfg:           setting.NewCfg(),
		log:           log.NewNopLogger(),
		RenderService: fixedFileRenderer{path: filePath},
	}
	return newFilteredServer(t, func(w http.ResponseWriter, r *http.Request) {
		c := newRangeReqContext(w, r, signedIn)
		middleware.ReqSignedIn.(func(*contextmodel.ReqContext))(c)
		if c.Resp.Written() {
			return
		}
		hs.RenderHandler(c)
	})
}

func newFilteredServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	cfg := setting.NewCfg()
	cfg.LoginCookieName = "grafana_session"
	var handler http.Handler = h
	handler = csrf.ProvideCSRFFilter(cfg).Middleware()(handler)
	handler = middleware.Gziper()(handler)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func newRangeReqContext(w http.ResponseWriter, r *http.Request, signedIn bool) *contextmodel.ReqContext {
	u := &user.SignedInUser{}
	if signedIn {
		u.UserID = 1
	}
	return &contextmodel.ReqContext{
		Context: &web.Context{
			Req:  r,
			Resp: web.NewResponseWriter(r.Method, w),
		},
		SignedInUser: u,
		IsSignedIn:   signedIn,
		Logger:       log.NewNopLogger(),
	}
}

func rangeRequest(t *testing.T, srv *httptest.Server, method, path, rangeHeader string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	require.NoError(t, err)
	req.Header.Set("Range", rangeHeader)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func assertFullContent(t *testing.T, resp *http.Response, method string, payload []byte) {
	t.Helper()
	t.Cleanup(func() { _ = resp.Body.Close() })
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equalf(t, http.StatusOK, resp.StatusCode,
		"Range header with more than %d specs must be ignored; got Content-Type %q",
		maxHonoredRanges, resp.Header.Get("Content-Type"))
	require.NotContains(t, resp.Header.Get("Content-Type"), "multipart/byteranges")
	if method == http.MethodHead {
		require.Empty(t, body)
		return
	}
	require.Equal(t, payload, body)
}

func assertPartial(t *testing.T, resp *http.Response) {
	t.Helper()
	t.Cleanup(func() { _ = resp.Body.Close() })
	_, err := io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusPartialContent, resp.StatusCode)
	require.Contains(t, resp.Header.Get("Content-Type"), "multipart/byteranges")
}

type rangePluginStore struct {
	plugin pluginstore.Plugin
}

func (s rangePluginStore) Plugin(context.Context, string) (pluginstore.Plugin, bool) {
	return s.plugin, true
}

func (s rangePluginStore) Plugins(context.Context, ...plugins.Type) []pluginstore.Plugin {
	return nil
}

type rangePluginFiles struct {
	content []byte
}

func (f rangePluginFiles) File(context.Context, string, string, string) (*plugins.File, error) {
	return &plugins.File{Content: append([]byte(nil), f.content...), ModTime: time.Unix(1_700_000_000, 0).UTC()}, nil
}

type fixedFileRenderer struct {
	path string
}

func (f fixedFileRenderer) IsAvailable(context.Context) bool { return true }
func (f fixedFileRenderer) Version() string                  { return "test" }
func (f fixedFileRenderer) Render(context.Context, rendering.RenderType, rendering.Opts) (*rendering.RenderResult, error) {
	return &rendering.RenderResult{FilePath: f.path}, nil
}
func (f fixedFileRenderer) RenderCSV(context.Context, rendering.CSVOpts) (*rendering.RenderCSVResult, error) {
	return nil, os.ErrInvalid
}
func (f fixedFileRenderer) RenderErrorImage(models.Theme, error) (*rendering.RenderResult, error) {
	return nil, os.ErrInvalid
}
func (f fixedFileRenderer) GetRenderUser(context.Context, string) (*rendering.RenderUser, bool) {
	return nil, false
}
func (f fixedFileRenderer) HasCapability(context.Context, rendering.CapabilityName) (rendering.CapabilitySupportRequestResult, error) {
	return rendering.CapabilitySupportRequestResult{}, nil
}
func (f fixedFileRenderer) IsCapabilitySupported(context.Context, rendering.CapabilityName) error {
	return nil
}
