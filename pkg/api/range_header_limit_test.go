package api

import (
	"bytes"
	"context"
	"errors"
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

	"github.com/grafana/grafana/pkg/api/webassets"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/rendering"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// Go 1.26.9's net/http ignores a Range header with more ranges than this
// (defaultMaxContentRanges) before parsing each one. These tests encode that
// behavior: a larger header must be treated as absent.
const maxServedContentRanges = 200

func manySingleByteRanges(n int) string {
	var b strings.Builder
	b.Grow(len("bytes=") + n*len("0-0,"))
	b.WriteString("bytes=")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("0-0")
	}
	return b.String()
}

func TestStaticRangeHeaderIsLimited(t *testing.T) {
	buildRoot := t.TempDir()
	// Larger than the sum of the one-byte ranges below. A smaller file makes
	// net/http discard the ranges only after it has parsed every one, which
	// hides the missing limit.
	asset := bytes.Repeat([]byte("abcdefghij"), 10_000)
	require.GreaterOrEqual(t, len(asset), 100_000)
	require.NoError(t, os.MkdirAll(filepath.Join(buildRoot, webassets.BuildDir), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(buildRoot, webassets.BuildDir, "app.js"), asset, 0o644))

	publicDir := filepath.Join("..", "..", "public")
	shipped, err := os.ReadFile(filepath.Join(publicDir, "img", "login_background_dark.svg"))
	require.NoError(t, err)
	require.Greater(t, len(shipped), maxServedContentRanges+1)

	cfg := setting.NewCfg()
	cfg.Env = setting.Prod
	hs := &HTTPServer{Cfg: cfg, log: log.NewNopLogger()}

	m := web.New()
	// Same middleware that runs before static files in production. Neither
	// may strip Range on a cookieless GET that does not ask for gzip.
	m.UseMiddleware(middleware.Gziper())
	m.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	hs.mapStatic(m, buildRoot, webassets.BuildDir, "public/build")
	hs.mapStatic(m, publicDir, "", "public")

	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.Timeout = 5 * time.Second

	t.Run("single range is still served", func(t *testing.T) {
		resp, body := getWithRange(t, client, srv.URL+"/public/build/app.js", "bytes=0-3")
		require.Equal(t, http.StatusPartialContent, resp.StatusCode)
		require.Equal(t, "bytes 0-3/"+strconv.Itoa(len(asset)), resp.Header.Get("Content-Range"))
		require.Equal(t, asset[:4], body)
	})

	t.Run("ranges over the limit are ignored", func(t *testing.T) {
		resp, body := getWithRange(t, client, srv.URL+"/public/build/app.js", manySingleByteRanges(maxServedContentRanges+1))
		requireFullContent(t, resp, body, asset)
	})

	t.Run("shipped public image ignores an oversized range", func(t *testing.T) {
		resp, body := getWithRange(t, client, srv.URL+"/public/img/login_background_dark.svg", manySingleByteRanges(maxServedContentRanges+1))
		requireFullContent(t, resp, body, shipped)
	})

	t.Run("a large range header is not parsed into a multipart body", func(t *testing.T) {
		const ranges = 100_000
		require.GreaterOrEqual(t, len(asset), ranges)
		header := manySingleByteRanges(ranges)
		require.Less(t, len(header), 1<<20, "header must fit under net/http DefaultMaxHeaderBytes, which Grafana leaves unset")

		start := time.Now()
		resp, body := getWithRange(t, client, srv.URL+"/public/build/app.js", header)
		elapsed := time.Since(start)
		if resp.StatusCode != http.StatusOK || strings.Contains(resp.Header.Get("Content-Type"), "multipart/byteranges") || !bytes.Equal(body, asset) || elapsed >= 200*time.Millisecond {
			t.Fatalf("status=%d content-type=%q body=%d elapsed=%s, want status=200, the full %d-byte file, and under 200ms", resp.StatusCode, resp.Header.Get("Content-Type"), len(body), elapsed, len(asset))
		}
	})
}

func TestPluginAssetRangeHeaderIsLimited(t *testing.T) {
	const pluginID = "range-plugin"
	dir := t.TempDir()
	body := bytes.Repeat([]byte("p"), 4096)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "module.js"), body, 0o644))

	p := createPlugin(plugins.JSONData{ID: pluginID}, plugins.ClassExternal, plugins.NewLocalFS(dir))
	registry := &pluginfakes.FakePluginRegistry{Store: map[string]*plugins.Plugin{p.ID: p}}
	url := "/public/plugins/" + pluginID + "/module.js"
	pattern := "/public/plugins/:pluginId/*"

	pluginAssetScenario(t, "single range is still served", url, pattern, setting.NewCfg(), registry, func(sc *scenarioContext) {
		sc.fakeReq(http.MethodGet, url)
		require.Empty(sc.t, sc.req.Cookies())
		sc.req.Header.Set("Range", "bytes=0-3")
		sc.exec()

		require.Equal(sc.t, http.StatusPartialContent, sc.resp.Code)
		require.Equal(sc.t, body[:4], sc.resp.Body.Bytes())
	})

	pluginAssetScenario(t, "ranges over the limit are ignored", url, pattern, setting.NewCfg(), registry, func(sc *scenarioContext) {
		sc.fakeReq(http.MethodGet, url)
		require.Empty(sc.t, sc.req.Cookies())
		sc.req.Header.Set("Range", manySingleByteRanges(maxServedContentRanges+1))
		sc.exec()

		require.Equal(sc.t, http.StatusOK, sc.resp.Code)
		require.NotContains(sc.t, sc.resp.Header().Get("Content-Type"), "multipart/byteranges")
		require.Equal(sc.t, body, sc.resp.Body.Bytes())
	})
}

func TestRenderRangeHeaderIsLimited(t *testing.T) {
	dir := t.TempDir()
	body := bytes.Repeat([]byte("r"), 4096)
	file := filepath.Join(dir, "panel.png")
	require.NoError(t, os.WriteFile(file, body, 0o644))

	hs := &HTTPServer{
		Cfg:           setting.NewCfg(),
		log:           log.NewNopLogger(),
		RenderService: &rangeRenderService{file: file},
	}

	t.Run("single range is still served", func(t *testing.T) {
		rec := renderWithRange(t, hs, "bytes=0-3")
		require.Equal(t, http.StatusPartialContent, rec.Code)
		require.Equal(t, body[:4], rec.Body.Bytes())
	})

	t.Run("ranges over the limit are ignored", func(t *testing.T) {
		rec := renderWithRange(t, hs, manySingleByteRanges(maxServedContentRanges+1))
		require.Equal(t, http.StatusOK, rec.Code)
		require.NotContains(t, rec.Header().Get("Content-Type"), "multipart/byteranges")
		require.Equal(t, body, rec.Body.Bytes())
	})
}

func getWithRange(t *testing.T, client *http.Client, url, rangeHeader string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Range", rangeHeader)
	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, got
}

func requireFullContent(t *testing.T, resp *http.Response, got, want []byte) {
	t.Helper()
	if resp.StatusCode != http.StatusOK || strings.Contains(resp.Header.Get("Content-Type"), "multipart/byteranges") || !bytes.Equal(got, want) {
		t.Fatalf("status=%d content-type=%q body=%d, want status=200 and the full %d-byte file", resp.StatusCode, resp.Header.Get("Content-Type"), len(got), len(want))
	}
}

func renderWithRange(t *testing.T, hs *HTTPServer, rangeHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/render/d-solo/abc", nil)
	req.Header.Set("Range", rangeHeader)
	rec := httptest.NewRecorder()
	hs.RenderHandler(&contextmodel.ReqContext{
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(req.Method, rec),
		},
		SignedInUser: &user.SignedInUser{UserID: 1, OrgID: 1},
		IsSignedIn:   true,
		Logger:       log.NewNopLogger(),
	})
	return rec
}

type rangeRenderService struct {
	file string
}

func (s *rangeRenderService) IsAvailable(context.Context) bool { return true }
func (s *rangeRenderService) Version() string                  { return "test" }
func (s *rangeRenderService) Render(context.Context, rendering.RenderType, rendering.Opts) (*rendering.RenderResult, error) {
	return &rendering.RenderResult{FilePath: s.file}, nil
}
func (s *rangeRenderService) RenderCSV(context.Context, rendering.CSVOpts) (*rendering.RenderCSVResult, error) {
	return nil, errors.New("unused")
}
func (s *rangeRenderService) RenderErrorImage(models.Theme, error) (*rendering.RenderResult, error) {
	return nil, errors.New("unused")
}
func (s *rangeRenderService) GetRenderUser(context.Context, string) (*rendering.RenderUser, bool) {
	return nil, false
}
func (s *rangeRenderService) HasCapability(context.Context, rendering.CapabilityName) (rendering.CapabilitySupportRequestResult, error) {
	return rendering.CapabilitySupportRequestResult{}, nil
}
func (s *rangeRenderService) IsCapabilitySupported(context.Context, rendering.CapabilityName) error {
	return nil
}
