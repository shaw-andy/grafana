package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/config"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/plugins/pluginscdn"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/rendering"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// stdlibMaxContentRanges is the cap net/http applies to a Range header once
// CVE-2026-78667 is fixed (Go 1.26.9, defaultMaxContentRanges). At or below this
// count the ranges are honored. Above it the header is ignored and the whole
// representation is returned. Go 1.26.6 parses every range, so these tests fail
// until the stdlib is upgraded.
const stdlibMaxContentRanges = 200

// thousandsOfRanges is large enough to show the header is unbounded, and small
// enough to fit under net/http's default 1MiB header limit ("0-0," is 4 bytes).
const thousandsOfRanges = 4000

func TestRangeHeaderLimit(t *testing.T) {
	// Bigger than every range count below, so a parsed header is a multipart
	// 206. A fixed parser ignores counts above stdlibMaxContentRanges and
	// returns this whole body with 200.
	payload := bytes.Repeat([]byte("x"), thousandsOfRanges+1)

	t.Run("public static files", func(t *testing.T) {
		// Same mount as HTTPServer.mapStatic for /public: no auth middleware in
		// front of it. A handler registered after it stands in for the auth
		// middleware production adds later; serving a file must not reach it.
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "asset.txt"), payload, 0o644))

		cfg := setting.NewCfg()
		cfg.Env = setting.Prod
		cfg.StaticRootPath = dir

		for _, tc := range rangeCases() {
			t.Run(tc.name, func(t *testing.T) {
				var reachedLaterMiddleware bool
				m := web.New()
				m.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
				(&HTTPServer{Cfg: cfg}).mapStatic(m, cfg.StaticRootPath, "", "public")
				m.Use(func(*web.Context) { reachedLaterMiddleware = true })

				rec := get(t, m, "/public/asset.txt", tc.ranges)
				tc.check(t, rec, payload)
				require.False(t, reachedLaterMiddleware, "static response was produced after later middleware")
			})
		}
	})

	t.Run("plugin assets", func(t *testing.T) {
		const pluginID = "range-plugin"
		hs := &HTTPServer{
			Cfg: setting.NewCfg(),
			log: log.NewNopLogger(),
			pluginStore: pluginstore.NewFakePluginStore(pluginstore.Plugin{
				JSONData: plugins.JSONData{ID: pluginID, Info: plugins.Info{Version: "1.0.0"}},
			}),
			pluginFileStore: &pluginfakes.FakePluginFileStore{
				FileFunc: func(context.Context, string, string, string) (*plugins.File, error) {
					return &plugins.File{Content: payload}, nil
				},
			},
			pluginsCDNService: pluginscdn.ProvideService(&config.PluginManagementCfg{}),
		}
		// Authenticate fails, as it does for a request with no credentials.
		// /public/plugins has no ReqSignedIn, so the handler still runs.
		ctxHdlr := contexthandler.ProvideService(hs.Cfg, &authntest.FakeService{
			ExpectedErr: errors.New("cannot authenticate request"),
		}, featuremgmt.WithFeatures())

		for _, tc := range rangeCases() {
			t.Run(tc.name, func(t *testing.T) {
				m := web.New()
				m.UseMiddleware(csrf.ProvideCSRFFilter(hs.Cfg).Middleware())
				m.Use(ctxHdlr.Middleware)
				m.Get("/public/plugins/:pluginId/*", func(c *contextmodel.ReqContext) {
					require.False(t, c.IsSignedIn)
					hs.getPluginAssets(c)
				})

				rec := get(t, m, "/public/plugins/"+pluginID+"/asset.txt", tc.ranges)
				tc.check(t, rec, payload)
			})
		}
	})

	t.Run("render", func(t *testing.T) {
		// Rendering is what produces the file. The Range header is parsed by
		// http.ServeFile on the caller's request, which is the product path
		// once a renderer is configured. A viewer is enough; the route only
		// requires a signed-in user.
		rendered := filepath.Join(t.TempDir(), "render.bin")
		require.NoError(t, os.WriteFile(rendered, payload, 0o644))

		cfg := setting.NewCfg()
		hs := &HTTPServer{
			Cfg:           cfg,
			log:           log.NewNopLogger(),
			RenderService: fileRenderService{path: rendered},
		}
		viewer := &authn.Identity{
			ID:       "1",
			Type:     claims.TypeUser,
			OrgID:    1,
			OrgRoles: map[int64]org.RoleType{1: org.RoleViewer},
		}
		ctxHdlr := contexthandler.ProvideService(cfg, &authntest.FakeService{
			ExpectedIdentity: viewer,
		}, featuremgmt.WithFeatures())

		for _, tc := range rangeCases() {
			t.Run(tc.name, func(t *testing.T) {
				m := web.New()
				m.Use(ctxHdlr.Middleware)
				m.Get("/render/*", middleware.ReqSignedIn, func(c *contextmodel.ReqContext) {
					require.True(t, c.IsSignedIn)
					require.False(t, c.IsGrafanaAdmin)
					require.Equal(t, org.RoleViewer, c.GetOrgRole())
					hs.RenderHandler(c)
				})

				rec := get(t, m, "/render/d-solo/abc/panel", tc.ranges)
				tc.check(t, rec, payload)
			})
		}
	})
}

type rangeCase struct {
	name   string
	ranges int
	check  func(t *testing.T, rec *httptest.ResponseRecorder, payload []byte)
}

func rangeCases() []rangeCase {
	return []rangeCase{
		{
			name:   "no range",
			ranges: 0,
			check: func(t *testing.T, rec *httptest.ResponseRecorder, payload []byte) {
				t.Helper()
				require.Equal(t, http.StatusOK, rec.Code)
				require.Equal(t, payload, rec.Body.Bytes())
			},
		},
		{
			name:   "single range",
			ranges: 1,
			check: func(t *testing.T, rec *httptest.ResponseRecorder, payload []byte) {
				t.Helper()
				require.Equal(t, http.StatusPartialContent, rec.Code)
				require.Equal(t, payload[:1], rec.Body.Bytes())
				require.NotContains(t, rec.Header().Get("Content-Type"), "multipart/byteranges")
			},
		},
		{
			name:   "at the limit",
			ranges: stdlibMaxContentRanges,
			check:  requireMultipart,
		},
		{
			name:   "one past the limit",
			ranges: stdlibMaxContentRanges + 1,
			check:  requireRangeIgnored,
		},
		{
			// Still far under the server's default 1MiB header limit, so a
			// client can actually send this. The whole header must be ignored
			// rather than turned into one part per range.
			name:   "thousands of ranges",
			ranges: thousandsOfRanges,
			check:  requireRangeIgnored,
		},
	}
}

func requireMultipart(t *testing.T, rec *httptest.ResponseRecorder, payload []byte) {
	t.Helper()
	require.Equal(t, http.StatusPartialContent, rec.Code)
	require.Contains(t, rec.Header().Get("Content-Type"), "multipart/byteranges")
	require.Greater(t, rec.Body.Len(), len(payload))
}

func requireRangeIgnored(t *testing.T, rec *httptest.ResponseRecorder, payload []byte) {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Header().Get("Content-Type"), "multipart/byteranges")
	require.Equal(t, len(payload), rec.Body.Len())
	require.True(t, bytes.Equal(payload, rec.Body.Bytes()))
}

// get issues one request. ranges is the number of "0-0" specs in the Range
// header; zero means the header is omitted. The client does not send
// Accept-Encoding or any credential.
func get(t *testing.T, handler http.Handler, path string, ranges int) *httptest.ResponseRecorder {
	t.Helper()

	var header string
	if ranges > 0 {
		header = repeatedRange(ranges)
		require.Less(t, len(header), http.DefaultMaxHeaderBytes)
	}

	req := httptest.NewRequest(http.MethodGet, path, nil)
	if header != "" {
		req.Header.Set("Range", header)
	}
	require.Empty(t, req.Header.Get("Authorization"))
	require.Empty(t, req.Header.Values("Cookie"))
	require.Empty(t, req.Header.Get("Accept-Encoding"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func repeatedRange(n int) string {
	var b strings.Builder
	b.Grow(len("bytes=") + n*4)
	b.WriteString("bytes=")
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("0-0")
	}
	return b.String()
}

// fileRenderService stands in for the image renderer. It only supplies the
// file RenderHandler already passes to http.ServeFile; it does not parse Range.
type fileRenderService struct {
	path string
}

func (s fileRenderService) IsAvailable(context.Context) bool { return true }
func (s fileRenderService) Version() string                  { return "test" }
func (s fileRenderService) Render(context.Context, rendering.RenderType, rendering.Opts) (*rendering.RenderResult, error) {
	return &rendering.RenderResult{FilePath: s.path}, nil
}
func (s fileRenderService) RenderCSV(context.Context, rendering.CSVOpts) (*rendering.RenderCSVResult, error) {
	return nil, errors.New("not used")
}
func (s fileRenderService) RenderErrorImage(models.Theme, error) (*rendering.RenderResult, error) {
	return nil, errors.New("not used")
}
func (s fileRenderService) GetRenderUser(context.Context, string) (*rendering.RenderUser, bool) {
	return nil, false
}
func (s fileRenderService) HasCapability(context.Context, rendering.CapabilityName) (rendering.CapabilitySupportRequestResult, error) {
	return rendering.CapabilitySupportRequestResult{}, nil
}
func (s fileRenderService) IsCapabilitySupported(context.Context, rendering.CapabilityName) error {
	return nil
}
