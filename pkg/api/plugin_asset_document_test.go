package api

import (
	"context"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/backendplugin"
	pluginsCfg "github.com/grafana/grafana/pkg/plugins/config"
	"github.com/grafana/grafana/pkg/plugins/envvars"
	"github.com/grafana/grafana/pkg/plugins/manager/filestore"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/plugins/manager/process"
	"github.com/grafana/grafana/pkg/plugins/manager/registry"
	"github.com/grafana/grafana/pkg/plugins/manager/sources"
	"github.com/grafana/grafana/pkg/plugins/pluginscdn"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/pluginsintegration"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/coreplugin"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pipeline"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/provisionedplugins"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

const (
	allowedPluginID = "allowed-unsigned-doc-plugin"
	blockedPluginID = "blocked-unsigned-doc-plugin"
)

// TestPluginAssetDocumentsAreNotExecutable loads plugins through the production
// plugin pipeline and requests their files on GET /public/plugins/:pluginId/*,
// the route registered without a login check. HTML and SVG documents from a
// plugin that the loader accepted must not be served as navigable documents
// that can run script, including when that plugin is on the frontend sandbox
// list and the global Content-Security-Policy setting is left off.
func TestPluginAssetDocumentsAreNotExecutable(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	allowedDir := filepath.Join(root, allowedPluginID)
	blockedDir := filepath.Join(root, blockedPluginID)
	writeDocumentPlugin(t, allowedDir, allowedPluginID)
	writeDocumentPlugin(t, blockedDir, blockedPluginID)

	pCfg := &pluginsCfg.PluginManagementCfg{
		DevMode:              false,
		PluginsAllowUnsigned: []string{allowedPluginID},
	}
	reg := registry.ProvideService()
	loader := pluginsintegration.CreateTestLoader(t, pCfg, pluginsintegration.LoaderOpts{
		Initializer: pipeline.ProvideInitializationStage(
			pCfg,
			reg,
			coreplugin.ProvideCoreProvider(coreplugin.NewRegistry(map[string]backendplugin.PluginFactoryFunc{})),
			process.ProvideService(),
			&pluginfakes.FakeAuthService{},
			pluginfakes.NewFakeRoleRegistry(),
			pluginfakes.NewFakeActionSetRegistry(),
			envvars.DefaultProvider(),
			tracing.InitializeTracerForTest(),
			provisionedplugins.NewNoop(),
		),
	})

	loaded, err := loader.Load(context.Background(), sources.NewLocalSource(plugins.ClassExternal, []string{root}))
	require.NoError(t, err)

	loadedIDs := make([]string, 0, len(loaded))
	for _, p := range loaded {
		loadedIDs = append(loadedIDs, p.ID)
	}
	require.ElementsMatch(t, []string{allowedPluginID}, loadedIDs)
	_, blockedRegistered := reg.Plugin(context.Background(), blockedPluginID, "")
	require.False(t, blockedRegistered, "production loader accepted an unsigned plugin that is not allow-listed")

	store, err := pluginstore.NewPluginStoreForTest(reg, &pluginfakes.FakeLoader{}, &pluginfakes.FakeSourceRegistry{})
	require.NoError(t, err)
	t.Cleanup(func() {
		store.StopAsync()
		_ = store.AwaitTerminated(context.Background())
	})

	cfg := setting.NewCfg()
	cfg.Env = setting.Prod
	// Shipped defaults from conf/defaults.ini. Global CSP stays off.
	cfg.ContentTypeProtectionHeader = true
	cfg.XSSProtectionHeader = true
	cfg.AllowEmbedding = false
	cfg.CSPEnabled = false
	cfg.CSPReportOnlyEnabled = false
	cfg.EnableFrontendSandboxForPlugins = []string{allowedPluginID}
	cfg.LoginCookieName = "grafana_session"

	hs := &HTTPServer{
		Cfg:             cfg,
		pluginStore:     store,
		pluginFileStore: filestore.ProvideService(reg),
		log:             log.NewNopLogger(),
		pluginsCDNService: pluginscdn.ProvideService(&pluginsCfg.PluginManagementCfg{
			PluginsCDNURLTemplate: cfg.PluginsCDNURLTemplate,
			PluginSettings:        cfg.PluginSettings,
		}),
	}

	m := web.New()
	m.Use(middleware.AddDefaultResponseHeaders(cfg))
	m.UseMiddleware(getContextHandler(t, cfg).Middleware)
	// Same registration as pkg/api/api.go: no reqSignedIn and no authorize().
	m.Get("/public/plugins/:pluginId/*", func(c *contextmodel.ReqContext) {
		hs.getPluginAssets(c)
	})

	sessionCookie := &http.Cookie{Name: cfg.LoginCookieName, Value: "placeholder-session"}

	cases := []struct {
		name       string
		method     string
		pluginID   string
		asset      string
		cookie     *http.Cookie
		rangeHdr   string
		marker     string
		mustBeSafe bool
		mustServe  bool
	}{
		{name: "html", method: http.MethodGet, pluginID: allowedPluginID, asset: "page.html", marker: "PLUGIN_HTML_MARKER", mustBeSafe: true},
		{name: "html with session cookie", method: http.MethodGet, pluginID: allowedPluginID, asset: "page.html", cookie: sessionCookie, marker: "PLUGIN_HTML_MARKER", mustBeSafe: true},
		{name: "html query", method: http.MethodGet, pluginID: allowedPluginID, asset: "page.html?x=1", marker: "PLUGIN_HTML_MARKER", mustBeSafe: true},
		{name: "html head", method: http.MethodHead, pluginID: allowedPluginID, asset: "page.html", mustBeSafe: true},
		{name: "html range", method: http.MethodGet, pluginID: allowedPluginID, asset: "page.html", rangeHdr: "bytes=0-20", marker: "PLUGIN_HTML_MARKER", mustBeSafe: true},
		{name: "htm", method: http.MethodGet, pluginID: allowedPluginID, asset: "page.htm", marker: "PLUGIN_HTM_MARKER", mustBeSafe: true},
		{name: "shtml", method: http.MethodGet, pluginID: allowedPluginID, asset: "page.shtml", marker: "PLUGIN_SHTML_MARKER", mustBeSafe: true},
		{name: "ehtml", method: http.MethodGet, pluginID: allowedPluginID, asset: "page.ehtml", marker: "PLUGIN_EHTML_MARKER", mustBeSafe: true},
		{name: "html uppercase", method: http.MethodGet, pluginID: allowedPluginID, asset: "PAGE.HTML", marker: "PLUGIN_HTML_UPPER_MARKER", mustBeSafe: true},
		{name: "nested html", method: http.MethodGet, pluginID: allowedPluginID, asset: "nested/dir/page.html", marker: "PLUGIN_NESTED_HTML_MARKER", mustBeSafe: true},
		{name: "xhtml", method: http.MethodGet, pluginID: allowedPluginID, asset: "page.xhtml", marker: "PLUGIN_XHTML_MARKER", mustBeSafe: true},
		{name: "xht", method: http.MethodGet, pluginID: allowedPluginID, asset: "page.xht", marker: "PLUGIN_XHT_MARKER", mustBeSafe: true},
		{name: "svg", method: http.MethodGet, pluginID: allowedPluginID, asset: "nested/icon.svg", marker: "PLUGIN_SVG_MARKER", mustBeSafe: true},
		{name: "svg head", method: http.MethodHead, pluginID: allowedPluginID, asset: "nested/icon.svg", mustBeSafe: true},
		{name: "module.js", method: http.MethodGet, pluginID: allowedPluginID, asset: "module.js", marker: "PLUGIN_MODULE_MARKER", mustServe: true},
		{name: "unsigned plugin not allow-listed", method: http.MethodGet, pluginID: blockedPluginID, asset: "page.html", marker: "PLUGIN_HTML_MARKER", mustBeSafe: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := requestPluginAsset(t, m, tc.method, tc.pluginID, tc.asset, tc.cookie, tc.rangeHdr)
			if tc.mustServe {
				require.Equal(t, http.StatusOK, rec.Code)
				require.Contains(t, rec.Body.String(), tc.marker)
				require.Contains(t, []string{"text/javascript", "application/javascript"}, mediaType(rec.Header().Get("Content-Type")))
				require.False(t, contentDispositionIsAttachment(rec.Header().Get("Content-Disposition")))
				return
			}

			require.Falsef(t, isExecutableNavigableDocument(rec.Header()),
				"served a navigable executable document: status=%d content-type=%q csp=%q report-only=%q disposition=%q x-content-type-options=%q x-frame-options=%q x-xss-protection=%q body=%q",
				rec.Code,
				rec.Header().Get("Content-Type"),
				rec.Header().Get("Content-Security-Policy"),
				rec.Header().Get("Content-Security-Policy-Report-Only"),
				rec.Header().Get("Content-Disposition"),
				rec.Header().Get("X-Content-Type-Options"),
				rec.Header().Get("X-Frame-Options"),
				rec.Header().Get("X-XSS-Protection"),
				bodySample(rec.Body.String()),
			)
		})
	}
}

func requestPluginAsset(t *testing.T, m *web.Macaron, method, pluginID, asset string, cookie *http.Cookie, rangeHdr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/public/plugins/"+pluginID+"/"+asset, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if rangeHdr != "" {
		req.Header.Set("Range", rangeHdr)
	}
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)
	return rec
}

func writeDocumentPlugin(t *testing.T, dir, id string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "nested", "dir"), 0o750))
	files := map[string]string{
		"plugin.json": `{
  "type": "panel",
  "name": "Document plugin",
  "id": "` + id + `",
  "info": {"version": "1.0.0"}
}
`,
		"module.js":            "export const plugin = {};\n// PLUGIN_MODULE_MARKER\n",
		"page.html":            htmlDocument("PLUGIN_HTML_MARKER"),
		"page.htm":             htmlDocument("PLUGIN_HTM_MARKER"),
		"page.shtml":           htmlDocument("PLUGIN_SHTML_MARKER"),
		"page.ehtml":           htmlDocument("PLUGIN_EHTML_MARKER"),
		"PAGE.HTML":            htmlDocument("PLUGIN_HTML_UPPER_MARKER"),
		"nested/dir/page.html": htmlDocument("PLUGIN_NESTED_HTML_MARKER"),
		"page.xhtml":           xhtmlDocument("PLUGIN_XHTML_MARKER"),
		"page.xht":             xhtmlDocument("PLUGIN_XHT_MARKER"),
		"nested/icon.svg":      svgDocument("PLUGIN_SVG_MARKER"),
	}
	for name, body := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
}

func htmlDocument(marker string) string {
	return "<!DOCTYPE html><html><body><script>window.__pluginDocument='" + marker + "';</script>" + marker + "</body></html>\n"
}

func xhtmlDocument(marker string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<html xmlns="http://www.w3.org/1999/xhtml"><body><script type="text/javascript">window.__pluginDocument='` +
		marker + `';</script>` + marker + `</body></html>`
}

func svgDocument(marker string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16">` +
		`<script type="text/javascript"><![CDATA[window.__pluginDocument='` + marker + `';]]></script>` +
		`<text>` + marker + `</text></svg>`
}

// executableDocumentTypes are the media types Go's mime table assigns to the
// extensions this route serves, and that a browser can navigate to as a document.
var executableDocumentTypes = map[string]struct{}{
	"text/html":             {},
	"application/xhtml+xml": {},
	"image/svg+xml":         {},
}

func isExecutableNavigableDocument(h http.Header) bool {
	if _, ok := executableDocumentTypes[mediaType(h.Get("Content-Type"))]; !ok {
		return false
	}
	if contentDispositionIsAttachment(h.Get("Content-Disposition")) {
		return false
	}
	if enforcedCSPBlocksDocumentScripts(h) {
		return false
	}
	return true
}

func mediaType(contentType string) string {
	if contentType == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	}
	return strings.ToLower(mt)
}

func contentDispositionIsAttachment(v string) bool {
	if strings.TrimSpace(v) == "" {
		return false
	}
	disp, _, err := mime.ParseMediaType(v)
	if err != nil {
		disp = strings.TrimSpace(strings.Split(v, ";")[0])
	}
	return strings.EqualFold(disp, "attachment")
}

// enforcedCSPBlocksDocumentScripts reports whether an enforced Content-Security-Policy
// stops a plugin document from running script. script-src 'self' does not count:
// the same plugin tree is served from this origin, so the document can load a
// sibling script. A nonce or hash makes 'unsafe-inline' ineffective. 'strict-dynamic'
// together with a nonce or hash makes host allowlists, including 'self', ineffective
// for script elements that were not loaded by a trusted script.
func enforcedCSPBlocksDocumentScripts(h http.Header) bool {
	for _, policy := range h.Values("Content-Security-Policy") {
		if cspPolicyBlocksDocumentScripts(policy) {
			return true
		}
	}
	return false
}

func cspPolicyBlocksDocumentScripts(policy string) bool {
	dirs := parseCSPDirectives(policy)
	if sandbox, ok := dirs["sandbox"]; ok && !cspHasToken(sandbox, "allow-scripts") {
		return true
	}
	sources, ok := dirs["script-src"]
	if !ok {
		sources, ok = dirs["default-src"]
	}
	if !ok {
		return false
	}
	return scriptSourceListBlocksDocumentScripts(sources)
}

func scriptSourceListBlocksDocumentScripts(sources []string) bool {
	if len(sources) == 1 && strings.EqualFold(sources[0], "'none'") {
		return true
	}

	hasNonceOrHash := false
	hasStrictDynamic := false
	allowsInline := false
	allowsExternal := false
	for _, source := range sources {
		token := strings.ToLower(source)
		switch {
		case token == "'none'":
		case token == "'strict-dynamic'":
			hasStrictDynamic = true
		case strings.HasPrefix(token, "'nonce-"),
			strings.HasPrefix(token, "'sha256-"),
			strings.HasPrefix(token, "'sha384-"),
			strings.HasPrefix(token, "'sha512-"):
			hasNonceOrHash = true
		case token == "'unsafe-inline'":
			allowsInline = true
		case token == "'unsafe-eval'", token == "'unsafe-hashes'", token == "'wasm-unsafe-eval'", token == "'report-sample'":
		default:
			allowsExternal = true
		}
	}
	if hasNonceOrHash {
		allowsInline = false
	}
	if hasStrictDynamic && hasNonceOrHash {
		allowsExternal = false
	}
	return !allowsInline && !allowsExternal
}

func parseCSPDirectives(policy string) map[string][]string {
	dirs := map[string][]string{}
	for _, part := range strings.Split(policy, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		dirs[name] = append(dirs[name], fields[1:]...)
	}
	return dirs
}

func cspHasToken(values []string, token string) bool {
	for _, value := range values {
		if strings.EqualFold(value, token) {
			return true
		}
	}
	return false
}

func bodySample(body string) string {
	const limit = 180
	if len(body) <= limit {
		return body
	}
	return body[:limit]
}
