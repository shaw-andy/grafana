package api

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/config"
	"github.com/grafana/grafana/pkg/plugins/manager/filestore"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/plugins/pluginscdn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

func TestGetPluginAssetsSymlinkEscapeUnauthenticated(t *testing.T) {
	t.Run("dev mode symlink already present", func(t *testing.T) {
		layout := newAssetLayout(t)
		require.NoError(t, os.Symlink(layout.outside, filepath.Join(layout.pluginDir, "module.js")))
		require.NoError(t, os.Mkdir(filepath.Join(layout.root, "outside"), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(layout.root, "outside", "note.txt"), layout.sentinel, 0o600))
		require.NoError(t, os.Symlink(filepath.Join(layout.root, "outside"), filepath.Join(layout.pluginDir, "assets")))
		fs := plugins.NewLocalFS(layout.pluginDir)
		assertUnauthedAssetHidden(t, layout, "symlink-plugin", fs, "module.js")
		assertUnauthedAssetHidden(t, layout, "symlink-plugin", fs, "assets/note.txt")
	})

	t.Run("production allowlisted file replaced with symlink", func(t *testing.T) {
		layout := newAssetLayout(t)
		require.NoError(t, os.WriteFile(filepath.Join(layout.pluginDir, "module.js"), layout.inside, 0o640))
		fs, err := plugins.NewStaticFS(plugins.NewLocalFS(layout.pluginDir))
		require.NoError(t, err)
		require.NoError(t, os.Remove(filepath.Join(layout.pluginDir, "module.js")))
		require.NoError(t, os.Symlink(layout.outside, filepath.Join(layout.pluginDir, "module.js")))
		assertUnauthedAssetHidden(t, layout, "symlink-plugin", fs, "module.js")
	})
}

func TestGetPluginMarkdownSymlinkEscapeUnauthenticated(t *testing.T) {
	t.Run("dev mode", func(t *testing.T) {
		layout := newAssetLayout(t)
		require.NoError(t, os.WriteFile(filepath.Join(layout.pluginDir, "OK.md"), layout.inside, 0o640))
		require.NoError(t, os.Symlink(layout.outside, filepath.Join(layout.pluginDir, "NOTES.md")))
		assertUnauthedMarkdownHidden(t, layout, plugins.NewLocalFS(layout.pluginDir))
	})

	t.Run("production allowlisted file replaced with symlink", func(t *testing.T) {
		layout := newAssetLayout(t)
		require.NoError(t, os.WriteFile(filepath.Join(layout.pluginDir, "OK.md"), layout.inside, 0o640))
		require.NoError(t, os.WriteFile(filepath.Join(layout.pluginDir, "NOTES.md"), layout.inside, 0o640))
		fs, err := plugins.NewStaticFS(plugins.NewLocalFS(layout.pluginDir))
		require.NoError(t, err)
		require.NoError(t, os.Remove(filepath.Join(layout.pluginDir, "NOTES.md")))
		require.NoError(t, os.Symlink(layout.outside, filepath.Join(layout.pluginDir, "NOTES.md")))
		assertUnauthedMarkdownHidden(t, layout, fs)
	})
}

type assetLayout struct {
	root      string
	pluginDir string
	outside   string
	sentinel  []byte
	inside    []byte
}

func newAssetLayout(t *testing.T) assetLayout {
	t.Helper()
	root := t.TempDir()
	pluginDir := filepath.Join(root, "plugin")
	require.NoError(t, os.Mkdir(pluginDir, 0o750))
	sentinel := []byte("outside-plugin-sentinel")
	outside := filepath.Join(root, "private.dat")
	require.NoError(t, os.WriteFile(outside, sentinel, 0o600))
	inside := []byte("inside-plugin-bytes")
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "ok.txt"), inside, 0o640))
	return assetLayout{root: root, pluginDir: pluginDir, outside: outside, sentinel: sentinel, inside: inside}
}

func assertUnauthedAssetHidden(t *testing.T, layout assetLayout, pluginID string, fs plugins.FS, attacked string) {
	t.Helper()
	sc := servePlugin(t, pluginID, fs)
	sc.url = "/public/plugins/" + pluginID + "/ok.txt"
	callGetPluginAsset(sc)
	require.Empty(t, sc.req.Header.Get("Cookie"))
	require.Empty(t, sc.req.Header.Get("Authorization"))
	require.NotNil(t, sc.context)
	require.False(t, sc.context.IsSignedIn)
	require.Error(t, sc.context.LookupTokenErr)
	require.Equal(t, http.StatusOK, sc.resp.Code)
	require.Equal(t, string(layout.inside), sc.resp.Body.String())

	sc.url = "/public/plugins/" + pluginID + "/" + attacked
	callGetPluginAsset(sc)
	requireOutsideHidden(t, layout, sc.resp.Code, sc.resp.Body.Bytes())
}

func assertUnauthedMarkdownHidden(t *testing.T, layout assetLayout, fs plugins.FS) {
	t.Helper()
	const pluginID = "symlink-plugin"
	sc := servePlugin(t, pluginID, fs)
	sc.m.Get("/api/plugins/:pluginId/markdown/:name", func(c *contextmodel.ReqContext) {
		sc.context = c
		routing.Wrap(sc.hs.GetPluginMarkdown)(c)
	})

	sc.url = "/api/plugins/" + pluginID + "/markdown/ok"
	sc.fakeReqWithParams("GET", sc.url, map[string]string{}).exec()
	require.Empty(t, sc.req.Header.Get("Cookie"))
	require.NotNil(t, sc.context)
	require.False(t, sc.context.IsSignedIn)
	require.Error(t, sc.context.LookupTokenErr)
	require.Equal(t, http.StatusOK, sc.resp.Code)
	require.Equal(t, string(layout.inside), sc.resp.Body.String())

	sc.url = "/api/plugins/" + pluginID + "/markdown/notes"
	sc.fakeReqWithParams("GET", sc.url, map[string]string{}).exec()
	requireOutsideHidden(t, layout, sc.resp.Code, sc.resp.Body.Bytes())
}

func requireOutsideHidden(t *testing.T, layout assetLayout, status int, body []byte) {
	t.Helper()
	after, err := os.ReadFile(layout.outside)
	require.NoError(t, err)
	require.Equal(t, layout.sentinel, after)
	if bytes.Contains(body, layout.sentinel) {
		t.Fatalf("response returned bytes from outside the plugin directory (status %d)", status)
	}
	if status == http.StatusOK {
		require.NotEqual(t, string(layout.sentinel), string(body))
	}
}

type pluginScenario struct {
	*scenarioContext
	hs *HTTPServer
}

func servePlugin(t *testing.T, pluginID string, fs plugins.FS) *pluginScenario {
	t.Helper()
	p := createPlugin(plugins.JSONData{
		ID:   pluginID,
		Type: plugins.TypePanel,
		Info: plugins.Info{Version: "1.0.0"},
	}, plugins.ClassExternal, fs)
	reg := &pluginfakes.FakePluginRegistry{Store: map[string]*plugins.Plugin{p.ID: p}}
	store, err := pluginstore.NewPluginStoreForTest(reg, &pluginfakes.FakeLoader{}, &pluginfakes.FakeSourceRegistry{})
	require.NoError(t, err)
	cfg := setting.NewCfg()
	hs := &HTTPServer{
		Cfg:             cfg,
		pluginStore:     store,
		pluginFileStore: filestore.ProvideService(reg),
		log:             log.NewNopLogger(),
		pluginsCDNService: pluginscdn.ProvideService(&config.PluginManagementCfg{
			PluginsCDNURLTemplate: cfg.PluginsCDNURLTemplate,
			PluginSettings:        cfg.PluginSettings,
		}),
	}

	viewsPath, err := filepath.Abs("../../public/views")
	require.NoError(t, err)
	exists, err := fsExists(viewsPath)
	require.NoError(t, err)
	require.True(t, exists)
	m := web.New()
	m.UseMiddleware(web.Renderer(viewsPath, "[[", "]]"))
	// Authentication failing is the unauthenticated case. The asset route does
	// not use a signed-in middleware, so this error must not block the handler.
	m.Use(contexthandler.ProvideService(cfg, &authntest.FakeService{
		ExpectedErr: errors.New("no credentials"),
	}, featuremgmt.WithFeatures()).Middleware)

	sc := &scenarioContext{t: t, m: m, cfg: cfg}
	ps := &pluginScenario{scenarioContext: sc, hs: hs}
	sc.defaultHandler = func(c *contextmodel.ReqContext) {
		sc.context = c
		hs.getPluginAssets(c)
	}
	sc.m.Get("/public/plugins/:pluginId/*", sc.defaultHandler)
	return ps
}

func fsExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
