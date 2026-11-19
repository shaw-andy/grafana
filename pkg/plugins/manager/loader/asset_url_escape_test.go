package loader

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/config"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/bootstrap"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/discovery"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/initialization"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/termination"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/validation"
	"github.com/grafana/grafana/pkg/plugins/manager/sources"
	"github.com/grafana/grafana/pkg/plugins/pluginerrs"
)

// TestLoadedPluginLogoAndScreenshotURLsDoNotEscapePluginDir loads plugin.json through the
// same discovery, bootstrap, and signature-validation pipeline Grafana uses for external
// plugins. Logo and screenshot paths are then resolved the way a browser resolves an
// image URL against the document base (conf/defaults.ini root_url, base href "/").
//
// HTTP(S) URL parsers treat "\" as "/". net/url does not, so the resolver converts
// backslashes before resolving. A path that still reaches /logout or /profile/switch-org/
// is the request the browser issues for that image, with the session cookie attached.
func TestLoadedPluginLogoAndScreenshotURLsDoNotEscapePluginDir(t *testing.T) {
	root := t.TempDir()
	writePlugin(t, root, "escape-datasource", `{
		"type": "datasource",
		"name": "Escape",
		"id": "escape-datasource",
		"info": {
			"version": "1.0.0",
			"logos": {
				"small": "img/../../../../logout",
				"large": "..\\..\\..\\..\\logout"
			},
			"screenshots": [
				{"name": "switch", "path": "../../../../profile/switch-org/2"},
				{"name": "nested", "path": "img/../../../../profile/switch-org/2"},
				{"name": "ok", "path": "img/shot.png"}
			]
		}
	}`)
	writePlugin(t, root, "safe-datasource", `{
		"type": "datasource",
		"name": "Safe",
		"id": "safe-datasource",
		"info": {
			"version": "1.0.0",
			"logos": {"small": "img/logo.svg", "large": "img/logo.svg"},
			"screenshots": [{"name": "ok", "path": "img/shot.png"}]
		}
	}`)

	t.Run("unsigned plugin is not loaded unless its id is allowlisted", func(t *testing.T) {
		loaded := loadExternalPlugins(t, nil, []string{root})
		require.Empty(t, loaded)
	})

	t.Run("allowlisted plugin asset URLs stay inside the plugin or use the default icon", func(t *testing.T) {
		loaded := loadExternalPlugins(t, []string{"escape-datasource", "safe-datasource"}, []string{root})
		byID := map[string]*plugins.Plugin{}
		for _, p := range loaded {
			byID[p.ID] = p
		}

		escapePlugin := byID["escape-datasource"]
		require.NotNil(t, escapePlugin, "allowlisted plugin must still load; only the asset URL is unsafe")
		assertSafeLogo(t, escapePlugin.ID, string(escapePlugin.Type), escapePlugin.Info.Logos.Small)
		assertSafeLogo(t, escapePlugin.ID, string(escapePlugin.Type), escapePlugin.Info.Logos.Large)
		require.NotEmpty(t, escapePlugin.Info.Screenshots)
		var keptSafeShot bool
		for _, shot := range escapePlugin.Info.Screenshots {
			assertSafeScreenshot(t, escapePlugin.ID, shot.Path)
			if shot.Name == "ok" && requestPath(t, shot.Path) == "/public/plugins/escape-datasource/img/shot.png" {
				keptSafeShot = true
			}
		}
		require.True(t, keptSafeShot, "a screenshot path inside the plugin directory must be preserved")

		safePlugin := byID["safe-datasource"]
		require.NotNil(t, safePlugin)
		require.Equal(t, "/public/plugins/safe-datasource/img/logo.svg", requestPath(t, safePlugin.Info.Logos.Small))
		require.Equal(t, "/public/plugins/safe-datasource/img/logo.svg", requestPath(t, safePlugin.Info.Logos.Large))
		require.Len(t, safePlugin.Info.Screenshots, 1)
		require.Equal(t, "/public/plugins/safe-datasource/img/shot.png", requestPath(t, safePlugin.Info.Screenshots[0].Path))
	})
}

func loadExternalPlugins(t *testing.T, allowUnsigned []string, paths []string) []*plugins.Plugin {
	t.Helper()
	cfg := &config.PluginManagementCfg{PluginsAllowUnsigned: allowUnsigned}
	terminationStage, err := termination.New(cfg, termination.Opts{})
	require.NoError(t, err)
	l := New(cfg,
		discovery.New(cfg, discovery.Opts{}),
		bootstrap.New(cfg, bootstrap.Opts{}),
		validation.New(cfg, validation.Opts{}),
		initialization.New(cfg, initialization.Opts{}),
		terminationStage,
		pluginerrs.ProvideErrorTracker(),
	)
	got, err := l.Load(context.Background(), sources.NewLocalSource(plugins.ClassExternal, paths))
	require.NoError(t, err)
	return got
}

func writePlugin(t *testing.T, root, id, pluginJSON string) {
	t.Helper()
	dir := filepath.Join(root, id)
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "plugin.json"), []byte(pluginJSON), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "module.js"), []byte("export default {}"), 0o600))
}

// requestPath is the path a browser requests for asset when the document base is the
// Grafana root. Empty assets are ignored and produce no request.
func requestPath(t *testing.T, asset string) string {
	t.Helper()
	if asset == "" {
		return ""
	}
	base, err := url.Parse("http://localhost:3000/")
	require.NoError(t, err)
	ref, err := url.Parse(strings.ReplaceAll(asset, `\`, `/`))
	require.NoError(t, err)
	return base.ResolveReference(ref).EscapedPath()
}

func assertSafeLogo(t *testing.T, pluginID, pluginType, logo string) {
	t.Helper()
	got := requestPath(t, logo)
	require.Falsef(t, isStateChangingRoute(got), "logo %q is requested as %s", logo, got)
	def := "/public/img/icn-" + pluginType + ".svg"
	prefix := "/public/plugins/" + pluginID + "/"
	require.Truef(t, got == def || strings.HasPrefix(got, prefix),
		"logo %q is requested as %s, outside the plugin directory and not the default icon", logo, got)
}

func assertSafeScreenshot(t *testing.T, pluginID, shotPath string) {
	t.Helper()
	got := requestPath(t, shotPath)
	if got == "" {
		return
	}
	require.Falsef(t, isStateChangingRoute(got), "screenshot %q is requested as %s", shotPath, got)
	prefix := "/public/plugins/" + pluginID + "/"
	require.Truef(t, strings.HasPrefix(got, prefix),
		"screenshot %q is requested as %s, outside the plugin directory", shotPath, got)
}

func isStateChangingRoute(requestPath string) bool {
	return requestPath == "/logout" || strings.HasPrefix(requestPath, "/profile/switch-org/")
}
