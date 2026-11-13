package sources

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/config"
	"github.com/grafana/grafana/pkg/plugins/log"
)

const sourcePluginJSON = `{"id":"symlink-plugin","name":"Symlink Plugin","type":"panel","info":{"version":"1.0.0"}}`

func TestDirAsLocalSourcesDevModeFollowsSymlinkOutsidePlugin(t *testing.T) {
	layout := newSourceLayout(t)
	require.NoError(t, os.Symlink(layout.outside, filepath.Join(layout.pluginDir, "module.js")))
	data, err := openDiscovered(t, layout, true, "module.js")
	layout.requireNotDisclosed(t, data, err)
}

func TestDirAsLocalSourcesStrictModeReplacedFileFollowsSymlink(t *testing.T) {
	layout := newSourceLayout(t)
	require.NoError(t, os.WriteFile(filepath.Join(layout.pluginDir, "module.js"), []byte("inside-plugin-bytes"), 0o640))
	fs := discover(t, layout, false)
	require.NoError(t, os.Remove(filepath.Join(layout.pluginDir, "module.js")))
	require.NoError(t, os.Symlink(layout.outside, filepath.Join(layout.pluginDir, "module.js")))
	data, err := readDiscovered(fs, "module.js")
	layout.requireNotDisclosed(t, data, err)
}

func TestDirAsLocalSourcesStrictModeDoesNotServeSymlinkPresentAtDiscover(t *testing.T) {
	layout := newSourceLayout(t)
	require.NoError(t, os.Symlink(layout.outside, filepath.Join(layout.pluginDir, "module.js")))
	srcs := sourcesFor(layout, false)
	require.Len(t, srcs, 1)
	bundles, err := srcs[0].Discover(context.Background())
	if err != nil {
		layout.outsideUnchanged(t)
		require.NotContains(t, err.Error(), "outside-plugin-sentinel")
		return
	}
	require.NotEmpty(t, bundles)
	data, err := readDiscovered(bundles[0].Primary.FS, "module.js")
	layout.requireNotDisclosed(t, data, err)
}

func TestUnsafeLocalSourceFollowsDirectorySymlink(t *testing.T) {
	layout := newSourceLayout(t)
	outsideDir := filepath.Join(layout.root, "outside")
	require.NoError(t, os.Mkdir(outsideDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(outsideDir, "note.txt"), layout.sentinel, 0o600))
	require.NoError(t, os.Symlink(outsideDir, filepath.Join(layout.pluginDir, "assets")))
	src := NewUnsafeLocalSource(plugins.ClassExternal, []string{layout.pluginDir})
	bundles, err := src.Discover(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, bundles)
	data, err := readDiscovered(bundles[0].Primary.FS, filepath.Join("assets", "note.txt"))
	layout.requireNotDisclosed(t, data, err)
}

type sourceLayout struct {
	root      string
	plugins   string
	pluginDir string
	outside   string
	sentinel  []byte
}

func newSourceLayout(t *testing.T) sourceLayout {
	t.Helper()
	root := t.TempDir()
	pluginsRoot := filepath.Join(root, "plugins")
	pluginDir := filepath.Join(pluginsRoot, "symlink-plugin")
	require.NoError(t, os.MkdirAll(pluginDir, 0o750))
	sentinel := []byte("outside-plugin-sentinel")
	outside := filepath.Join(root, "private.dat")
	require.NoError(t, os.WriteFile(outside, sentinel, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte(sourcePluginJSON), 0o640))
	return sourceLayout{root: root, plugins: pluginsRoot, pluginDir: pluginDir, outside: outside, sentinel: sentinel}
}

func (l sourceLayout) outsideUnchanged(t *testing.T) {
	t.Helper()
	got, err := os.ReadFile(l.outside)
	require.NoError(t, err)
	require.Equal(t, l.sentinel, got)
}

func (l sourceLayout) requireNotDisclosed(t *testing.T, data []byte, err error) {
	t.Helper()
	l.outsideUnchanged(t)
	if err != nil {
		if strings.Contains(err.Error(), "outside-plugin-sentinel") {
			t.Fatalf("error returned bytes from outside the plugin directory: %v", err)
		}
		return
	}
	if bytes.Contains(data, l.sentinel) {
		t.Fatalf("read returned bytes from outside the plugin directory")
	}
}

func sourcesFor(layout sourceLayout, devMode bool) []*LocalSource {
	return DirAsLocalSources(&config.PluginManagementCfg{DevMode: devMode}, []string{layout.plugins}, plugins.ClassExternal, log.New("test"))
}

func discover(t *testing.T, layout sourceLayout, devMode bool) plugins.FS {
	t.Helper()
	srcs := sourcesFor(layout, devMode)
	require.Len(t, srcs, 1)
	bundles, err := srcs[0].Discover(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, bundles)
	return bundles[0].Primary.FS
}

func openDiscovered(t *testing.T, layout sourceLayout, devMode bool, name string) ([]byte, error) {
	t.Helper()
	return readDiscovered(discover(t, layout, devMode), name)
}

func readDiscovered(fs plugins.FS, name string) ([]byte, error) {
	f, err := fs.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
