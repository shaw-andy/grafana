package plugins

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	outsidePluginSentinel = "outside-plugin-sentinel"
	insidePluginBytes     = "inside-plugin-bytes"
)

// pluginEscapeLayout is a plugin directory and a file that lives outside it.
// The outside file stands in for server state the plugin directory's writer
// must not be able to read back through the plugin file API.
type pluginEscapeLayout struct {
	root       string
	pluginDir  string
	outside    string
	sentinel   []byte
	inside     []byte
	outsidePre []byte
}

func newPluginEscapeLayout(t *testing.T) pluginEscapeLayout {
	t.Helper()
	root := t.TempDir()
	pluginDir := filepath.Join(root, "plugin")
	require.NoError(t, os.Mkdir(pluginDir, 0o750))
	sentinel := []byte(outsidePluginSentinel)
	outside := filepath.Join(root, "private.dat")
	require.NoError(t, os.WriteFile(outside, sentinel, 0o600))
	inside := []byte(insidePluginBytes)
	return pluginEscapeLayout{
		root:       root,
		pluginDir:  pluginDir,
		outside:    outside,
		sentinel:   sentinel,
		inside:     inside,
		outsidePre: append([]byte(nil), sentinel...),
	}
}

func (l pluginEscapeLayout) writeInside(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(l.pluginDir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, l.inside, 0o640))
	return path
}

func (l pluginEscapeLayout) symlinkOutside(t *testing.T, name string, target string) string {
	t.Helper()
	path := filepath.Join(l.pluginDir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.Symlink(target, path))
	return path
}

func (l pluginEscapeLayout) outsideUnchanged(t *testing.T) {
	t.Helper()
	got, err := os.ReadFile(l.outside)
	require.NoError(t, err)
	require.Equal(t, l.outsidePre, got)
}

func (l pluginEscapeLayout) requireNotDisclosed(t *testing.T, data []byte, err error) {
	t.Helper()
	l.outsideUnchanged(t)
	if err != nil {
		if strings.Contains(err.Error(), outsidePluginSentinel) {
			t.Fatalf("error returned bytes from outside the plugin directory: %v", err)
		}
		return
	}
	if bytes.Contains(data, l.sentinel) {
		t.Fatalf("read returned bytes from outside the plugin directory")
	}
}

func readPluginFile(fs FS, name string) ([]byte, error) {
	f, err := fs.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func TestLocalFSOpenFollowsSymlinkOutsidePlugin(t *testing.T) {
	for _, name := range []string{"module.js", "plugin.json"} {
		t.Run(name, func(t *testing.T) {
			layout := newPluginEscapeLayout(t)
			layout.symlinkOutside(t, name, layout.outside)
			data, err := readPluginFile(NewLocalFS(layout.pluginDir), name)
			layout.requireNotDisclosed(t, data, err)
		})
	}
}

func TestLocalFSOpenFollowsRelativeSymlinkOutsidePlugin(t *testing.T) {
	layout := newPluginEscapeLayout(t)
	rel, err := filepath.Rel(layout.pluginDir, layout.outside)
	require.NoError(t, err)
	layout.symlinkOutside(t, "module.js", rel)
	data, readErr := readPluginFile(NewLocalFS(layout.pluginDir), "module.js")
	layout.requireNotDisclosed(t, data, readErr)
}

func TestLocalFSOpenFollowsSymlinkChainOutsidePlugin(t *testing.T) {
	layout := newPluginEscapeLayout(t)
	layout.symlinkOutside(t, "hop", layout.outside)
	layout.symlinkOutside(t, "module.js", "hop")
	data, err := readPluginFile(NewLocalFS(layout.pluginDir), "module.js")
	layout.requireNotDisclosed(t, data, err)
}

func TestLocalFSOpenFollowsDirectorySymlinkOutsidePlugin(t *testing.T) {
	layout := newPluginEscapeLayout(t)
	outsideDir := filepath.Join(layout.root, "outside")
	require.NoError(t, os.Mkdir(outsideDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(outsideDir, "note.txt"), layout.sentinel, 0o600))
	layout.symlinkOutside(t, "assets", outsideDir)
	data, err := readPluginFile(NewLocalFS(layout.pluginDir), filepath.Join("assets", "note.txt"))
	layout.requireNotDisclosed(t, data, err)
}

func TestLocalFSOpenAllowsSymlinkInsidePlugin(t *testing.T) {
	layout := newPluginEscapeLayout(t)
	layout.writeInside(t, "real.txt")
	layout.symlinkOutside(t, "module.js", "real.txt")
	data, err := readPluginFile(NewLocalFS(layout.pluginDir), "module.js")
	require.NoError(t, err)
	require.Equal(t, layout.inside, data)
	layout.outsideUnchanged(t)
}

func TestLocalFSReadFollowsSymlinkSwappedAfterOpen(t *testing.T) {
	layout := newPluginEscapeLayout(t)
	layout.writeInside(t, "module.js")
	fs := NewLocalFS(layout.pluginDir)
	f, err := fs.Open("module.js")
	require.NoError(t, err)
	defer f.Close()

	// The confinement decision has already returned. Replacing the allowlisted
	// name before the bytes are read is the window between that decision and
	// the open that supplies the response body.
	require.NoError(t, os.Remove(filepath.Join(layout.pluginDir, "module.js")))
	layout.symlinkOutside(t, "module.js", layout.outside)

	data, err := io.ReadAll(f)
	layout.requireNotDisclosed(t, data, err)
	if err == nil {
		require.Equal(t, layout.inside, data)
	}
}

func TestStaticFSOpenFollowsSymlinkReplacingAllowlistedFile(t *testing.T) {
	for _, name := range []string{"module.js", "plugin.json"} {
		t.Run(name, func(t *testing.T) {
			layout := newPluginEscapeLayout(t)
			layout.writeInside(t, "module.js")
			layout.writeInside(t, "plugin.json")
			fs, err := NewStaticFS(NewLocalFS(layout.pluginDir))
			require.NoError(t, err)
			require.NoError(t, os.Remove(filepath.Join(layout.pluginDir, name)))
			layout.symlinkOutside(t, name, layout.outside)
			data, err := readPluginFile(fs, name)
			layout.requireNotDisclosed(t, data, err)
		})
	}
}

func TestStaticFSReadFollowsSymlinkSwappedAfterOpen(t *testing.T) {
	layout := newPluginEscapeLayout(t)
	layout.writeInside(t, "module.js")
	fs, err := NewStaticFS(NewLocalFS(layout.pluginDir))
	require.NoError(t, err)
	f, err := fs.Open("module.js")
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, os.Remove(filepath.Join(layout.pluginDir, "module.js")))
	layout.symlinkOutside(t, "module.js", layout.outside)
	data, err := io.ReadAll(f)
	layout.requireNotDisclosed(t, data, err)
	if err == nil {
		require.Equal(t, layout.inside, data)
	}
}

func TestStaticFSOpenRejectsFileAddedAfterAllowlist(t *testing.T) {
	layout := newPluginEscapeLayout(t)
	layout.writeInside(t, "module.js")
	fs, err := NewStaticFS(NewLocalFS(layout.pluginDir))
	require.NoError(t, err)
	layout.symlinkOutside(t, "extra.js", layout.outside)
	data, err := readPluginFile(fs, "extra.js")
	layout.requireNotDisclosed(t, data, err)
}

func TestStaticFSBuildDoesNotServeEscapingSymlink(t *testing.T) {
	layout := newPluginEscapeLayout(t)
	layout.writeInside(t, "plugin.json")
	layout.symlinkOutside(t, "module.js", layout.outside)
	fs, err := NewStaticFS(NewLocalFS(layout.pluginDir))
	if err != nil {
		layout.outsideUnchanged(t)
		require.NotContains(t, err.Error(), outsidePluginSentinel)
		return
	}
	data, err := readPluginFile(fs, "module.js")
	layout.requireNotDisclosed(t, data, err)
}

func TestPluginFileFollowsSymlinkOutsidePlugin(t *testing.T) {
	layout := newPluginEscapeLayout(t)
	layout.symlinkOutside(t, "module.js", layout.outside)
	p := &Plugin{FS: NewLocalFS(layout.pluginDir)}
	f, err := p.File("module.js")
	if err != nil {
		layout.requireNotDisclosed(t, nil, err)
		return
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		layout.requireNotDisclosed(t, data, err)
		return
	}
	if _, statErr := f.Stat(); statErr != nil {
		layout.requireNotDisclosed(t, nil, statErr)
		return
	}
	layout.requireNotDisclosed(t, data, nil)
	require.False(t, bytes.Contains(data, layout.sentinel))
}
