package filestore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/registry"
)

func TestServiceFileFollowsSymlinkOutsidePlugin(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	pluginDir := filepath.Join(root, "plugin")
	require.NoError(t, os.Mkdir(pluginDir, 0o750))
	sentinel := []byte("outside-plugin-sentinel")
	outside := filepath.Join(root, "private.dat")
	require.NoError(t, os.WriteFile(outside, sentinel, 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(pluginDir, "module.js")))

	reg := registry.NewInMemory()
	require.NoError(t, reg.Add(ctx, &plugins.Plugin{
		JSONData: plugins.JSONData{ID: "symlink-plugin", Info: plugins.Info{Version: "1.0.0"}},
		FS:       plugins.NewLocalFS(pluginDir),
	}))
	got, err := ProvideService(reg).File(ctx, "symlink-plugin", "1.0.0", "module.js")
	after, readErr := os.ReadFile(outside)
	require.NoError(t, readErr)
	require.Equal(t, sentinel, after)
	if err != nil {
		if strings.Contains(err.Error(), "outside-plugin-sentinel") {
			t.Fatalf("error returned bytes from outside the plugin directory: %v", err)
		}
		return
	}
	if bytes.Contains(got.Content, sentinel) {
		t.Fatalf("read returned bytes from outside the plugin directory")
	}
}

func TestServiceFileFollowsSymlinkReplacingAllowlistedFile(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	pluginDir := filepath.Join(root, "plugin")
	require.NoError(t, os.Mkdir(pluginDir, 0o750))
	sentinel := []byte("outside-plugin-sentinel")
	outside := filepath.Join(root, "private.dat")
	require.NoError(t, os.WriteFile(outside, sentinel, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "module.js"), []byte("inside-plugin-bytes"), 0o640))

	fs, err := plugins.NewStaticFS(plugins.NewLocalFS(pluginDir))
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(pluginDir, "module.js")))
	require.NoError(t, os.Symlink(outside, filepath.Join(pluginDir, "module.js")))

	reg := registry.NewInMemory()
	require.NoError(t, reg.Add(ctx, &plugins.Plugin{
		JSONData: plugins.JSONData{ID: "symlink-plugin", Info: plugins.Info{Version: "1.0.0"}},
		FS:       fs,
	}))
	got, err := ProvideService(reg).File(ctx, "symlink-plugin", "1.0.0", "module.js")
	after, readErr := os.ReadFile(outside)
	require.NoError(t, readErr)
	require.Equal(t, sentinel, after)
	if err != nil {
		if strings.Contains(err.Error(), "outside-plugin-sentinel") {
			t.Fatalf("error returned bytes from outside the plugin directory: %v", err)
		}
		return
	}
	if bytes.Contains(got.Content, sentinel) {
		t.Fatalf("read returned bytes from outside the plugin directory")
	}
}
