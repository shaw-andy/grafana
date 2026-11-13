package dashboards

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/filestore"
	"github.com/grafana/grafana/pkg/plugins/manager/registry"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
)

func TestGetPluginDashboardFileContentsFollowsSymlink(t *testing.T) {
	for _, strict := range []bool{false, true} {
		name := "dev"
		if strict {
			name = "strict-replaced"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			pluginDir := filepath.Join(root, "plugin")
			require.NoError(t, os.MkdirAll(filepath.Join(pluginDir, "dashboards"), 0o750))
			sentinel := []byte("outside-plugin-sentinel")
			outside := filepath.Join(root, "private.dat")
			require.NoError(t, os.WriteFile(outside, sentinel, 0o600))
			inside := []byte("inside-plugin-bytes")
			okPath := filepath.Join(pluginDir, "dashboards", "ok.json")
			overview := filepath.Join(pluginDir, "dashboards", "overview.json")
			require.NoError(t, os.WriteFile(okPath, inside, 0o640))
			if strict {
				require.NoError(t, os.WriteFile(overview, inside, 0o640))
			} else {
				require.NoError(t, os.Symlink(outside, overview))
			}

			var fs plugins.FS = plugins.NewLocalFS(pluginDir)
			if strict {
				staticFS, err := plugins.NewStaticFS(fs)
				require.NoError(t, err)
				fs = staticFS
				require.NoError(t, os.Remove(overview))
				require.NoError(t, os.Symlink(outside, overview))
			}

			p := &plugins.Plugin{
				JSONData: plugins.JSONData{
					ID:   "symlink-plugin",
					Type: plugins.TypePanel,
					Info: plugins.Info{Version: "1.0.0"},
					Includes: []*plugins.Includes{
						{Type: plugins.TypeDashboard, Path: "dashboards/ok.json"},
						{Type: plugins.TypeDashboard, Path: "dashboards/overview.json"},
					},
				},
				FS: fs,
			}
			reg := registry.NewInMemory()
			require.NoError(t, reg.Add(ctx, p))
			mgr := &FileStoreManager{
				pluginStore:     pluginstore.NewFakePluginStore(pluginstore.ToGrafanaDTO(p)),
				pluginFileStore: filestore.ProvideService(reg),
			}

			okFile, err := mgr.GetPluginDashboardFileContents(ctx, &GetPluginDashboardFileContentsArgs{
				PluginID:      "symlink-plugin",
				FileReference: "dashboards/ok.json",
			})
			require.NoError(t, err)
			require.Equal(t, inside, okFile.Content)

			got, err := mgr.GetPluginDashboardFileContents(ctx, &GetPluginDashboardFileContentsArgs{
				PluginID:      "symlink-plugin",
				FileReference: "dashboards/overview.json",
			})
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
		})
	}
}
