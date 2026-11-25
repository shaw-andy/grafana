package manager

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/config"
	"github.com/grafana/grafana/pkg/plugins/log"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/plugins/manager/registry"
	"github.com/grafana/grafana/pkg/plugins/repo"
	"github.com/grafana/grafana/pkg/plugins/storage"
)

// PluginInstaller.Add updates an already installed plugin through
// updateFromCatalog. That path reads the catalog checksum and then downloads
// the archive URL without it. These tests drive the real repository client.
// The first catalog response is the one that selects the version and URL.
// A later response is a different record. The archive has to match the first
// checksum, and a mismatch must not leave the substituted archive on disk.

func TestPluginInstallerUpdateVerifiesCatalogChecksum(t *testing.T) {
	const pluginID = "checksum-update-panel"
	const installedVersion = "0.9.0"
	const catalogVersion = "1.2.3"

	t.Run("substituted archive is rejected", func(t *testing.T) {
		legitimate := updateZip(t, pluginID, catalogVersion, "legitimate")
		substituted := updateZip(t, pluginID, catalogVersion, "substituted")
		pluginsDir := t.TempDir()
		srv := newUpdateCatalog(t, pluginID, catalogVersion, []string{sha256HexOf(legitimate), sha256HexOf(substituted)}, substituted)

		err := updateInstalledPlugin(t, pluginsDir, srv.URL, pluginID, installedVersion, "")
		require.False(t, updateTreeContains(pluginsDir, "substituted"), "substituted archive was written: %v", err)
		require.ErrorIs(t, err, repo.ErrChecksumMismatchBase)
	})

	t.Run("archive matching the selecting response is installed", func(t *testing.T) {
		legitimate := updateZip(t, pluginID, catalogVersion, "legitimate")
		other := updateZip(t, pluginID, catalogVersion, "substituted")
		pluginsDir := t.TempDir()
		srv := newUpdateCatalog(t, pluginID, catalogVersion, []string{sha256HexOf(legitimate), sha256HexOf(other)}, legitimate)

		err := updateInstalledPlugin(t, pluginsDir, srv.URL, pluginID, installedVersion, catalogVersion)
		require.NoError(t, err)
		data, readErr := os.ReadFile(filepath.Join(pluginsDir, pluginID, "payload.txt"))
		require.NoError(t, readErr)
		require.Equal(t, "legitimate", string(data))
		require.False(t, updateTreeContains(pluginsDir, "substituted"))
	})
}

func updateInstalledPlugin(t *testing.T, pluginsDir, repoURL, pluginID, installedVersion, requestedVersion string) error {
	t.Helper()

	reg := registry.NewInMemory()
	require.NoError(t, reg.Add(context.Background(), &plugins.Plugin{
		JSONData: plugins.JSONData{
			ID:   pluginID,
			Type: plugins.TypeDataSource,
			Info: plugins.Info{Version: installedVersion},
		},
		Class: plugins.ClassExternal,
	}))

	loader := &pluginfakes.FakeLoader{
		UnloadFunc: func(_ context.Context, p *plugins.Plugin) (*plugins.Plugin, error) {
			return p, nil
		},
	}
	pluginRepo := repo.NewManager(repo.ManagerCfg{
		BaseURL: repoURL,
		Logger:  log.NewTestPrettyLogger(),
	})
	inst := New(
		&config.PluginManagementCfg{},
		reg,
		loader,
		pluginRepo,
		storage.FileSystem(log.NewTestPrettyLogger(), pluginsDir),
		storage.SimpleDirNameGeneratorFunc,
		&pluginfakes.FakeAuthService{},
		&pluginfakes.FakeRBACCleaner{},
	)
	return inst.Add(context.Background(), pluginID, requestedVersion, plugins.NewAddOpts("10.0.0", runtime.GOOS, runtime.GOARCH, ""))
}

type updateCatalogPlugin struct {
	version   string
	checksums []string
	body      []byte

	mu   sync.Mutex
	hits int
}

func (p *updateCatalogPlugin) nextChecksum() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := p.hits
	p.hits++
	if idx >= len(p.checksums) {
		idx = len(p.checksums) - 1
	}
	return p.checksums[idx]
}

func newUpdateCatalog(t *testing.T, pluginID, version string, checksums []string, body []byte) *httptest.Server {
	t.Helper()
	plugin := &updateCatalogPlugin{version: version, checksums: checksums, body: body}
	platform := strings.ToLower(runtime.GOOS) + "-" + runtime.GOARCH

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 2 || parts[0] != pluginID || parts[1] != "versions" {
			http.NotFound(w, r)
			return
		}
		if len(parts) == 4 && parts[3] == "download" {
			if parts[2] != plugin.version {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(plugin.body)
			return
		}

		var ver string
		switch len(parts) {
		case 2:
			ver = plugin.version
		case 3:
			ver = parts[2]
			if ver != plugin.version {
				http.NotFound(w, r)
				return
			}
		default:
			http.NotFound(w, r)
			return
		}

		doc := map[string]any{
			"version":      ver,
			"status":       "active",
			"isCompatible": true,
			"url":          "https://example.test/plugins/" + pluginID,
			"packages": map[string]any{
				platform: map[string]string{"sha256": plugin.nextChecksum()},
			},
		}
		var payload any = doc
		if len(parts) == 2 {
			payload = map[string]any{"items": []any{doc}}
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(payload))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func updateZip(t *testing.T, id, version, marker string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	pluginJSON := fmt.Sprintf(`{"id":%q,"type":"datasource","name":%q,"info":{"version":%q}}`, id, marker, version)
	for name, contents := range map[string]string{
		id + "/plugin.json": pluginJSON,
		id + "/payload.txt": marker,
	} {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(contents))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func sha256HexOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func updateTreeContains(root, needle string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr == nil && strings.Contains(string(data), needle) {
			found = true
			return fmt.Errorf("stop")
		}
		return nil
	})
	return found
}
