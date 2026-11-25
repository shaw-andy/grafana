package commands

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

	"github.com/grafana/grafana/pkg/cmd/grafana-cli/services"
	"github.com/grafana/grafana/pkg/plugins/repo"
)

// These tests exercise grafana cli plugins install (installPlugin, which
// plugins install, plugins update, and plugins update-all all call). The
// catalog responses are a stand-in for the Grafana.com version API that
// Manager.GetPluginArchiveInfo parses. The first response is the one that
// selects the version and download URL. Every later response is a different
// record an attacker could return on a second lookup.
//
// A substituted archive must be rejected using the checksum from that first
// record. Fetching the catalog again and trusting the later checksum must
// not make the substituted archive install, and must not reject an archive
// that matches the first record.

func TestInstallPluginVerifiesCatalogChecksum(t *testing.T) {
	services.Init("10.0.0", false, false)

	t.Run("latest version rejects a substituted archive", func(t *testing.T) {
		assertCatalogChecksumEnforced(t, "")
	})

	t.Run("explicit version rejects a substituted archive", func(t *testing.T) {
		assertCatalogChecksumEnforced(t, "1.2.3")
	})

	t.Run("archive matching the selecting response is installed", func(t *testing.T) {
		const pluginID = "checksum-bound-panel"
		const version = "1.2.3"
		legitimate := zipPlugin(t, pluginID, version, "legitimate")
		other := zipPlugin(t, pluginID, version, "substituted")
		pluginsDir := t.TempDir()
		srv := newCatalogServer(t, &catalogPlugin{
			id:      pluginID,
			version: version,
			// The checksum that belongs to this install is the first one.
			// A later lookup returns a checksum for a different archive.
			checksums: []string{sha256Hex(legitimate), sha256Hex(other)},
			body:      legitimate,
		})

		err := installPlugin(context.Background(), pluginID, version, pluginInstallOpts{
			repoURL:   srv.URL,
			pluginDir: pluginsDir,
		})
		require.NoError(t, err)
		require.Equal(t, "legitimate", installedMarker(t, pluginsDir, pluginID))
		require.False(t, treeContains(pluginsDir, "substituted"))
	})

	t.Run("dependency archive is held to the checksum that selected it", func(t *testing.T) {
		const parentID = "checksum-parent-app"
		const depID = "checksum-dep-datasource"
		const version = "1.2.3"
		parent := zipPluginWithDependency(t, parentID, version, "legitimate", depID)
		depLegitimate := zipPlugin(t, depID, version, "legitimate")
		depSubstituted := zipPlugin(t, depID, version, "substituted")
		pluginsDir := t.TempDir()
		srv := newCatalogServer(t,
			&catalogPlugin{
				id:        parentID,
				version:   version,
				checksums: []string{sha256Hex(parent)},
				body:      parent,
			},
			&catalogPlugin{
				id:        depID,
				version:   version,
				checksums: []string{sha256Hex(depLegitimate), sha256Hex(depSubstituted)},
				body:      depSubstituted,
			},
		)

		err := installPlugin(context.Background(), parentID, version, pluginInstallOpts{
			repoURL:   srv.URL,
			pluginDir: pluginsDir,
		})
		require.False(t, treeContains(pluginsDir, "substituted"), "dependency archive was written: %v", err)
		require.ErrorIs(t, err, repo.ErrChecksumMismatchBase)
	})

	t.Run("catalog record without a checksum is rejected", func(t *testing.T) {
		const pluginID = "checksum-missing-panel"
		const version = "1.2.3"
		body := zipPlugin(t, pluginID, version, "substituted")
		pluginsDir := t.TempDir()
		srv := newCatalogServer(t, &catalogPlugin{
			id:        pluginID,
			version:   version,
			checksums: []string{""},
			body:      body,
		})

		err := installPlugin(context.Background(), pluginID, "", pluginInstallOpts{
			repoURL:   srv.URL,
			pluginDir: pluginsDir,
		})
		require.False(t, treeContains(pluginsDir, "substituted"), "archive was written without a catalog checksum: %v", err)
		require.Error(t, err)
	})
}

func assertCatalogChecksumEnforced(t *testing.T, requestedVersion string) {
	t.Helper()

	const pluginID = "checksum-catalog-panel"
	const version = "1.2.3"
	legitimate := zipPlugin(t, pluginID, version, "legitimate")
	substituted := zipPlugin(t, pluginID, version, "substituted")
	pluginsDir := t.TempDir()
	srv := newCatalogServer(t, &catalogPlugin{
		id:      pluginID,
		version: version,
		// First record is the checksum of the archive the catalog published.
		// The body at the download URL is a different archive. A second lookup
		// reports a checksum that matches that substituted body.
		checksums: []string{sha256Hex(legitimate), sha256Hex(substituted)},
		body:      substituted,
	})

	err := installPlugin(context.Background(), pluginID, requestedVersion, pluginInstallOpts{
		repoURL:   srv.URL,
		pluginDir: pluginsDir,
	})
	require.False(t, treeContains(pluginsDir, "substituted"), "substituted archive was written into the plugins directory: %v", err)
	require.ErrorIs(t, err, repo.ErrChecksumMismatchBase)
}

type catalogPlugin struct {
	id        string
	version   string
	checksums []string
	body      []byte

	mu   sync.Mutex
	hits int
}

func (p *catalogPlugin) nextChecksum() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := p.hits
	p.hits++
	if idx >= len(p.checksums) {
		idx = len(p.checksums) - 1
	}
	return p.checksums[idx]
}

func newCatalogServer(t *testing.T, plugins ...*catalogPlugin) *httptest.Server {
	t.Helper()

	byID := make(map[string]*catalogPlugin, len(plugins))
	for _, p := range plugins {
		byID[p.id] = p
	}
	platform := strings.ToLower(runtime.GOOS) + "-" + runtime.GOARCH

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 2 || parts[1] != "versions" {
			http.NotFound(w, r)
			return
		}
		plugin := byID[parts[0]]
		if plugin == nil {
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

		var version string
		switch len(parts) {
		case 2:
			version = plugin.version
		case 3:
			version = parts[2]
			if version != plugin.version {
				http.NotFound(w, r)
				return
			}
		default:
			http.NotFound(w, r)
			return
		}

		doc := map[string]any{
			"version":      version,
			"status":       "active",
			"isCompatible": true,
			"url":          "https://example.test/plugins/" + plugin.id,
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

func zipPlugin(t *testing.T, id, version, marker string) []byte {
	t.Helper()
	return zipPluginJSON(t, id, fmt.Sprintf(`{"id":%q,"type":"datasource","name":%q,"info":{"version":%q}}`, id, marker, version), marker)
}

func zipPluginWithDependency(t *testing.T, id, version, marker, dependencyID string) []byte {
	t.Helper()
	raw := fmt.Sprintf(`{"id":%q,"type":"datasource","name":%q,"info":{"version":%q},"dependencies":{"plugins":[{"id":%q,"type":"datasource","name":"dependency"}]}}`, id, marker, version, dependencyID)
	return zipPluginJSON(t, id, raw, marker)
}

func zipPluginJSON(t *testing.T, id, pluginJSON, marker string) []byte {
	t.Helper()

	// Archive member names follow the layout Extract accepts: a single top-level
	// directory, rewritten to the plugin id, containing plugin.json.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	writeZipFile(t, zw, id+"/plugin.json", pluginJSON)
	writeZipFile(t, zw, id+"/payload.txt", marker)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func writeZipFile(t *testing.T, zw *zip.Writer, name, contents string) {
	t.Helper()
	w, err := zw.Create(name)
	require.NoError(t, err)
	_, err = w.Write([]byte(contents))
	require.NoError(t, err)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func installedMarker(t *testing.T, pluginsDir, pluginID string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(pluginsDir, pluginID, "payload.txt"))
	require.NoError(t, err)
	return string(data)
}

func treeContains(root, needle string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr == nil && strings.Contains(string(data), needle) {
			found = true
			return errStopWalk
		}
		return nil
	})
	return found
}

var errStopWalk = fmt.Errorf("stop walk")
