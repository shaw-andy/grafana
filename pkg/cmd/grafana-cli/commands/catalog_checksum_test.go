package commands

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/cmd/grafana-cli/services"
)

const (
	cliPluginID         = "cli-installed-plugin"
	cliInstalledVersion = "1.0.0"
	cliCatalogVersion   = "2.0.0"
	cliOriginalToken    = "original-cli-plugin"
	cliSubstitutedToken = "substituted-cli-archive"
)

func TestCLICatalogInstall_RejectsSubstitutedArchive(t *testing.T) {
	restoreCLIGlobals(t)

	substituted := cliZip(t, cliPluginJSON("attacker-plugin", "9.9.9", cliSubstitutedToken), true)
	published := cliZip(t, cliPluginJSON(cliPluginID, cliCatalogVersion, "published-archive"), false)
	require.NotEqual(t, sha256Sum(substituted), sha256Sum(published))

	t.Run("fresh install", func(t *testing.T) {
		pluginsDir := t.TempDir()
		srv := cliCatalogServer(t, cliCatalogVersion, sha256Sum(published), substituted)
		err := installPlugin(context.Background(), cliPluginID, cliCatalogVersion, pluginInstallOpts{
			repoURL:   srv.URL,
			pluginDir: pluginsDir,
		})
		_, statErr := os.Stat(filepath.Join(pluginsDir, cliPluginID))
		if err == nil || statErr == nil {
			t.Fatalf("cli catalog install accepted a substituted archive: err=%v extracted=%v", err, statErr == nil)
		}
	})

	t.Run("update of an installed plugin", func(t *testing.T) {
		pluginsDir := t.TempDir()
		original := writeCLIPlugin(t, pluginsDir, cliPluginID, cliInstalledVersion, cliOriginalToken)
		srv := cliCatalogServer(t, cliCatalogVersion, sha256Sum(published), substituted)
		err := installPlugin(context.Background(), cliPluginID, cliCatalogVersion, pluginInstallOpts{
			repoURL:   srv.URL,
			pluginDir: pluginsDir,
		})
		got, readErr := os.ReadFile(filepath.Join(pluginsDir, cliPluginID, "plugin.json"))
		_, markerErr := os.Stat(filepath.Join(pluginsDir, cliPluginID, "pwned.txt"))
		if err == nil || readErr != nil || string(got) != original || markerErr == nil {
			t.Fatalf("cli catalog update accepted a substituted archive: err=%v readErr=%v originalIntact=%v marker=%v",
				err, readErr, readErr == nil && string(got) == original, markerErr == nil)
		}
	})
}

func TestCLICatalogInstall_EmptyChecksumIsRejected(t *testing.T) {
	restoreCLIGlobals(t)
	pluginsDir := t.TempDir()
	srv := cliCatalogServer(t, cliCatalogVersion, "", cliZip(t, cliPluginJSON("attacker-plugin", "9.9.9", cliSubstitutedToken), true))
	err := installPlugin(context.Background(), cliPluginID, cliCatalogVersion, pluginInstallOpts{
		repoURL:   srv.URL,
		pluginDir: pluginsDir,
	})
	_, statErr := os.Stat(filepath.Join(pluginsDir, cliPluginID))
	if err == nil || statErr == nil {
		t.Fatalf("cli catalog install accepted an empty checksum: err=%v extracted=%v", err, statErr == nil)
	}
}

func TestCLIUpgrade_RejectsSubstitutedArchiveBeforeUninstall(t *testing.T) {
	restoreCLIGlobals(t)
	pluginsDir := t.TempDir()
	original := writeCLIPlugin(t, pluginsDir, cliPluginID, cliInstalledVersion, cliOriginalToken)
	published := cliZip(t, cliPluginJSON(cliPluginID, cliCatalogVersion, "published-archive"), false)
	substituted := cliZip(t, cliPluginJSON("attacker-plugin", "9.9.9", cliSubstitutedToken), true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repo/"+cliPluginID {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": cliPluginID,
				"versions": []any{
					map[string]any{"version": cliCatalogVersion},
				},
			})
			return
		}
		platform := fmt.Sprintf("%s-%s", strings.ToLower(runtime.GOOS), runtime.GOARCH)
		switch {
		case strings.HasSuffix(r.URL.Path, "/download"):
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(substituted)
		case strings.HasSuffix(r.URL.Path, "/versions"):
			writeCLIVersion(w, cliCatalogVersion, platform, sha256Sum(published), true)
		default:
			writeCLIVersion(w, cliCatalogVersion, platform, sha256Sum(published), false)
		}
	}))
	t.Cleanup(srv.Close)

	err := upgradeCommand(newTestCommandLine([]string{cliPluginID}, pluginsDir, srv.URL))
	got, readErr := os.ReadFile(filepath.Join(pluginsDir, cliPluginID, "plugin.json"))
	_, markerErr := os.Stat(filepath.Join(pluginsDir, cliPluginID, "pwned.txt"))
	if err == nil || readErr != nil || string(got) != original || markerErr == nil {
		t.Fatalf("cli upgrade removed or replaced the plugin before the archive matched the catalog checksum: err=%v readErr=%v originalIntact=%v marker=%v",
			err, readErr, readErr == nil && string(got) == original, markerErr == nil)
	}
}

func restoreCLIGlobals(t *testing.T) {
	t.Helper()
	prevVersion := services.GrafanaVersion
	prevLogger := services.Logger
	prevClient := services.HttpClient
	services.Init("10.0.0", false, false)
	t.Cleanup(func() {
		services.GrafanaVersion = prevVersion
		services.Logger = prevLogger
		services.HttpClient = prevClient
	})
}

func cliCatalogServer(t *testing.T, version, checksum string, archive []byte) *httptest.Server {
	t.Helper()
	platform := fmt.Sprintf("%s-%s", strings.ToLower(runtime.GOOS), runtime.GOARCH)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/download"):
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(archive)
		case strings.HasSuffix(r.URL.Path, "/versions"):
			writeCLIVersion(w, version, platform, checksum, true)
		default:
			writeCLIVersion(w, version, platform, checksum, false)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeCLIVersion(w http.ResponseWriter, version, platform, checksum string, list bool) {
	w.Header().Set("Content-Type", "application/json")
	versionObj := map[string]any{
		"version":      version,
		"status":       "active",
		"isCompatible": true,
		"packages": map[string]any{
			platform: map[string]string{"sha256": checksum},
		},
	}
	if list {
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{versionObj}})
		return
	}
	_ = json.NewEncoder(w).Encode(versionObj)
}

func cliPluginJSON(id, version, token string) string {
	return fmt.Sprintf(`{"id":%q,"name":"CLI plugin","type":"panel","info":{"version":%q,"description":%q}}`, id, version, token)
}

func cliZip(t *testing.T, pluginJSON string, substituted bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string]string{"plugin.json": pluginJSON}
	if substituted {
		files["pwned.txt"] = cliSubstitutedToken
		files["module.js"] = "/* " + cliSubstitutedToken + " */"
	}
	for name, content := range files {
		w, err := zw.Create("bundle/" + name)
		require.NoError(t, err)
		_, err = io.WriteString(w, content)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func sha256Sum(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}

func writeCLIPlugin(t *testing.T, pluginsDir, id, version, token string) string {
	t.Helper()
	dir := filepath.Join(pluginsDir, id)
	require.NoError(t, os.MkdirAll(dir, 0o750))
	body := cliPluginJSON(id, version, token)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "plugin.json"), []byte(body), 0o644))
	return body
}
