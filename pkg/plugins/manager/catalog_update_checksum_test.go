package manager

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"

	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/backendplugin/provider"
	"github.com/grafana/grafana/pkg/plugins/config"
	"github.com/grafana/grafana/pkg/plugins/log"
	"github.com/grafana/grafana/pkg/plugins/manager/loader"
	"github.com/grafana/grafana/pkg/plugins/manager/loader/angular/angularinspector"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/bootstrap"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/discovery"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/initialization"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/termination"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/validation"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/plugins/manager/process"
	"github.com/grafana/grafana/pkg/plugins/manager/registry"
	"github.com/grafana/grafana/pkg/plugins/manager/signature"
	"github.com/grafana/grafana/pkg/plugins/pluginassets"
	"github.com/grafana/grafana/pkg/plugins/pluginerrs"
	"github.com/grafana/grafana/pkg/plugins/pluginscdn"
	"github.com/grafana/grafana/pkg/plugins/repo"
	"github.com/grafana/grafana/pkg/plugins/storage"
)

const (
	installedPluginID      = "installed-plugin"
	installedPluginVersion = "1.0.0"
	catalogPluginVersion   = "2.0.0"
	originalPluginToken    = "original-catalog-plugin"
	substitutedToken       = "substituted-archive"
)

// productionPluginCfg matches conf/defaults.ini: app_mode=production and an empty
// allow_loading_unsigned_plugins list, so signature validation is the production one.
func productionPluginCfg(pluginsDir string) *config.PluginManagementCfg {
	return &config.PluginManagementCfg{
		PluginsPaths: []string{pluginsDir},
	}
}

func newProductionLoader(t *testing.T, cfg *config.PluginManagementCfg, reg registry.Service, errs pluginerrs.ErrorTracker) loader.Service {
	t.Helper()

	proc := process.ProvideService()
	terminate, err := termination.New(cfg, termination.Opts{
		TerminateFuncs: []termination.TerminateFunc{
			termination.BackendProcessTerminatorStep(proc),
			termination.DeregisterStep(reg),
		},
	})
	require.NoError(t, err)

	return loader.New(cfg,
		discovery.New(cfg, discovery.Opts{
			FilterFuncs: []discovery.FilterFunc{
				discovery.NewPermittedPluginTypesFilterStep([]plugins.Type{
					plugins.TypeDataSource, plugins.TypeApp, plugins.TypePanel,
				}),
			},
		}),
		bootstrap.New(cfg, bootstrap.Opts{
			ConstructFunc: bootstrap.DefaultConstructFunc(cfg, signature.DefaultCalculator(cfg), pluginassets.NewLocalProvider()),
			DecorateFuncs: bootstrap.DefaultDecorateFuncs(cfg, pluginscdn.ProvideService(cfg)),
		}),
		validation.New(cfg, validation.Opts{
			ValidateFuncs: []validation.ValidateFunc{
				validation.SignatureValidationStep(signature.NewValidator(signature.NewUnsignedAuthorizer(cfg))),
				validation.ModuleJSValidationStep(),
				validation.AngularDetectionStep(cfg, angularinspector.NewStaticInspector()),
			},
		}),
		initialization.New(cfg, initialization.Opts{
			InitializeFuncs: []initialization.InitializeFunc{
				initialization.BackendClientInitStep(pluginfakes.NewFakePluginEnvProvider(), provider.New(), otel.Tracer("catalog-checksum-test")),
				initialization.BackendProcessStartStep(proc),
				initialization.PluginRegistrationStep(reg),
			},
		}),
		terminate,
		errs,
	)
}

type catalogStub struct {
	version    string
	checksum   string
	downloads  [][]byte
	downloadN  int
	infoN      int
	redirectTo string
}

func (c *catalogStub) handler() http.Handler {
	platform := fmt.Sprintf("%s-%s", strings.ToLower(runtime.GOOS), runtime.GOARCH)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/download"):
			if c.redirectTo != "" {
				http.Redirect(w, r, c.redirectTo, http.StatusFound)
				return
			}
			body := c.downloads[len(c.downloads)-1]
			if c.downloadN < len(c.downloads) {
				body = c.downloads[c.downloadN]
			}
			c.downloadN++
			w.Header().Set("Content-Type", "application/zip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		case strings.HasSuffix(r.URL.Path, "/versions"):
			c.infoN++
			writeVersionList(w, c.version, platform, c.checksum)
		default:
			c.infoN++
			writeVersion(w, c.version, platform, c.checksum)
		}
	})
}

func writeVersion(w http.ResponseWriter, version, platform, checksum string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version":      version,
		"status":       "active",
		"isCompatible": true,
		"packages": map[string]any{
			platform: map[string]string{"sha256": checksum},
		},
	})
}

func writeVersionList(w http.ResponseWriter, version, platform, checksum string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"items": []any{
			map[string]any{
				"version":      version,
				"status":       "active",
				"isCompatible": true,
				"packages": map[string]any{
					platform: map[string]string{"sha256": checksum},
				},
			},
		},
	})
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}

func zipFiles(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create("bundle/" + name)
		require.NoError(t, err)
		_, err = io.WriteString(w, content)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func zipDir(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		w, err := zw.Create("bundle/" + filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = w.Write(contents)
		return err
	})
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func pluginJSON(id, version, token string) string {
	return fmt.Sprintf(`{
		"id": %q,
		"name": "Catalog plugin",
		"type": "panel",
		"info": {"version": %q, "description": %q}
	}`, id, version, token)
}

func substitutedArchive(t *testing.T) []byte {
	t.Helper()
	return zipFiles(t, map[string]string{
		"plugin.json": pluginJSON("attacker-plugin", "9.9.9", substitutedToken),
		"module.js":   "/* " + substitutedToken + " */",
		"pwned.txt":   substitutedToken,
	})
}

func installOriginalPlugin(t *testing.T, pluginsDir string, reg registry.Service) string {
	t.Helper()
	pluginDir := filepath.Join(pluginsDir, installedPluginID)
	require.NoError(t, os.MkdirAll(pluginDir, 0o750))
	body := pluginJSON(installedPluginID, installedPluginVersion, originalPluginToken)
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte(body), 0o644))

	p := createPlugin(t, installedPluginID, plugins.ClassExternal, false, false, func(plugin *plugins.Plugin) {
		plugin.Info.Version = installedPluginVersion
		plugin.FS = plugins.NewLocalFS(pluginDir)
	})
	require.NoError(t, reg.Add(context.Background(), p))
	return body
}

type updateHarness struct {
	pluginsDir string
	reg        registry.Service
	errs       *pluginerrs.ErrorRegistry
	inst       *PluginInstaller
	catalog    *catalogStub
	srv        *httptest.Server
	original   string
}

func newUpdateHarness(t *testing.T, checksum string, downloads [][]byte) *updateHarness {
	t.Helper()
	pluginsDir := t.TempDir()
	reg := registry.NewInMemory()
	errs := pluginerrs.ProvideErrorTracker()
	cfg := productionPluginCfg(pluginsDir)
	original := installOriginalPlugin(t, pluginsDir, reg)

	catalog := &catalogStub{
		version:   catalogPluginVersion,
		checksum:  checksum,
		downloads: downloads,
	}
	srv := httptest.NewServer(catalog.handler())
	t.Cleanup(srv.Close)

	mgr := repo.NewManager(repo.ManagerCfg{
		BaseURL: srv.URL,
		Logger:  log.NewTestPrettyLogger(),
	})
	inst := New(cfg, reg, newProductionLoader(t, cfg, reg, errs), mgr,
		storage.FileSystem(log.NewTestPrettyLogger(), pluginsDir),
		storage.SimpleDirNameGeneratorFunc,
		&pluginfakes.FakeAuthService{},
		&pluginfakes.FakeRBACCleaner{},
	)
	return &updateHarness{
		pluginsDir: pluginsDir,
		reg:        reg,
		errs:       errs,
		inst:       inst,
		catalog:    catalog,
		srv:        srv,
		original:   original,
	}
}

func (h *updateHarness) update(ctx context.Context, version string) error {
	return h.inst.Add(ctx, installedPluginID, version, testCompatOpts())
}

func assertUpdateRejected(t *testing.T, h *updateHarness, err error, forbiddenIDs ...string) {
	t.Helper()
	got, readErr := os.ReadFile(filepath.Join(h.pluginsDir, installedPluginID, "plugin.json"))
	marker := filepath.Join(h.pluginsDir, installedPluginID, "pwned.txt")
	_, markerErr := os.Stat(marker)
	_, stillInstalled := h.reg.Plugin(context.Background(), installedPluginID, installedPluginVersion)

	var loaded []string
	for _, id := range forbiddenIDs {
		if _, ok := h.reg.Plugin(context.Background(), id, ""); ok {
			loaded = append(loaded, id)
		}
	}

	if err == nil || readErr != nil || string(got) != h.original || markerErr == nil || !stillInstalled || len(loaded) > 0 {
		t.Fatalf("catalog update accepted a substituted archive: addErr=%v readErr=%v originalIntact=%v markerWritten=%v stillInstalled=%v loaded=%v infoRequests=%d downloadRequests=%d loaderErrors=%v",
			err, readErr, readErr == nil && string(got) == h.original, markerErr == nil, stillInstalled, loaded, h.catalog.infoN, h.catalog.downloadN, h.errs.Errors(context.Background()))
	}
}

func TestCatalogUpdate_RejectsSubstitutedArchive(t *testing.T) {
	substituted := substitutedArchive(t)
	signed := zipDir(t, filepath.Join("testdata", "test-app"))
	require.NotEqual(t, sha256Hex(substituted), sha256Hex(signed))

	t.Run("explicit version ignores catalog checksum", func(t *testing.T) {
		// Catalog publishes the checksum of a different archive. The download is the attacker's zip.
		h := newUpdateHarness(t, sha256Hex(signed), [][]byte{substituted})
		err := h.update(context.Background(), catalogPluginVersion)
		assertUpdateRejected(t, h, err, "attacker-plugin")
		require.Greater(t, h.catalog.infoN, 0)
		require.Greater(t, h.catalog.downloadN, 0)
	})

	t.Run("latest version ignores catalog checksum", func(t *testing.T) {
		h := newUpdateHarness(t, sha256Hex(signed), [][]byte{substituted})
		err := h.update(context.Background(), "")
		assertUpdateRejected(t, h, err, "attacker-plugin")
	})

	t.Run("signed archive with a different id is not installed", func(t *testing.T) {
		// The archive verifies under the Grafana plugin signing key, but it is not the
		// archive the catalog checksum identifies and its id is not the one requested.
		// Its declared dependencies are already installed at the catalog version, so the
		// update is not rejected for an unrelated dependency download.
		h := newUpdateHarness(t, sha256Hex(substituted), [][]byte{signed})
		for _, depID := range []string{"graphite", "graph"} {
			dep := createPlugin(t, depID, plugins.ClassExternal, false, false, func(plugin *plugins.Plugin) {
				plugin.Info.Version = catalogPluginVersion
			})
			require.NoError(t, h.reg.Add(context.Background(), dep))
		}
		err := h.update(context.Background(), catalogPluginVersion)
		assertUpdateRejected(t, h, err, "test-app")
	})

	t.Run("download redirected off the catalog host", func(t *testing.T) {
		substituted := substitutedArchive(t)
		cdnHits := 0
		cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cdnHits++
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(substituted)
		}))
		t.Cleanup(cdn.Close)

		h := newUpdateHarness(t, sha256Hex(signed), nil)
		h.catalog.redirectTo = cdn.URL + "/plugin.zip"
		err := h.update(context.Background(), catalogPluginVersion)
		assertUpdateRejected(t, h, err, "attacker-plugin")
		require.Greater(t, cdnHits, 0)
	})
}

func TestCatalogUpdate_EmptyCatalogChecksumIsRejected(t *testing.T) {
	h := newUpdateHarness(t, "", [][]byte{substitutedArchive(t)})
	err := h.update(context.Background(), catalogPluginVersion)
	assertUpdateRejected(t, h, err, "attacker-plugin")
}

func TestCatalogUpdate_RejectsIDAndVersionMismatch(t *testing.T) {
	// The checksum matches the downloaded bytes, so a checksum-only check would pass.
	// The archive's id and version are not the ones the update requested.
	mismatched := zipFiles(t, map[string]string{
		"plugin.json": pluginJSON(installedPluginID, "9.9.9", substitutedToken),
		"pwned.txt":   substitutedToken,
	})
	h := newUpdateHarness(t, sha256Hex(mismatched), [][]byte{mismatched})
	err := h.update(context.Background(), catalogPluginVersion)
	assertUpdateRejected(t, h, err)
}

func TestCatalogUpdate_ExtractsOnlyTheChecksummedDownload(t *testing.T) {
	// A fix that verifies one download and then downloads again must not extract the second body.
	// The catalog checksum stays the same across lookups; only the body changes.
	good := zipFiles(t, map[string]string{
		"plugin.json": pluginJSON(installedPluginID, catalogPluginVersion, "checksummed-archive"),
		"good.txt":    "checksummed-archive",
	})
	bad := substitutedArchive(t)
	require.NotEqual(t, sha256Hex(good), sha256Hex(bad))

	h := newUpdateHarness(t, sha256Hex(good), [][]byte{good, bad})
	err := h.update(context.Background(), catalogPluginVersion)

	_, badMarkerErr := os.Stat(filepath.Join(h.pluginsDir, installedPluginID, "pwned.txt"))
	if badMarkerErr == nil {
		t.Fatalf("extracted a later download that was not the checksummed body (downloads=%d)", h.catalog.downloadN)
	}
	if _, ok := h.reg.Plugin(context.Background(), "attacker-plugin", ""); ok {
		t.Fatal("loaded the plugin from a later download")
	}
	if err != nil {
		got, readErr := os.ReadFile(filepath.Join(h.pluginsDir, installedPluginID, "plugin.json"))
		if readErr != nil || string(got) != h.original {
			t.Fatalf("rejected the update after replacing the installed plugin: addErr=%v readErr=%v", err, readErr)
		}
		return
	}
	got, readErr := os.ReadFile(filepath.Join(h.pluginsDir, installedPluginID, "good.txt"))
	require.NoError(t, readErr)
	require.Equal(t, "checksummed-archive", string(got))
}

func TestCatalogInstall_FreshInstallRejectsMismatchedChecksum(t *testing.T) {
	pluginsDir := t.TempDir()
	reg := registry.NewInMemory()
	errs := pluginerrs.ProvideErrorTracker()
	cfg := productionPluginCfg(pluginsDir)
	body := substitutedArchive(t)
	catalog := &catalogStub{
		version:   catalogPluginVersion,
		checksum:  sha256Hex(zipFiles(t, map[string]string{"plugin.json": pluginJSON("fresh-plugin", catalogPluginVersion, "other")})),
		downloads: [][]byte{body},
	}
	srv := httptest.NewServer(catalog.handler())
	t.Cleanup(srv.Close)

	inst := New(cfg, reg, newProductionLoader(t, cfg, reg, errs),
		repo.NewManager(repo.ManagerCfg{BaseURL: srv.URL, Logger: log.NewTestPrettyLogger()}),
		storage.FileSystem(log.NewTestPrettyLogger(), pluginsDir),
		storage.SimpleDirNameGeneratorFunc,
		&pluginfakes.FakeAuthService{},
		&pluginfakes.FakeRBACCleaner{},
	)
	err := inst.Add(context.Background(), "fresh-plugin", catalogPluginVersion, testCompatOpts())
	_, statErr := os.Stat(filepath.Join(pluginsDir, "fresh-plugin"))
	if err == nil || statErr == nil {
		t.Fatalf("fresh catalog install accepted a mismatched archive: addErr=%v extracted=%v downloads=%d", err, statErr == nil, catalog.downloadN)
	}
}

func TestCatalogInstall_EmptyChecksumIsRejected(t *testing.T) {
	pluginsDir := t.TempDir()
	reg := registry.NewInMemory()
	errs := pluginerrs.ProvideErrorTracker()
	cfg := productionPluginCfg(pluginsDir)
	catalog := &catalogStub{
		version:   catalogPluginVersion,
		checksum:  "",
		downloads: [][]byte{substitutedArchive(t)},
	}
	srv := httptest.NewServer(catalog.handler())
	t.Cleanup(srv.Close)

	inst := New(cfg, reg, newProductionLoader(t, cfg, reg, errs),
		repo.NewManager(repo.ManagerCfg{BaseURL: srv.URL, Logger: log.NewTestPrettyLogger()}),
		storage.FileSystem(log.NewTestPrettyLogger(), pluginsDir),
		storage.SimpleDirNameGeneratorFunc,
		&pluginfakes.FakeAuthService{},
		&pluginfakes.FakeRBACCleaner{},
	)
	err := inst.Add(context.Background(), "fresh-plugin", catalogPluginVersion, testCompatOpts())
	_, statErr := os.Stat(filepath.Join(pluginsDir, "fresh-plugin"))
	if err == nil || statErr == nil {
		t.Fatalf("fresh catalog install accepted an archive with an empty catalog checksum: addErr=%v extracted=%v", err, statErr == nil)
	}
}
