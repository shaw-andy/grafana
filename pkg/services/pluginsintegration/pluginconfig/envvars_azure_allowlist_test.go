package pluginconfig

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-azure-sdk-go/v2/azsettings"

	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/backendplugin/provider"
	"github.com/grafana/grafana/pkg/plugins/config"
	pluginslog "github.com/grafana/grafana/pkg/plugins/log"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/bootstrap"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/initialization"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/plugins/manager/process"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsso"
	"github.com/grafana/grafana/pkg/setting"
)

// shippedAzureForwardPlugins is the allowlist comment in conf/defaults.ini names as the
// plugins that receive Azure settings. The test loads that list from defaults.ini rather
// than copying it, then asserts these ids are present so a future default change is visible.
var shippedAzureForwardPlugins = []string{
	"grafana-azure-monitor-datasource",
	"prometheus",
	"grafana-azure-data-explorer-datasource",
	"mssql",
	"grafana-azureprometheus-datasource",
	"grafana-databricks-datasource",
}

func TestAzureSettingsStayOffUnlistedPluginProcess(t *testing.T) {
	cfg := loadAzureOverrideCfg(t, `
[azure]
user_identity_enabled = true
user_identity_token_url = https://login.microsoftonline.com/placeholder-tenant/oauth2/v2.0/token
user_identity_client_authentication = client_secret_post
user_identity_client_id = placeholder-user-identity-client-id
user_identity_client_secret = placeholder-user-identity-client-secret
managed_identity_enabled = true
managed_identity_client_id = placeholder-managed-identity-client-id
workload_identity_enabled = true
workload_identity_tenant_id = placeholder-workload-tenant
workload_identity_client_id = placeholder-workload-client
workload_identity_token_file = /placeholder/workload-token
`)
	require.Equal(t, shippedAzureForwardPlugins, cfg.Azure.ForwardSettingsPlugins)

	// Host identity variables are copied only for allowlisted plugins. Set them on the
	// Grafana process so a missing allowlist check would put them in the plugin process.
	t.Setenv("IDENTITY_HEADER", "placeholder-identity-header")
	t.Setenv("IDENTITY_ENDPOINT", "http://127.0.0.1:9/placeholder")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/placeholder/federated-token")
	t.Setenv("AZURE_CLIENT_ID", "placeholder-host-workload-client")

	pCfg, err := ProvidePluginInstanceConfig(cfg, setting.ProvideProvider(cfg), featuremgmt.WithFeatures())
	require.NoError(t, err)
	envProvider := NewEnvVarsProvider(pCfg, nil, &fakeSSOSettingsProvider{}, newTestMarketplaceLicensing(""))
	requests := NewRequestConfigProvider(pCfg, &fakeSSOSettingsProvider{})

	unlisted := "community-untrusted-datasource"
	require.NotContains(t, cfg.Azure.ForwardSettingsPlugins, unlisted)

	unlistedEnv := startBackendAndReadProcessEnv(t, envProvider, unlisted)
	assert.NotEmpty(t, envKeys(unlistedEnv, "GF_VERSION"), "plugin process did not receive the explicit environment")
	assert.Empty(t, envKeysWithPrefix(unlistedEnv, "GFAZPL_"), "unlisted plugin process received Azure settings: %v", envKeysWithPrefix(unlistedEnv, "GFAZPL_"))
	assert.Empty(t, envKeys(unlistedEnv, "IDENTITY_HEADER", "IDENTITY_ENDPOINT", "AZURE_FEDERATED_TOKEN_FILE", "AZURE_CLIENT_ID"))

	unlistedRequest := requests.PluginRequestConfig(context.Background(), unlisted, nil)
	assert.NotContains(t, unlistedRequest, azsettings.UserIdentityClientSecret)
	assert.NotContains(t, unlistedRequest, azsettings.ManagedIdentityClientID)

	allowedID := "grafana-azure-monitor-datasource"
	allowedEnv := startBackendAndReadProcessEnv(t, envProvider, allowedID)
	assert.Contains(t, envKeys(allowedEnv, azsettings.UserIdentityClientSecret), azsettings.UserIdentityClientSecret)
	assert.Contains(t, envKeys(allowedEnv, azsettings.ManagedIdentityClientID), azsettings.ManagedIdentityClientID)
	assert.Contains(t, envKeys(allowedEnv, azsettings.WorkloadIdentityTokenFile), azsettings.WorkloadIdentityTokenFile)
	assert.Contains(t, envKeys(allowedEnv, "IDENTITY_HEADER"), "IDENTITY_HEADER")
	assert.Contains(t, envKeys(allowedEnv, "AZURE_FEDERATED_TOKEN_FILE"), "AZURE_FEDERATED_TOKEN_FILE")

	allowedRequest := requests.PluginRequestConfig(context.Background(), allowedID, nil)
	_, secretInRequest := allowedRequest[azsettings.UserIdentityClientSecret]
	assert.True(t, secretInRequest, "allowlisted plugin request config omitted %s", azsettings.UserIdentityClientSecret)

	// getAzureSettings merges into the shared Azure settings object. A later unlisted
	// plugin must still be filtered by its own id after that merge has run.
	secondUnlisted := "another-community-datasource"
	require.NotContains(t, cfg.Azure.ForwardSettingsPlugins, secondUnlisted)
	secondEnv := startBackendAndReadProcessEnv(t, envProvider, secondUnlisted)
	assert.Empty(t, envKeysWithPrefix(secondEnv, "GFAZPL_"), "unlisted plugin process received Azure settings after an allowlisted plugin started: %v", envKeysWithPrefix(secondEnv, "GFAZPL_"))
	assert.Empty(t, envKeys(secondEnv, "IDENTITY_HEADER", "AZURE_FEDERATED_TOKEN_FILE"))
}

func TestAzureSSOSecretStaysOffUnlistedPluginProcess(t *testing.T) {
	cfg := loadAzureOverrideCfg(t, `
[azure]
user_identity_enabled = true
`)
	require.Equal(t, shippedAzureForwardPlugins, cfg.Azure.ForwardSettingsPlugins)
	require.Empty(t, cfg.Azure.UserIdentityTokenEndpoint.ClientSecret)

	sso := &fakeSSOSettingsProvider{GetForProviderFunc: func(_ context.Context, provider string) (*pluginsso.Settings, error) {
		require.Equal(t, "azuread", provider)
		return &pluginsso.Settings{Values: map[string]any{
			"token_url":             "https://login.microsoftonline.com/placeholder-tenant/oauth2/v2.0/token",
			"client_authentication": "client_secret_post",
			"client_id":             "placeholder-sso-client-id",
			"client_secret":         "placeholder-sso-client-secret",
		}}, nil
	}}

	pCfg, err := ProvidePluginInstanceConfig(cfg, setting.ProvideProvider(cfg), featuremgmt.WithFeatures())
	require.NoError(t, err)
	envProvider := NewEnvVarsProvider(pCfg, nil, sso, newTestMarketplaceLicensing(""))
	requests := NewRequestConfigProvider(pCfg, sso)

	unlisted := "community-untrusted-datasource"
	unlistedEnv := startBackendAndReadProcessEnv(t, envProvider, unlisted)
	assert.NotEmpty(t, envKeys(unlistedEnv, "GF_VERSION"))
	assert.Empty(t, envKeys(unlistedEnv, azsettings.UserIdentityClientSecret), "unlisted plugin process received the SSO client secret field")
	assert.NotContains(t, requests.PluginRequestConfig(context.Background(), unlisted, nil), azsettings.UserIdentityClientSecret)

	allowedEnv := startBackendAndReadProcessEnv(t, envProvider, "grafana-azure-monitor-datasource")
	assert.Contains(t, envKeys(allowedEnv, azsettings.UserIdentityClientSecret), azsettings.UserIdentityClientSecret)

	// The allowlisted start merges the SSO secret into the shared settings object.
	// The next unlisted plugin has to be decided from its own id, not from that object now holding a secret.
	afterEnv := startBackendAndReadProcessEnv(t, envProvider, "another-community-datasource")
	assert.Empty(t, envKeys(afterEnv, azsettings.UserIdentityClientSecret))
}

func TestAzureSettingsRequireExactForwardPluginID(t *testing.T) {
	cfg := loadAzureOverrideCfg(t, `
[azure]
user_identity_enabled = true
user_identity_client_id = placeholder-user-identity-client-id
user_identity_client_secret = placeholder-user-identity-client-secret
managed_identity_enabled = true
managed_identity_client_id = placeholder-managed-identity-client-id
`)
	pCfg, err := ProvidePluginInstanceConfig(cfg, setting.ProvideProvider(cfg), featuremgmt.WithFeatures())
	require.NoError(t, err)
	envProvider := NewEnvVarsProvider(pCfg, nil, &fakeSSOSettingsProvider{}, newTestMarketplaceLicensing(""))

	for _, pluginID := range []string{
		"prometheus-community",
		"mssql-extra",
		"grafana-azure-monitor-datasource-fork",
		"grafana-azure-monitor-datasource ",
		"Prometheus",
	} {
		t.Run(pluginID, func(t *testing.T) {
			env := envProvider.PluginEnvVars(context.Background(), &plugins.Plugin{JSONData: plugins.JSONData{ID: pluginID, Backend: true}})
			assert.Empty(t, envKeysWithPrefix(strings.Join(env, "\n"), "GFAZPL_"), "plugin %q received Azure settings: %v", pluginID, envKeysWithPrefix(strings.Join(env, "\n"), "GFAZPL_"))
		})
	}

	allowed := envProvider.PluginEnvVars(context.Background(), &plugins.Plugin{JSONData: plugins.JSONData{ID: "prometheus", Backend: true}})
	assert.Contains(t, envKeys(strings.Join(allowed, "\n"), azsettings.UserIdentityClientSecret), azsettings.UserIdentityClientSecret)
}

func TestEmptyAzureForwardListWithholdsSettings(t *testing.T) {
	cfg := loadAzureOverrideCfg(t, `
[azure]
user_identity_enabled = true
user_identity_client_secret = placeholder-user-identity-client-secret
`)
	cleared := *cfg.Azure
	cleared.ForwardSettingsPlugins = nil
	cfg.Azure = &cleared

	pCfg, err := ProvidePluginInstanceConfig(cfg, setting.ProvideProvider(cfg), featuremgmt.WithFeatures())
	require.NoError(t, err)
	envProvider := NewEnvVarsProvider(pCfg, nil, &fakeSSOSettingsProvider{}, newTestMarketplaceLicensing(""))

	for _, pluginID := range []string{"community-untrusted-datasource", "grafana-azure-monitor-datasource", "prometheus"} {
		env := envProvider.PluginEnvVars(context.Background(), &plugins.Plugin{JSONData: plugins.JSONData{ID: pluginID, Backend: true}})
		assert.Empty(t, envKeysWithPrefix(strings.Join(env, "\n"), "GFAZPL_"), "plugin %q received Azure settings from an empty allowlist: %v", pluginID, envKeysWithPrefix(strings.Join(env, "\n"), "GFAZPL_"))
	}
}

func loadAzureOverrideCfg(t *testing.T, override string) *setting.Cfg {
	t.Helper()
	// Keep Load from publishing ZONEINFO into the process permanently.
	if _, ok := os.LookupEnv("ZONEINFO"); !ok {
		t.Setenv("ZONEINFO", "placeholder-zoneinfo")
	}
	previousAppURL := setting.AppUrl
	previousAppSubURL := setting.AppSubUrl
	t.Cleanup(func() {
		setting.AppUrl = previousAppURL
		setting.AppSubUrl = previousAppSubURL
	})

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "custom.ini")
	require.NoError(t, os.WriteFile(cfgPath, []byte(override), 0o600))

	cfg, err := setting.NewCfgFromArgs(setting.CommandLineArgs{
		HomePath: grafanaHome(t),
		Config:   cfgPath,
	})
	require.NoError(t, err)
	require.NotNil(t, cfg.Azure)
	return cfg
}

func grafanaHome(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "conf", "defaults.ini")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "conf/defaults.ini not found from %s", dir)
		dir = parent
	}
}

// startBackendAndReadProcessEnv runs the backend init and start steps used for an
// installed external plugin and returns the environment of the process that was started.
// The executable is not a plugin, so the handshake fails after the process has recorded
// its environment.
func startBackendAndReadProcessEnv(t *testing.T, envProvider *EnvVarsProvider, pluginID string) string {
	t.Helper()

	pluginDir := t.TempDir()
	copyProbe(t, pluginDir)

	p := &plugins.Plugin{
		JSONData: plugins.JSONData{
			ID:         pluginID,
			Type:       plugins.TypeDataSource,
			Backend:    true,
			Executable: "probe",
		},
		FS:    plugins.NewLocalFS(pluginDir),
		Class: plugins.ClassExternal,
	}
	p.SetLogger(pluginslog.New("azure-allowlist-test"))

	// An empty forward_host_env_vars list, which is the shipped default, makes Grafana
	// pass only the explicit environment into the plugin process.
	mgmt := config.NewPluginManagementCfg(false, nil, nil, nil, "", "", config.Features{}, "", nil, nil, "")
	decorated, err := bootstrap.SkipHostEnvVarsDecorateFunc(mgmt)(context.Background(), p)
	require.NoError(t, err)
	require.True(t, decorated.SkipHostEnvVars)

	stage := initialization.New(mgmt, initialization.Opts{
		InitializeFuncs: []initialization.InitializeFunc{
			initialization.BackendClientInitStep(envProvider, provider.New(), pluginfakes.InitializeNoopTracerForTest()),
			initialization.BackendProcessStartStep(process.ProvideService()),
		},
	})
	_, err = stage.Initialize(context.Background(), decorated)
	require.Error(t, err, "probe executable is not a plugin and the handshake should fail")

	recorded, readErr := os.ReadFile(filepath.Join(pluginDir, "received.env"))
	require.NoError(t, readErr, "plugin process did not record its environment")
	return string(recorded)
}

func envKeys(envText string, keys ...string) []string {
	want := map[string]struct{}{}
	for _, key := range keys {
		want[key] = struct{}{}
	}
	var found []string
	for _, line := range strings.Split(envText, "\n") {
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if _, needed := want[key]; needed {
			found = append(found, key)
		}
	}
	return found
}

func envKeysWithPrefix(envText, prefix string) []string {
	var found []string
	for _, line := range strings.Split(envText, "\n") {
		key, _, ok := strings.Cut(line, "=")
		if ok && strings.HasPrefix(key, prefix) {
			found = append(found, key)
		}
	}
	return found
}

var (
	probeOnce sync.Once
	probePath string
	probeErr  error
)

func copyProbe(t *testing.T, pluginDir string) {
	t.Helper()
	probeOnce.Do(func() {
		probePath, probeErr = buildEnvProbe()
	})
	require.NoError(t, probeErr)

	name := "probe_" + strings.ToLower(runtime.GOOS) + "_" + strings.ToLower(runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	destination := filepath.Join(pluginDir, name)

	source, err := os.Open(probePath)
	require.NoError(t, err)
	defer source.Close()

	target, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	require.NoError(t, err)
	_, err = io.Copy(target, source)
	closeErr := target.Close()
	require.NoError(t, err)
	require.NoError(t, closeErr)
}

func buildEnvProbe() (string, error) {
	dir, err := os.MkdirTemp("", "azure-env-probe")
	if err != nil {
		return "", err
	}
	source := `package main

import (
	"os"
	"path/filepath"
	"strings"
)

func main() {
	exe, err := os.Executable()
	if err != nil {
		os.Exit(2)
	}
	payload := strings.Join(os.Environ(), "\n")
	path := filepath.Join(filepath.Dir(exe), "received.env")
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		os.Exit(3)
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "probe.go"), []byte(source), 0o600); err != nil {
		return "", err
	}
	out := filepath.Join(dir, "probe")
	cmd := exec.Command("go", "build", "-o", out, "probe.go")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GO111MODULE=off", "CGO_ENABLED=0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", &probeBuildError{err: err, output: output}
	}
	return out, nil
}

type probeBuildError struct {
	err    error
	output []byte
}

func (e *probeBuildError) Error() string {
	return e.err.Error() + ": " + string(e.output)
}
