package pluginsintegration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/setting"
)

func TestEmptySecretDoesNotInstallPluginRequestIDMiddleware(t *testing.T) {
	disabled := loadIPRangeCfg(t, "enabled = false\nallow_list = https://logs.example.test\n")
	empty := loadIPRangeCfg(t, "enabled = true\nallow_list = https://logs.example.test\n")
	configured := loadIPRangeCfg(t, "enabled = true\nsecret_key = test-signing-key\nallow_list = https://logs.example.test\n")

	require.False(t, disabled.IPRangeACEnabled)
	require.Empty(t, empty.IPRangeACSecretKey)
	require.True(t, configured.IPRangeACEnabled)

	disabledCount := middlewareCount(disabled)
	require.Equal(t, disabledCount, middlewareCount(empty), "signing middleware must not be installed when secret_key is empty")
	require.Equal(t, disabledCount+1, middlewareCount(configured), "a configured signing key still installs the middleware")
	require.False(t, empty.IPRangeACEnabled, "IP range access control must stay disabled when secret_key is empty")
}

func middlewareCount(cfg *setting.Cfg) int {
	middlewares := CreateMiddlewares(cfg, nil, nil, nil, nil, prometheus.NewRegistry(), nil)
	return len(middlewares)
}

func loadIPRangeCfg(t *testing.T, body string) *setting.Cfg {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.ini")
	require.NoError(t, os.WriteFile(path, []byte("[datasources.ip_range_security]\n"+body), 0o600))
	cfg := setting.NewCfg()
	err := cfg.Load(setting.CommandLineArgs{
		HomePath: filepath.Join("..", "..", ".."),
		Config:   path,
	})
	require.NoError(t, err)
	return cfg
}
