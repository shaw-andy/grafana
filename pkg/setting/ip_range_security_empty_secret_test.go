package setting

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// IP range access control must stay off when the signing key is empty.
// These tests fail while an empty secret_key still leaves the feature enabled.
func TestIPRangeAccessControlStaysDisabledWhenSecretKeyIsEmpty(t *testing.T) {
	t.Run("custom ini omits secret_key", func(t *testing.T) {
		cfg := loadIPRangeSecurityCfg(t, ""+
			"enabled = true\n"+
			"allow_list = https://logs.example.test\n")
		requireIPRangeDisabled(t, cfg)
	})

	t.Run("custom ini sets secret_key to an empty value", func(t *testing.T) {
		cfg := loadIPRangeSecurityCfg(t, ""+
			"enabled = true\n"+
			"secret_key =\n"+
			"allow_list = https://logs.example.test\n")
		requireIPRangeDisabled(t, cfg)
	})

	t.Run("ini bytes set secret_key to an empty value", func(t *testing.T) {
		cfg, err := NewCfgFromBytes([]byte("" +
			"[datasources.ip_range_security]\n" +
			"enabled = true\n" +
			"secret_key =\n" +
			"allow_list = https://logs.example.test\n"))
		require.NoError(t, err)
		requireIPRangeDisabled(t, cfg)
	})
}

func TestIPRangeAccessControlStaysEnabledWhenSecretKeyIsConfigured(t *testing.T) {
	cfg := loadIPRangeSecurityCfg(t, ""+
		"enabled = true\n"+
		"secret_key = test-signing-key\n"+
		"allow_list = https://logs.example.test\n")
	require.True(t, cfg.IPRangeACEnabled)
	require.Equal(t, "test-signing-key", cfg.IPRangeACSecretKey)
	require.NotEmpty(t, cfg.IPRangeACAllowedURLs)
	require.Equal(t, "https", cfg.IPRangeACAllowedURLs[0].Scheme)
	require.Equal(t, "logs.example.test", cfg.IPRangeACAllowedURLs[0].Host)
}

func loadIPRangeSecurityCfg(t *testing.T, body string) *Cfg {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.ini")
	content := "[datasources.ip_range_security]\n" + body
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	cfg := NewCfg()
	err := cfg.Load(CommandLineArgs{
		HomePath: filepath.Join("..", ".."),
		Config:   path,
	})
	require.NoError(t, err)
	return cfg
}

func requireIPRangeDisabled(t *testing.T, cfg *Cfg) {
	t.Helper()
	require.Empty(t, cfg.IPRangeACSecretKey)
	require.NotEmpty(t, cfg.IPRangeACAllowedURLs, "allow list must still be parsed so a later check cannot drop it to hide signing")
	require.False(t, cfg.IPRangeACEnabled, "IP range access control must stay disabled when secret_key is empty")
}
