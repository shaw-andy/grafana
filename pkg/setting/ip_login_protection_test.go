package setting

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"
)

// IP login protection has to be on for a default install, including when the
// security key is missing, so one client cannot keep trying other accounts
// after the attempt limit.
func TestShippedDefaultsEnableIPLoginProtection(t *testing.T) {
	cfg := loadSecurityCfg(t, false)
	assertIPLoginProtectionOn(t, cfg)
}

func TestAbsentIPLoginProtectionKeyEnablesLimit(t *testing.T) {
	cfg := loadSecurityCfg(t, true)
	assertIPLoginProtectionOn(t, cfg)
}

func assertIPLoginProtectionOn(t *testing.T, cfg *Cfg) {
	t.Helper()
	require.False(t, cfg.DisableBruteForceLoginProtection)
	require.False(t, cfg.DisableUsernameLoginProtection)
	require.False(t, cfg.DisableIPAddressLoginProtection)
	require.Equal(t, int64(5), cfg.BruteForceLoginProtectionMaxAttempts)
}

func loadSecurityCfg(t *testing.T, stripIPKey bool) *Cfg {
	t.Helper()
	// An environment override would hide the shipped default this test loads.
	t.Setenv("GF_SECURITY_DISABLE_BRUTE_FORCE_LOGIN_PROTECTION", "")
	t.Setenv("GF_SECURITY_DISABLE_USERNAME_LOGIN_PROTECTION", "")
	t.Setenv("GF_SECURITY_DISABLE_IP_ADDRESS_LOGIN_PROTECTION", "")
	t.Setenv("GF_SECURITY_BRUTE_FORCE_LOGIN_PROTECTION_MAX_ATTEMPTS", "")

	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	shipped := filepath.Join(root, "conf", "defaults.ini")

	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, "conf"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "data", "log"), 0o755))

	if stripIPKey {
		parsed, err := ini.Load(shipped)
		require.NoError(t, err)
		parsed.Section("security").DeleteKey("disable_ip_address_login_protection")
		require.NoError(t, parsed.SaveTo(filepath.Join(home, "conf", "defaults.ini")))
	} else {
		body, err := os.ReadFile(shipped)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(home, "conf", "defaults.ini"), body, 0o644))
	}

	cfg := NewCfg()
	require.NoError(t, cfg.Load(CommandLineArgs{
		HomePath: home,
		Config:   filepath.Join(home, "conf", "defaults.ini"),
	}))
	return cfg
}
