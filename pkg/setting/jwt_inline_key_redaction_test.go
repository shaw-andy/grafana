package setting

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
)

// placeholderInlineKeyMaterial is an obvious stand-in for configured key
// material. It is not a credential.
const placeholderInlineKeyMaterial = "placeholder-not-a-secret"

func TestRedactedValueHidesInlineJWTKeyMaterial(t *testing.T) {
	t.Parallel()

	keys := []string{
		EnvKey("auth.jwt", "jwk_set_value"),
		EnvKey("auth.jwt", "key_value"),
		"auth.jwt.jwk_set_value",
		"auth.jwt.key_value",
		"default.auth.jwt.jwk_set_value",
		"default.auth.jwt.key_value",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			got := RedactedValue(key, placeholderInlineKeyMaterial)
			if got == placeholderInlineKeyMaterial || strings.Contains(got, placeholderInlineKeyMaterial) {
				t.Fatalf("redaction left inline JWT key material visible for %s", key)
			}
			require.Equal(t, RedactedPassword, got)
		})
	}

	t.Run("empty value stays empty", func(t *testing.T) {
		t.Parallel()
		require.Empty(t, RedactedValue(EnvKey("auth.jwt", "jwk_set_value"), ""))
		require.Empty(t, RedactedValue(EnvKey("auth.jwt", "key_value"), ""))
	})
}

func TestInlineJWTKeyMaterialIsRedactedFromStartupLog(t *testing.T) {
	logsDir := t.TempDir()
	dataDir := t.TempDir()
	t.Setenv("GF_PATHS_LOGS", logsDir)
	t.Setenv("GF_PATHS_DATA", dataDir)
	t.Setenv("GF_LOG_MODE", "file")
	t.Setenv("GF_AUTH_JWT_ENABLED", "true")
	t.Setenv(EnvKey("auth.jwt", "jwk_set_value"), placeholderInlineKeyMaterial)
	t.Setenv(EnvKey("auth.jwt", "key_value"), placeholderInlineKeyMaterial)

	cfg := NewCfg()
	require.NoError(t, cfg.Load(CommandLineArgs{HomePath: "../../"}))
	t.Cleanup(func() {
		_ = log.Close()
	})

	logText := readStartupLog(t, cfg)
	assertInlineKeyRedacted(t, "startup log", logText)
	assertOverrideRedacted(t, cfg.appliedEnvOverrides, EnvKey("auth.jwt", "jwk_set_value"))
	assertOverrideRedacted(t, cfg.appliedEnvOverrides, EnvKey("auth.jwt", "key_value"))

	bag := ProvideProvider(cfg).Current()
	assertSettingsBagRedactsInlineKeys(t, bag)

	// The process still needs the configured value. Redaction is only for
	// logs and the settings document.
	require.Equal(t, placeholderInlineKeyMaterial, cfg.JWTAuth.JWKSetValue)
	require.Equal(t, placeholderInlineKeyMaterial, cfg.JWTAuth.KeyValue)
	require.True(t, cfg.JWTAuth.Enabled)
}

func TestInlineJWTKeyMaterialFromINIIsRedactedInSettings(t *testing.T) {
	logsDir := t.TempDir()
	dataDir := t.TempDir()
	t.Setenv("GF_PATHS_LOGS", logsDir)
	t.Setenv("GF_PATHS_DATA", dataDir)
	t.Setenv("GF_LOG_MODE", "file")

	custom := filepath.Join(t.TempDir(), "custom.ini")
	body := "[auth.jwt]\nenabled = true\njwk_set_value = " + placeholderInlineKeyMaterial + "\nkey_value = " + placeholderInlineKeyMaterial + "\n"
	require.NoError(t, os.WriteFile(custom, []byte(body), 0o600))

	cfg := NewCfg()
	require.NoError(t, cfg.Load(CommandLineArgs{HomePath: "../../", Config: custom}))
	t.Cleanup(func() {
		_ = log.Close()
	})

	assertSettingsBagRedactsInlineKeys(t, ProvideProvider(cfg).Current())
	require.Equal(t, placeholderInlineKeyMaterial, cfg.JWTAuth.JWKSetValue)
	require.Equal(t, placeholderInlineKeyMaterial, cfg.JWTAuth.KeyValue)
}

func TestCommandLineInlineJWTKeyMaterialIsRedactedFromStartupLog(t *testing.T) {
	logsDir := t.TempDir()
	dataDir := t.TempDir()
	t.Setenv("GF_PATHS_LOGS", logsDir)
	t.Setenv("GF_PATHS_DATA", dataDir)
	t.Setenv("GF_LOG_MODE", "file")

	cfg := NewCfg()
	require.NoError(t, cfg.Load(CommandLineArgs{
		HomePath: "../../",
		Args: []string{
			"cfg:default.auth.jwt.jwk_set_value=" + placeholderInlineKeyMaterial,
			"cfg:default.auth.jwt.key_value=" + placeholderInlineKeyMaterial,
			"cfg:auth.jwt.jwk_set_value=" + placeholderInlineKeyMaterial,
			"cfg:auth.jwt.key_value=" + placeholderInlineKeyMaterial,
		},
	}))
	t.Cleanup(func() {
		_ = log.Close()
	})

	logText := readStartupLog(t, cfg)
	assertInlineKeyRedacted(t, "startup log", logText)
	assertOverrideRedacted(t, cfg.appliedCommandLineProperties, "default.auth.jwt.jwk_set_value")
	assertOverrideRedacted(t, cfg.appliedCommandLineProperties, "default.auth.jwt.key_value")
	assertOverrideRedacted(t, cfg.appliedCommandLineProperties, "auth.jwt.jwk_set_value")
	assertOverrideRedacted(t, cfg.appliedCommandLineProperties, "auth.jwt.key_value")
	assertSettingsBagRedactsInlineKeys(t, ProvideProvider(cfg).Current())
}

func assertSettingsBagRedactsInlineKeys(t *testing.T, bag SettingsBag) {
	t.Helper()
	section, ok := bag["auth.jwt"]
	require.True(t, ok, "auth.jwt section missing from settings document")
	for _, key := range []string{"jwk_set_value", "key_value"} {
		got := section[key]
		if got == placeholderInlineKeyMaterial || strings.Contains(got, placeholderInlineKeyMaterial) {
			t.Errorf("settings document contains inline JWT key material for auth.jwt %s", key)
		}
		if got != RedactedPassword {
			t.Errorf("settings document did not redact auth.jwt %s", key)
		}
	}
}

func assertOverrideRedacted(t *testing.T, overrides []string, name string) {
	t.Helper()
	prefix := name + "="
	found := false
	for _, line := range overrides {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		found = true
		if strings.Contains(line, placeholderInlineKeyMaterial) || line != prefix+RedactedPassword {
			t.Errorf("override %s is not redacted", name)
		}
	}
	if !found {
		t.Errorf("override %s was not recorded", name)
	}
}

func assertInlineKeyRedacted(t *testing.T, where, text string) {
	t.Helper()
	if strings.Contains(text, placeholderInlineKeyMaterial) {
		t.Errorf("%s contains inline JWT key material", where)
	}
}

func readStartupLog(t *testing.T, cfg *Cfg) string {
	t.Helper()
	path := filepath.Join(cfg.LogsPath, "grafana.log")
	// Logging writes the file directly. Read it back from the path config selected.
	body, err := os.ReadFile(path)
	require.NoError(t, err, "startup log file")
	return string(body)
}
