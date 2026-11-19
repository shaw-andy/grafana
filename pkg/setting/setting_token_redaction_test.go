package setting

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
)

const (
	// Obvious placeholders. These stand in for the NATS bus token and the
	// external snapshot bearer token; they are not real credentials.
	natsBusTokenPlaceholder        = "placeholder-nats-bus-token"
	snapshotBearerTokenPlaceholder = "placeholder-snapshot-bearer-token"
	zanzanaClientTokenPlaceholder  = "placeholder-zanzana-client-token"
)

// TestBusAndSnapshotTokensAreRedactedBeforeLogsAndSettings drives the startup
// configuration load that records environment and command-line overrides, then
// the settings document returned by the admin settings provider. The displayed
// values must be the redaction placeholder. The configured values themselves
// stay available to the NATS client and the external snapshot client.
func TestBusAndSnapshotTokensAreRedactedBeforeLogsAndSettings(t *testing.T) {
	skipStaticRootValidation = true

	t.Run("environment overrides are redacted in the startup log and the settings document", func(t *testing.T) {
		t.Setenv("GF_NATS_ENABLED", "true")
		t.Setenv("GF_NATS_AUTH_MODE", "token")
		t.Setenv("GF_NATS_TOKEN", natsBusTokenPlaceholder)
		t.Setenv("GF_SNAPSHOTS_EXTERNAL_SNAPSHOT_TOKEN", snapshotBearerTokenPlaceholder)
		// Read during startup through DynamicSection, which logs with the same helper.
		t.Setenv("GF_ZANZANA_CLIENT_TOKEN", zanzanaClientTokenPlaceholder)

		cfg, logs := loadWithCapture(t, CommandLineArgs{HomePath: "../../"})

		require.Equal(t, natsBusTokenPlaceholder, cfg.NATS.Auth.Token)
		require.Equal(t, NATSAuthModeToken, cfg.NATS.Auth.Mode)
		require.True(t, cfg.NATS.Enabled)
		require.Equal(t, snapshotBearerTokenPlaceholder, cfg.ExternalSnapshotToken)
		require.Equal(t, zanzanaClientTokenPlaceholder, cfg.ZanzanaClient.Token)

		loggedTokens := tokenLogLines(logs)
		requireNoSecret(t, loggedTokens, natsBusTokenPlaceholder, snapshotBearerTokenPlaceholder, zanzanaClientTokenPlaceholder)
		requireRedactedOverride(t, cfg.appliedEnvOverrides, "GF_NATS_TOKEN", natsBusTokenPlaceholder)
		requireRedactedOverride(t, cfg.appliedEnvOverrides, "GF_SNAPSHOTS_EXTERNAL_SNAPSHOT_TOKEN", snapshotBearerTokenPlaceholder)
		requireNoSecret(t, strings.Join(cfg.appliedEnvOverrides, "\n"), natsBusTokenPlaceholder, snapshotBearerTokenPlaceholder, zanzanaClientTokenPlaceholder)
		require.Contains(t, loggedTokens, "GF_NATS_TOKEN="+RedactedPassword)
		require.Contains(t, loggedTokens, "GF_SNAPSHOTS_EXTERNAL_SNAPSHOT_TOKEN="+RedactedPassword)
		require.Contains(t, loggedTokens, "GF_ZANZANA_CLIENT_TOKEN="+RedactedPassword)

		assertSettingsDocumentRedacts(t, cfg, map[string]map[string]string{
			"nats":           {"token": natsBusTokenPlaceholder},
			"snapshots":      {"external_snapshot_token": snapshotBearerTokenPlaceholder},
			"zanzana.client": {"token": zanzanaClientTokenPlaceholder},
		})
	})

	t.Run("ini file values are redacted in the settings document", func(t *testing.T) {
		configPath := writeTokenConfig(t, `[nats]
enabled = true
auth_mode = token
token = `+natsBusTokenPlaceholder+`

[snapshots]
external_snapshot_token = `+snapshotBearerTokenPlaceholder+`
`)
		cfg, logs := loadWithCapture(t, CommandLineArgs{HomePath: "../../", Config: configPath})

		require.Equal(t, natsBusTokenPlaceholder, cfg.NATS.Auth.Token)
		require.Equal(t, snapshotBearerTokenPlaceholder, cfg.ExternalSnapshotToken)
		requireNoSecret(t, tokenLogLines(logs), natsBusTokenPlaceholder, snapshotBearerTokenPlaceholder)
		assertSettingsDocumentRedacts(t, cfg, map[string]map[string]string{
			"nats":      {"token": natsBusTokenPlaceholder},
			"snapshots": {"external_snapshot_token": snapshotBearerTokenPlaceholder},
		})
	})

	t.Run("command line default overrides are redacted in the startup log and the settings document", func(t *testing.T) {
		cfg, logs := loadWithCapture(t, CommandLineArgs{
			HomePath: "../../",
			Args: []string{
				"cfg:default.nats.enabled=true",
				"cfg:default.nats.auth_mode=token",
				"cfg:default.nats.token=" + natsBusTokenPlaceholder,
				"cfg:default.snapshots.external_snapshot_token=" + snapshotBearerTokenPlaceholder,
			},
		})

		require.Equal(t, natsBusTokenPlaceholder, cfg.NATS.Auth.Token)
		require.Equal(t, snapshotBearerTokenPlaceholder, cfg.ExternalSnapshotToken)
		loggedTokens := tokenLogLines(logs)
		requireNoSecret(t, loggedTokens, natsBusTokenPlaceholder, snapshotBearerTokenPlaceholder)
		requireRedactedOverride(t, cfg.appliedCommandLineProperties, "default.nats.token", natsBusTokenPlaceholder)
		requireRedactedOverride(t, cfg.appliedCommandLineProperties, "default.snapshots.external_snapshot_token", snapshotBearerTokenPlaceholder)
		requireNoSecret(t, strings.Join(cfg.appliedCommandLineProperties, "\n"), natsBusTokenPlaceholder, snapshotBearerTokenPlaceholder)
		require.Contains(t, loggedTokens, "default.nats.token="+RedactedPassword)
		require.Contains(t, loggedTokens, "default.snapshots.external_snapshot_token="+RedactedPassword)

		assertSettingsDocumentRedacts(t, cfg, map[string]map[string]string{
			"nats":      {"token": natsBusTokenPlaceholder},
			"snapshots": {"external_snapshot_token": snapshotBearerTokenPlaceholder},
		})
	})
}

func loadWithCapture(t *testing.T, args CommandLineArgs) (*Cfg, string) {
	t.Helper()
	logger := &captureLogger{}
	cfg := NewCfg()
	cfg.Logger = logger
	require.NoError(t, cfg.Load(args))
	return cfg, logger.String()
}

func assertSettingsDocumentRedacts(t *testing.T, cfg *Cfg, secrets map[string]map[string]string) {
	t.Helper()
	document := ProvideProvider(cfg).Current()
	encoded, err := json.Marshal(document)
	require.NoError(t, err)
	for section, keys := range secrets {
		for key, secret := range keys {
			require.Equal(t, secret, cfg.Raw.Section(section).Key(key).Value())
			require.Equal(t, RedactedPassword, document[section][key])
			require.NotContains(t, string(encoded), secret)
		}
	}
}

func requireRedactedOverride(t *testing.T, overrides []string, key, secret string) {
	t.Helper()
	require.Contains(t, overrides, key+"="+RedactedPassword)
	for _, line := range overrides {
		if strings.HasPrefix(line, key+"=") {
			require.NotContains(t, line, secret)
		}
	}
}

func tokenLogLines(logs string) string {
	var b strings.Builder
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(strings.ToUpper(line), "TOKEN") {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func requireNoSecret(t *testing.T, haystack string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		require.NotContains(t, haystack, secret)
	}
}

func writeTokenConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "custom.ini")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// captureLogger records info lines emitted while configuration is loaded.
type captureLogger struct {
	info []string
}

func (c *captureLogger) New(ctx ...any) *log.ConcreteLogger {
	return log.NewNopLogger()
}

func (c *captureLogger) Log(keyvals ...any) error { return nil }

func (c *captureLogger) Debug(string, ...any) {}

func (c *captureLogger) Info(msg string, ctx ...any) {
	c.info = append(c.info, formatLog(msg, ctx))
}

func (c *captureLogger) Warn(string, ...any) {}

func (c *captureLogger) Error(string, ...any) {}

func (c *captureLogger) FromContext(context.Context) log.Logger { return c }

func (c *captureLogger) String() string {
	return strings.Join(c.info, "\n")
}

func formatLog(msg string, ctx []any) string {
	parts := make([]string, 0, len(ctx)+1)
	parts = append(parts, msg)
	for _, value := range ctx {
		parts = append(parts, fmt.Sprint(value))
	}
	return strings.Join(parts, " ")
}
