package setting

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
)

// TestCommandLineOverridesAreRedactedInStartupLog loads Grafana with cfg:
// arguments and reads the startup log produced by LogConfigSources.
//
// Sensitive overrides must be recorded and logged as the string RedactedValue
// already returns for that key. The setting itself must still take the
// override. A non-sensitive override must stay visible. cfg:default.* is
// already redacted before it is recorded; that record must stay redacted.
func TestCommandLineOverridesAreRedactedInStartupLog(t *testing.T) {
	skipStaticRootValidation = true

	const (
		dbPassword        = "placeholder-db-password"
		smtpPassword      = "placeholder-smtp-password"
		adminPassword     = "placeholder-admin-password"
		metricsPassword   = "placeholder-metrics-password"
		secretKey         = "placeholder-secret-key"
		clientSecret      = "placeholder-client-secret"
		rendererToken     = "placeholder-renderer-token"
		apiToken          = "placeholder-api-token"
		proxyToken        = "placeholder-proxy-token"
		accountKey        = "placeholder-account-key"
		dbURLPassword     = "placeholder-db-url-password"
		defaultDBPassword = "placeholder-default-db-password"
		instanceName      = "placeholder-instance-name"
	)
	dbURL := "mysql://dbuser:" + dbURLPassword + "@127.0.0.1:3306/grafana"

	logsDir := t.TempDir()
	cfg := NewCfg()
	err := cfg.Load(CommandLineArgs{
		HomePath: "../../",
		Args: []string{
			"cfg:log.mode=file",
			"cfg:paths.logs=" + logsDir,
			"cfg:default.database.password=" + defaultDBPassword,
			"cfg:database.password=" + dbPassword,
			"cfg:database.url=" + dbURL,
			"cfg:smtp.password=" + smtpPassword,
			"cfg:security.admin_password=" + adminPassword,
			"cfg:security.secret_key=" + secretKey,
			"cfg:metrics.basic_auth_password=" + metricsPassword,
			"cfg:auth.github.client_secret=" + clientSecret,
			"cfg:rendering.renderer_token=" + rendererToken,
			"cfg:grafana_com.sso_api_token=" + apiToken,
			"cfg:grafana_com.proxy_token=" + proxyToken,
			"cfg:external_image_storage.azure_blob.account_key=" + accountKey,
			"cfg:instance_name=" + instanceName,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = log.Close() })
	require.NoError(t, log.Close())

	logBytes, err := os.ReadFile(filepath.Join(logsDir, "grafana.log"))
	require.NoError(t, err)
	logText := string(logBytes)
	require.Contains(t, logText, "Config overridden from command line")

	// The override has to be the value Grafana will use. Redaction is only
	// about what the startup log records.
	require.Equal(t, dbPassword, cfg.Raw.Section("database").Key("password").String())
	require.Equal(t, dbURL, cfg.Raw.Section("database").Key("url").String())
	require.Equal(t, smtpPassword, cfg.Smtp.Password)
	require.Equal(t, adminPassword, cfg.AdminPassword)
	require.Equal(t, secretKey, cfg.SecretKey)
	require.Equal(t, metricsPassword, cfg.MetricsEndpointBasicAuthPassword)
	require.Equal(t, clientSecret, cfg.Raw.Section("auth.github").Key("client_secret").String())
	require.Equal(t, rendererToken, cfg.RendererAuthToken)
	require.Equal(t, apiToken, cfg.GrafanaComSSOAPIToken)
	require.Equal(t, proxyToken, cfg.GrafanaComProxyAPIToken)
	require.Equal(t, accountKey, cfg.Raw.Section("external_image_storage.azure_blob").Key("account_key").String())
	require.Equal(t, instanceName, cfg.InstanceName)

	cases := []struct {
		key       string
		raw       string
		leak      string
		sensitive bool
	}{
		{key: "database.password", raw: dbPassword, sensitive: true},
		// database.url is not a password key. RedactedValue still hides the
		// userinfo password via RedactedURL. The leak is that password.
		{key: "database.url", raw: dbURL, leak: dbURLPassword, sensitive: true},
		{key: "smtp.password", raw: smtpPassword, sensitive: true},
		{key: "security.admin_password", raw: adminPassword, sensitive: true},
		{key: "security.secret_key", raw: secretKey, sensitive: true},
		{key: "metrics.basic_auth_password", raw: metricsPassword, sensitive: true},
		{key: "auth.github.client_secret", raw: clientSecret, sensitive: true},
		{key: "rendering.renderer_token", raw: rendererToken, sensitive: true},
		{key: "grafana_com.sso_api_token", raw: apiToken, sensitive: true},
		{key: "grafana_com.proxy_token", raw: proxyToken, sensitive: true},
		{key: "external_image_storage.azure_blob.account_key", raw: accountKey, sensitive: true},
		{key: "default.database.password", raw: defaultDBPassword, sensitive: true},
		{key: "instance_name", raw: instanceName, sensitive: false},
		{key: "log.mode", raw: "file", sensitive: false},
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			redacted := RedactedValue(tc.key, tc.raw)
			leak := tc.raw
			if tc.leak != "" {
				leak = tc.leak
			}
			if tc.sensitive {
				require.NotEqual(t, tc.raw, redacted)
				require.NotContains(t, redacted, leak)
			} else {
				require.Equal(t, tc.raw, redacted)
			}

			recorded, ok := commandLineOverrideValue(cfg.appliedCommandLineProperties, tc.key)
			require.True(t, ok, "cfg override was not recorded")
			require.Equal(t, redacted, recorded)
			require.Contains(t, logText, tc.key+"="+redacted)
			if tc.sensitive {
				// The startup log is the record a log reader sees. The raw
				// override must not appear on any line, including the
				// command-line override line.
				require.NotContains(t, logText, leak)
			}
		})
	}
}

func commandLineOverrideValue(records []string, key string) (string, bool) {
	for _, record := range records {
		name, value, ok := strings.Cut(record, "=")
		if ok && name == key {
			return value, true
		}
	}
	return "", false
}
