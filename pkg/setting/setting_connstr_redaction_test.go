package setting

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	gokitlog "github.com/go-kit/log"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/infra/log"
)

// connstrSecretPlaceholder is an obvious stand-in for a connection-string
// credential. These tests fail while that value is still present in redacted
// settings, startup logs, or the settings provider.
const connstrSecretPlaceholder = "connstr-secret-placeholder"

func redisCacheConnStr(secret string) string {
	return "network=tcp,addr=127.0.0.1:6379,pool_size=100,db=0,username=grafana,password=" + secret + ",ssl=false"
}

func postgresKeywordConnStr(secret string) string {
	return "host=127.0.0.1 port=5432 user=grafana password=" + secret + " dbname=annotations sslmode=disable"
}

func postgresURLConnStr(secret string) string {
	return "postgres://grafana:" + secret + "@127.0.0.1:5432/annotations?sslmode=disable"
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "conf", "defaults.ini")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir)
		dir = parent
	}
}

func withCapturedStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()

	closed := false
	defer func() {
		os.Stdout = orig
		if !closed {
			_ = w.Close()
			<-done
		}
		_ = r.Close()
	}()

	fn()
	os.Stdout = orig
	require.NoError(t, w.Close())
	closed = true
	<-done
	return buf.String()
}

func requireCredentialRemoved(t *testing.T, sink, output, secret string, markers ...string) {
	t.Helper()
	require.NotContains(t, output, secret, sink)
	if output == RedactedPassword || strings.TrimSpace(output) == RedactedPassword {
		return
	}
	for _, marker := range markers {
		require.Contains(t, output, marker, sink)
	}
}

func overrideLine(overrides []string, envKey string) string {
	for _, line := range overrides {
		if strings.HasPrefix(line, envKey+"=") {
			return line
		}
	}
	return ""
}

func TestConnectionStringPasswordFieldsAreRedacted(t *testing.T) {
	t.Run("redis cache connection string", func(t *testing.T) {
		value := redisCacheConnStr(connstrSecretPlaceholder)
		got := RedactedValue(EnvKey("remote_cache", "connstr"), value)
		requireCredentialRemoved(t, "RedactedValue", got, connstrSecretPlaceholder, "addr=127.0.0.1:6379", "username=grafana")
	})

	t.Run("postgres keyword connection string", func(t *testing.T) {
		value := postgresKeywordConnStr(connstrSecretPlaceholder)
		parsed, err := pgxpool.ParseConfig(value)
		require.NoError(t, err)
		require.Equal(t, connstrSecretPlaceholder, parsed.ConnConfig.Password)

		got := RedactedValue(EnvKey("annotations.app_platform", "postgres_connection_string"), value)
		requireCredentialRemoved(t, "RedactedValue", got, connstrSecretPlaceholder, "host=127.0.0.1", "user=grafana")
	})

	t.Run("passwd field on a setting whose name is not a secret", func(t *testing.T) {
		value := "host=127.0.0.1 user=grafana passwd=" + connstrSecretPlaceholder + " dbname=annotations"
		got := RedactedValue("GF_CUSTOM_DSN", value)
		requireCredentialRemoved(t, "RedactedValue", got, connstrSecretPlaceholder, "host=127.0.0.1", "user=grafana")
	})

	t.Run("url userinfo password stays redacted", func(t *testing.T) {
		value := postgresURLConnStr(connstrSecretPlaceholder)
		got := RedactedValue(EnvKey("annotations.app_platform", "postgres_connection_string"), value)
		requireCredentialRemoved(t, "RedactedValue", got, connstrSecretPlaceholder, "127.0.0.1:5432")
	})
}

func TestConnectionStringPasswordsStayOutOfStartupLog(t *testing.T) {
	skipStaticRootValidation = true
	secret := connstrSecretPlaceholder
	redisValue := redisCacheConnStr(secret)
	postgresValue := postgresKeywordConnStr(secret)
	const altEnv = "GF_REMOTE_CACHE_ALT_CONN"

	t.Setenv("GF_LOG_MODE", "console")
	t.Setenv("GF_PATHS_DATA", t.TempDir())
	t.Setenv("GF_PATHS_LOGS", t.TempDir())
	t.Setenv("GF_REMOTE_CACHE_TYPE", "redis")
	t.Setenv(EnvKey("remote_cache", "connstr"), redisValue)
	t.Setenv(EnvKey("annotations.app_platform", "postgres_connection_string"), postgresValue)
	// Key is not in defaults.ini, so the second env-override pass records it.
	t.Setenv(altEnv, redisValue)

	var cfg *Cfg
	stdout := withCapturedStdout(t, func() {
		cfg = NewCfg()
		require.NoError(t, cfg.Load(CommandLineArgs{HomePath: repoRoot(t)}))
		// DynamicSection logs the same helper when a section is read after startup.
		_ = cfg.SectionWithEnvOverrides("remote_cache").Key("connstr").Value()
		_ = cfg.SectionWithEnvOverrides("annotations.app_platform").Key("postgres_connection_string").Value()
	})

	require.Contains(t, cfg.RemoteCacheOptions.ConnStr, "password="+secret)
	require.Equal(t, "redis", cfg.RemoteCacheOptions.Name)
	require.Contains(t, cfg.AnnotationAppPlatform.PostgresConnectionString, "password="+secret)
	require.Contains(t, stdout, EnvKey("remote_cache", "connstr"))
	require.Contains(t, stdout, EnvKey("annotations.app_platform", "postgres_connection_string"))
	require.Contains(t, stdout, altEnv)
	requireCredentialRemoved(t, "startup log", stdout, secret, EnvKey("remote_cache", "connstr"))

	for _, envKey := range []string{
		EnvKey("remote_cache", "connstr"),
		EnvKey("annotations.app_platform", "postgres_connection_string"),
		altEnv,
	} {
		line := overrideLine(cfg.appliedEnvOverrides, envKey)
		require.NotEmpty(t, line, envKey)
		requireCredentialRemoved(t, envKey, line, secret, envKey)
	}

	bag := ProvideProvider(cfg).Current()
	requireCredentialRemoved(t, "settings provider remote_cache.connstr", bag["remote_cache"]["connstr"], secret, "addr=127.0.0.1:6379")
	requireCredentialRemoved(t,
		"settings provider annotations.app_platform.postgres_connection_string",
		bag["annotations.app_platform"]["postgres_connection_string"],
		secret,
		"host=127.0.0.1",
	)
	requireCredentialRemoved(t, "settings provider remote_cache.alt_conn", bag["remote_cache"]["alt_conn"], secret, "addr=127.0.0.1:6379")
}

func TestURLConnectionStringPasswordStaysOutOfStartupLog(t *testing.T) {
	skipStaticRootValidation = true
	secret := connstrSecretPlaceholder
	value := postgresURLConnStr(secret)
	envKey := EnvKey("annotations.app_platform", "postgres_connection_string")

	t.Setenv("GF_LOG_MODE", "console")
	t.Setenv("GF_PATHS_DATA", t.TempDir())
	t.Setenv("GF_PATHS_LOGS", t.TempDir())
	t.Setenv(envKey, value)

	var cfg *Cfg
	stdout := withCapturedStdout(t, func() {
		cfg = NewCfg()
		require.NoError(t, cfg.Load(CommandLineArgs{HomePath: repoRoot(t)}))
	})

	require.Equal(t, value, cfg.AnnotationAppPlatform.PostgresConnectionString)
	line := overrideLine(cfg.appliedEnvOverrides, envKey)
	require.NotEmpty(t, line)
	requireCredentialRemoved(t, envKey, line, secret, "127.0.0.1")
	require.Contains(t, stdout, envKey)
	requireCredentialRemoved(t, "startup log", stdout, secret, envKey)

	published := ProvideProvider(cfg).Current()["annotations.app_platform"]["postgres_connection_string"]
	requireCredentialRemoved(t, "settings provider", published, secret, "127.0.0.1")
}

func TestCommandLineDefaultConnectionStringIsRedactedInStartupLog(t *testing.T) {
	secret := connstrSecretPlaceholder
	redisValue := redisCacheConnStr(secret)

	cfg := NewCfg()
	file := ini.Empty()
	section, err := file.NewSection("remote_cache")
	require.NoError(t, err)
	_, err = section.NewKey("connstr", "")
	require.NoError(t, err)

	cfg.commandLineProps = map[string]string{
		"default.remote_cache.connstr": redisValue,
	}
	cfg.applyCommandLineDefaultProperties(file)

	require.Equal(t, redisValue, file.Section("remote_cache").Key("connstr").Value())
	line := overrideLine(cfg.appliedCommandLineProperties, "default.remote_cache.connstr")
	require.NotEmpty(t, line)
	requireCredentialRemoved(t, "command line default", line, secret, "default.remote_cache.connstr")

	logger, ok := cfg.Logger.(*log.ConcreteLogger)
	require.True(t, ok)
	var buf bytes.Buffer
	logger.Swap(gokitlog.NewLogfmtLogger(&buf))
	cfg.LogConfigSources()
	require.Contains(t, buf.String(), "default.remote_cache.connstr")
	requireCredentialRemoved(t, "LogConfigSources", buf.String(), secret, "default.remote_cache.connstr")
}
