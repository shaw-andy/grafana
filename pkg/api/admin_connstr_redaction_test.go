package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

func TestAdminGetSettingsRedactsConnectionStringPasswords(t *testing.T) {
	const secret = "connstr-secret-placeholder"
	redisValue := "network=tcp,addr=127.0.0.1:6379,pool_size=100,db=0,username=grafana,password=" + secret + ",ssl=false"
	postgresValue := "host=127.0.0.1 port=5432 user=grafana password=" + secret + " dbname=annotations sslmode=disable"

	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(root, "conf", "defaults.ini")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		require.NotEqual(t, parent, root)
		root = parent
	}

	t.Setenv("GF_LOG_MODE", "console")
	t.Setenv("GF_PATHS_DATA", t.TempDir())
	t.Setenv("GF_PATHS_LOGS", t.TempDir())
	t.Setenv(setting.EnvKey("remote_cache", "connstr"), redisValue)
	t.Setenv(setting.EnvKey("annotations.app_platform", "postgres_connection_string"), postgresValue)

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{HomePath: root}))
	require.Contains(t, cfg.RemoteCacheOptions.ConnStr, "password="+secret)
	require.Contains(t, cfg.AnnotationAppPlatform.PostgresConnectionString, "password="+secret)

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		// Route registration touches public-dashboard middleware only when this
		// flag is on. The settings request does not use that middleware.
		cfg.PublicDashboardsEnabled = false
		hs.Cfg = cfg
		hs.SettingsProvider = setting.ProvideProvider(cfg)
	})

	res, err := server.Send(webtest.RequestWithSignedInUser(
		server.NewGetRequest("/api/admin/settings"),
		userWithPermissions(1, []accesscontrol.Permission{{
			Action: accesscontrol.ActionSettingsRead,
			Scope:  accesscontrol.ScopeSettingsAll,
		}}),
	))
	require.NoError(t, err)
	defer func() {
		require.NoError(t, res.Body.Close())
	}()
	require.Equal(t, http.StatusOK, res.StatusCode)

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	var settings map[string]map[string]string
	require.NoError(t, json.Unmarshal(body, &settings))

	connstr := settings["remote_cache"]["connstr"]
	postgres := settings["annotations.app_platform"]["postgres_connection_string"]
	require.NotEmpty(t, connstr)
	require.NotEmpty(t, postgres)
	require.NotContains(t, connstr, secret)
	require.NotContains(t, postgres, secret)
	require.NotContains(t, string(body), secret)
	if connstr != setting.RedactedPassword {
		require.Contains(t, connstr, "addr=127.0.0.1:6379")
	}
	if postgres != setting.RedactedPassword {
		require.Contains(t, postgres, "host=127.0.0.1")
	}
}
