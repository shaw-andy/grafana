package api

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

func TestAdminGetSettingsRedactsInlineJWTKeySet(t *testing.T) {
	const kid = "placeholder-kid"
	key := placeholderOctetKey(32)
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       key,
		KeyID:     kid,
		Algorithm: string(jose.HS256),
		Use:       "sig",
	}}})
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(raw)

	logsDir := t.TempDir()
	dataDir := t.TempDir()
	t.Setenv("GF_PATHS_LOGS", logsDir)
	t.Setenv("GF_PATHS_DATA", dataDir)
	t.Setenv("GF_LOG_MODE", "file")
	t.Setenv("GF_AUTH_JWT_ENABLED", "true")
	t.Setenv(setting.EnvKey("auth.jwt", "jwk_set_value"), encoded)
	t.Setenv(setting.EnvKey("auth.jwt", "key_value"), "placeholder-not-a-secret")

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{HomePath: "../../"}))
	t.Cleanup(func() {
		_ = log.Close()
	})
	// The loaded defaults turn on routes whose handlers are not part of this
	// request. Leave those routes unregistered so the settings API can be served.
	cfg.PublicDashboardsEnabled = false

	cases := []struct {
		name        string
		permissions []accesscontrol.Permission
	}{
		{
			name: "settings reader",
			permissions: []accesscontrol.Permission{{
				Action: accesscontrol.ActionSettingsRead,
				Scope:  accesscontrol.ScopeSettingsAll,
			}},
		},
		{
			name: "auth.jwt section reader",
			permissions: []accesscontrol.Permission{{
				Action: accesscontrol.ActionSettingsRead,
				Scope:  accesscontrol.Scope("settings", "auth.jwt", "*"),
			}},
		},
		{
			name: "jwk_set_value reader",
			permissions: []accesscontrol.Permission{{
				Action: accesscontrol.ActionSettingsRead,
				Scope:  accesscontrol.Scope("settings", "auth.jwt", "jwk_set_value"),
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := SetupAPITestServer(t, func(hs *HTTPServer) {
				hs.Cfg = cfg
				hs.SettingsProvider = setting.ProvideProvider(cfg)
			})
			res, err := server.Send(webtest.RequestWithSignedInUser(server.NewGetRequest("/api/admin/settings"), userWithPermissions(1, tc.permissions)))
			require.NoError(t, err)
			defer func() {
				_ = res.Body.Close()
			}()
			require.Equal(t, http.StatusOK, res.StatusCode)
			body, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			if strings.Contains(string(body), encoded) || strings.Contains(string(body), "placeholder-not-a-secret") {
				t.Fatalf("GET /api/admin/settings returned inline JWT key material to %s", tc.name)
			}

			var bag setting.SettingsBag
			require.NoError(t, json.Unmarshal(body, &bag))
			section := bag["auth.jwt"]
			require.NotNil(t, section)
			if _, ok := section["jwk_set_value"]; ok && section["jwk_set_value"] != setting.RedactedPassword {
				t.Fatal("GET /api/admin/settings did not redact jwk_set_value")
			}
			if _, ok := section["key_value"]; ok && section["key_value"] != setting.RedactedPassword {
				t.Fatal("GET /api/admin/settings did not redact key_value")
			}
		})
	}
}

func placeholderOctetKey(n int) []byte {
	const label = "placeholder-not-a-secret"
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, label...)
	}
	return out[:n]
}
