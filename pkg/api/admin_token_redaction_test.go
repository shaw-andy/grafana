package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

const (
	natsBusTokenPlaceholder        = "placeholder-nats-bus-token"
	snapshotBearerTokenPlaceholder = "placeholder-snapshot-bearer-token"
)

// TestAdminGetSettingsRedactsBusAndSnapshotTokens loads configuration the way
// the server does, then calls GET /api/admin/settings as a principal whose only
// grant is settings:read. The JSON body must carry the redaction placeholder
// for the NATS bus token and the external snapshot bearer token.
func TestAdminGetSettingsRedactsBusAndSnapshotTokens(t *testing.T) {
	t.Run("environment overrides", func(t *testing.T) {
		t.Setenv("GF_NATS_ENABLED", "true")
		t.Setenv("GF_NATS_AUTH_MODE", "token")
		t.Setenv("GF_NATS_TOKEN", natsBusTokenPlaceholder)
		t.Setenv("GF_SNAPSHOTS_EXTERNAL_SNAPSHOT_TOKEN", snapshotBearerTokenPlaceholder)

		cfg := setting.NewCfg()
		require.NoError(t, cfg.Load(setting.CommandLineArgs{HomePath: "../../"}))
		require.Equal(t, natsBusTokenPlaceholder, cfg.NATS.Auth.Token)
		require.Equal(t, snapshotBearerTokenPlaceholder, cfg.ExternalSnapshotToken)

		assertAdminSettingsRedactsTokens(t, cfg)
	})

	t.Run("ini file values", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "custom.ini")
		body := "[nats]\nenabled = true\nauth_mode = token\ntoken = " + natsBusTokenPlaceholder +
			"\n\n[snapshots]\nexternal_snapshot_token = " + snapshotBearerTokenPlaceholder + "\n"
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

		cfg := setting.NewCfg()
		require.NoError(t, cfg.Load(setting.CommandLineArgs{HomePath: "../../", Config: path}))
		require.Equal(t, natsBusTokenPlaceholder, cfg.NATS.Auth.Token)
		require.Equal(t, snapshotBearerTokenPlaceholder, cfg.ExternalSnapshotToken)

		assertAdminSettingsRedactsTokens(t, cfg)
	})
}

func assertAdminSettingsRedactsTokens(t *testing.T, cfg *setting.Cfg) {
	t.Helper()

	// Full startup config turns public dashboards on. Route registration for that
	// page needs services this test does not build. The admin settings route does
	// not. Leave the loaded ini, including the tokens, in place.
	cfg.PublicDashboardsEnabled = false

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.SettingsProvider = setting.ProvideProvider(cfg)
	})

	readers := []struct {
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
			name: "property reader",
			permissions: []accesscontrol.Permission{
				{Action: accesscontrol.ActionSettingsRead, Scope: "settings:nats:token"},
				{Action: accesscontrol.ActionSettingsRead, Scope: "settings:snapshots:external_snapshot_token"},
			},
		},
	}

	for _, reader := range readers {
		t.Run(reader.name, func(t *testing.T) {
			body := readAdminSettings(t, server, reader.permissions, http.StatusOK)
			require.NotContains(t, body, natsBusTokenPlaceholder)
			require.NotContains(t, body, snapshotBearerTokenPlaceholder)

			parsed := map[string]map[string]string{}
			require.NoError(t, json.Unmarshal([]byte(body), &parsed))
			require.Equal(t, setting.RedactedPassword, parsed["nats"]["token"])
			require.Equal(t, setting.RedactedPassword, parsed["snapshots"]["external_snapshot_token"])
			require.Equal(t, natsBusTokenPlaceholder, cfg.Raw.Section("nats").Key("token").Value())
			require.Equal(t, snapshotBearerTokenPlaceholder, cfg.Raw.Section("snapshots").Key("external_snapshot_token").Value())
		})
	}

	t.Run("caller without settings read", func(t *testing.T) {
		body := readAdminSettings(t, server, []accesscontrol.Permission{{Action: "wrong"}}, http.StatusForbidden)
		require.NotContains(t, body, natsBusTokenPlaceholder)
		require.NotContains(t, body, snapshotBearerTokenPlaceholder)
	})
}

func readAdminSettings(t *testing.T, server *webtest.Server, permissions []accesscontrol.Permission, status int) string {
	t.Helper()
	res, err := server.Send(webtest.RequestWithSignedInUser(
		server.NewGetRequest("/api/admin/settings"),
		userWithPermissions(1, permissions),
	))
	require.NoError(t, err)
	defer func() { require.NoError(t, res.Body.Close()) }()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, status, res.StatusCode, string(body))
	return string(body)
}
