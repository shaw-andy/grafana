package api

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"sync"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	datasources "github.com/grafana/grafana/pkg/services/datasources/fakes"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginaccesscontrol"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/plugincontext"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	pluginSettingsService "github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings/service"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	fakeSecrets "github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web/webtest"
)

const (
	pluginHealthSecretField = "token"

	pluginHealthSecretAppID    = "secret-app"
	pluginHealthOtherAppID     = "other-app"
	pluginHealthAutoAppID      = "auto-app"
	pluginHealthDisabledAppID  = "disabled-app"
	pluginHealthSecretAppValue = "placeholder-app-secret"
	pluginHealthOtherAppValue  = "placeholder-other-secret"
	pluginHealthAutoAppValue   = "placeholder-auto-secret"

	pluginHealthWithSecretMessage    = "health-with-secret"
	pluginHealthWithoutSecretMessage = "health-without-secret"
	pluginHealthDetailsMarker        = "health-checked"
)

// countingSecrets counts DecryptJsonData calls. The embedded fake still performs
// the map conversion used by plugin settings: each stored value is returned as a string.
type countingSecrets struct {
	fakeSecrets.FakeSecretsService

	mu       sync.Mutex
	decrypts int
}

func (s *countingSecrets) DecryptJsonData(ctx context.Context, sjd map[string][]byte) (map[string]string, error) {
	s.mu.Lock()
	s.decrypts++
	s.mu.Unlock()
	return s.FakeSecretsService.DecryptJsonData(ctx, sjd)
}

func (s *countingSecrets) decryptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.decrypts
}

// recordingHealthClient is the plugin process boundary. It records the context Grafana
// handed over and returns a health payload derived from whether that context contained
// a non-empty secure field. It does not copy the field value into the response.
type recordingHealthClient struct {
	*pluginfakes.FakePluginClient

	mu        sync.Mutex
	health    []backend.CheckHealthRequest
	resources int
	unhealthy bool
}

func (c *recordingHealthClient) CheckHealth(_ context.Context, req *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	copied := backend.CheckHealthRequest{}
	if req != nil {
		copied = *req
		if req.PluginContext.AppInstanceSettings != nil {
			settings := *req.PluginContext.AppInstanceSettings
			settings.DecryptedSecureJSONData = maps.Clone(req.PluginContext.AppInstanceSettings.DecryptedSecureJSONData)
			copied.PluginContext.AppInstanceSettings = &settings
		}
	}

	c.mu.Lock()
	c.health = append(c.health, copied)
	unhealthy := c.unhealthy
	c.mu.Unlock()

	message := pluginHealthWithoutSecretMessage
	if req != nil && req.PluginContext.AppInstanceSettings != nil &&
		req.PluginContext.AppInstanceSettings.DecryptedSecureJSONData[pluginHealthSecretField] != "" {
		message = pluginHealthWithSecretMessage
	}
	status := backend.HealthStatusOk
	if unhealthy {
		status = backend.HealthStatusError
	}
	return &backend.CheckHealthResult{
		Status:      status,
		Message:     message,
		JSONDetails: []byte(`{"marker":"` + pluginHealthDetailsMarker + `"}`),
	}, nil
}

func (c *recordingHealthClient) CallResource(_ context.Context, _ *backend.CallResourceRequest, sender backend.CallResourceResponseSender) error {
	c.mu.Lock()
	c.resources++
	c.mu.Unlock()
	return sender.Send(&backend.CallResourceResponse{Status: http.StatusOK, Body: []byte(`{}`)})
}

func (c *recordingHealthClient) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health = nil
	c.resources = 0
}

func (c *recordingHealthClient) healthCalls() []backend.CheckHealthRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]backend.CheckHealthRequest, len(c.health))
	copy(out, c.health)
	return out
}

func (c *recordingHealthClient) resourceCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resources
}

func TestIntegrationPluginHealthRequiresAppAccess(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	store := db.NewTestStore(t)
	secretsSvc := &countingSecrets{}
	settingsSvc := pluginSettingsService.ProvideService(store, secretsSvc)
	ctx := context.Background()
	orgID := int64(1)

	pluginStore := pluginstore.NewFakePluginStore(
		appPlugin(pluginHealthSecretAppID, false),
		appPlugin(pluginHealthOtherAppID, false),
		appPlugin(pluginHealthAutoAppID, true),
		appPlugin(pluginHealthDisabledAppID, false),
	)
	cfg := setting.NewCfg()
	provider := plugincontext.ProvideService(
		cfg,
		localcache.ProvideService(),
		pluginStore,
		&datasources.FakeCacheService{},
		&datasources.FakeDataSourceService{},
		settingsSvc,
		pluginconfig.NewFakePluginRequestConfigProvider(),
	)
	client := &recordingHealthClient{FakePluginClient: &pluginfakes.FakePluginClient{}}

	require.NoError(t, settingsSvc.UpdatePluginSetting(ctx, enabledSetting(pluginHealthSecretAppID, orgID, pluginHealthSecretAppValue)))
	require.NoError(t, settingsSvc.UpdatePluginSetting(ctx, enabledSetting(pluginHealthOtherAppID, orgID, pluginHealthOtherAppValue)))
	require.NoError(t, settingsSvc.UpdatePluginSetting(ctx, enabledSetting(pluginHealthAutoAppID, orgID, pluginHealthAutoAppValue)))
	require.NoError(t, settingsSvc.UpdatePluginSetting(ctx, &pluginsettings.UpdateArgs{
		PluginID:       pluginHealthDisabledAppID,
		OrgID:          orgID,
		Enabled:        false,
		JSONData:       map[string]any{},
		SecureJSONData: map[string]string{pluginHealthSecretField: pluginHealthSecretAppValue},
	}))
	// Saving settings encrypts them. Decryption must not have run yet, so the first
	// health request is what reveals whether the handler decrypts before authorizing.
	require.Zero(t, secretsSvc.decryptCount())

	srv := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.log = log.New("plugin-health-access-test")
		hs.pluginStore = pluginStore
		hs.PluginSettings = settingsSvc
		hs.pluginContextProvider = provider
		hs.pluginClient = client
	})

	noAccess := authedUserWithPermissions(2, orgID, nil)
	otherAppAccess := authedUserWithPermissions(3, orgID, []accesscontrol.Permission{{
		Action: pluginaccesscontrol.ActionAppAccess,
		Scope:  pluginaccesscontrol.ScopeProvider.GetResourceScope(pluginHealthOtherAppID),
	}})
	secretAppAccess := authedUserWithPermissions(4, orgID, []accesscontrol.Permission{{
		Action: pluginaccesscontrol.ActionAppAccess,
		Scope:  pluginaccesscontrol.ScopeProvider.GetResourceScope(pluginHealthSecretAppID),
	}})
	allAppAccess := authedUserWithPermissions(5, orgID, []accesscontrol.Permission{{
		Action: pluginaccesscontrol.ActionAppAccess,
		Scope:  pluginaccesscontrol.ScopeProvider.GetResourceAllScope(),
	}})
	otherOrg := authedUserWithPermissions(6, 2, nil)

	t.Run("signed-in user without plugins.app:access does not receive decrypted app settings", func(t *testing.T) {
		client.reset()
		decrypts := secretsSvc.decryptCount()

		status, body := getPluginHealth(t, srv, pluginHealthSecretAppID, noAccess)

		require.Equal(t, http.StatusForbidden, status)
		require.Empty(t, client.healthCalls())
		require.Equal(t, decrypts, secretsSvc.decryptCount())
		requireNoHealthDisclosure(t, body)
	})

	t.Run("access to a different plugin does not authorize this plugin", func(t *testing.T) {
		client.reset()
		decrypts := secretsSvc.decryptCount()

		status, body := getPluginHealth(t, srv, pluginHealthSecretAppID, otherAppAccess)

		require.Equal(t, http.StatusForbidden, status)
		require.Empty(t, client.healthCalls())
		require.Equal(t, decrypts, secretsSvc.decryptCount())
		requireNoHealthDisclosure(t, body)
	})

	t.Run("query plugin id is not the plugin that is authorized or checked", func(t *testing.T) {
		client.reset()
		decrypts := secretsSvc.decryptCount()

		// The path selects the plugin. A query value with the same name must not
		// authorize a different plugin than the one whose health is checked.
		status, body := getPluginHealthQuery(t, srv, pluginHealthSecretAppID, "pluginId="+pluginHealthOtherAppID, otherAppAccess)

		require.Equal(t, http.StatusForbidden, status)
		require.Empty(t, client.healthCalls())
		require.Equal(t, decrypts, secretsSvc.decryptCount())
		requireNoHealthDisclosure(t, body)
	})

	t.Run("auto-enabled app with stored settings follows the same access check", func(t *testing.T) {
		client.reset()
		decrypts := secretsSvc.decryptCount()

		status, body := getPluginHealth(t, srv, pluginHealthAutoAppID, noAccess)

		require.Equal(t, http.StatusForbidden, status)
		require.Empty(t, client.healthCalls())
		require.Equal(t, decrypts, secretsSvc.decryptCount())
		requireNoHealthDisclosure(t, body)
	})

	t.Run("disabled app is forbidden before settings are decrypted", func(t *testing.T) {
		client.reset()
		decrypts := secretsSvc.decryptCount()

		status, body := getPluginHealth(t, srv, pluginHealthDisabledAppID, noAccess)

		require.Equal(t, http.StatusForbidden, status)
		require.Empty(t, client.healthCalls())
		require.Equal(t, decrypts, secretsSvc.decryptCount())
		requireNoHealthDisclosure(t, body)
	})

	t.Run("caller in another organization is forbidden before this organization's settings are decrypted", func(t *testing.T) {
		client.reset()
		decrypts := secretsSvc.decryptCount()

		status, body := getPluginHealth(t, srv, pluginHealthSecretAppID, otherOrg)

		require.Equal(t, http.StatusForbidden, status)
		require.Empty(t, client.healthCalls())
		require.Equal(t, decrypts, secretsSvc.decryptCount())
		requireNoHealthDisclosure(t, body)
	})

	t.Run("unhealthy result is not returned to a caller without access", func(t *testing.T) {
		client.reset()
		client.mu.Lock()
		client.unhealthy = true
		client.mu.Unlock()
		t.Cleanup(func() {
			client.mu.Lock()
			client.unhealthy = false
			client.mu.Unlock()
		})
		decrypts := secretsSvc.decryptCount()

		status, body := getPluginHealth(t, srv, pluginHealthSecretAppID, noAccess)

		require.Equal(t, http.StatusForbidden, status)
		require.Empty(t, client.healthCalls())
		require.Equal(t, decrypts, secretsSvc.decryptCount())
		requireNoHealthDisclosure(t, body)
	})

	t.Run("anonymous caller is unauthorized and the plugin is not called", func(t *testing.T) {
		client.reset()
		decrypts := secretsSvc.decryptCount()

		status, body := getPluginHealth(t, srv, pluginHealthSecretAppID, nil)

		require.Equal(t, http.StatusUnauthorized, status)
		require.Empty(t, client.healthCalls())
		require.Equal(t, decrypts, secretsSvc.decryptCount())
		requireNoHealthDisclosure(t, body)
	})

	t.Run("plugin resource route denies the same caller before the plugin is called", func(t *testing.T) {
		client.reset()
		decrypts := secretsSvc.decryptCount()

		req := webtest.RequestWithSignedInUser(srv.NewGetRequest("/api/plugins/"+pluginHealthSecretAppID+"/resources/health"), noAccess)
		resp, err := srv.Send(req)
		require.NoError(t, err)
		body := readBody(t, resp)

		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		require.Zero(t, client.resourceCalls())
		require.Empty(t, client.healthCalls())
		require.Equal(t, decrypts, secretsSvc.decryptCount())
		requireNoHealthDisclosure(t, body)
	})

	t.Run("caller granted this plugin receives its health result and its decrypted settings", func(t *testing.T) {
		client.reset()

		status, body := getPluginHealth(t, srv, pluginHealthSecretAppID, secretAppAccess)

		require.Equal(t, http.StatusOK, status)
		requireHealthPayload(t, body, pluginHealthWithSecretMessage, backend.HealthStatusOk.String())
		calls := client.healthCalls()
		require.Len(t, calls, 1)
		require.Equal(t, pluginHealthSecretAppID, calls[0].PluginContext.PluginID)
		requireDecryptedSecret(t, calls[0], pluginHealthSecretAppValue)
	})

	t.Run("wildcard app access receives this plugin's settings and not another plugin's", func(t *testing.T) {
		client.reset()

		status, body := getPluginHealth(t, srv, pluginHealthSecretAppID, allAppAccess)

		require.Equal(t, http.StatusOK, status)
		requireHealthPayload(t, body, pluginHealthWithSecretMessage, backend.HealthStatusOk.String())
		calls := client.healthCalls()
		require.Len(t, calls, 1)
		require.Equal(t, pluginHealthSecretAppID, calls[0].PluginContext.PluginID)
		requireDecryptedSecret(t, calls[0], pluginHealthSecretAppValue)
	})

	t.Run("granted caller checking the other plugin does not receive this plugin's settings", func(t *testing.T) {
		client.reset()
		decrypts := secretsSvc.decryptCount()

		status, body := getPluginHealth(t, srv, pluginHealthOtherAppID, secretAppAccess)

		require.Equal(t, http.StatusForbidden, status)
		require.Empty(t, client.healthCalls())
		require.Equal(t, decrypts, secretsSvc.decryptCount())
		requireNoHealthDisclosure(t, body)
	})

	t.Run("granted caller receives an unhealthy result's message and details", func(t *testing.T) {
		client.reset()
		client.mu.Lock()
		client.unhealthy = true
		client.mu.Unlock()
		t.Cleanup(func() {
			client.mu.Lock()
			client.unhealthy = false
			client.mu.Unlock()
		})

		status, body := getPluginHealth(t, srv, pluginHealthSecretAppID, secretAppAccess)

		require.Equal(t, http.StatusBadRequest, status)
		requireHealthPayload(t, body, pluginHealthWithSecretMessage, backend.HealthStatusError.String())
		calls := client.healthCalls()
		require.Len(t, calls, 1)
		requireDecryptedSecret(t, calls[0], pluginHealthSecretAppValue)
	})

	t.Run("granted caller of a disabled app is not given decrypted settings", func(t *testing.T) {
		client.reset()
		decrypts := secretsSvc.decryptCount()

		status, body := getPluginHealth(t, srv, pluginHealthDisabledAppID, allAppAccess)

		require.Equal(t, http.StatusNotFound, status)
		require.Empty(t, client.healthCalls())
		require.Equal(t, decrypts, secretsSvc.decryptCount())
		requireNoHealthDisclosure(t, body)
	})
}

func appPlugin(id string, autoEnabled bool) pluginstore.Plugin {
	return pluginstore.Plugin{
		JSONData: plugins.JSONData{
			ID:          id,
			Type:        plugins.TypeApp,
			AutoEnabled: autoEnabled,
			Info:        plugins.Info{Version: "1.0.0"},
		},
	}
}

func enabledSetting(pluginID string, orgID int64, secretValue string) *pluginsettings.UpdateArgs {
	return &pluginsettings.UpdateArgs{
		PluginID:       pluginID,
		OrgID:          orgID,
		Enabled:        true,
		JSONData:       map[string]any{},
		SecureJSONData: map[string]string{pluginHealthSecretField: secretValue},
	}
}

func getPluginHealth(t *testing.T, srv *webtest.Server, pluginID string, usr *user.SignedInUser) (int, []byte) {
	t.Helper()
	return getPluginHealthQuery(t, srv, pluginID, "", usr)
}

func getPluginHealthQuery(t *testing.T, srv *webtest.Server, pluginID, rawQuery string, usr *user.SignedInUser) (int, []byte) {
	t.Helper()
	req := srv.NewGetRequest("/api/plugins/" + pluginID + "/health")
	req.URL.RawQuery = rawQuery
	if usr != nil {
		req = webtest.RequestWithSignedInUser(req, usr)
	} else {
		req = webtest.RequestWithWebContext(req, &contextmodel.ReqContext{})
	}
	resp, err := srv.Send(req)
	require.NoError(t, err)
	return resp.StatusCode, readBody(t, resp)
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return body
}

func requireNoHealthDisclosure(t *testing.T, body []byte) {
	t.Helper()
	text := string(body)
	require.NotContains(t, text, pluginHealthSecretAppValue)
	require.NotContains(t, text, pluginHealthOtherAppValue)
	require.NotContains(t, text, pluginHealthAutoAppValue)
	require.NotContains(t, text, pluginHealthWithSecretMessage)
	require.NotContains(t, text, pluginHealthDetailsMarker)
}

func requireHealthPayload(t *testing.T, body []byte, message, status string) {
	t.Helper()
	var payload struct {
		Status  string         `json:"status"`
		Message string         `json:"message"`
		Details map[string]any `json:"details"`
	}
	require.NoError(t, json.Unmarshal(body, &payload))
	require.Equal(t, status, payload.Status)
	require.Equal(t, message, payload.Message)
	require.Equal(t, pluginHealthDetailsMarker, payload.Details["marker"])
}

func requireDecryptedSecret(t *testing.T, call backend.CheckHealthRequest, secretValue string) {
	t.Helper()
	require.NotNil(t, call.PluginContext.AppInstanceSettings)
	require.Equal(t, secretValue, call.PluginContext.AppInstanceSettings.DecryptedSecureJSONData[pluginHealthSecretField])
}
