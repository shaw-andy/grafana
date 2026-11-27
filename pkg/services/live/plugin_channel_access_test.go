package live

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/centrifugal/centrifuge"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/backendplugin"
	"github.com/grafana/grafana/pkg/plugins/manager/client"
	"github.com/grafana/grafana/pkg/plugins/manager/registry"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginaccesscontrol"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/plugincontext"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

const (
	orgNamespace = "default"
	testOrgID    = int64(1)

	restrictedAppID  = "restricted-app"
	otherAppID       = "other-app"
	disabledAppID    = "disabled-app"
	missingAppID     = "missing-app"
	autoAppID        = "auto-app"
	autoDisabledID   = "auto-disabled-app"
	toggleAppID      = "toggle-app"
	appJSONEndpoint  = "https://example.invalid/feed"
	secureSettingKey = "secureSetting"
	// Obvious placeholder. The test only checks that the value stored for the
	// organization is the value the plugin stream handler receives.
	secureSettingValue = "placeholder-not-a-secret"

	// plugincontext caches plugin settings under this prefix.
	pluginSettingsCachePrefix = "plugin-setting-"
)

// TestPluginChannelRequiresAppAccessAndEnabledState is the specification for
// Live channels plugin/<appId>/<path>. These cases fail until subscribe,
// websocket publish, and POST /api/live/publish apply the same plugins.app:access
// and app-enabled checks as the HTTP app routes, on every call.
func TestPluginChannelRequiresAppAccessAndEnabledState(t *testing.T) {
	h := newPluginChannelHarness(t)

	exact := h.user("exact-user", pluginScope(restrictedAppID), pluginScope(toggleAppID), pluginScope(disabledAppID), pluginScope(missingAppID), pluginScope(autoAppID), pluginScope(autoDisabledID))
	wildcard := h.user("wildcard-user", pluginaccesscontrol.ScopeProvider.GetResourceAllScope())
	otherOnly := h.user("other-only-user", pluginScope(otherAppID))
	writerOnly := h.user("writer-only-user")
	writerOnly.Permissions[testOrgID] = map[string][]string{
		pluginaccesscontrol.ActionWrite: {pluginScope(restrictedAppID)},
	}
	noPerms := h.user("no-perms-user")

	require.True(t, appAccess(exact, restrictedAppID))
	require.False(t, appAccess(exact, otherAppID))
	require.True(t, appAccess(wildcard, restrictedAppID))
	require.True(t, appAccess(wildcard, otherAppID))
	require.False(t, appAccess(otherOnly, restrictedAppID))
	require.True(t, appAccess(otherOnly, otherAppID))
	require.False(t, appAccess(writerOnly, restrictedAppID))
	require.False(t, appAccess(noPerms, restrictedAppID))

	shared := pluginChannel(restrictedAppID, "shared")
	h.requireAllowed(t, exact, shared, restrictedAppID, true)
	// The handler for this channel is cached after the first call. A later
	// authorized user must still be the user the plugin runs as.
	h.requireAllowed(t, wildcard, shared, restrictedAppID, true)
	// A user who is not allowed to this app must still be refused after the
	// handler was cached for someone who is.
	h.requireDenied(t, otherOnly, shared)
	h.requireDenied(t, writerOnly, shared)
	h.requireDenied(t, noPerms, shared)

	h.requireDenied(t, otherOnly, pluginChannel(restrictedAppID, "first-request"))
	h.requireDenied(t, exact, pluginChannel(otherAppID, "not-this-app"))
	h.requireDenied(t, exact, pluginChannel(disabledAppID, "disabled"))
	h.requireDenied(t, exact, pluginChannel(missingAppID, "no-settings"))
	h.requireDenied(t, exact, pluginChannel(autoDisabledID, "auto-but-disabled"))
	h.requireAllowed(t, exact, pluginChannel(autoAppID, "auto-enabled"), autoAppID, false)

	toggleChannel := pluginChannel(toggleAppID, "while-enabled")
	h.requireAllowed(t, exact, toggleChannel, toggleAppID, true)
	h.settings.setEnabled(toggleAppID, false)
	h.settingsCache.Delete(pluginSettingsCachePrefix + toggleAppID)
	h.requireDenied(t, exact, toggleChannel)
}

func pluginScope(pluginID string) string {
	return pluginaccesscontrol.ScopeProvider.GetResourceScope(pluginID)
}

func pluginChannel(pluginID, path string) string {
	return "plugin/" + pluginID + "/" + path
}

func appAccess(user identity.Requester, pluginID string) bool {
	return accesscontrol.EvalPermission(
		pluginaccesscontrol.ActionAppAccess,
		pluginScope(pluginID),
	).Evaluate(user.GetPermissions())
}

type channelOp string

const (
	opSubscribe   channelOp = "subscribe"
	opWSPublish   channelOp = "ws-publish"
	opHTTPPublish channelOp = "http-publish"
)

var allOps = []channelOp{opSubscribe, opWSPublish, opHTTPPublish}

type streamCall struct {
	kind     string
	pluginID string
	path     string
	login    string
	orgID    int64
	data     []byte
	secure   map[string]string
	jsonData []byte
}

type recordingBackend struct {
	backendplugin.Plugin
	mu    sync.Mutex
	calls []streamCall
}

func (b *recordingBackend) IsDecommissioned() bool { return false }

func (b *recordingBackend) record(kind string, pCtx backend.PluginContext, path string, data []byte) {
	call := streamCall{
		kind:     kind,
		pluginID: pCtx.PluginID,
		path:     path,
		data:     append([]byte(nil), data...),
		orgID:    pCtx.OrgID,
	}
	if pCtx.AppInstanceSettings != nil {
		call.jsonData = append([]byte(nil), pCtx.AppInstanceSettings.JSONData...)
		call.secure = maps.Clone(pCtx.AppInstanceSettings.DecryptedSecureJSONData)
	}
	if pCtx.User != nil {
		call.login = pCtx.User.Login
	}
	b.mu.Lock()
	b.calls = append(b.calls, call)
	b.mu.Unlock()
}

func (b *recordingBackend) SubscribeStream(_ context.Context, req *backend.SubscribeStreamRequest) (*backend.SubscribeStreamResponse, error) {
	b.record("subscribe", req.PluginContext, req.Path, req.Data)
	return &backend.SubscribeStreamResponse{Status: backend.SubscribeStreamStatusOK}, nil
}

func (b *recordingBackend) PublishStream(_ context.Context, req *backend.PublishStreamRequest) (*backend.PublishStreamResponse, error) {
	b.record("publish", req.PluginContext, req.Path, req.Data)
	return &backend.PublishStreamResponse{Status: backend.PublishStreamStatusOK}, nil
}

func (b *recordingBackend) RunStream(_ context.Context, req *backend.RunStreamRequest, _ *backend.StreamSender) error {
	b.record("run", req.PluginContext, req.Path, req.Data)
	return nil
}

func (b *recordingBackend) mark() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.calls)
}

func (b *recordingBackend) since(n int) []streamCall {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]streamCall, len(b.calls)-n)
	copy(out, b.calls[n:])
	return out
}

type memoryPluginSettings struct {
	mu        sync.Mutex
	byID      map[string]*pluginsettings.DTO
	decrypted map[string]map[string]string
}

func (s *memoryPluginSettings) GetPluginSettings(_ context.Context, _ *pluginsettings.GetArgs) ([]*pluginsettings.InfoDTO, error) {
	return nil, nil
}

func (s *memoryPluginSettings) GetPluginSettingByPluginID(_ context.Context, args *pluginsettings.GetByPluginIDArgs) (*pluginsettings.DTO, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dto, ok := s.byID[args.PluginID]
	if !ok || dto.OrgID != args.OrgID {
		return nil, pluginsettings.ErrPluginSettingNotFound
	}
	copy := *dto
	return &copy, nil
}

func (s *memoryPluginSettings) UpdatePluginSetting(context.Context, *pluginsettings.UpdateArgs) error {
	return errors.New("not implemented")
}

func (s *memoryPluginSettings) UpdatePluginSettingPluginVersion(context.Context, *pluginsettings.UpdatePluginVersionArgs) error {
	return errors.New("not implemented")
}

func (s *memoryPluginSettings) DecryptedValues(ps *pluginsettings.DTO) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.decrypted[ps.PluginID])
}

func (s *memoryPluginSettings) setEnabled(pluginID string, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[pluginID].Enabled = enabled
}

type dtoPluginStore struct {
	plugins map[string]pluginstore.Plugin
}

func (s dtoPluginStore) Plugin(_ context.Context, pluginID string) (pluginstore.Plugin, bool) {
	p, ok := s.plugins[pluginID]
	return p, ok
}

func (s dtoPluginStore) Plugins(context.Context, ...plugins.Type) []pluginstore.Plugin {
	out := make([]pluginstore.Plugin, 0, len(s.plugins))
	for _, p := range s.plugins {
		out = append(out, p)
	}
	return out
}

type pluginChannelHarness struct {
	t             *testing.T
	live          *GrafanaLive
	backend       *recordingBackend
	settings      *memoryPluginSettings
	settingsCache *localcache.CacheService
}

func newPluginChannelHarness(t *testing.T) *pluginChannelHarness {
	t.Helper()

	backend := &recordingBackend{}
	reg := registry.NewInMemory()
	settings := &memoryPluginSettings{
		byID:      map[string]*pluginsettings.DTO{},
		decrypted: map[string]map[string]string{},
	}
	storePlugins := map[string]pluginstore.Plugin{}

	add := func(id string, auto, enabled, withSettings bool) {
		t.Helper()
		p := &plugins.Plugin{JSONData: plugins.JSONData{
			ID:          id,
			Type:        plugins.TypeApp,
			AutoEnabled: auto,
			Backend:     true,
			Info:        plugins.Info{Version: "1.0.0"},
		}}
		p.RegisterClient(backend)
		require.NoError(t, reg.Add(context.Background(), p))
		dto := pluginstore.ToGrafanaDTO(p)
		require.True(t, dto.SupportsStreaming(), id)
		require.True(t, dto.IsApp(), id)
		storePlugins[id] = dto
		if withSettings {
			settings.byID[id] = &pluginsettings.DTO{
				ID:       int64(len(settings.byID) + 1),
				OrgID:    testOrgID,
				PluginID: id,
				JSONData: map[string]any{"endpoint": appJSONEndpoint},
				Enabled:  enabled,
				Updated:  time.Unix(1_700_000_000, 0).UTC(),
			}
			settings.decrypted[id] = map[string]string{secureSettingKey: secureSettingValue}
		}
	}

	add(restrictedAppID, false, true, true)
	add(otherAppID, false, true, true)
	add(disabledAppID, false, false, true)
	add(missingAppID, false, false, false)
	add(autoAppID, true, false, false)
	add(autoDisabledID, true, false, true)
	add(toggleAppID, false, true, true)

	cache := localcache.New(time.Minute, time.Minute)
	provider := plugincontext.ProvideService(
		setting.NewCfg(),
		cache,
		dtoPluginStore{plugins: storePlugins},
		nil,
		nil,
		settings,
		pluginconfig.NewFakePluginRequestConfigProvider(),
	)
	cfg := setting.NewCfg()
	g, err := ProvideService(
		cfg,
		routing.NewRouteRegister(),
		provider,
		dtoPluginStore{plugins: storePlugins},
		client.ProvideService(reg),
		nil,
		&usagestats.UsageStatsMock{T: t},
		featuremgmt.WithFeatures(),
		&dashboards.FakeDashboardService{},
		nil,
	)
	require.NoError(t, err)

	runCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = g.Run(runCtx) }()

	return &pluginChannelHarness{
		t:             t,
		live:          g,
		backend:       backend,
		settings:      settings,
		settingsCache: cache,
	}
}

func (h *pluginChannelHarness) user(login string, scopes ...string) *user.SignedInUser {
	perms := map[string][]string{}
	if len(scopes) > 0 {
		perms[pluginaccesscontrol.ActionAppAccess] = scopes
	}
	return &user.SignedInUser{
		UserID:    42,
		OrgID:     testOrgID,
		OrgRole:   identity.RoleViewer,
		Login:     login,
		Namespace: orgNamespace,
		Permissions: map[int64]map[string][]string{
			testOrgID: perms,
		},
	}
}

func (h *pluginChannelHarness) requireAllowed(t *testing.T, usr *user.SignedInUser, channel, pluginID string, withSettings bool) {
	t.Helper()
	for _, op := range allOps {
		t.Run(string(op)+" "+usr.Login+" "+channel, func(t *testing.T) {
			payload := []byte(fmt.Sprintf(`{"op":%q,"user":%q}`, op, usr.Login))
			mark := h.backend.mark()
			status := h.perform(t, usr, channel, op, payload)
			require.Equal(t, http.StatusOK, status)
			h.assertCalls(t, mark, pluginID, usr, channel, payload, withSettings, op)
		})
	}
}

func (h *pluginChannelHarness) requireDenied(t *testing.T, usr *user.SignedInUser, channel string) {
	t.Helper()
	for _, op := range allOps {
		t.Run(string(op)+" "+usr.Login+" "+channel, func(t *testing.T) {
			mark := h.backend.mark()
			status := h.perform(t, usr, channel, op, []byte(`{"op":"denied"}`))
			added := h.backend.since(mark)
			require.Equalf(t, http.StatusForbidden, status, "plugin stream calls: %d", len(added))
			require.Empty(t, added)
		})
	}
}

func (h *pluginChannelHarness) assertCalls(t *testing.T, mark int, pluginID string, usr *user.SignedInUser, channel string, payload []byte, withSettings bool, op channelOp) {
	t.Helper()
	path := channelPath(channel)
	immediate := callsOfKind(h.backend.since(mark), string(kindForOp(op)))
	require.NotEmpty(t, immediate)
	for _, call := range immediate {
		assertStreamCall(t, call, pluginID, usr, path, payload, withSettings)
	}
	if op != opSubscribe {
		return
	}
	require.Eventually(t, func() bool {
		return len(callsOfKind(h.backend.since(mark), "run")) > 0
	}, time.Second, 10*time.Millisecond)
	for _, call := range callsOfKind(h.backend.since(mark), "run") {
		assertStreamCall(t, call, pluginID, usr, path, payload, withSettings)
	}
}

func assertStreamCall(t *testing.T, call streamCall, pluginID string, usr *user.SignedInUser, path string, payload []byte, withSettings bool) {
	t.Helper()
	require.Equal(t, pluginID, call.pluginID)
	require.Equal(t, usr.Login, call.login)
	require.Equal(t, usr.GetOrgID(), call.orgID)
	require.Equal(t, path, call.path)
	require.JSONEq(t, string(payload), string(call.data))
	if withSettings {
		require.Equal(t, map[string]string{secureSettingKey: secureSettingValue}, call.secure)
		require.Contains(t, string(call.jsonData), appJSONEndpoint)
		return
	}
	require.Empty(t, call.secure)
	require.Empty(t, call.jsonData)
}

func kindForOp(op channelOp) string {
	if op == opSubscribe {
		return "subscribe"
	}
	return "publish"
}

func callsOfKind(calls []streamCall, kind string) []streamCall {
	out := make([]streamCall, 0, len(calls))
	for _, call := range calls {
		if call.kind == kind {
			out = append(out, call)
		}
	}
	return out
}

func channelPath(channel string) string {
	// plugin/<id>/<path>
	rest := channel[len("plugin/"):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[i+1:]
		}
	}
	return ""
}

func (h *pluginChannelHarness) perform(t *testing.T, usr *user.SignedInUser, channel string, op channelOp, payload []byte) int {
	t.Helper()
	switch op {
	case opSubscribe:
		return wsStatus(h.subscribe(t, usr, channel, payload))
	case opWSPublish:
		return wsStatus(h.wsPublish(t, usr, channel, payload))
	case opHTTPPublish:
		return h.httpPublish(t, usr, channel, payload).Status()
	default:
		t.Fatalf("unknown op %s", op)
		return 0
	}
}

func (h *pluginChannelHarness) subscribe(t *testing.T, usr *user.SignedInUser, channel string, payload []byte) error {
	t.Helper()
	ctx := identity.WithRequester(context.Background(), usr)
	c, _, err := centrifuge.NewClient(ctx, h.live.node, newDummyTransport(usr.Login+"-sub-"+channel))
	require.NoError(t, err)
	_, err = h.live.handleOnSubscribe(ctx, c, centrifuge.SubscribeEvent{
		Channel: orgNamespace + "/" + channel,
		Data:    payload,
	})
	return err
}

func (h *pluginChannelHarness) wsPublish(t *testing.T, usr *user.SignedInUser, channel string, payload []byte) error {
	t.Helper()
	ctx := identity.WithRequester(context.Background(), usr)
	c, _, err := centrifuge.NewClient(ctx, h.live.node, newDummyTransport(usr.Login+"-pub-"+channel))
	require.NoError(t, err)
	_, err = h.live.handleOnPublish(ctx, c, centrifuge.PublishEvent{
		Channel: orgNamespace + "/" + channel,
		Data:    payload,
	})
	return err
}

func (h *pluginChannelHarness) httpPublish(t *testing.T, usr *user.SignedInUser, channel string, payload []byte) interface{ Status() int } {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"channel": channel,
		"data":    json.RawMessage(payload),
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/live/publish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(identity.WithRequester(req.Context(), usr))
	reqCtx := &contextmodel.ReqContext{
		Context:      &web.Context{Req: req},
		SignedInUser: usr,
		IsSignedIn:   true,
	}
	resp := h.live.HandleHTTPPublish(reqCtx)
	require.NotNil(t, resp)
	return resp
}

func wsStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var cerr *centrifuge.Error
	if errors.As(err, &cerr) {
		if cerr.Code == centrifuge.ErrorPermissionDenied.Code || cerr.Code == uint32(http.StatusForbidden) {
			return http.StatusForbidden
		}
		return int(cerr.Code)
	}
	return http.StatusInternalServerError
}
