package live

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/centrifugal/centrifuge"
	"github.com/centrifugal/protocol"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/authlib/types"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	plugindata "github.com/grafana/grafana-plugin-sdk-go/live"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/live/features"
	"github.com/grafana/grafana/pkg/services/live/model"
	"github.com/grafana/grafana/pkg/services/live/orgchannel"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// shippedLiveLimits are the [live] values Grafana loads from conf/defaults.ini.
// setting.readLiveSettings falls back to 65536 only when that key is absent.
func shippedLiveLimits(t *testing.T) (messageSize, clientQueue int) {
	t.Helper()
	file, err := ini.Load(filepath.Join("..", "..", "..", "conf", "defaults.ini"))
	require.NoError(t, err)
	section := file.Section("live")
	messageSize = section.Key("message_size_limit").MustInt(0)
	clientQueue = section.Key("client_queue_max_size").MustInt(0)
	require.Positive(t, messageSize)
	require.Positive(t, clientQueue)
	return messageSize, clientQueue
}

func TestHTTPPublish_DashboardBroadcastsHandlerPayloadNotRawBody(t *testing.T) {
	const (
		dashboardUID = "dash-a"
		sessionID    = "other-session"
		marker       = "watcher-toast-marker"
	)
	access := newRecordingDashboardAccess("dash-a", "dash-b")
	g := setupPublishLive(t, access, 4096, 1024)
	counter := wrapDashboardPublishCounter(t, g)

	editor := editorFor(t, dashboardUID)
	watcher := subscribeLive(t, g, editor, orgchannel.PrependK8sNamespace(editor.GetNamespace(), dashboardChannel(dashboardUID)))

	body := publishBody(t, dashboardChannel(dashboardUID), editingStartedJSON(t, dashboardUID, sessionID, marker, strings.Repeat("x", 64)))
	resp := postLivePublish(t, g, editor, body)

	require.Equal(t, http.StatusOK, resp.Status())
	require.Equal(t, int32(1), counter.calls())
	require.Equal(t, []string{dashboardUID}, access.updateAllows())

	payloads := watcher.waitPayloads(t, 1)
	require.Len(t, payloads, 1)
	require.JSONEq(t, string(reencodedEditingStarted(t, dashboardUID, sessionID)), string(payloads[0]))
	require.NotContains(t, string(payloads[0]), marker)
	requireNoSlowDisconnect(t, watcher)
}

func TestHTTPPublish_DashboardRejectsBodyOverMessageLimitBeforeHandler(t *testing.T) {
	const (
		dashboardUID = "dash-a"
		sessionID    = "other-session"
		marker       = "over-limit-marker"
		messageLimit = 1024
	)
	access := newRecordingDashboardAccess(dashboardUID)
	g := setupPublishLive(t, access, messageLimit, 4096)
	counter := wrapDashboardPublishCounter(t, g)
	editor := editorFor(t, dashboardUID)
	watcher := subscribeLive(t, g, editor, orgchannel.PrependK8sNamespace(editor.GetNamespace(), dashboardChannel(dashboardUID)))

	data := editingStartedJSON(t, dashboardUID, sessionID, marker, strings.Repeat("y", messageLimit))
	require.Greater(t, len(data), messageLimit)
	resp := postLivePublish(t, g, editor, publishBody(t, dashboardChannel(dashboardUID), data))

	require.GreaterOrEqual(t, resp.Status(), 400)
	require.Less(t, resp.Status(), 500)
	require.Zero(t, counter.calls(), "channel handler ran before the oversized body was refused")
	require.Empty(t, access.callsSnapshot())
	require.Empty(t, watcher.waitPayloads(t, 0))
}

func TestHTTPPublish_ShippedMessageLimitRejectsBeforeHandler(t *testing.T) {
	messageLimit, clientQueue := shippedLiveLimits(t)
	require.Equal(t, 8388608, messageLimit)
	require.Equal(t, 4194304, clientQueue)

	const (
		dashboardUID = "dash-a"
		sessionID    = "other-session"
		marker       = "shipped-limit-marker"
	)
	access := newRecordingDashboardAccess(dashboardUID)
	g := setupPublishLive(t, access, messageLimit, clientQueue)
	counter := wrapDashboardPublishCounter(t, g)
	editor := editorFor(t, dashboardUID)

	// Larger than the configured live message limit, still under web.MaxBindBodyBytes (100 MiB).
	data := editingStartedJSON(t, dashboardUID, sessionID, marker, strings.Repeat("z", messageLimit))
	require.Greater(t, len(data), messageLimit)
	require.Less(t, len(data), 100<<20)
	resp := postLivePublish(t, g, editor, publishBody(t, dashboardChannel(dashboardUID), data))

	require.GreaterOrEqual(t, resp.Status(), 400)
	require.Less(t, resp.Status(), 500)
	require.Zero(t, counter.calls(), "channel handler ran before the oversized body was refused")
	require.Empty(t, access.callsSnapshot())
}

func TestHTTPPublish_BodyUnderMessageLimitOverClientQueueIsNotBroadcastRaw(t *testing.T) {
	messageLimit, clientQueue := shippedLiveLimits(t)
	require.Greater(t, messageLimit, clientQueue)

	const (
		dashboardUID = "dash-a"
		sessionID    = "other-session"
		marker       = "queue-bound-marker"
	)
	access := newRecordingDashboardAccess(dashboardUID)
	g := setupPublishLive(t, access, messageLimit, clientQueue)
	editor := editorFor(t, dashboardUID)
	watcher := subscribeLive(t, g, editor, orgchannel.PrependK8sNamespace(editor.GetNamespace(), dashboardChannel(dashboardUID)))

	// Under the configured message limit, so a handler may run, and over the client queue.
	data := editingStartedJSON(t, dashboardUID, sessionID, marker, strings.Repeat("q", clientQueue))
	require.Greater(t, len(data), clientQueue)
	require.LessOrEqual(t, len(data), messageLimit)
	resp := postLivePublish(t, g, editor, publishBody(t, dashboardChannel(dashboardUID), data))

	require.Equal(t, http.StatusOK, resp.Status())
	require.Equal(t, []string{dashboardUID}, access.updateAllows())
	payloads := watcher.waitPayloads(t, 1)
	requireNoSlowDisconnect(t, watcher)
	require.Len(t, payloads, 1)
	require.JSONEq(t, string(reencodedEditingStarted(t, dashboardUID, sessionID)), string(payloads[0]))
	require.NotContains(t, string(payloads[0]), marker)
}

func TestHTTPPublish_RefusesDashboardThatWasNotAuthorized(t *testing.T) {
	access := newRecordingDashboardAccess("dash-a", "dash-b")
	g := setupPublishLive(t, access, 4096, 1024)
	editor := editorFor(t, "dash-b")
	fullA := orgchannel.PrependK8sNamespace(editor.GetNamespace(), dashboardChannel("dash-a"))
	watcher := subscribeLive(t, g, editor, fullA)

	// Update permission exists for dash-b. The channel being published is dash-a.
	data := editingStartedJSON(t, "dash-b", "sess", "cross-dashboard-marker", "")
	resp := postLivePublish(t, g, editor, publishBody(t, dashboardChannel("dash-a"), data))

	require.NotEqual(t, http.StatusOK, resp.Status())
	require.Empty(t, watcher.waitPayloads(t, 0))
	for _, call := range access.callsSnapshot() {
		if call.ok && call.verb == utils.VerbUpdate {
			require.Equal(t, "dash-a", call.name)
		}
	}
}

func TestHTTPPublish_ViewerCannotBroadcast(t *testing.T) {
	access := newRecordingDashboardAccess("dash-a")
	g := setupPublishLive(t, access, 4096, 1024)
	viewer := &user.SignedInUser{
		UserID:    3,
		OrgID:     1,
		OrgRole:   identity.RoleViewer,
		Namespace: types.OrgNamespaceFormatter(1),
		Permissions: map[int64]map[string][]string{
			1: {dashboards.ActionDashboardsRead: {dashboards.ScopeDashboardsProvider.GetResourceScopeUID("dash-a")}},
		},
	}
	watcher := subscribeLive(t, g, viewer, orgchannel.PrependK8sNamespace(viewer.GetNamespace(), dashboardChannel("dash-a")))
	data := editingStartedJSON(t, "dash-a", "sess", "viewer-marker", "")
	resp := postLivePublish(t, g, viewer, publishBody(t, dashboardChannel("dash-a"), data))

	require.NotEqual(t, http.StatusOK, resp.Status())
	require.Empty(t, watcher.waitPayloads(t, 0))
	require.NotContains(t, access.updateAllows(), "dash-a")
}

func TestHTTPPublish_PluginAndDatasourceBroadcastHandlerPayload(t *testing.T) {
	const marker = "plugin-raw-marker"
	replacement := []byte(`{"kind":"replaced"}`)
	access := newRecordingDashboardAccess()
	g := setupPublishLive(t, access, 4096, 1024)
	editor := editorFor(t)

	cases := []struct {
		name    string
		channel string
	}{
		{name: "plugin", channel: plugindata.ScopePlugin + "/streamplug/room"},
		{name: "datasource", channel: plugindata.ScopeDatasource + "/dsuid/room"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stream := &replacingStreamHandler{data: replacement}
			installPluginRunner(t, g, tc.channel, stream)
			watcher := subscribeLive(t, g, editor, orgchannel.PrependK8sNamespace(editor.GetNamespace(), tc.channel))

			raw, err := json.Marshal(map[string]string{"secret": marker, "blob": strings.Repeat("p", 32)})
			require.NoError(t, err)
			resp := postLivePublish(t, g, editor, publishBody(t, tc.channel, raw))

			require.Equal(t, http.StatusOK, resp.Status())
			require.Equal(t, int32(1), stream.calls.Load())
			payloads := watcher.waitPayloads(t, 1)
			require.Len(t, payloads, 1)
			require.JSONEq(t, string(replacement), string(payloads[0]))
			require.NotContains(t, string(payloads[0]), marker)
		})
	}
}

func TestHTTPPublish_PluginBodyOverMessageLimitDoesNotCallPlugin(t *testing.T) {
	const messageLimit = 512
	access := newRecordingDashboardAccess()
	g := setupPublishLive(t, access, messageLimit, 4096)
	editor := editorFor(t)
	channel := plugindata.ScopePlugin + "/streamplug/room"
	stream := &replacingStreamHandler{data: []byte(`{"kind":"replaced"}`)}
	installPluginRunner(t, g, channel, stream)

	raw, err := json.Marshal(map[string]string{"blob": strings.Repeat("p", messageLimit)})
	require.NoError(t, err)
	require.Greater(t, len(raw), messageLimit)
	resp := postLivePublish(t, g, editor, publishBody(t, channel, raw))

	require.GreaterOrEqual(t, resp.Status(), 400)
	require.Less(t, resp.Status(), 500)
	require.Zero(t, stream.calls.Load(), "plugin publish ran before the oversized body was refused")
}

func TestWebsocketPublish_DashboardBroadcastsHandlerPayload(t *testing.T) {
	const (
		dashboardUID = "dash-a"
		sessionID    = "other-session"
		marker       = "websocket-must-drop-marker"
	)
	access := newRecordingDashboardAccess(dashboardUID)
	g := setupPublishLive(t, access, 4096, 1024)
	editor := editorFor(t, dashboardUID)
	full := orgchannel.PrependK8sNamespace(editor.GetNamespace(), dashboardChannel(dashboardUID))
	watcher := subscribeLive(t, g, editor, full)

	data := editingStartedJSON(t, dashboardUID, sessionID, marker, "tiny")
	ctx := identity.WithRequester(context.Background(), editor)
	_, err := g.handleOnPublish(ctx, watcher.client, centrifuge.PublishEvent{Channel: full, Data: data})
	require.NoError(t, err)

	payloads := watcher.waitPayloads(t, 1)
	require.Len(t, payloads, 1)
	require.JSONEq(t, string(reencodedEditingStarted(t, dashboardUID, sessionID)), string(payloads[0]))
	require.NotContains(t, string(payloads[0]), marker)
}

type accessCall struct {
	verb      string
	namespace string
	name      string
	ok        bool
}

type recordingDashboardAccess struct {
	mu         sync.Mutex
	dashboards map[string]struct{}
	calls      []accessCall
}

func newRecordingDashboardAccess(uids ...string) *recordingDashboardAccess {
	known := make(map[string]struct{}, len(uids))
	for _, uid := range uids {
		known[uid] = struct{}{}
	}
	return &recordingDashboardAccess{dashboards: known}
}

func (a *recordingDashboardAccess) HasDashboardAccess(_ context.Context, requester identity.Requester, verb, namespace, name string) (bool, error) {
	var action string
	switch verb {
	case utils.VerbGet:
		action = dashboards.ActionDashboardsRead
	case utils.VerbUpdate:
		action = dashboards.ActionDashboardsWrite
	default:
		a.record(verb, namespace, name, false)
		return false, nil
	}
	_, known := a.dashboards[name]
	scope := dashboards.ScopeDashboardsProvider.GetResourceScopeUID(name)
	ok := known && permissionAllows(requester, action, scope)
	a.record(verb, namespace, name, ok)
	return ok, nil
}

func (a *recordingDashboardAccess) record(verb, namespace, name string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, accessCall{verb: verb, namespace: namespace, name: name, ok: ok})
}

func (a *recordingDashboardAccess) callsSnapshot() []accessCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]accessCall, len(a.calls))
	copy(out, a.calls)
	return out
}

func (a *recordingDashboardAccess) updateAllows() []string {
	var names []string
	for _, call := range a.callsSnapshot() {
		if call.ok && call.verb == utils.VerbUpdate {
			names = append(names, call.name)
		}
	}
	return names
}

func permissionAllows(requester identity.Requester, action, scope string) bool {
	for _, granted := range requester.GetPermissions()[action] {
		if granted == scope || granted == dashboards.ScopeDashboardsAll {
			return true
		}
	}
	return false
}

func requireNoSlowDisconnect(t *testing.T, watcher *liveWatcher) {
	t.Helper()
	// DisconnectSlow is applied from the broadcast path in another goroutine.
	deadline := time.Now().Add(200 * time.Millisecond)
	for {
		codes := watcher.disconnectCodes()
		if slices.Contains(codes, centrifuge.DisconnectSlow.Code) {
			require.Failf(t, "subscriber disconnected slow", "codes=%v", codes)
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func editorFor(t *testing.T, writeUIDs ...string) *user.SignedInUser {
	t.Helper()
	scopes := make([]string, 0, len(writeUIDs))
	for _, uid := range writeUIDs {
		scopes = append(scopes, dashboards.ScopeDashboardsProvider.GetResourceScopeUID(uid))
	}
	return &user.SignedInUser{
		UserID:    2,
		OrgID:     1,
		OrgRole:   identity.RoleEditor,
		Login:     "editor",
		Namespace: types.OrgNamespaceFormatter(1),
		Permissions: map[int64]map[string][]string{
			1: {dashboards.ActionDashboardsWrite: scopes},
		},
	}
}

func setupPublishLive(t *testing.T, access dashboards.DashboardAccessService, messageLimit, clientQueue int) *GrafanaLive {
	t.Helper()
	cfg := setting.NewCfg()
	cfg.LiveMessageSizeLimit = messageLimit
	cfg.LiveClientQueueMaxSize = clientQueue
	cfg.LiveMaxConnections = 100
	g, err := ProvideService(cfg, routing.NewRouteRegister(), nil, nil, nil, nil, &usagestats.UsageStatsMock{T: t}, featuremgmt.WithFeatures(), access, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = g.node.Shutdown(context.Background())
	})
	return g
}

type publishCounter struct {
	model.ChannelHandlerFactory
	handler *countingHandler
}

func (p *publishCounter) GetHandlerForPath(path string) (model.ChannelHandler, error) {
	inner, err := p.ChannelHandlerFactory.GetHandlerForPath(path)
	if err != nil {
		return nil, err
	}
	p.handler = &countingHandler{inner: inner}
	return p.handler, nil
}

type countingHandler struct {
	inner model.ChannelHandler
	calls atomic.Int32
}

func (h *countingHandler) OnSubscribe(ctx context.Context, user identity.Requester, e model.SubscribeEvent) (model.SubscribeReply, backend.SubscribeStreamStatus, error) {
	return h.inner.OnSubscribe(ctx, user, e)
}

func (h *countingHandler) OnPublish(ctx context.Context, user identity.Requester, e model.PublishEvent) (model.PublishReply, backend.PublishStreamStatus, error) {
	h.calls.Add(1)
	return h.inner.OnPublish(ctx, user, e)
}

func wrapDashboardPublishCounter(t *testing.T, g *GrafanaLive) *publishCounter {
	t.Helper()
	counter := &publishCounter{ChannelHandlerFactory: g.GrafanaScope.Features["dashboard"]}
	g.GrafanaScope.Features["dashboard"] = counter
	return counter
}

func (p *publishCounter) calls() int32 {
	if p.handler == nil {
		return 0
	}
	return p.handler.calls.Load()
}

type replacingStreamHandler struct {
	data  []byte
	calls atomic.Int32
}

func (h *replacingStreamHandler) SubscribeStream(context.Context, *backend.SubscribeStreamRequest) (*backend.SubscribeStreamResponse, error) {
	return &backend.SubscribeStreamResponse{Status: backend.SubscribeStreamStatusOK}, nil
}

func (h *replacingStreamHandler) PublishStream(_ context.Context, _ *backend.PublishStreamRequest) (*backend.PublishStreamResponse, error) {
	h.calls.Add(1)
	return &backend.PublishStreamResponse{Status: backend.PublishStreamStatusOK, Data: append([]byte(nil), h.data...)}, nil
}

func (h *replacingStreamHandler) RunStream(context.Context, *backend.RunStreamRequest, *backend.StreamSender) error {
	return nil
}

type staticPluginContext struct{}

func (staticPluginContext) GetPluginContext(context.Context, identity.Requester, string, string, bool) (backend.PluginContext, error) {
	return backend.PluginContext{}, nil
}

func installPluginRunner(t *testing.T, g *GrafanaLive, channel string, stream backend.StreamHandler) {
	t.Helper()
	addr, err := plugindata.ParseChannel(channel)
	require.NoError(t, err)
	factory := features.NewPluginRunner(addr.Namespace, "", nil, staticPluginContext{}, stream)
	handler, err := factory.GetHandlerForPath(addr.Path)
	require.NoError(t, err)
	g.channelsMu.Lock()
	g.channels[channel] = handler
	g.channelsMu.Unlock()
}

func dashboardChannel(uid string) string {
	return plugindata.ScopeGrafana + "/dashboard/uid/" + uid
}

type wireDashboardEvent struct {
	UID       string `json:"uid"`
	Action    string `json:"action"`
	SessionID string `json:"sessionId,omitempty"`
	RV        string `json:"rv,omitempty"`
}

func editingStartedJSON(t *testing.T, uid, sessionID, message, blob string) []byte {
	t.Helper()
	body := map[string]any{
		"uid":       uid,
		"action":    "editing-started",
		"sessionId": sessionID,
		"message":   message,
	}
	if blob != "" {
		body["blob"] = blob
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	return raw
}

func reencodedEditingStarted(t *testing.T, uid, sessionID string) []byte {
	t.Helper()
	raw, err := json.Marshal(wireDashboardEvent{UID: uid, Action: "editing-started", SessionID: sessionID})
	require.NoError(t, err)
	return raw
}

func publishBody(t *testing.T, channel string, data []byte) []byte {
	t.Helper()
	raw, err := json.Marshal(struct {
		Channel string          `json:"channel"`
		Data    json.RawMessage `json:"data"`
	}{Channel: channel, Data: data})
	require.NoError(t, err)
	return raw
}

func postLivePublish(t *testing.T, g *GrafanaLive, signedIn *user.SignedInUser, body []byte) response.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/live/publish", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	reqCtx := &contextmodel.ReqContext{
		Context:      &web.Context{Req: req},
		SignedInUser: signedIn,
		IsSignedIn:   true,
	}
	return g.HandleHTTPPublish(reqCtx)
}

type liveWatcher struct {
	client    *centrifuge.Client
	transport *recordingTransport
	mark      int
}

func subscribeLive(t *testing.T, g *GrafanaLive, signedIn *user.SignedInUser, fullChannel string) *liveWatcher {
	t.Helper()
	transport := &recordingTransport{}
	ctx := centrifuge.SetCredentials(context.Background(), &centrifuge.Credentials{
		UserID: strconv.FormatInt(signedIn.UserID, 10),
	})
	ctx = identity.WithRequester(ctx, signedIn)
	client, _, err := centrifuge.NewClient(ctx, g.node, transport)
	require.NoError(t, err)
	t.Cleanup(func() {
		client.Disconnect(centrifuge.DisconnectConnectionClosed)
	})
	ok := client.HandleCommand(&protocol.Command{Id: 1, Connect: &protocol.ConnectRequest{}}, 1)
	require.True(t, ok)
	require.NoError(t, client.Subscribe(fullChannel))
	// Drop the connect and subscribe pushes. Later writes are publications.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && transport.writeCount() < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	return &liveWatcher{client: client, transport: transport, mark: transport.writeCount()}
}

func (w *liveWatcher) waitPayloads(t *testing.T, want int) [][]byte {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	if want == 0 {
		// Publications are written asynchronously. Wait long enough to see one
		// that the handler should have refused.
		deadline = time.Now().Add(200 * time.Millisecond)
	}
	var payloads [][]byte
	for {
		payloads = publicationPayloads(w.transport.writesSince(w.mark))
		if want > 0 && len(payloads) >= want {
			return payloads
		}
		if want > 0 && len(payloads) == 0 && slices.Contains(w.disconnectCodes(), centrifuge.DisconnectSlow.Code) {
			return payloads
		}
		if want == 0 && len(payloads) > 0 {
			return payloads
		}
		if time.Now().After(deadline) {
			return payloads
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (w *liveWatcher) disconnectCodes() []uint32 {
	w.transport.mu.Lock()
	defer w.transport.mu.Unlock()
	codes := make([]uint32, 0, len(w.transport.closes))
	for _, disconnect := range w.transport.closes {
		codes = append(codes, disconnect.Code)
	}
	return codes
}

func publicationPayloads(frames [][]byte) [][]byte {
	var out [][]byte
	for _, frame := range frames {
		var parsed struct {
			Push struct {
				Pub struct {
					Data json.RawMessage `json:"data"`
				} `json:"pub"`
			} `json:"push"`
		}
		if err := json.Unmarshal(frame, &parsed); err != nil || len(parsed.Push.Pub.Data) == 0 {
			continue
		}
		out = append(out, append([]byte(nil), parsed.Push.Pub.Data...))
	}
	return out
}

type recordingTransport struct {
	mu     sync.Mutex
	writes [][]byte
	closes []centrifuge.Disconnect
	closed bool
}

func (t *recordingTransport) Name() string                      { return "websocket" }
func (t *recordingTransport) AcceptProtocol() string            { return "centrifuge-json" }
func (t *recordingTransport) Protocol() centrifuge.ProtocolType { return centrifuge.ProtocolTypeJSON }
func (t *recordingTransport) ProtocolVersion() centrifuge.ProtocolVersion {
	return centrifuge.ProtocolVersion2
}
func (t *recordingTransport) Emulation() bool           { return false }
func (t *recordingTransport) Unidirectional() bool      { return false }
func (t *recordingTransport) DisabledPushFlags() uint64 { return 0 }
func (t *recordingTransport) PingPongConfig() centrifuge.PingPongConfig {
	return centrifuge.PingPongConfig{}
}

func (t *recordingTransport) Write(data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return io.EOF
	}
	t.writes = append(t.writes, append([]byte(nil), data...))
	return nil
}

func (t *recordingTransport) WriteMany(messages ...[]byte) error {
	for _, message := range messages {
		if err := t.Write(message); err != nil {
			return err
		}
	}
	return nil
}

func (t *recordingTransport) Close(disconnect centrifuge.Disconnect) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	t.closes = append(t.closes, disconnect)
	return nil
}

func (t *recordingTransport) writeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.writes)
}

func (t *recordingTransport) writesSince(mark int) [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	if mark > len(t.writes) {
		return nil
	}
	out := make([][]byte, len(t.writes)-mark)
	copy(out, t.writes[mark:])
	return out
}
