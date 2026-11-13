package features

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/live"
	"github.com/stretchr/testify/require"

	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/plugins/backendplugin/coreplugin"
	pluginslog "github.com/grafana/grafana/pkg/plugins/log"
	"github.com/grafana/grafana/pkg/services/live/model"
	"github.com/grafana/grafana/pkg/services/live/orgchannel"
	"github.com/grafana/grafana/pkg/services/live/runstream"
	"github.com/grafana/grafana/pkg/services/user"
	testdatasource "github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource"
)

const testDataPluginID = "grafana-testdata-datasource"

// streamCounter delegates to the real core plugin stream handler and records
// every RunStream call that reaches it.
type streamCounter struct {
	next backend.StreamHandler

	mu       sync.Mutex
	calls    map[string]int
	inflight map[string]int
}

func (s *streamCounter) SubscribeStream(ctx context.Context, req *backend.SubscribeStreamRequest) (*backend.SubscribeStreamResponse, error) {
	return s.next.SubscribeStream(ctx, req)
}

func (s *streamCounter) PublishStream(ctx context.Context, req *backend.PublishStreamRequest) (*backend.PublishStreamResponse, error) {
	return s.next.PublishStream(ctx, req)
}

func (s *streamCounter) RunStream(ctx context.Context, req *backend.RunStreamRequest, sender *backend.StreamSender) error {
	s.mu.Lock()
	if s.calls == nil {
		s.calls = map[string]int{}
		s.inflight = map[string]int{}
	}
	s.calls[req.Path]++
	s.inflight[req.Path]++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inflight[req.Path]--
		s.mu.Unlock()
	}()
	return s.next.RunStream(ctx, req, sender)
}

func (s *streamCounter) callsFor(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[path]
}

func (s *streamCounter) inflightFor(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inflight[path]
}

func (s *streamCounter) totalCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		n += c
	}
	return n
}

type recordingPublisher struct {
	mu sync.Mutex
	n  map[string]int
}

func (p *recordingPublisher) PublishLocal(channel string, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.n == nil {
		p.n = map[string]int{}
	}
	p.n[channel]++
	return nil
}

func (p *recordingPublisher) count(channel string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n[channel]
}

type fixedSubscribers struct {
	n int
}

func (f fixedSubscribers) GetNumLocalSubscribers(string) (int, error) {
	return f.n, nil
}

// viewerPluginContext returns a plugin context for any signed-in user. Plugin
// scope does not consult datasource query permissions.
type viewerPluginContext struct{}

func (viewerPluginContext) GetPluginContext(_ context.Context, user identity.Requester, pluginID, _ string, _ bool) (backend.PluginContext, error) {
	return backend.PluginContext{OrgID: user.GetOrgID(), PluginID: pluginID}, nil
}

type liveHarness struct {
	counter   *streamCounter
	publisher *recordingPublisher
	manager   *runstream.Manager
	cancel    context.CancelFunc
	viewer    *user.SignedInUser
}

func newLiveHarness(t *testing.T) *liveHarness {
	t.Helper()
	svc := testdatasource.ProvideService()
	plugin, err := coreplugin.New(backend.ServeOpts{
		StreamHandler:    svc,
		QueryDataHandler: svc,
	})(testDataPluginID, pluginslog.New("test.testdata"), nil, nil)
	require.NoError(t, err)
	handler, ok := plugin.(backend.StreamHandler)
	require.True(t, ok)

	counter := &streamCounter{next: handler}
	publisher := &recordingPublisher{}
	manager := runstream.NewManager(publisher, fixedSubscribers{n: 1}, viewerPluginContext{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = manager.Run(ctx)
	}()

	viewer := &user.SignedInUser{
		UserID:    42,
		OrgID:     1,
		OrgRole:   identity.RoleViewer,
		Login:     "viewer",
		Namespace: claims.OrgNamespaceFormatter(1),
	}
	require.True(t, viewer.HasRole(identity.RoleViewer))
	require.False(t, viewer.HasRole(identity.RoleEditor))
	require.False(t, viewer.IsGrafanaAdmin)

	return &liveHarness{
		counter:   counter,
		publisher: publisher,
		manager:   manager,
		cancel:    cancel,
		viewer:    viewer,
	}
}

func (h *liveHarness) runner(datasourceUID string) *PluginRunner {
	return NewPluginRunner(testDataPluginID, datasourceUID, h.manager, viewerPluginContext{}, h.counter)
}

// subscribeAsProduction parses the channel the way Grafana Live does, then
// calls the plugin runner OnSubscribe for that path.
func (h *liveHarness) subscribe(t *testing.T, scope, namespace, path string) (model.SubscribeReply, backend.SubscribeStreamStatus, error) {
	t.Helper()
	channel := scope + "/" + namespace + "/" + path
	full := orgchannel.PrependK8sNamespace(h.viewer.GetNamespace(), channel)
	info, stripped, err := orgchannel.StripK8sNamespace(full)
	require.NoError(t, err)
	require.Equal(t, h.viewer.GetNamespace(), info.Value)
	addr, err := live.ParseChannel(stripped)
	require.NoError(t, err)
	require.Equal(t, path, addr.Path)
	require.Equal(t, scope, addr.Scope)
	require.Equal(t, namespace, addr.Namespace)

	handler, err := h.runner("").GetHandlerForPath(addr.Path)
	if scope == live.ScopeDatasource {
		handler, err = h.runner(namespace).GetHandlerForPath(addr.Path)
	}
	require.NoError(t, err)
	return handler.OnSubscribe(context.Background(), h.viewer, model.SubscribeEvent{
		Channel: stripped,
		Path:    addr.Path,
	})
}

func (h *liveHarness) streamChannel(scope, namespace, path string) string {
	return orgchannel.PrependK8sNamespace(h.viewer.GetNamespace(), scope+"/"+namespace+"/"+path)
}

func TestViewerCannotStartDistinctTestDataStreamsPerPath(t *testing.T) {
	h := newLiveHarness(t)

	type sub struct {
		scope     string
		namespace string
		path      string
	}
	targets := []sub{
		{live.ScopePlugin, testDataPluginID, "random-20Hz-stream-1"},
		{live.ScopePlugin, testDataPluginID, "random-20Hz-stream-2"},
		{live.ScopePlugin, testDataPluginID, "random-20Hz-stream-3"},
		{live.ScopePlugin, testDataPluginID, "random-20Hz-stream-17"},
		{live.ScopePlugin, testDataPluginID, "random-20Hz-stream-1-extra"},
		{live.ScopePlugin, testDataPluginID, "prefix-random-20Hz-stream"},
		{live.ScopePlugin, testDataPluginID, "random-20Hz-streamX"},
		{live.ScopePlugin, testDataPluginID, "not-a-stream"},
		{live.ScopePlugin, testDataPluginID, "random-2s-stream-4"},
		{live.ScopePlugin, testDataPluginID, "custom-labeled"},
		{live.ScopeDatasource, "testdata-uid", "random-20Hz-stream-8"},
		{live.ScopeDatasource, "testdata-uid", "another-path"},
	}
	for i := 20; i < 36; i++ {
		targets = append(targets, sub{
			scope:     live.ScopePlugin,
			namespace: testDataPluginID,
			path:      "random-20Hz-stream-" + itoa(i),
		})
	}

	var accepted []string
	for _, target := range targets {
		_, status, err := h.subscribe(t, target.scope, target.namespace, target.path)
		if err == nil && status == backend.SubscribeStreamStatusOK {
			accepted = append(accepted, target.scope+"/"+target.namespace+"/"+target.path)
		}
	}

	// Give the runstream manager time to enter RunStream and, for paths it
	// rejects, to retry. A fixed handler refuses these subscriptions before
	// that goroutine is started.
	time.Sleep(700 * time.Millisecond)

	var inflight int
	var published int
	for _, target := range targets {
		inflight += h.counter.inflightFor(target.path)
		published += h.publisher.count(h.streamChannel(target.scope, target.namespace, target.path))
	}
	require.Zero(t, len(accepted)+h.counter.totalCalls()+inflight+published,
		"accepted=%v runCalls=%d inflight=%d published=%d", accepted, h.counter.totalCalls(), inflight, published)
}

func TestListedTestDataStreamsStillRunOnce(t *testing.T) {
	h := newLiveHarness(t)
	paths := []string{
		"random-2s-stream",
		"random-flakey-stream",
		"random-labeled-stream",
		"random-20Hz-stream",
	}
	for _, path := range paths {
		_, status, err := h.subscribe(t, live.ScopePlugin, testDataPluginID, path)
		require.NoError(t, err)
		require.Equal(t, backend.SubscribeStreamStatusOK, status, path)
	}

	require.Eventually(t, func() bool {
		return h.counter.callsFor("random-20Hz-stream") >= 1 &&
			h.publisher.count(h.streamChannel(live.ScopePlugin, testDataPluginID, "random-20Hz-stream")) >= 1
	}, 2*time.Second, 20*time.Millisecond)

	time.Sleep(300 * time.Millisecond)
	for _, path := range paths {
		require.Equal(t, 1, h.counter.callsFor(path), path)
		require.Equal(t, 1, h.counter.inflightFor(path), path)
	}

	// A second subscriber on the same channel must not start another stream.
	_, status, err := h.subscribe(t, live.ScopePlugin, testDataPluginID, "random-20Hz-stream")
	require.NoError(t, err)
	require.Equal(t, backend.SubscribeStreamStatusOK, status)
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, 1, h.counter.callsFor("random-20Hz-stream"))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
