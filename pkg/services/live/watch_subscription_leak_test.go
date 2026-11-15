package live

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/centrifugal/protocol"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/services/apiserver"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// These tests are the spec for the Grafana Live provisioning watch lifecycle.
// They fail while a subscription leaves its Kubernetes watch running after the
// subscriber is gone, and they pass once the last subscriber leaving, or the
// websocket closing, stops that watch and drops it.

const (
	watchNamespace = "default"
	watchOrgID     = int64(1)
	testUserHeader = "X-Live-Test-User"
)

func TestWatchStopsWhenTheLastSubscriberLeaves(t *testing.T) {
	t.Run("one subscriber", func(t *testing.T) {
		h := newWatchHarness(t, 100)
		viewer := h.viewer("viewer-1", 11)
		session := h.dial(t, viewer)
		channel := watchChannel("repositories", "repo-one", viewer)
		reply := session.subscribe(t, channel, `{"resourceVersion":"42"}`)
		require.Nil(t, reply.Error, "subscribe reply: %+v", reply.Error)

		opened := h.api.requireActive(t, 1)
		require.Equal(t, "/apis/provisioning.grafana.app/v0alpha1/namespaces/default/repositories", opened[0].path)
		require.Equal(t, "metadata.name=repo-one", opened[0].query.Get("fieldSelector"))
		require.Equal(t, "42", opened[0].query.Get("resourceVersion"))
		require.Equal(t, "true", opened[0].query.Get("watch"))

		session.unsubscribe(t, channel)
		h.api.requireGone(t, opened[0].id)
		require.Zero(t, h.api.activeCount())
	})

	t.Run("shared watch stays until the second subscriber leaves", func(t *testing.T) {
		h := newWatchHarness(t, 100)
		viewer := h.viewer("viewer-1", 11)
		first := h.dial(t, viewer)
		second := h.dial(t, viewer)
		channel := watchChannel("repositories", "repo-shared", viewer)

		first.subscribe(t, channel, "")
		opened := h.api.requireActive(t, 1)
		second.subscribe(t, channel, "")
		require.Equal(t, []int{opened[0].id}, h.api.activeIDs(), "a second subscriber on the same channel must join the existing watch")

		first.unsubscribe(t, channel)
		time.Sleep(200 * time.Millisecond)
		require.Equal(t, []int{opened[0].id}, h.api.activeIDs(), "the watch must keep running while another subscriber remains")

		second.unsubscribe(t, channel)
		h.api.requireGone(t, opened[0].id)
		require.Zero(t, h.api.activeCount())
	})

	t.Run("leaving one channel leaves the other running", func(t *testing.T) {
		h := newWatchHarness(t, 100)
		viewer := h.viewer("viewer-1", 11)
		session := h.dial(t, viewer)
		keep := watchChannel("repositories", "repo-keep", viewer)
		drop := watchChannel("repositories", "repo-drop", viewer)
		session.subscribe(t, keep, "")
		session.subscribe(t, drop, "")
		opened := h.api.requireActive(t, 2)

		session.unsubscribe(t, drop)
		h.api.requireActive(t, 1)
		var kept watchCall
		for _, call := range opened {
			if strings.Contains(call.query.Get("fieldSelector"), "repo-keep") {
				kept = call
			}
		}
		require.NotZero(t, kept.id)
		require.Equal(t, []int{kept.id}, h.api.activeIDs())

		session.unsubscribe(t, keep)
		h.api.requireGone(t, kept.id)
	})
}

func TestWatchStopsWhenTheSocketCloses(t *testing.T) {
	h := newWatchHarness(t, 100)
	viewer := h.viewer("viewer-1", 11)
	session := h.dial(t, viewer)

	session.subscribe(t, watchChannel("repositories", "repo-a", viewer), "")
	session.subscribe(t, watchChannel("repositories", "repo-b", viewer), "")
	opened := h.api.requireActive(t, 2)

	session.close()
	h.api.requireGone(t, opened[0].id, opened[1].id)
	require.Zero(t, h.api.activeCount())
}

func TestWatchStopsForEveryProvisioningResource(t *testing.T) {
	for _, resource := range []string{"repositories", "connections", "jobs", "historicjobs", "settings", "stats"} {
		t.Run(resource, func(t *testing.T) {
			h := newWatchHarness(t, 100)
			viewer := h.viewer("viewer-1", 11)
			before := h.api.activeIDs()
			session := h.dial(t, viewer)
			name := resource + "-item"
			session.subscribe(t, watchChannel(resource, name, viewer), "")
			opened := h.api.requireActive(t, len(before)+1)
			var call watchCall
			for _, candidate := range opened {
				if strings.HasSuffix(candidate.path, "/"+resource) && candidate.query.Get("fieldSelector") == "metadata.name="+name {
					call = candidate
				}
			}
			require.NotZero(t, call.id, "watch for %s was not opened, active: %+v", resource, opened)

			session.close()
			h.api.requireGone(t, call.id)
		})
	}
}

func TestDisconnectedWatchesDoNotAccumulatePastTheConnectionCap(t *testing.T) {
	h := newWatchHarness(t, 1)
	viewer := h.viewer("viewer-1", 11)

	var previous []int
	for i := 0; i < 3; i++ {
		session := h.dialWhenConnected(t, viewer)
		session.subscribe(t, watchChannel("repositories", fmt.Sprintf("repo-%d", i), viewer), "")
		opened := h.api.requireActive(t, 1)
		require.NotContains(t, previous, opened[0].id, "watch from an earlier connection is still running")
		previous = append(previous, opened[0].id)
		session.close()
		h.api.requireGone(t, opened[0].id)
	}
	require.Zero(t, h.api.activeCount())
}

func TestResubscribeAfterLeaveOpensAFreshWatch(t *testing.T) {
	h := newWatchHarness(t, 100)
	viewer := h.viewer("viewer-1", 11)
	session := h.dial(t, viewer)
	channel := watchChannel("repositories", "repo-again", viewer)

	session.subscribe(t, channel, "")
	first := h.api.requireActive(t, 1)
	session.unsubscribe(t, channel)
	h.api.requireGone(t, first[0].id)

	session.subscribe(t, channel, "")
	second := h.api.requireActive(t, 1)
	require.NotEqual(t, first[0].id, second[0].id)
	session.unsubscribe(t, channel)
	h.api.requireGone(t, second[0].id)
}

func TestWatchIsNotSharedAcrossUsers(t *testing.T) {
	h := newWatchHarness(t, 100)
	firstUser := h.viewer("viewer-1", 11)
	secondUser := h.viewer("viewer-2", 12)

	first := h.dial(t, firstUser)
	second := h.dial(t, secondUser)
	first.subscribe(t, watchChannel("repositories", "same-repo", firstUser), "")
	second.subscribe(t, watchChannel("repositories", "same-repo", secondUser), "")
	opened := h.api.requireActive(t, 2)

	first.close()
	h.api.requireActive(t, 1)
	var remaining watchCall
	for _, call := range opened {
		if h.api.isActive(call.id) {
			remaining = call
		}
	}
	require.NotZero(t, remaining.id)
	require.Contains(t, remaining.path, "/namespaces/default/")

	second.close()
	h.api.requireGone(t, remaining.id)
}

func TestRejectedWatchSubscribeDoesNotOpenAWatch(t *testing.T) {
	h := newWatchHarness(t, 100)
	viewer := h.viewer("viewer-1", 11)
	session := h.dial(t, viewer)

	cases := []struct {
		name    string
		channel string
	}{
		{name: "other user's suffix", channel: watchNamespace + "/watch/provisioning.grafana.app/v0alpha1/repositories=repo-x/viewer-2"},
		{name: "non provisioning group", channel: watchNamespace + "/watch/dashboard.grafana.app/v0alpha1/dashboards=abc/viewer-1"},
		{name: "other org namespace", channel: "org-2/watch/provisioning.grafana.app/v0alpha1/repositories=repo-x/viewer-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply := session.roundTrip(t, protocol.Command{Subscribe: &protocol.SubscribeRequest{Channel: tc.channel}})
			require.NotNil(t, reply.Error, "subscribe must be refused")
			time.Sleep(100 * time.Millisecond)
			require.Zero(t, h.api.activeCount(), "a refused subscribe must not leave a watch behind")
		})
	}

	t.Run("publish does not open a watch", func(t *testing.T) {
		reply := session.roundTrip(t, protocol.Command{Publish: &protocol.PublishRequest{
			Channel: watchChannel("repositories", "repo-pub", viewer),
			Data:    protocol.Raw(`{}`),
		}})
		require.NotNil(t, reply.Error)
		require.Zero(t, h.api.activeCount())
	})
}

func TestUnsignedLiveSocketDoesNotOpenAWatch(t *testing.T) {
	h := newWatchHarness(t, 100)
	wsURL := "ws" + strings.TrimPrefix(h.http.URL, "http") + "/api/live/ws"
	_, resp, err := h.dialer.Dial(wsURL, nil)
	require.Error(t, err)
	if resp != nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "body: %s", body)
	}
	require.Zero(t, h.api.activeCount())
}

type watchCall struct {
	id    int
	path  string
	query url.Values
}

type watchAPI struct {
	server *httptest.Server
	mu     sync.Mutex
	next   int
	active map[int]watchCall
	seen   []watchCall
}

func newWatchAPI() *watchAPI {
	api := &watchAPI{active: map[int]watchCall{}}
	api.server = httptest.NewServer(http.HandlerFunc(api.serve))
	return api
}

func (a *watchAPI) URL() string { return a.server.URL }

func (a *watchAPI) Close() {
	// Outstanding watches are the bug under test. Close the client side of
	// those connections first so Server.Close does not wait on them.
	a.server.CloseClientConnections()
	a.server.Close()
}

func (a *watchAPI) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("watch") != "true" {
		http.Error(w, "not a watch", http.StatusNotFound)
		return
	}
	call := watchCall{path: r.URL.Path, query: r.URL.Query()}
	a.mu.Lock()
	a.next++
	call.id = a.next
	a.active[call.id] = call
	a.seen = append(a.seen, call)
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		delete(a.active, call.id)
		a.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	<-r.Context().Done()
}

func (a *watchAPI) activeCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.active)
}

func (a *watchAPI) activeIDs() []int {
	a.mu.Lock()
	defer a.mu.Unlock()
	ids := make([]int, 0, len(a.active))
	for id := range a.active {
		ids = append(ids, id)
	}
	return ids
}

func (a *watchAPI) isActive(id int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.active[id]
	return ok
}

func (a *watchAPI) requireActive(t *testing.T, want int) []watchCall {
	t.Helper()
	var got []watchCall
	require.Eventually(t, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		if len(a.active) != want {
			return false
		}
		got = make([]watchCall, 0, len(a.active))
		for _, call := range a.active {
			got = append(got, call)
		}
		return true
	}, time.Second, 10*time.Millisecond, "active watches = %d (%s), want %d", a.activeCount(), a.debug(), want)
	return got
}

func (a *watchAPI) requireGone(t *testing.T, ids ...int) {
	t.Helper()
	require.Eventually(t, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, id := range ids {
			if _, ok := a.active[id]; ok {
				return false
			}
		}
		return true
	}, time.Second, 10*time.Millisecond, "watches %v still running (%s)", ids, a.debug())
}

func (a *watchAPI) debug() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	parts := make([]string, 0, len(a.active))
	for _, call := range a.active {
		parts = append(parts, fmt.Sprintf("%d %s?%s", call.id, call.path, call.query.Encode()))
	}
	return strings.Join(parts, "; ")
}

type watchHarness struct {
	api    *watchAPI
	http   *httptest.Server
	users  map[string]*user.SignedInUser
	dialer websocket.Dialer
}

func newWatchHarness(t *testing.T, maxConnections int) *watchHarness {
	t.Helper()
	api := newWatchAPI()
	t.Cleanup(api.Close)

	cfg := setting.NewCfg()
	cfg.LiveMaxConnections = maxConnections
	cfg.AppURL = "http://localhost:3000/"
	routes := routing.NewRouteRegister()
	_, err := ProvideService(
		cfg,
		routes,
		nil, nil, nil, nil,
		&usagestats.UsageStatsMock{T: t},
		featuremgmt.WithFeatures(),
		&dashboards.FakeDashboardService{},
		apiserver.RestConfigProviderFunc(func(context.Context) (*rest.Config, error) {
			return &rest.Config{
				Host: api.URL(),
				// Keep the watch on the test server. A nil proxy follows the environment.
				Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
			}, nil
		}),
	)
	require.NoError(t, err)

	h := &watchHarness{
		api:   api,
		users: map[string]*user.SignedInUser{},
		dialer: websocket.Dialer{
			Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
		},
	}

	mux := web.New()
	mux.Use(func(c *web.Context) {
		reqCtx := &contextmodel.ReqContext{
			Context: c,
			Logger:  log.New("live-watch-test"),
		}
		if uid := c.Req.Header.Get(testUserHeader); uid != "" {
			reqCtx.SignedInUser = h.users[uid]
			reqCtx.IsSignedIn = reqCtx.SignedInUser != nil
		}
		c.Req = c.Req.WithContext(ctxkey.Set(c.Req.Context(), reqCtx))
	})
	routes.Register(mux)
	h.http = httptest.NewServer(mux)
	t.Cleanup(func() {
		h.http.CloseClientConnections()
		h.http.Close()
	})
	return h
}

func (h *watchHarness) viewer(uid string, id int64) *user.SignedInUser {
	viewer := &user.SignedInUser{
		UserID:    id,
		UserUID:   uid,
		OrgID:     watchOrgID,
		OrgRole:   identity.RoleViewer,
		Namespace: watchNamespace,
		Login:     uid,
		Name:      uid,
	}
	h.users[uid] = viewer
	return viewer
}

func (h *watchHarness) dial(t *testing.T, viewer *user.SignedInUser) *liveSession {
	t.Helper()
	session, err := h.open(t, viewer)
	require.NoError(t, err)
	t.Cleanup(session.close)
	reply := session.roundTrip(t, protocol.Command{Connect: &protocol.ConnectRequest{}})
	require.Nil(t, reply.Error, "connect reply: %+v", reply.Error)
	require.NotNil(t, reply.Connect)
	return session
}

// dialWhenConnected opens a socket once the connection cap has room again.
// Disconnect tears the previous socket down asynchronously, so a retry is
// required when the cap is one.
func (h *watchHarness) dialWhenConnected(t *testing.T, viewer *user.SignedInUser) *liveSession {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		session, err := h.open(t, viewer)
		if err != nil {
			last = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		reply, err := session.exchange(protocol.Command{Connect: &protocol.ConnectRequest{}})
		if err != nil || reply.Error != nil || reply.Connect == nil {
			last = fmt.Errorf("connect failed: %v %+v", err, reply.Error)
			session.close()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		// The connection cap is enforced after the connect reply, and it closes
		// the socket asynchronously. Wait until that decision has landed.
		time.Sleep(50 * time.Millisecond)
		if session.failed() {
			last = fmt.Errorf("socket closed after connect")
			session.close()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		t.Cleanup(session.close)
		return session
	}
	t.Fatalf("could not open a live socket under the connection cap: %v", last)
	return nil
}

func (h *watchHarness) open(t *testing.T, viewer *user.SignedInUser) (*liveSession, error) {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(h.http.URL, "http") + "/api/live/ws"
	conn, resp, err := h.dialer.Dial(wsURL, http.Header{testUserHeader: []string{viewer.UserUID}})
	if err != nil {
		body := ""
		if resp != nil {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = string(raw)
		}
		return nil, fmt.Errorf("websocket handshake: %w (%s)", err, body)
	}
	session := &liveSession{conn: conn, replies: map[uint32]protocol.Reply{}}
	go session.read()
	return session, nil
}

type liveSession struct {
	conn    *websocket.Conn
	mu      sync.Mutex
	next    uint32
	replies map[uint32]protocol.Reply
	readErr error
	closed  bool
}

func (s *liveSession) read() {
	for {
		_, data, err := s.conn.ReadMessage()
		if err != nil {
			s.mu.Lock()
			s.readErr = err
			s.mu.Unlock()
			return
		}
		var reply protocol.Reply
		if json.Unmarshal(data, &reply) != nil || reply.Id == 0 {
			continue
		}
		s.mu.Lock()
		s.replies[reply.Id] = reply
		s.mu.Unlock()
	}
}

func (s *liveSession) roundTrip(t *testing.T, cmd protocol.Command) protocol.Reply {
	t.Helper()
	reply, err := s.exchange(cmd)
	require.NoError(t, err)
	return reply
}

func (s *liveSession) exchange(cmd protocol.Command) (protocol.Reply, error) {
	s.mu.Lock()
	s.next++
	cmd.Id = s.next
	s.mu.Unlock()

	body, err := json.Marshal(cmd)
	if err != nil {
		return protocol.Reply{}, err
	}
	if err := s.conn.WriteMessage(websocket.TextMessage, body); err != nil {
		return protocol.Reply{}, err
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		reply, ok := s.replies[cmd.Id]
		readErr := s.readErr
		s.mu.Unlock()
		if ok {
			return reply, nil
		}
		if readErr != nil {
			return protocol.Reply{}, fmt.Errorf("socket closed waiting for reply %d: %w", cmd.Id, readErr)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return protocol.Reply{}, fmt.Errorf("timed out waiting for reply %d", cmd.Id)
}

func (s *liveSession) subscribe(t *testing.T, channel, data string) protocol.Reply {
	t.Helper()
	cmd := protocol.Command{Subscribe: &protocol.SubscribeRequest{Channel: channel}}
	if data != "" {
		cmd.Subscribe.Data = protocol.Raw(data)
	}
	reply := s.roundTrip(t, cmd)
	require.Nil(t, reply.Error, "subscribe %s: %+v", channel, reply.Error)
	return reply
}

func (s *liveSession) unsubscribe(t *testing.T, channel string) {
	t.Helper()
	reply := s.roundTrip(t, protocol.Command{Unsubscribe: &protocol.UnsubscribeRequest{Channel: channel}})
	require.Nil(t, reply.Error, "unsubscribe %s: %+v", channel, reply.Error)
}

func (s *liveSession) failed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readErr != nil
}

func (s *liveSession) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	_ = s.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	_ = s.conn.Close()
}

func watchChannel(resource, name string, viewer *user.SignedInUser) string {
	return fmt.Sprintf("%s/watch/provisioning.grafana.app/v0alpha1/%s=%s/%s", watchNamespace, resource, name, viewer.GetIdentifier())
}
