package sims

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"
)

// Security contract for the process-wide simulation map.
//
// Every entry point that resolves a simulation (query JSON, resource path,
// subscribe, and run-stream) must enforce these limits before it inserts a
// map entry or calls a simulation constructor:
//
//   - maxLiveSimulations: at most this many simulations are retained.
//   - maxSimulationUIDBytes: a longer uid is rejected and not constructed.
//
// When an insert would exceed the cap, the least recently used simulation that
// has no active RunStream is closed and removed first, and only then is the
// new simulation constructed. A simulation with an active RunStream is not
// eligible. If every retained simulation has an active RunStream, the new
// request is rejected and nothing is constructed or inserted.
//
// RunStream removes and closes its simulation before it returns, including
// when its context is canceled. A failed request (bad tick, unknown type,
// oversized uid, invalid resource body) must not construct a simulation and
// must not leave a map entry behind.
const (
	maxLiveSimulations    = 32
	maxSimulationUIDBytes = 128
)

type closeSpy struct {
	key    simulationKey
	once   sync.Once
	closed chan struct{}
}

func newCloseSpy(key simulationKey) *closeSpy {
	return &closeSpy{key: key, closed: make(chan struct{})}
}

func (s *closeSpy) GetState() simulationState { return simulationState{Key: s.key} }

func (s *closeSpy) SetConfig(map[string]any) error { return nil }

func (s *closeSpy) NewFrame(size int) *data.Frame {
	return data.NewFrame("",
		data.NewField("time", nil, make([]time.Time, size)),
		data.NewField("value", nil, make([]float64, size)),
	)
}

func (s *closeSpy) GetValues(t time.Time) map[string]any {
	return map[string]any{"time": t, "value": float64(1)}
}

func (s *closeSpy) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func (s *closeSpy) wasClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// spyEngine records every simulation the engine constructs. create always
// returns a simulation so a missing length check is visible as a retained entry.
type spyEngine struct {
	eng     *SimulationEngine
	mu      sync.Mutex
	peak    int
	created int
	sims    map[string]*closeSpy
}

func newSpyEngine(t *testing.T) *spyEngine {
	t.Helper()
	eng, err := NewSimulationEngine()
	require.NoError(t, err)
	s := &spyEngine{eng: eng, sims: map[string]*closeSpy{}}
	require.NoError(t, eng.register(simulationInfo{
		Type: "spy",
		Name: "spy",
		create: func(cfg simulationState) (Simulation, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			// Lookup holds eng.mutex across create, so this length is the
			// number of entries already retained at construction time.
			if n := len(eng.running); n > s.peak {
				s.peak = n
			}
			s.created++
			sim := newCloseSpy(cfg.Key)
			s.sims[cfg.Key.UID] = sim
			return sim, nil
		},
	}))
	return s
}

func (s *spyEngine) createdCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.created
}

func (s *spyEngine) peakCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peak
}

func (s *spyEngine) spy(uid string) *closeSpy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sims[uid]
}

func runningSnapshot(eng *SimulationEngine) map[string]Simulation {
	eng.mutex.Lock()
	defer eng.mutex.Unlock()
	out := make(map[string]Simulation, len(eng.running))
	for k, v := range eng.running {
		out[k] = v
	}
	return out
}

func requireKeyAbsent(t *testing.T, eng *SimulationEngine, key string) {
	t.Helper()
	_, ok := runningSnapshot(eng)[key]
	require.Falsef(t, ok, "simulation %s was retained", key)
}

func requireRunningLen(t *testing.T, eng *SimulationEngine, n int) {
	t.Helper()
	require.Len(t, runningSnapshot(eng), n)
}

func simQueryJSON(typ, uid string) []byte {
	raw, err := json.Marshal(map[string]any{
		"scenarioId": "simulation",
		"sim": map[string]any{
			"last": true,
			"key": map[string]any{
				"type": typ,
				"tick": 1,
				"uid":  uid,
			},
		},
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func queryRequest(raws ...[]byte) *backend.QueryDataRequest {
	queries := make([]backend.DataQuery, len(raws))
	for i, raw := range raws {
		queries[i] = backend.DataQuery{
			RefID:         fmt.Sprintf("A%d", i),
			JSON:          raw,
			Interval:      time.Second,
			MaxDataPoints: 10,
			TimeRange: backend.TimeRange{
				From: time.Now().Add(-time.Minute),
				To:   time.Now().Add(time.Minute),
			},
		}
	}
	return &backend.QueryDataRequest{Queries: queries}
}

func uid(i int) string {
	return fmt.Sprintf("u%04d", i)
}

func spyKey(uid string) string {
	return simulationKey{Type: "spy", TickHZ: 1, UID: uid}.String()
}

// streamTick is fast enough that RunStream emits its first frame immediately,
// and slow enough to stay inside the engine's allowed tick range.
const streamTick = 50

func streamKey(uid string) string {
	return simulationKey{Type: "spy", TickHZ: streamTick, UID: uid}.String()
}

func (s *spyEngine) queryUID(t *testing.T, uid string) error {
	t.Helper()
	_, err := s.eng.QueryData(context.Background(), queryRequest(simQueryJSON("spy", uid)))
	return err
}

func (s *spyEngine) fill(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		require.NoError(t, s.queryUID(t, uid(i)))
	}
}

type packetSink struct {
	once sync.Once
	got  chan struct{}
}

func newPacketSink() *packetSink {
	return &packetSink{got: make(chan struct{})}
}

func (p *packetSink) Send(*backend.StreamPacket) error {
	p.once.Do(func() { close(p.got) })
	return nil
}

func (s *spyEngine) startStream(t *testing.T, uid string) (cancel func(), done <-chan error) {
	t.Helper()
	ctx, cancelCtx := context.WithCancel(context.Background())
	sink := newPacketSink()
	finished := make(chan error, 1)
	go func() {
		finished <- s.eng.RunStream(ctx, &backend.RunStreamRequest{
			Path: "sim/" + streamKey(uid),
		}, backend.NewStreamSender(sink))
	}()
	select {
	case <-sink.got:
	case err := <-finished:
		t.Fatalf("RunStream for %s returned before sending a frame: %v", uid, err)
	case <-time.After(2 * time.Second):
		cancelCtx()
		t.Fatalf("RunStream for %s did not send a frame", uid)
	}
	return cancelCtx, finished
}

func TestSimulationRetention_QueryDataCapsDistinctUIDs(t *testing.T) {
	s := newSpyEngine(t)
	const extra = 8
	raws := make([][]byte, maxLiveSimulations+extra)
	for i := range raws {
		raws[i] = simQueryJSON("spy", uid(i))
	}
	_, err := s.eng.QueryData(context.Background(), queryRequest(raws...))
	require.NoError(t, err)

	require.Less(t, s.peakCount(), maxLiveSimulations, "a simulation was constructed while the map was already at the cap")
	requireRunningLen(t, s.eng, maxLiveSimulations)
	for i := 0; i < extra; i++ {
		requireKeyAbsent(t, s.eng, spyKey(uid(i)))
		require.True(t, s.spy(uid(i)).wasClosed(), "evicted simulation %s was not closed", uid(i))
	}
	for i := extra; i < maxLiveSimulations+extra; i++ {
		_, ok := runningSnapshot(s.eng)[spyKey(uid(i))]
		require.Truef(t, ok, "most recently queried simulation %s was evicted", uid(i))
		require.False(t, s.spy(uid(i)).wasClosed())
	}
}

func TestSimulationRetention_BuiltInTypesShareTheCap(t *testing.T) {
	for _, typ := range []string{"sine", "flight", "tank"} {
		t.Run(typ, func(t *testing.T) {
			eng, err := NewSimulationEngine()
			require.NoError(t, err)
			raws := make([][]byte, maxLiveSimulations+5)
			for i := range raws {
				raws[i] = simQueryJSON(typ, uid(i))
			}
			_, err = eng.QueryData(context.Background(), queryRequest(raws...))
			require.NoError(t, err)
			require.LessOrEqual(t, len(runningSnapshot(eng)), maxLiveSimulations)
			key := simulationKey{Type: typ, TickHZ: 1, UID: uid(len(raws) - 1)}.String()
			_, ok := runningSnapshot(eng)[key]
			require.True(t, ok, "newest %s simulation was not retained", typ)
			first := simulationKey{Type: typ, TickHZ: 1, UID: uid(0)}.String()
			requireKeyAbsent(t, eng, first)
		})
	}
}

func TestSimulationRetention_RequeryRefreshesLeastRecentlyUsed(t *testing.T) {
	s := newSpyEngine(t)
	s.fill(t, maxLiveSimulations)
	require.NoError(t, s.queryUID(t, uid(0)))
	require.NoError(t, s.queryUID(t, "fresh"))

	requireRunningLen(t, s.eng, maxLiveSimulations)
	_, ok := runningSnapshot(s.eng)[spyKey(uid(0))]
	require.True(t, ok, "a simulation that was queried again was evicted")
	require.False(t, s.spy(uid(0)).wasClosed())
	requireKeyAbsent(t, s.eng, spyKey(uid(1)))
	require.True(t, s.spy(uid(1)).wasClosed())
	_, ok = runningSnapshot(s.eng)[spyKey("fresh")]
	require.True(t, ok)
}

func TestSimulationRetention_RepeatedUIDStaysOneEntry(t *testing.T) {
	s := newSpyEngine(t)
	for i := 0; i < maxLiveSimulations*2; i++ {
		require.NoError(t, s.queryUID(t, "same"))
	}
	requireRunningLen(t, s.eng, 1)
	require.Equal(t, 1, s.createdCount())
	require.False(t, s.spy("same").wasClosed())
}

func TestSimulationRetention_OversizedUIDIsRejectedBeforeCreate(t *testing.T) {
	s := newSpyEngine(t)
	exact := strings.Repeat("a", maxSimulationUIDBytes)
	over := strings.Repeat("b", maxSimulationUIDBytes+1)
	huge := strings.Repeat("c", 1<<20)

	require.NoError(t, s.queryUID(t, exact))
	requireRunningLen(t, s.eng, 1)
	require.Equal(t, 1, s.createdCount())

	for _, uid := range []string{over, huge} {
		before := s.createdCount()
		_, err := s.eng.QueryData(context.Background(), queryRequest(simQueryJSON("spy", uid)))
		require.Error(t, err)
		require.Equal(t, before, s.createdCount(), "oversized uid %d was constructed", len(uid))
		requireKeyAbsent(t, s.eng, spyKey(uid))
	}
	requireRunningLen(t, s.eng, 1)
}

func TestSimulationRetention_InvalidQueryDoesNotInsert(t *testing.T) {
	s := newSpyEngine(t)
	before := runningSnapshot(s.eng)

	_, err := s.eng.QueryData(context.Background(), queryRequest([]byte(`{"sim":`)))
	require.Error(t, err)

	_, err = s.eng.QueryData(context.Background(), queryRequest(simQueryJSON("missing", "x")))
	require.Error(t, err)

	tooFast, err := json.Marshal(map[string]any{
		"sim": map[string]any{"last": true, "key": map[string]any{"type": "spy", "tick": 51, "uid": "fast"}},
	})
	require.NoError(t, err)
	_, err = s.eng.QueryData(context.Background(), queryRequest(tooFast))
	require.Error(t, err)

	tooSlow, err := json.Marshal(map[string]any{
		"sim": map[string]any{"last": true, "key": map[string]any{"type": "spy", "tick": 0.01, "uid": "slow"}},
	})
	require.NoError(t, err)
	_, err = s.eng.QueryData(context.Background(), queryRequest(tooSlow))
	require.Error(t, err)

	require.Equal(t, 0, s.createdCount())
	require.Equal(t, before, runningSnapshot(s.eng))

	// A valid query earlier in the same request is kept. The rejected query is not created.
	_, err = s.eng.QueryData(context.Background(), queryRequest(simQueryJSON("spy", "kept"), simQueryJSON("spy", strings.Repeat("z", maxSimulationUIDBytes+1))))
	require.Error(t, err)
	require.Equal(t, 1, s.createdCount())
	_, ok := runningSnapshot(s.eng)[spyKey("kept")]
	require.True(t, ok)
	requireKeyAbsent(t, s.eng, spyKey(strings.Repeat("z", maxSimulationUIDBytes+1)))
}

func TestSimulationRetention_ConcurrentQueriesStayWithinCap(t *testing.T) {
	s := newSpyEngine(t)
	var wg sync.WaitGroup
	for i := 0; i < maxLiveSimulations*4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = s.eng.QueryData(context.Background(), queryRequest(simQueryJSON("spy", uid(i))))
		}(i)
	}
	wg.Wait()
	require.LessOrEqual(t, len(runningSnapshot(s.eng)), maxLiveSimulations)
	require.Less(t, s.peakCount(), maxLiveSimulations)
}

func TestSimulationRetention_ResourcePathSharesTheCap(t *testing.T) {
	s := newSpyEngine(t)
	for i := 0; i < maxLiveSimulations+3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/sim/"+spyKey(uid(i)), nil)
		rr := httptest.NewRecorder()
		s.eng.GetSimulationHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	}
	require.Less(t, s.peakCount(), maxLiveSimulations)
	requireRunningLen(t, s.eng, maxLiveSimulations)
	requireKeyAbsent(t, s.eng, spyKey(uid(0)))
	require.True(t, s.spy(uid(0)).wasClosed())
	_, ok := runningSnapshot(s.eng)[spyKey(uid(maxLiveSimulations+2))]
	require.True(t, ok)

	// After 0..2 were evicted, uid 3 is the least recently used entry still
	// in the map. Reading it makes uid 4 the eviction victim.
	req := httptest.NewRequest(http.MethodGet, "/sim/"+spyKey(uid(3)), nil)
	rr := httptest.NewRecorder()
	s.eng.GetSimulationHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	req = httptest.NewRequest(http.MethodGet, "/sim/"+spyKey("from-resource"), nil)
	rr = httptest.NewRecorder()
	s.eng.GetSimulationHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	_, ok = runningSnapshot(s.eng)[spyKey(uid(3))]
	require.True(t, ok, "resource read did not refresh the simulation")
	requireKeyAbsent(t, s.eng, spyKey(uid(4)))
	require.True(t, s.spy(uid(4)).wasClosed())
}

func TestSimulationRetention_ResourcePostFailureDoesNotCreate(t *testing.T) {
	s := newSpyEngine(t)
	req := httptest.NewRequest(http.MethodPost, "/sim/"+spyKey("post-fail"), strings.NewReader("{"))
	rr := httptest.NewRecorder()
	s.eng.GetSimulationHandler(rr, req)
	require.GreaterOrEqual(t, rr.Code, 400)
	require.Equal(t, 0, s.createdCount())
	requireKeyAbsent(t, s.eng, spyKey("post-fail"))
	requireRunningLen(t, s.eng, 0)
}

func TestSimulationRetention_ResourceRejectsOversizedAndUnknown(t *testing.T) {
	s := newSpyEngine(t)
	cases := []string{
		"/sim/" + spyKey(strings.Repeat("p", maxSimulationUIDBytes+1)),
		"/sim/nope/1hz/x",
		"/sim/spy/51hz/x",
		"/sim/spy/0.01hz/x",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()
			s.eng.GetSimulationHandler(rr, req)
			require.GreaterOrEqualf(t, rr.Code, 400, path)
		})
	}
	require.Equal(t, 0, s.createdCount())
	requireRunningLen(t, s.eng, 0)
}

func TestSimulationRetention_SubscribeAndRunStreamShareTheCap(t *testing.T) {
	s := newSpyEngine(t)
	for i := 0; i < maxLiveSimulations; i++ {
		resp, err := s.eng.SubscribeStream(context.Background(), &backend.SubscribeStreamRequest{
			Path: "sim/" + spyKey(uid(i)),
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, backend.SubscribeStreamStatusOK, resp.Status)
	}
	requireRunningLen(t, s.eng, maxLiveSimulations)

	resp, err := s.eng.SubscribeStream(context.Background(), &backend.SubscribeStreamRequest{
		Path: "sim/" + spyKey("sub-new"),
	})
	require.NoError(t, err)
	require.Equal(t, backend.SubscribeStreamStatusOK, resp.Status)
	require.Less(t, s.peakCount(), maxLiveSimulations)
	requireRunningLen(t, s.eng, maxLiveSimulations)
	requireKeyAbsent(t, s.eng, spyKey(uid(0)))
	require.True(t, s.spy(uid(0)).wasClosed())

	over := strings.Repeat("q", maxSimulationUIDBytes+1)
	before := s.createdCount()
	_, err = s.eng.SubscribeStream(context.Background(), &backend.SubscribeStreamRequest{
		Path: "sim/" + spyKey(over),
	})
	require.Error(t, err)
	require.Equal(t, before, s.createdCount())
	requireKeyAbsent(t, s.eng, spyKey(over))

	err = s.eng.RunStream(context.Background(), &backend.RunStreamRequest{
		Path: "sim/" + spyKey(over),
	}, backend.NewStreamSender(newPacketSink()))
	require.Error(t, err)
	require.Equal(t, before, s.createdCount())
	requireKeyAbsent(t, s.eng, spyKey(over))
}

func TestSimulationRetention_RunStreamIsReleasedWhenItReturns(t *testing.T) {
	s := newSpyEngine(t)
	cancel, done := s.startStream(t, "held")
	_, ok := runningSnapshot(s.eng)[streamKey("held")]
	require.True(t, ok)
	require.False(t, s.spy("held").wasClosed())

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunStream did not return after cancel")
	}
	requireKeyAbsent(t, s.eng, streamKey("held"))
	require.True(t, s.spy("held").wasClosed())
	requireRunningLen(t, s.eng, 0)
}

func TestSimulationRetention_ActiveRunStreamIsNotEvicted(t *testing.T) {
	s := newSpyEngine(t)
	cancel, done := s.startStream(t, "held")
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})

	for i := 0; i < maxLiveSimulations-1; i++ {
		require.NoError(t, s.queryUID(t, uid(i)))
	}
	requireRunningLen(t, s.eng, maxLiveSimulations)
	require.NoError(t, s.queryUID(t, "overflow"))

	require.Less(t, s.peakCount(), maxLiveSimulations)
	requireRunningLen(t, s.eng, maxLiveSimulations)
	_, ok := runningSnapshot(s.eng)[streamKey("held")]
	require.True(t, ok, "active RunStream was evicted")
	require.False(t, s.spy("held").wasClosed())
	requireKeyAbsent(t, s.eng, spyKey(uid(0)))
	require.True(t, s.spy(uid(0)).wasClosed())
	_, ok = runningSnapshot(s.eng)[spyKey("overflow")]
	require.True(t, ok)
}

func TestSimulationRetention_FullOfActiveStreamsRejectsWithoutCreate(t *testing.T) {
	s := newSpyEngine(t)
	cancels := make([]func(), 0, maxLiveSimulations)
	dones := make([]<-chan error, 0, maxLiveSimulations)
	t.Cleanup(func() {
		for _, cancel := range cancels {
			cancel()
		}
		for _, done := range dones {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
		}
	})
	for i := 0; i < maxLiveSimulations; i++ {
		cancel, done := s.startStream(t, uid(i))
		cancels = append(cancels, cancel)
		dones = append(dones, done)
	}
	requireRunningLen(t, s.eng, maxLiveSimulations)
	before := s.createdCount()

	t.Run("query", func(t *testing.T) {
		err := s.queryUID(t, "no-room")
		require.Error(t, err)
		require.Equal(t, before, s.createdCount())
		requireKeyAbsent(t, s.eng, spyKey("no-room"))
		requireRunningLen(t, s.eng, maxLiveSimulations)
	})

	t.Run("stream", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		streamDone := make(chan error, 1)
		go func() {
			streamDone <- s.eng.RunStream(ctx, &backend.RunStreamRequest{
				Path: "sim/" + streamKey("no-room-stream"),
			}, backend.NewStreamSender(newPacketSink()))
		}()
		select {
		case err := <-streamDone:
			require.Error(t, err)
		case <-time.After(time.Second):
			t.Fatal("RunStream past the cap blocked instead of rejecting")
		}
		require.Equal(t, before, s.createdCount())
		requireKeyAbsent(t, s.eng, streamKey("no-room-stream"))
	})
	for i := 0; i < maxLiveSimulations; i++ {
		_, ok := runningSnapshot(s.eng)[streamKey(uid(i))]
		require.Truef(t, ok, "active stream %s was removed", uid(i))
		require.False(t, s.spy(uid(i)).wasClosed())
	}
}
