package testdatasource

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/dtos"
)

// These match the limits in sims/retention_test.go. Query JSON, chunked
// queries, resource calls, and streams on the testdata service all have to
// enforce them. The numbers are the contract a fix has to implement.
const (
	maxLiveSimulations    = 32
	maxSimulationUIDBytes = 128
)

func retainedKeys(t *testing.T, svc *Service) map[string]struct{} {
	t.Helper()
	eng := reflect.ValueOf(svc).Elem().FieldByName("sims")
	require.True(t, eng.IsValid())
	require.False(t, eng.IsNil())
	running := eng.Elem().FieldByName("running")
	require.Equal(t, reflect.Map, running.Kind())
	out := make(map[string]struct{}, running.Len())
	iter := running.MapRange()
	for iter.Next() {
		out[iter.Key().String()] = struct{}{}
	}
	return out
}

func simulationMapKey(typ string, tick float64, uid string) string {
	hz := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", tick), "0"), ".")
	if uid != "" {
		return fmt.Sprintf("%s/%shz/%s", typ, hz, uid)
	}
	return fmt.Sprintf("%s/%shz", typ, hz)
}

func uidOf(i int) string {
	return fmt.Sprintf("u%04d", i)
}

// dataQueriesFromMetricBody performs the JSON decoding and re-encoding that
// QueryMetricsV2 does before the plugin sees a query: Bind into MetricRequest,
// then MarshalJSON of each query object (queryToJson with no per-query time
// range) and copy queryType onto DataQuery.
func dataQueriesFromMetricBody(t *testing.T, body []byte) []backend.DataQuery {
	t.Helper()
	var mr dtos.MetricRequest
	require.NoError(t, json.Unmarshal(body, &mr))
	require.NotEmpty(t, mr.Queries)
	out := make([]backend.DataQuery, 0, len(mr.Queries))
	for _, q := range mr.Queries {
		raw, err := q.MarshalJSON()
		require.NoError(t, err)
		out = append(out, backend.DataQuery{
			RefID:         q.Get("refId").MustString("A"),
			MaxDataPoints: q.Get("maxDataPoints").MustInt64(100),
			Interval:      time.Duration(q.Get("intervalMs").MustInt64(1000)) * time.Millisecond,
			QueryType:     q.Get("queryType").MustString(""),
			JSON:          raw,
			TimeRange: backend.TimeRange{
				From: time.Now().Add(-time.Minute),
				To:   time.Now().Add(time.Minute),
			},
		})
	}
	return out
}

func simulationMetricBody(t *testing.T, queryType, typ string, uids []string, includeTick bool) []byte {
	t.Helper()
	queries := make([]any, len(uids))
	for i, uid := range uids {
		key := map[string]any{"type": typ, "uid": uid}
		if includeTick {
			key["tick"] = 1
		}
		q := map[string]any{
			"refId":         fmt.Sprintf("A%d", i),
			"datasource":    map[string]any{"type": "grafana-testdata-datasource", "uid": "testdata"},
			"intervalMs":    1000,
			"maxDataPoints": 10,
			"scenarioId":    "simulation",
			"sim":           map[string]any{"last": true, "key": key},
		}
		if queryType != "" {
			q["queryType"] = queryType
		}
		queries[i] = q
	}
	raw, err := json.Marshal(map[string]any{
		"from":    "now-5m",
		"to":      "now",
		"queries": queries,
	})
	require.NoError(t, err)
	return raw
}

func uids(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = uidOf(i)
	}
	return out
}

type nopChunked struct{}

func (nopChunked) WriteFrame(context.Context, string, string, *data.Frame) error { return nil }

func (nopChunked) WriteError(context.Context, string, backend.Status, error) error { return nil }

type captureResource struct {
	status int
	body   []byte
}

func (c *captureResource) Send(resp *backend.CallResourceResponse) error {
	if resp.Status != 0 {
		c.status = resp.Status
	}
	c.body = append(c.body, resp.Body...)
	return nil
}

func callResource(t *testing.T, svc *Service, method, path string, body []byte) *captureResource {
	t.Helper()
	got := &captureResource{}
	err := svc.CallResource(context.Background(), &backend.CallResourceRequest{
		Path:   path,
		Method: method,
		URL:    path,
		Body:   body,
	}, got)
	require.NoError(t, err)
	return got
}

type signalPackets struct {
	once sync.Once
	got  chan struct{}
}

func newSignalPackets() *signalPackets {
	return &signalPackets{got: make(chan struct{})}
}

func (s *signalPackets) Send(*backend.StreamPacket) error {
	s.once.Do(func() { close(s.got) })
	return nil
}

func TestSimulationRetention_QueryJSONCapsDistinctUIDs(t *testing.T) {
	const extra = 8
	ids := uids(maxLiveSimulations + extra)

	t.Run("query type", func(t *testing.T) {
		svc := ProvideService()
		queries := dataQueriesFromMetricBody(t, simulationMetricBody(t, "simulation", "sine", ids, true))
		_, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: queries})
		require.NoError(t, err)
		keys := retainedKeys(t, svc)
		require.LessOrEqual(t, len(keys), maxLiveSimulations)
		_, newest := keys[simulationMapKey("sine", 1, ids[len(ids)-1])]
		require.True(t, newest, "newest simulation uid was not retained")
		_, oldest := keys[simulationMapKey("sine", 1, ids[0])]
		require.False(t, oldest, "least recently used simulation was retained")
	})

	t.Run("scenario id fallback", func(t *testing.T) {
		svc := ProvideService()
		queries := dataQueriesFromMetricBody(t, simulationMetricBody(t, "", "flight", ids, true))
		_, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: queries})
		require.NoError(t, err)
		keys := retainedKeys(t, svc)
		require.LessOrEqual(t, len(keys), maxLiveSimulations)
		_, newest := keys[simulationMapKey("flight", 1, ids[len(ids)-1])]
		require.True(t, newest)
		_, oldest := keys[simulationMapKey("flight", 1, ids[0])]
		require.False(t, oldest)
	})

	t.Run("omitted tick still counts", func(t *testing.T) {
		svc := ProvideService()
		queries := dataQueriesFromMetricBody(t, simulationMetricBody(t, "simulation", "tank", ids, false))
		_, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: queries})
		require.NoError(t, err)
		keys := retainedKeys(t, svc)
		require.LessOrEqual(t, len(keys), maxLiveSimulations)
		_, newest := keys[simulationMapKey("tank", 10, ids[len(ids)-1])]
		require.True(t, newest, "defaulted tick did not produce the expected key")
		_, oldest := keys[simulationMapKey("tank", 10, ids[0])]
		require.False(t, oldest)
	})
}

func TestSimulationRetention_ChunkedQueriesShareTheCap(t *testing.T) {
	svc := ProvideService()
	ids := uids(maxLiveSimulations * 2)
	queries := dataQueriesFromMetricBody(t, simulationMetricBody(t, "simulation", "sine", ids, true))
	err := svc.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{Queries: queries}, nopChunked{})
	require.NoError(t, err)
	require.LessOrEqual(t, len(retainedKeys(t, svc)), maxLiveSimulations)
}

func TestSimulationRetention_OversizedUIDFromQueryJSONIsNotRetained(t *testing.T) {
	over := strings.Repeat("b", maxSimulationUIDBytes+1)
	huge := strings.Repeat("c", 1<<20)

	t.Run("query type", func(t *testing.T) {
		svc := ProvideService()
		queries := dataQueriesFromMetricBody(t, simulationMetricBody(t, "simulation", "sine", []string{over, huge}, true))
		_, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: queries})
		keys := retainedKeys(t, svc)
		_, hasOver := keys[simulationMapKey("sine", 1, over)]
		_, hasHuge := keys[simulationMapKey("sine", 1, huge)]
		require.False(t, hasOver)
		require.False(t, hasHuge)
		require.Empty(t, keys)
		require.Error(t, err)
	})

	t.Run("scenario id fallback", func(t *testing.T) {
		svc := ProvideService()
		queries := dataQueriesFromMetricBody(t, simulationMetricBody(t, "", "sine", []string{huge}, true))
		_, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: queries})
		require.NoError(t, err) // the scenario fallback logs handler errors and still returns nil
		_, hasHuge := retainedKeys(t, svc)[simulationMapKey("sine", 1, huge)]
		require.False(t, hasHuge, "fallback path retained an oversized uid")
	})
}

func TestSimulationRetention_InvalidSimulationIsNotRetained(t *testing.T) {
	svc := ProvideService()
	body, err := json.Marshal(map[string]any{
		"from": "now-5m",
		"to":   "now",
		"queries": []any{
			map[string]any{
				"refId":      "A",
				"queryType":  "simulation",
				"scenarioId": "simulation",
				"sim":        map[string]any{"last": true, "key": map[string]any{"type": "nope", "tick": 1, "uid": "x"}},
			},
			map[string]any{
				"refId":      "B",
				"queryType":  "simulation",
				"scenarioId": "simulation",
				"sim":        map[string]any{"last": true, "key": map[string]any{"type": "sine", "tick": 51, "uid": "fast"}},
			},
		},
	})
	require.NoError(t, err)
	queries := dataQueriesFromMetricBody(t, body)
	// Each query is dispatched on its own only when the types differ. Both use
	// the simulation query type, so the engine returns on the first rejection.
	_, err = svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: queries[:1]})
	require.Error(t, err)
	_, err = svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: queries[1:]})
	require.Error(t, err)
	require.Empty(t, retainedKeys(t, svc))
}

func TestSimulationRetention_RepeatedUIDIsOneEntry(t *testing.T) {
	svc := ProvideService()
	ids := make([]string, maxLiveSimulations*2)
	for i := range ids {
		ids[i] = "same"
	}
	queries := dataQueriesFromMetricBody(t, simulationMetricBody(t, "simulation", "sine", ids, true))
	_, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: queries})
	require.NoError(t, err)
	keys := retainedKeys(t, svc)
	require.Equal(t, map[string]struct{}{simulationMapKey("sine", 1, "same"): {}}, keys)
}

func TestSimulationRetention_ResourcePathSharesTheCap(t *testing.T) {
	t.Run("cap", func(t *testing.T) {
		svc := ProvideService()
		for i := 0; i < maxLiveSimulations+5; i++ {
			resp := callResource(t, svc, "GET", "sim/"+simulationMapKey("sine", 1, uidOf(i)), nil)
			require.Equal(t, 200, resp.status)
		}
		keys := retainedKeys(t, svc)
		require.LessOrEqual(t, len(keys), maxLiveSimulations)
		_, newest := keys[simulationMapKey("sine", 1, uidOf(maxLiveSimulations+4))]
		require.True(t, newest)
		_, oldest := keys[simulationMapKey("sine", 1, uidOf(0))]
		require.False(t, oldest)
	})

	t.Run("oversized", func(t *testing.T) {
		svc := ProvideService()
		over := strings.Repeat("d", maxSimulationUIDBytes+1)
		resp := callResource(t, svc, "GET", "sim/"+simulationMapKey("sine", 1, over), nil)
		require.GreaterOrEqual(t, resp.status, 400)
		_, hasOver := retainedKeys(t, svc)[simulationMapKey("sine", 1, over)]
		require.False(t, hasOver)
		require.Empty(t, retainedKeys(t, svc))
	})

	t.Run("post failure", func(t *testing.T) {
		svc := ProvideService()
		resp := callResource(t, svc, "POST", "sim/"+simulationMapKey("sine", 1, "post-fail"), []byte("{"))
		require.GreaterOrEqual(t, resp.status, 400)
		_, hasPost := retainedKeys(t, svc)[simulationMapKey("sine", 1, "post-fail")]
		require.False(t, hasPost)
		require.Empty(t, retainedKeys(t, svc))
	})
}

func TestSimulationRetention_StreamsShareTheCapAndRelease(t *testing.T) {
	t.Run("subscribe cap", func(t *testing.T) {
		svc := ProvideService()
		for i := 0; i < maxLiveSimulations+3; i++ {
			resp, err := svc.SubscribeStream(context.Background(), &backend.SubscribeStreamRequest{
				Path: "sim/" + simulationMapKey("sine", 1, uidOf(i)),
			})
			require.NoError(t, err)
			require.Equal(t, backend.SubscribeStreamStatusOK, resp.Status)
		}
		keys := retainedKeys(t, svc)
		require.LessOrEqual(t, len(keys), maxLiveSimulations)
		_, oldest := keys[simulationMapKey("sine", 1, uidOf(0))]
		require.False(t, oldest)
	})

	t.Run("oversized subscribe", func(t *testing.T) {
		svc := ProvideService()
		over := strings.Repeat("e", maxSimulationUIDBytes+1)
		_, err := svc.SubscribeStream(context.Background(), &backend.SubscribeStreamRequest{
			Path: "sim/" + simulationMapKey("sine", 1, over),
		})
		require.Error(t, err)
		_, hasOver := retainedKeys(t, svc)[simulationMapKey("sine", 1, over)]
		require.False(t, hasOver)
		require.Empty(t, retainedKeys(t, svc))
	})

	t.Run("run stream releases", func(t *testing.T) {
		svc := ProvideService()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sink := newSignalPackets()
		done := make(chan error, 1)
		path := "sim/" + simulationMapKey("sine", 50, "held")
		go func() {
			done <- svc.RunStream(ctx, &backend.RunStreamRequest{Path: path}, backend.NewStreamSender(sink))
		}()
		select {
		case <-sink.got:
		case err := <-done:
			t.Fatalf("RunStream returned before sending a frame: %v", err)
		case <-time.After(2 * time.Second):
			t.Fatal("RunStream did not send a frame")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("RunStream did not return after cancel")
		}
		_, held := retainedKeys(t, svc)[simulationMapKey("sine", 50, "held")]
		require.False(t, held, "RunStream retained its simulation after it returned")
	})
}

func TestSimulationRetention_ConcurrentQueryJSONStaysWithinCap(t *testing.T) {
	svc := ProvideService()
	const n = maxLiveSimulations * 3
	requests := make([]*backend.QueryDataRequest, n)
	for i := range requests {
		queries := dataQueriesFromMetricBody(t, simulationMetricBody(t, "simulation", "sine", []string{uidOf(i)}, true))
		requests[i] = &backend.QueryDataRequest{Queries: queries}
	}
	var wg sync.WaitGroup
	for i := range requests {
		wg.Add(1)
		go func(req *backend.QueryDataRequest) {
			defer wg.Done()
			_, _ = svc.QueryData(context.Background(), req)
		}(requests[i])
	}
	wg.Wait()
	require.LessOrEqual(t, len(retainedKeys(t, svc)), maxLiveSimulations)
}
