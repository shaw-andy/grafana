package testdatasource

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
)

// stepThatOverflowsToZero is a positive second count. Both predictable scenarios
// multiply it by 1000 to convert to milliseconds, and 2^61 * 1000 wraps to 0 in int64.
const stepThatOverflowsToZero int64 = 1 << 61

func TestPredictableSeriesRejectsNonPositiveTimeStep(t *testing.T) {
	from := time.Unix(1_700_000_000, 0).UTC()
	to := from.Add(time.Hour)

	rejected := []struct {
		name      string
		queryType string
		body      string
	}{
		{
			name: "pulse explicit zero step via scenario id",
			body: `{"scenarioId":"predictable_pulse","pulseWave":{"timeStep":0,"onCount":1,"offCount":1,"onValue":1,"offValue":0}}`,
		},
		{
			name:      "pulse explicit zero step via query type",
			queryType: "predictable_pulse",
			body:      `{"pulseWave":{"timeStep":0,"onCount":1,"offCount":1,"onValue":1,"offValue":0}}`,
		},
		{
			name: "pulse omitted time step",
			body: `{"scenarioId":"predictable_pulse","pulseWave":{"onCount":1,"offCount":1,"onValue":1,"offValue":0}}`,
		},
		{
			name: "pulse omitted pulseWave",
			body: `{"scenarioId":"predictable_pulse"}`,
		},
		{
			name: "pulse negative time step",
			body: `{"scenarioId":"predictable_pulse","pulseWave":{"timeStep":-1,"onCount":1,"offCount":1,"onValue":1,"offValue":0}}`,
		},
		{
			name: "pulse time step wraps to zero when converted to milliseconds",
			body: fmt.Sprintf(`{"scenarioId":"predictable_pulse","pulseWave":{"timeStep":%d,"onCount":1,"offCount":1,"onValue":1,"offValue":0}}`, stepThatOverflowsToZero),
		},
		{
			name: "pulse positive step with zero on and off counts",
			body: `{"scenarioId":"predictable_pulse","pulseWave":{"timeStep":1,"onCount":0,"offCount":0,"onValue":1,"offValue":0}}`,
		},
		{
			name: "csv explicit zero step via scenario id",
			body: `{"scenarioId":"predictable_csv_wave","csvWave":[{"valuesCSV":"1","timeStep":0}]}`,
		},
		{
			name:      "csv explicit zero step via query type",
			queryType: "predictable_csv_wave",
			body:      `{"csvWave":[{"valuesCSV":"1","timeStep":0}]}`,
		},
		{
			name: "csv omitted time step",
			body: `{"scenarioId":"predictable_csv_wave","csvWave":[{"valuesCSV":"1"}]}`,
		},
		{
			name: "csv negative time step",
			body: `{"scenarioId":"predictable_csv_wave","csvWave":[{"valuesCSV":"1","timeStep":-5}]}`,
		},
		{
			name: "csv time step wraps to zero when converted to milliseconds",
			body: fmt.Sprintf(`{"scenarioId":"predictable_csv_wave","csvWave":[{"valuesCSV":"1,2","timeStep":%d}]}`, stepThatOverflowsToZero),
		},
		{
			name: "csv later wave has a zero time step",
			body: `{"scenarioId":"predictable_csv_wave","csvWave":[{"valuesCSV":"1,2","timeStep":1,"name":"ok"},{"valuesCSV":"3","timeStep":0,"name":"bad"}]}`,
		},
	}

	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			svc := ProvideService()
			q := predictableQuery(tc.queryType, tc.body, from, to)
			assertPredictableQueryRejected(t, svc, q)
			assertPredictableChunkedQueryRejected(t, svc, q)
		})
	}

	t.Run("valid pulse still returns points", func(t *testing.T) {
		svc := ProvideService()
		q := predictableQuery("", `{"scenarioId":"predictable_pulse","pulseWave":{"timeStep":60,"onCount":3,"offCount":3,"onValue":2,"offValue":0}}`, from, to)
		resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: []backend.DataQuery{q}})
		require.NoError(t, err)
		frame := onlyFrame(t, resp, q.RefID)
		require.Greater(t, frame.Rows(), 0)
	})

	t.Run("valid csv wave still returns points", func(t *testing.T) {
		svc := ProvideService()
		q := predictableQuery("", `{"scenarioId":"predictable_csv_wave","csvWave":[{"valuesCSV":"1,2,3","timeStep":1,"name":"wave"}]}`, from, to)
		resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: []backend.DataQuery{q}})
		require.NoError(t, err)
		frame := onlyFrame(t, resp, q.RefID)
		require.Greater(t, frame.Rows(), 0)
		require.Equal(t, "wave", frame.Name)
	})

	t.Run("invalid pulse does not sink a sibling query", func(t *testing.T) {
		svc := ProvideService()
		good := predictableQuery("", `{"scenarioId":"random_walk","startValue":1,"spread":1}`, from, to)
		good.RefID = "good"
		bad := predictableQuery("", `{"scenarioId":"predictable_pulse","pulseWave":{"timeStep":0,"onCount":1,"offCount":1,"onValue":1,"offValue":0}}`, from, to)
		bad.RefID = "bad"

		require.NotPanics(t, func() {
			resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{
				Queries: []backend.DataQuery{good, bad},
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			goodResp, ok := resp.Responses[good.RefID]
			require.True(t, ok, "sibling query response missing")
			require.NoError(t, goodResp.Error)
			require.NotEmpty(t, goodResp.Frames)
			require.Greater(t, goodResp.Frames[0].Rows(), 0)
			assertDownstreamResponse(t, resp, bad.RefID)
		})
	})
}

func predictableQuery(queryType, body string, from, to time.Time) backend.DataQuery {
	return backend.DataQuery{
		RefID:         "A",
		QueryType:     queryType,
		TimeRange:     backend.TimeRange{From: from, To: to},
		Interval:      time.Second,
		MaxDataPoints: 100,
		JSON:          []byte(body),
	}
}

func assertPredictableQueryRejected(t *testing.T, svc *Service, q backend.DataQuery) {
	t.Helper()
	require.NotPanics(t, func() {
		resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{
			Queries: []backend.DataQuery{q},
		})
		if err != nil {
			require.Truef(t, backend.IsDownstreamError(err), "returned error must be downstream, got %v", err)
			return
		}
		assertDownstreamResponse(t, resp, q.RefID)
	})
}

func assertDownstreamResponse(t *testing.T, resp *backend.QueryDataResponse, refID string) {
	t.Helper()
	require.NotNil(t, resp)
	dr, ok := resp.Responses[refID]
	require.Truef(t, ok, "response for %s missing", refID)
	require.Error(t, dr.Error)
	downstream := backend.IsDownstreamError(dr.Error) || dr.ErrorSource == backend.ErrorSourceDownstream
	require.Truef(t, downstream, "error for %s must be downstream, source=%q err=%v", refID, dr.ErrorSource, dr.Error)
}

func assertPredictableChunkedQueryRejected(t *testing.T, svc *Service, q backend.DataQuery) {
	t.Helper()
	w := &recordChunkWriter{}
	require.NotPanics(t, func() {
		err := svc.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{
			Queries: []backend.DataQuery{q},
		}, w)
		if err != nil {
			require.Truef(t, backend.IsDownstreamError(err), "chunked error must be downstream, got %v", err)
			return
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		got, ok := w.errors[q.RefID]
		require.Truef(t, ok, "chunked query for %s returned no error", q.RefID)
		require.Error(t, got)
		require.Truef(t, backend.IsDownstreamError(got), "chunked response error must be downstream, got %v", got)
	})
}

func onlyFrame(t *testing.T, resp *backend.QueryDataResponse, refID string) *data.Frame {
	t.Helper()
	require.NotNil(t, resp)
	dr, ok := resp.Responses[refID]
	require.True(t, ok)
	require.NoError(t, dr.Error)
	require.Len(t, dr.Frames, 1)
	return dr.Frames[0]
}

type recordChunkWriter struct {
	mu     sync.Mutex
	errors map[string]error
}

func (w *recordChunkWriter) WriteFrame(context.Context, string, string, *data.Frame) error {
	return nil
}

func (w *recordChunkWriter) WriteError(_ context.Context, refID string, _ backend.Status, err error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.errors == nil {
		w.errors = map[string]error{}
	}
	w.errors[refID] = err
	return nil
}
