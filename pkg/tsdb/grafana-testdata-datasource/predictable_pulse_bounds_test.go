package testdatasource

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana-plugin-sdk-go/genproto/pluginv2"
	"github.com/stretchr/testify/require"
)

// Attack-sized predictable pulse. onCount is a single JSON integer. The time
// range sits in the off portion of the cycle, so each of the 10000 samples
// walks the whole onCount. A bounded implementation finishes well under the
// budget; the unbounded scan does not.
const (
	attackOnCount  = int64(2_000_000)
	attackOffCount = int64(10_000)
	attackPoints   = int64(10_000)
	attackBudget   = 400 * time.Millisecond
)

func TestPredictablePulseFromScenarioIDIsBounded(t *testing.T) {
	s := newTestDataService(t)
	start := time.Now()
	resp, err := s.QueryData(context.Background(), attackPulseRequest(""))
	elapsed := time.Since(start)

	require.LessOrEqualf(t, elapsed, attackBudget, "scenarioId predictable_pulse scanned onCount for every point")
	require.NoError(t, err)
	requireQueryFinishedWithinBudget(t, resp, "A")
}

func TestPredictablePulseFromQueryTypeIsBounded(t *testing.T) {
	s := newTestDataService(t)
	start := time.Now()
	resp, err := s.QueryData(context.Background(), attackPulseRequest("predictable_pulse"))
	elapsed := time.Since(start)

	require.LessOrEqualf(t, elapsed, attackBudget, "queryType predictable_pulse scanned onCount for every point")
	require.NoError(t, err)
	requireQueryFinishedWithinBudget(t, resp, "A")
}

func TestPredictablePulseCanceledContextReturnsBeforeScan(t *testing.T) {
	s := newTestDataService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A normal series, so a fix cannot satisfy this by rejecting the size alone.
	body := `{"scenarioId":"predictable_pulse","pulseWave":{"timeStep":10,"onCount":2,"offCount":2,"onValue":2,"offValue":-3}}`
	resp, err := s.QueryData(ctx, pulseRequest("", body, time.UnixMilli(0), time.UnixMilli(40_000)))
	requireContextStopped(t, err, resp, "A", context.Canceled)
}

func TestPredictablePulseAlertEvaluationTimeoutStopsScan(t *testing.T) {
	s := newTestDataService(t)
	// ngalert wraps evaluation in a timeout and passes that context through to
	// the datasource query. Checking the context only before the scan leaves
	// the timeout unable to interrupt onCount.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	resp, err := s.QueryData(ctx, attackPulseRequest(""))
	elapsed := time.Since(start)

	require.LessOrEqualf(t, elapsed, attackBudget, "alert evaluation timeout did not stop predictable_pulse")
	if err == nil && resp != nil {
		if dr, ok := resp.Responses["A"]; ok && dr.Error == nil {
			require.NotEmpty(t, dr.Frames)
		}
	}
}

func TestPredictablePulseRejectsNonPositiveTimeStepAndCycle(t *testing.T) {
	s := newTestDataService(t)
	cases := []struct {
		name string
		json string
	}{
		{name: "zero timeStep", json: `{"scenarioId":"predictable_pulse","pulseWave":{"timeStep":0,"onCount":3,"offCount":3,"onValue":1,"offValue":0}}`},
		{name: "negative timeStep", json: `{"scenarioId":"predictable_pulse","pulseWave":{"timeStep":-1,"onCount":3,"offCount":3,"onValue":1,"offValue":0}}`},
		{name: "zero cycle", json: `{"scenarioId":"predictable_pulse","pulseWave":{"timeStep":1,"onCount":0,"offCount":0,"onValue":1,"offValue":0}}`},
		{name: "negative cycle", json: `{"scenarioId":"predictable_pulse","pulseWave":{"timeStep":1,"onCount":2,"offCount":-4,"onValue":1,"offValue":0}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var resp *backend.QueryDataResponse
			var err error
			require.NotPanics(t, func() {
				resp, err = s.QueryData(context.Background(), pulseRequest("", tc.json, time.UnixMilli(0), time.UnixMilli(10_000)))
			})
			requireVisibleError(t, err, resp, "A")
		})
	}
}

func TestPredictablePulseNormalSeries(t *testing.T) {
	s := newTestDataService(t)
	// 10 second steps, two on samples then two off samples, aligned to epoch.
	body := `{"scenarioId":"predictable_pulse","pulseWave":{"timeStep":10,"onCount":2,"offCount":2,"onValue":2,"offValue":-3}}`
	resp, err := s.QueryData(context.Background(), pulseRequest("", body, time.UnixMilli(0), time.UnixMilli(40_000)))
	require.NoError(t, err)
	frame := requireSingleFrame(t, resp, "A")
	require.Equal(t, 4, frame.Fields[0].Len())
	require.Equal(t, []float64{2, 2, -3, -3}, fieldFloats(t, frame.Fields[1]))
}

func TestPredictableCSVWaveCanceledContextReturnsBeforeScan(t *testing.T) {
	s := newTestDataService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	body := `{"scenarioId":"predictable_csv_wave","csvWave":[{"timeStep":10,"valuesCSV":"2,2,-3,-3"}]}`
	resp, err := s.QueryData(ctx, pulseRequest("", body, time.UnixMilli(0), time.UnixMilli(40_000)))
	requireContextStopped(t, err, resp, "A", context.Canceled)
}

func TestPredictableCSVWaveFromQueryTypeHonorsCancel(t *testing.T) {
	s := newTestDataService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	body := `{"scenarioId":"predictable_csv_wave","csvWave":[{"timeStep":10,"valuesCSV":"2,2,-3,-3"}]}`
	resp, err := s.QueryData(ctx, pulseRequest("predictable_csv_wave", body, time.UnixMilli(0), time.UnixMilli(40_000)))
	requireContextStopped(t, err, resp, "A", context.Canceled)
}

func TestPredictableCSVWaveRejectsNonPositiveTimeStep(t *testing.T) {
	s := newTestDataService(t)
	cases := []struct {
		name string
		json string
	}{
		{name: "zero timeStep", json: `{"scenarioId":"predictable_csv_wave","csvWave":[{"timeStep":0,"valuesCSV":"1,0"}]}`},
		{name: "negative timeStep", json: `{"scenarioId":"predictable_csv_wave","csvWave":[{"timeStep":-5,"valuesCSV":"1,0"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var resp *backend.QueryDataResponse
			var err error
			require.NotPanics(t, func() {
				resp, err = s.QueryData(context.Background(), pulseRequest("", tc.json, time.UnixMilli(0), time.UnixMilli(10_000)))
			})
			requireVisibleError(t, err, resp, "A")
		})
	}
}

func TestPredictableCSVWaveNormalSeries(t *testing.T) {
	s := newTestDataService(t)
	body := `{"scenarioId":"predictable_csv_wave","csvWave":[{"timeStep":10,"valuesCSV":"2,2,-3,-3"}]}`
	resp, err := s.QueryData(context.Background(), pulseRequest("", body, time.UnixMilli(0), time.UnixMilli(40_000)))
	require.NoError(t, err)
	frame := requireSingleFrame(t, resp, "A")
	require.Equal(t, 4, frame.Fields[0].Len())
	require.Equal(t, []float64{2, 2, -3, -3}, fieldFloats(t, frame.Fields[1]))
}

func TestPredictablePulseChunkedQueryHonorsCancel(t *testing.T) {
	s := newTestDataService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var frames int
	writer := backend.NewChunkedDataWriter(backend.DataFrameFormat_JSON, func(chunk *pluginv2.QueryChunkedDataResponse) error {
		if len(chunk.GetFrame()) > 0 {
			frames++
		}
		return nil
	})
	body := `{"scenarioId":"predictable_pulse","pulseWave":{"timeStep":10,"onCount":2,"offCount":2,"onValue":2,"offValue":-3}}`
	req := attackFromPulse(pulseRequest("", body, time.UnixMilli(0), time.UnixMilli(40_000)))
	err := s.QueryChunkedData(ctx, req, writer)
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, frames, "chunked predictable_pulse wrote a frame after the context was canceled")
}

func newTestDataService(t *testing.T) *Service {
	t.Helper()
	svc := ProvideService()
	require.NotNil(t, svc)
	return svc
}

func attackPulseRequest(queryType string) *backend.QueryDataRequest {
	// Samples start at the first off step and stay there for attackPoints steps.
	fromMs := attackOnCount * 1000
	toMs := fromMs + attackPoints*1000
	body := fmt.Sprintf(
		`{"refId":"A","scenarioId":"predictable_pulse","pulseWave":{"timeStep":1,"onCount":%d,"offCount":%d,"onValue":1,"offValue":0}}`,
		attackOnCount, attackOffCount,
	)
	return pulseRequest(queryType, body, time.UnixMilli(fromMs), time.UnixMilli(toMs))
}

func pulseRequest(queryType, body string, from, to time.Time) *backend.QueryDataRequest {
	return &backend.QueryDataRequest{
		Queries: []backend.DataQuery{{
			RefID: "A",
			TimeRange: backend.TimeRange{
				From: from,
				To:   to,
			},
			QueryType: queryType,
			JSON:      []byte(body),
		}},
	}
}

func attackFromPulse(req *backend.QueryDataRequest) *backend.QueryChunkedDataRequest {
	return &backend.QueryChunkedDataRequest{
		Queries: req.Queries,
	}
}

func requireQueryFinishedWithinBudget(t *testing.T, resp *backend.QueryDataResponse, refID string) {
	t.Helper()
	require.NotNil(t, resp)
	dr, ok := resp.Responses[refID]
	require.True(t, ok)
	if dr.Error != nil {
		return
	}
	require.NotEmpty(t, dr.Frames)
}

func requireVisibleError(t *testing.T, err error, resp *backend.QueryDataResponse, refID string) {
	t.Helper()
	if err != nil {
		return
	}
	require.NotNil(t, resp)
	dr, ok := resp.Responses[refID]
	require.Truef(t, ok && dr.Error != nil, "query was accepted, ref %s responses %#v", refID, resp.Responses)
	require.Empty(t, dr.Frames)
}

func requireContextStopped(t *testing.T, err error, resp *backend.QueryDataResponse, refID string, cause error) {
	t.Helper()
	if err != nil {
		require.ErrorIs(t, err, cause)
		return
	}
	require.NotNil(t, resp)
	dr, ok := resp.Responses[refID]
	require.True(t, ok)
	require.ErrorIs(t, dr.Error, cause)
	require.Empty(t, dr.Frames)
}

func requireSingleFrame(t *testing.T, resp *backend.QueryDataResponse, refID string) *data.Frame {
	t.Helper()
	require.NotNil(t, resp)
	dr, ok := resp.Responses[refID]
	require.True(t, ok)
	require.NoError(t, dr.Error)
	require.Len(t, dr.Frames, 1)
	require.GreaterOrEqual(t, len(dr.Frames[0].Fields), 2)
	return dr.Frames[0]
}

func fieldFloats(t *testing.T, field *data.Field) []float64 {
	t.Helper()
	out := make([]float64, field.Len())
	for i := range out {
		v, ok := field.ConcreteAt(i)
		require.True(t, ok)
		switch n := v.(type) {
		case float64:
			out[i] = n
		case *float64:
			require.NotNil(t, n)
			out[i] = *n
		default:
			t.Fatalf("field value %d has type %T", i, v)
		}
	}
	return out
}
