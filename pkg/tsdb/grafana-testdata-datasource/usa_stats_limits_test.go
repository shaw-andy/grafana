package testdatasource

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"
)

// TestUSAScenarioRejectsStateAndFieldProductAboveCap is the spec for the USA
// scenario memory cap. maxUSAResults is documented as a cap on
// maxDataPoints × states × fields, but the handler only shrinks maxDataPoints
// and never below 1. states and fields are taken from the query JSON and are
// not limited. These tests fail while that behavior remains: an oversized list
// is accepted and one frame (or one field, or one row) is built per name.
//
// A fix must refuse the query when len(states)×len(fields) exceeds
// maxUSAResults, before any frame is built. Returning an error after the
// frames already exist does not pass. Lists at or under the cap must still run.
//
// Covered entries are Service.QueryData (empty query type, which falls back to
// scenarioId, and query type "usa") and Service.QueryChunkedData, which calls
// the same handlers when no chunked handler is registered. Modes covered:
// timeseries, timeseries-wide, values-as-fields, values-as-labeled-fields,
// values-as-rows, and the empty mode (both use getStateValueAsRow). Any other
// mode string also falls through to getStateValueAsRow and is covered by those
// two cases.
func TestUSAScenarioRejectsStateAndFieldProductAboveCap(t *testing.T) {
	svc := ProvideService()
	ctx := context.Background()

	modes := []string{
		modeTimeseries,
		modeTimeseriesWide,
		modeValueAsFields,
		modeValueAsLabeledFields,
		modeValueAsRow,
		"",
	}
	entries := []struct {
		name      string
		queryType string
	}{
		{name: "scenarioId fallback", queryType: ""},
		{name: "query type usa", queryType: "usa"},
	}

	over := []struct {
		name   string
		states int
		fields int
	}{
		{name: "states alone exceed cap", states: int(maxUSAResults) + 1, fields: 1},
		{name: "fields alone exceed cap", states: 1, fields: int(maxUSAResults) + 1},
		// Each list is under the cap. Only the product is over it.
		{name: "product exceeds cap", states: 100, fields: int(maxUSAResults)/100 + 1},
	}

	for _, entry := range entries {
		t.Run(entry.name, func(t *testing.T) {
			for _, mode := range modes {
				modeName := mode
				if modeName == "" {
					modeName = "empty mode"
				}
				t.Run(modeName, func(t *testing.T) {
					for _, size := range over {
						t.Run(size.name, func(t *testing.T) {
							req := usaQueryRequest(t, entry.queryType, mode, size.states, size.fields, 100)
							resp, err := svc.QueryData(ctx, req)
							requireOversizedRejected(t, resp, err, size.states, size.fields)
						})
					}

					t.Run("chunked query", func(t *testing.T) {
						states := int(maxUSAResults) + 1
						req := usaQueryRequest(t, entry.queryType, mode, states, 1, 100)
						writer := &usaFrameWriter{}
						err := svc.QueryChunkedData(ctx, &backend.QueryChunkedDataRequest{
							Headers: req.Headers,
							Queries: req.Queries,
						}, writer)
						frames, fields := writer.load()
						require.Zerof(t, frames, "chunked query wrote %d frames (%d fields) before refusing %d states", frames, fields, states)
						require.Truef(t, err != nil || writer.errors > 0, "chunked query accepted %d states", states)
					})
				})
			}
		})
	}
}

// TestUSAScenarioAllowsStateAndFieldListsAtTheCap keeps queries whose
// state×field product is at or under maxUSAResults working, including one
// series per pair. A fix that rejects every USA query fails here.
func TestUSAScenarioAllowsStateAndFieldListsAtTheCap(t *testing.T) {
	svc := ProvideService()
	ctx := context.Background()

	cases := []struct {
		name   string
		mode   string
		states int
		fields int
	}{
		{name: "timeseries small", mode: modeTimeseries, states: 2, fields: 2},
		{name: "timeseries at cap", mode: modeTimeseries, states: int(maxUSAResults), fields: 1},
		{name: "timeseries-wide small", mode: modeTimeseriesWide, states: 2, fields: 2},
		{name: "timeseries-wide at cap", mode: modeTimeseriesWide, states: int(maxUSAResults), fields: 1},
		{name: "values-as-fields small", mode: modeValueAsFields, states: 3, fields: 2},
		{name: "values-as-fields at cap", mode: modeValueAsFields, states: int(maxUSAResults), fields: 1},
		{name: "values-as-labeled-fields small", mode: modeValueAsLabeledFields, states: 3, fields: 2},
		{name: "values-as-labeled-fields at cap", mode: modeValueAsLabeledFields, states: int(maxUSAResults), fields: 1},
		{name: "values-as-rows small", mode: modeValueAsRow, states: 4, fields: 2},
		{name: "values-as-rows at cap", mode: modeValueAsRow, states: int(maxUSAResults), fields: 1},
		{name: "empty mode small", mode: "", states: 4, fields: 2},
		{name: "empty mode at cap", mode: "", states: int(maxUSAResults), fields: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := usaQueryRequest(t, "", tc.mode, tc.states, tc.fields, 100)
			resp, err := svc.QueryData(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			dr, ok := resp.Responses["A"]
			require.True(t, ok)
			require.NoError(t, dr.Error)
			assertUSAShape(t, tc.mode, tc.states, tc.fields, dr)
		})
	}
}

// TestUSAScenarioOversizedListAllocatesBeforeAnyResponse guards a fix that
// builds the frames and then returns an error with an empty response. Parsing
// the same JSON and failing the period check happens before doStateQuery.
// Building one frame per state has to allocate more than that parse.
func TestUSAScenarioOversizedListAllocatesBeforeAnyResponse(t *testing.T) {
	svc := ProvideService()
	ctx := context.Background()
	states := int(maxUSAResults) + 1

	// Warm logger and tracer allocations so they are not part of the delta.
	warmup := usaQueryRequest(t, "usa", modeTimeseries, 1, 1, 10)
	_, err := svc.QueryData(ctx, warmup)
	require.NoError(t, err)

	rejected := usaQueryWithPeriod(t, "usa", modeTimeseries, states, 1, 100, "not-a-duration")
	baseline := allocatedBytes(func() {
		resp, qerr := svc.QueryData(ctx, rejected)
		require.Error(t, qerr)
		require.Nil(t, resp)
	})

	attack := usaQueryRequest(t, "usa", modeTimeseries, states, 1, 100)
	var attackResp *backend.QueryDataResponse
	var attackErr error
	used := allocatedBytes(func() {
		attackResp, attackErr = svc.QueryData(ctx, attack)
	})

	// The oversized query must not allocate a frame per state on top of the
	// cost of reading the same JSON. 1MiB is well under one frame object per
	// extra state and above the noise of a second parse of this payload.
	const slack = 1 << 20
	require.LessOrEqualf(t, int64(used), int64(baseline)+slack,
		"oversized USA query allocated %d bytes after a %d byte parse-and-reject of the same state list (frames=%d err=%v)",
		used, baseline, responseFrames(attackResp), attackErr)
}

func usaQueryRequest(t *testing.T, queryType, mode string, states, fields, maxDataPoints int) *backend.QueryDataRequest {
	t.Helper()
	return usaQueryWithPeriod(t, queryType, mode, states, fields, maxDataPoints, "1m")
}

func usaQueryWithPeriod(t *testing.T, queryType, mode string, states, fields, maxDataPoints int, period string) *backend.QueryDataRequest {
	t.Helper()
	body := struct {
		ScenarioID string   `json:"scenarioId"`
		USA        usaQuery `json:"usa"`
	}{
		ScenarioID: "usa",
		USA: usaQuery{
			Mode:   mode,
			Period: period,
			Fields: repeatedNames("f", fields),
			States: repeatedNames("s", states),
		},
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)

	from := time.Date(2020, time.January, 10, 23, 0, 0, 0, time.UTC)
	return &backend.QueryDataRequest{
		Queries: []backend.DataQuery{{
			RefID:         "A",
			QueryType:     queryType,
			TimeRange:     backend.TimeRange{From: from, To: from.Add(10 * time.Second)},
			Interval:      time.Second,
			MaxDataPoints: int64(maxDataPoints),
			JSON:          raw,
		}},
	}
}

func repeatedNames(prefix string, n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = prefix
	}
	return names
}

func requireOversizedRejected(t *testing.T, resp *backend.QueryDataResponse, err error, states, fields int) {
	t.Helper()
	gotFrames, gotFields := responseLoad(resp)
	require.Zerof(t, gotFrames, "built %d frames (%d fields) for %d states x %d fields (product %d, cap %d) and returned err=%v", gotFrames, gotFields, states, fields, states*fields, maxUSAResults, err)
	if err != nil {
		return
	}
	require.NotNil(t, resp)
	dr, ok := resp.Responses["A"]
	require.True(t, ok)
	require.Errorf(t, dr.Error, "accepted %d states x %d fields (product %d exceeds cap %d)", states, fields, states*fields, maxUSAResults)
}

func responseLoad(resp *backend.QueryDataResponse) (frames, fields int) {
	if resp == nil {
		return 0, 0
	}
	for _, dr := range resp.Responses {
		frames += len(dr.Frames)
		for _, frame := range dr.Frames {
			fields += len(frame.Fields)
		}
	}
	return frames, fields
}

func assertUSAShape(t *testing.T, mode string, states, fields int, dr backend.DataResponse) {
	t.Helper()
	switch mode {
	case modeTimeseries:
		require.Len(t, dr.Frames, states*fields)
	case modeTimeseriesWide:
		require.Len(t, dr.Frames, 1)
		require.Len(t, dr.Frames[0].Fields, 1+states*fields)
	case modeValueAsFields, modeValueAsLabeledFields:
		require.Len(t, dr.Frames, fields)
		for _, frame := range dr.Frames {
			require.Len(t, frame.Fields, states)
		}
	default:
		require.Len(t, dr.Frames, 1)
		require.Len(t, dr.Frames[0].Fields, 1+fields)
		require.Equal(t, states, dr.Frames[0].Fields[0].Len())
	}
}

func allocatedBytes(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// usaFrameWriter records frames the chunked query path emits. It does not
// marshal them, so a refusal that never calls WriteFrame stays at zero frames.
type usaFrameWriter struct {
	mu     sync.Mutex
	frames []*data.Frame
	errors int
}

func (w *usaFrameWriter) WriteFrame(_ context.Context, _ string, _ string, f *data.Frame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.frames = append(w.frames, f)
	return nil
}

func (w *usaFrameWriter) WriteError(_ context.Context, _ string, _ backend.Status, _ error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.errors++
	return nil
}

func (w *usaFrameWriter) load() (frames, fields int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	frames = len(w.frames)
	for _, frame := range w.frames {
		if frame != nil {
			fields += len(frame.Fields)
		}
	}
	return frames, fields
}

func responseFrames(resp *backend.QueryDataResponse) int {
	frames, _ := responseLoad(resp)
	return frames
}
