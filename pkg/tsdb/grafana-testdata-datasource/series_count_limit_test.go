package testdatasource

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource/kinds"
)

// maxSeriesCountPerQuery is the most frames one TestData query may build from
// seriesCount. RandomWalk keeps at most 10_000 points per frame (about 1.7MB
// on the measured build), so a few thousand series is gigabytes. 100 still
// covers the counts the editor and existing callers use.
const maxSeriesCountPerQuery = 100

// farOverLimit is large enough that building one frame per series is visible
// in TotalAlloc, and small enough that a run against the uncapped loop stays
// in the tens of megabytes.
const farOverLimit = 5000

// maxAllocForRejectedSeriesCount is above the cost of refusing a query and
// below the cost of building farOverLimit frames. Measured on this commit,
// 5000 empty random-walk frames allocate about 33MB and 100 allocate under 1MB.
const maxAllocForRejectedSeriesCount = 4 << 20

func TestRandomWalkSeriesCountLimit(t *testing.T) {
	svc := ProvideService()

	t.Run("count at the limit is returned", func(t *testing.T) {
		resp, err := svc.QueryData(context.Background(), randomWalkRequest("", maxSeriesCountPerQuery))
		require.NoError(t, err)
		dr, ok := resp.Responses["A"]
		require.True(t, ok)
		require.NoError(t, dr.Error)
		require.Len(t, dr.Frames, maxSeriesCountPerQuery)
	})

	t.Run("count just above the limit is rejected", func(t *testing.T) {
		for _, queryType := range []string{"", string(kinds.TestDataQueryTypeRandomWalk)} {
			t.Run(queryTypeLabel(queryType), func(t *testing.T) {
				resp, err := svc.QueryData(context.Background(), randomWalkRequest(queryType, maxSeriesCountPerQuery+1))
				assertSeriesCountRejected(t, resp, err, "A")
			})
		}
	})

	t.Run("count far above the limit is rejected before the frames are built", func(t *testing.T) {
		for _, queryType := range []string{"", string(kinds.TestDataQueryTypeRandomWalk)} {
			t.Run(queryTypeLabel(queryType), func(t *testing.T) {
				var resp *backend.QueryDataResponse
				var err error
				alloc := allocDuring(func() {
					resp, err = svc.QueryData(context.Background(), randomWalkRequest(queryType, farOverLimit))
				})
				assertSeriesCountRejected(t, resp, err, "A")
				require.LessOrEqualf(t, alloc, uint64(maxAllocForRejectedSeriesCount),
					"refusing seriesCount=%d allocated %d bytes; the frames were built before the query was refused",
					farOverLimit, alloc)
			})
		}
	})

	t.Run("chunked query is rejected before the frames are built", func(t *testing.T) {
		for _, queryType := range []string{"", string(kinds.TestDataQueryTypeRandomWalk)} {
			t.Run(queryTypeLabel(queryType), func(t *testing.T) {
				writer := &captureChunkWriter{}
				req := randomWalkRequest(queryType, farOverLimit)
				var err error
				alloc := allocDuring(func() {
					err = svc.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{
						PluginContext: req.PluginContext,
						Headers:       req.Headers,
						Queries:       req.Queries,
					}, writer)
				})
				require.Truef(t, err != nil || writer.errors > 0,
					"chunked seriesCount=%d was accepted, frames=%d", farOverLimit, writer.frames)
				require.LessOrEqualf(t, writer.frames, maxSeriesCountPerQuery,
					"chunked query wrote %d frames", writer.frames)
				require.LessOrEqualf(t, alloc, uint64(maxAllocForRejectedSeriesCount),
					"refusing chunked seriesCount=%d allocated %d bytes", farOverLimit, alloc)
			})
		}
	})

	t.Run("an over-limit query is refused when another query in the request is within the limit", func(t *testing.T) {
		req := randomWalkRequest("", 1)
		req.Queries = append(req.Queries, randomWalkRequest("", farOverLimit).Queries[0])
		req.Queries[1].RefID = "B"

		var resp *backend.QueryDataResponse
		var err error
		alloc := allocDuring(func() {
			resp, err = svc.QueryData(context.Background(), req)
		})
		assertSeriesCountRejected(t, resp, err, "B")
		if err == nil && resp != nil {
			require.LessOrEqualf(t, len(resp.Responses["A"].Frames), maxSeriesCountPerQuery,
				"the in-limit sibling query returned %d frames", len(resp.Responses["A"].Frames))
		}
		require.LessOrEqualf(t, alloc, uint64(maxAllocForRejectedSeriesCount),
			"refusing the sibling seriesCount allocated %d bytes", alloc)
	})
}

func queryTypeLabel(queryType string) string {
	if queryType == "" {
		return "scenarioId only"
	}
	return "queryType " + queryType
}

func randomWalkRequest(queryType string, seriesCount int) *backend.QueryDataRequest {
	now := time.Unix(1_700_000_000, 0).UTC()
	return &backend.QueryDataRequest{
		Queries: []backend.DataQuery{{
			RefID:     "A",
			QueryType: queryType,
			TimeRange: backend.TimeRange{
				From: now,
				To:   now,
			},
			Interval: time.Second,
			JSON:     []byte(fmt.Sprintf(`{"scenarioId":%q,"seriesCount":%d}`, kinds.TestDataQueryTypeRandomWalk, seriesCount)),
		}},
	}
}

// assertSeriesCountRejected requires the caller to observe a refusal and no
// expanded frame list. A handler error that is dropped before it reaches
// QueryData, or a response that still carries the requested frames, is not a
// refusal.
func assertSeriesCountRejected(t *testing.T, resp *backend.QueryDataResponse, err error, refID string) {
	t.Helper()

	frames := 0
	var respErr error
	if resp != nil {
		dr := resp.Responses[refID]
		frames = len(dr.Frames)
		respErr = dr.Error
	}
	require.Truef(t, err != nil || respErr != nil,
		"seriesCount above %d was accepted for ref %s with %d frames and no error",
		maxSeriesCountPerQuery, refID, frames)
	require.LessOrEqualf(t, frames, maxSeriesCountPerQuery,
		"ref %s returned %d frames after a seriesCount the query should have refused", refID, frames)
	require.Zerof(t, frames, "refused query for ref %s still returned %d frames", refID, frames)
}

func allocDuring(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

type captureChunkWriter struct {
	frames int
	errors int
}

func (w *captureChunkWriter) WriteFrame(_ context.Context, _ string, _ string, _ *data.Frame) error {
	w.frames++
	return nil
}

func (w *captureChunkWriter) WriteError(_ context.Context, _ string, _ backend.Status, _ error) error {
	w.errors++
	return nil
}
