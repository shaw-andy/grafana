package testdatasource

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
)

// maxPredictableCSVWaves is the most series one predictable_csv_wave query may
// allocate. predictableSeries already stops at maxPredictableCSVWavePoints, so
// an uncapped csvWave array is the dimension that turns a small JSON body into
// a large in-memory response.
const (
	maxPredictableCSVWaves      = 100
	maxPredictableCSVWavePoints = 10000
)

func TestPredictableCSVWaveQueryData(t *testing.T) {
	svc := ProvideService()
	shortFrom := time.Unix(0, 0).UTC()
	shortTo := shortFrom.Add(2 * time.Second)

	t.Run("one hundred waves is the maximum a query may return", func(t *testing.T) {
		resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{
			Queries: []backend.DataQuery{
				predictableCSVWaveQuery("A", "", maxPredictableCSVWaves, shortFrom, shortTo),
			},
		})
		require.NoError(t, err)
		frames := responseFrames(t, resp, "A")
		require.Len(t, frames, maxPredictableCSVWaves)
		for _, frame := range frames {
			require.Positive(t, frame.Rows())
			require.LessOrEqual(t, frame.Rows(), maxPredictableCSVWavePoints)
		}
	})

	t.Run("scenarioId without queryType cannot request more waves than the cap", func(t *testing.T) {
		resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{
			Queries: []backend.DataQuery{
				predictableCSVWaveQuery("A", "", maxPredictableCSVWaves+1, shortFrom, shortTo),
			},
		})
		requireCSVWaveBounded(t, resp, err)
	})

	t.Run("queryType predictable_csv_wave cannot request more waves than the cap", func(t *testing.T) {
		resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{
			Queries: []backend.DataQuery{
				predictableCSVWaveQuery("A", "predictable_csv_wave", maxPredictableCSVWaves+1, shortFrom, shortTo),
			},
		})
		requireCSVWaveBounded(t, resp, err)
	})

	t.Run("each query in one request is capped on its own", func(t *testing.T) {
		resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{
			Queries: []backend.DataQuery{
				predictableCSVWaveQuery("A", "", maxPredictableCSVWaves+1, shortFrom, shortTo),
				predictableCSVWaveQuery("B", "predictable_csv_wave", maxPredictableCSVWaves+1, shortFrom, shortTo),
			},
		})
		requireCSVWaveBounded(t, resp, err)
	})

	t.Run("one wave still fills the existing per-series point ceiling", func(t *testing.T) {
		from := time.Unix(0, 0).UTC()
		to := from.Add(20000 * time.Second)
		resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{
			Queries: []backend.DataQuery{
				predictableCSVWaveQuery("A", "", 1, from, to),
			},
		})
		require.NoError(t, err)
		frames := responseFrames(t, resp, "A")
		require.Len(t, frames, 1)
		require.Equal(t, maxPredictableCSVWavePoints, frames[0].Rows())
	})
}

func TestPredictableCSVWaveChunkedQuery(t *testing.T) {
	svc := ProvideService()
	from := time.Unix(0, 0).UTC()
	to := from.Add(2 * time.Second)
	writer := &countingChunkWriter{}

	err := svc.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{
		Queries: []backend.DataQuery{
			predictableCSVWaveQuery("A", "", maxPredictableCSVWaves+1, from, to),
		},
	}, writer)
	if err != nil {
		t.Logf("chunked query rejected: %v", err)
	}

	require.LessOrEqual(t, writer.frames, maxPredictableCSVWaves)
	require.LessOrEqual(t, writer.maxRows, maxPredictableCSVWavePoints)
}

func predictableCSVWaveQuery(refID, queryType string, waves int, from, to time.Time) backend.DataQuery {
	var body strings.Builder
	body.WriteString(`{"scenarioId":"predictable_csv_wave","csvWave":[`)
	for i := 0; i < waves; i++ {
		if i > 0 {
			body.WriteByte(',')
		}
		body.WriteString(`{"timeStep":1,"valuesCSV":"1"}`)
	}
	body.WriteString(`]}`)

	return backend.DataQuery{
		RefID:         refID,
		QueryType:     queryType,
		TimeRange:     backend.TimeRange{From: from, To: to},
		Interval:      time.Second,
		MaxDataPoints: 100,
		JSON:          []byte(body.String()),
	}
}

func responseFrames(t *testing.T, resp *backend.QueryDataResponse, refID string) data.Frames {
	t.Helper()
	require.NotNil(t, resp)
	result, ok := resp.Responses[refID]
	require.True(t, ok, "missing response for %s", refID)
	require.NoError(t, result.Error)
	return result.Frames
}

// requireCSVWaveBounded accepts either a rejected query or a response that
// never materializes more than maxPredictableCSVWaves frames for any refId.
// An error that still carries the oversized frames does not count.
func requireCSVWaveBounded(t *testing.T, resp *backend.QueryDataResponse, err error) {
	t.Helper()
	if err != nil && resp == nil {
		return
	}
	require.NotNil(t, resp)
	for refID, result := range resp.Responses {
		require.LessOrEqual(t, len(result.Frames), maxPredictableCSVWaves, "ref %s", refID)
		for _, frame := range result.Frames {
			require.LessOrEqual(t, frame.Rows(), maxPredictableCSVWavePoints, "ref %s", refID)
		}
	}
}

type countingChunkWriter struct {
	mu      sync.Mutex
	frames  int
	maxRows int
}

func (w *countingChunkWriter) WriteFrame(_ context.Context, _ string, _ string, frame *data.Frame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.frames++
	if frame != nil && frame.Rows() > w.maxRows {
		w.maxRows = frame.Rows()
	}
	return nil
}

func (w *countingChunkWriter) WriteError(context.Context, string, backend.Status, error) error {
	return nil
}
