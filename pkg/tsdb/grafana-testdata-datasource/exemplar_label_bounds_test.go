package testdatasource

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
)

// Bounds the exemplars scenario must enforce before it allocates label columns.
// A few dozen columns still have to work; dozens more, or a product of columns,
// rows, and value length past a few megabytes, must be refused up front.
// The same byte budget covers every query in one QueryData or QueryChunkedData
// call. Row count and value length are already clamped (10000 and 128); the
// budget uses those clamped sizes, so a single full-length column still fits.
const (
	exemplarLabelColumnLimit       = 48
	exemplarLabelRequestByteBudget = 4 << 20
	// Headroom for the time/value columns and the reference random walk.
	// Label-value strings for an over-budget request are several times this.
	exemplarLabelAllocSlack = 1 << 20
)

func TestExemplarLabelAllocationBounds(t *testing.T) {
	svc := ProvideService()

	t.Run("within budget by scenario id", func(t *testing.T) {
		frames := queryExemplars(t, svc, "", []exemplarSpec{{refID: "A", count: 100, labels: 24, length: 16}})
		cols, payload := labelPayload(frames)
		require.Equal(t, 24, cols)
		require.Equal(t, 24*100*16, payload)
	})

	t.Run("within budget by query type", func(t *testing.T) {
		frames := queryExemplars(t, svc, string(kindsExemplar), []exemplarSpec{{refID: "A", count: 100, labels: 24, length: 16}})
		cols, payload := labelPayload(frames)
		require.Equal(t, 24, cols)
		require.Equal(t, 24*100*16, payload)
	})

	t.Run("clamps are applied before the budget", func(t *testing.T) {
		// Unclamped numbers would look enormous. After the existing caps this
		// is one column of 10000 values of length 128, which has to succeed.
		frames := queryExemplars(t, svc, "", []exemplarSpec{{refID: "A", count: 1_000_000, labels: 1, length: 1_000_000}})
		cols, payload := labelPayload(frames)
		require.Equal(t, 1, cols)
		require.Equal(t, maxExemplarCount*maxExemplarLabelLength, payload)
		require.LessOrEqual(t, payload, exemplarLabelRequestByteBudget)
	})

	t.Run("column count is capped", func(t *testing.T) {
		// 80 columns of 2 short values is a few hundred bytes, so only the
		// column cap stands in the way. Refusing the query or dropping columns
		// past the cap both satisfy it; returning every column does not.
		frames := collectExemplars(t, svc, "", []exemplarSpec{{refID: "A", count: 2, labels: 80, length: 4}})
		cols, _ := labelPayload(frames)
		require.LessOrEqual(t, cols, exemplarLabelColumnLimit)
	})

	t.Run("column count is capped for an explicit query type", func(t *testing.T) {
		frames := collectExemplars(t, svc, string(kindsExemplar), []exemplarSpec{{refID: "A", count: 2, labels: 80, length: 4}})
		cols, _ := labelPayload(frames)
		require.LessOrEqual(t, cols, exemplarLabelColumnLimit)
	})

	overBudget := exemplarSpec{refID: "A", count: 2000, labels: 24, length: 128} // 24*2000*128 = 6144000
	require.Greater(t, overBudget.product(), exemplarLabelRequestByteBudget)

	t.Run("byte budget by scenario id", func(t *testing.T) {
		assertRefusedUnderBudget(t, svc, "", []exemplarSpec{overBudget})
	})

	t.Run("byte budget by query type", func(t *testing.T) {
		assertRefusedUnderBudget(t, svc, string(kindsExemplar), []exemplarSpec{overBudget})
	})

	t.Run("byte budget across queries", func(t *testing.T) {
		// Each query is under the budget. Together they are not.
		specs := make([]exemplarSpec, 4)
		for i := range specs {
			specs[i] = exemplarSpec{refID: string(rune('A' + i)), count: 700, labels: 24, length: 128} // 2150400 each
			require.LessOrEqual(t, specs[i].product(), exemplarLabelRequestByteBudget)
		}
		sum := 0
		for _, spec := range specs {
			sum += spec.product()
		}
		require.Greater(t, sum, exemplarLabelRequestByteBudget)
		assertRefusedUnderBudget(t, svc, "", specs)
	})

	t.Run("chunked column count is capped", func(t *testing.T) {
		frames := collectChunkedExemplars(t, svc, "", []exemplarSpec{{refID: "A", count: 2, labels: 80, length: 4}})
		cols, _ := labelPayload(frames)
		require.LessOrEqual(t, cols, exemplarLabelColumnLimit)
	})

	t.Run("chunked byte budget", func(t *testing.T) {
		assertChunkedRefusedUnderBudget(t, svc, string(kindsExemplar), []exemplarSpec{overBudget})
	})

	t.Run("chunked byte budget across queries", func(t *testing.T) {
		specs := make([]exemplarSpec, 4)
		for i := range specs {
			specs[i] = exemplarSpec{refID: string(rune('A' + i)), count: 700, labels: 24, length: 128}
		}
		assertChunkedRefusedUnderBudget(t, svc, "", specs)
	})
}

// kindsExemplar is the scenario id the query mux registers. Kept as a local
// name so the dispatch tests read as the two ways a request reaches that handler.
const kindsExemplar = "exemplars"

type exemplarSpec struct {
	refID  string
	count  int
	labels int
	length int
}

func (s exemplarSpec) product() int {
	count := s.count
	if count <= 0 {
		count = defaultExemplarCount
	}
	if count > maxExemplarCount {
		count = maxExemplarCount
	}
	length := s.length
	if length <= 0 {
		length = defaultExemplarLabelLength
	}
	if length > maxExemplarLabelLength {
		length = maxExemplarLabelLength
	}
	return s.labels * count * length
}

func (s exemplarSpec) query(queryType string, from time.Time) backend.DataQuery {
	var b strings.Builder
	b.WriteString(`{"scenarioId":"exemplars","exemplarCount":`)
	b.WriteString(strconv.Itoa(s.count))
	b.WriteString(`,"exemplarLabels":[`)
	for i := 0; i < s.labels; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"name":"l%d","length":%d}`, i, s.length)
	}
	b.WriteString(`]}`)
	return backend.DataQuery{
		RefID:     s.refID,
		QueryType: queryType,
		TimeRange: backend.TimeRange{From: from, To: from.Add(time.Second)},
		Interval:  time.Second,
		JSON:      []byte(b.String()),
	}
}

func queryExemplars(t *testing.T, svc *Service, queryType string, specs []exemplarSpec) []*data.Frame {
	t.Helper()
	resp, err := svc.QueryData(context.Background(), requestFor(queryType, specs))
	require.NoError(t, err)
	require.NotNil(t, resp)
	for refID, dr := range resp.Responses {
		require.NoErrorf(t, dr.Error, "query %s", refID)
	}
	return framesOf(resp)
}

// collectExemplars returns whatever frames the call materialized. A refused
// query contributes none, which is what the column cap allows.
func collectExemplars(t *testing.T, svc *Service, queryType string, specs []exemplarSpec) []*data.Frame {
	t.Helper()
	resp, err := svc.QueryData(context.Background(), requestFor(queryType, specs))
	if err != nil {
		return nil
	}
	return framesOf(resp)
}

func assertRefusedUnderBudget(t *testing.T, svc *Service, queryType string, specs []exemplarSpec) {
	t.Helper()
	req := requestFor(queryType, specs)
	jsonBytes := 0
	for _, q := range req.Queries {
		jsonBytes += len(q.JSON)
	}

	var resp *backend.QueryDataResponse
	var err error
	used := allocDuring(func() {
		resp, err = svc.QueryData(context.Background(), req)
	})

	require.Lessf(t, used, uint64(exemplarLabelAllocSlack),
		"query JSON is %d bytes; QueryData allocated %d bytes before returning", jsonBytes, used)

	frames := []*data.Frame{}
	if err == nil && resp != nil {
		refused := false
		for _, dr := range resp.Responses {
			if dr.Error != nil {
				refused = true
			}
		}
		require.Truef(t, refused || len(resp.Responses) == 0, "over-budget exemplars query succeeded")
		frames = framesOf(resp)
	}
	_, payload := labelPayload(frames)
	require.LessOrEqualf(t, payload, exemplarLabelRequestByteBudget,
		"refused query still returned %d label-value bytes", payload)
}

func collectChunkedExemplars(t *testing.T, svc *Service, queryType string, specs []exemplarSpec) []*data.Frame {
	t.Helper()
	w := &captureChunkWriter{}
	if err := svc.QueryChunkedData(context.Background(), chunkRequestFor(queryType, specs), w); err != nil {
		return nil
	}
	return w.frames
}

func assertChunkedRefusedUnderBudget(t *testing.T, svc *Service, queryType string, specs []exemplarSpec) {
	t.Helper()
	req := chunkRequestFor(queryType, specs)
	jsonBytes := 0
	for _, q := range req.Queries {
		jsonBytes += len(q.JSON)
	}

	w := &captureChunkWriter{}
	var err error
	used := allocDuring(func() {
		err = svc.QueryChunkedData(context.Background(), req, w)
	})

	require.Lessf(t, used, uint64(exemplarLabelAllocSlack),
		"query JSON is %d bytes; QueryChunkedData allocated %d bytes before returning", jsonBytes, used)

	require.Truef(t, err != nil || w.errors > 0, "over-budget chunked exemplars query succeeded")
	_, payload := labelPayload(w.frames)
	require.LessOrEqualf(t, payload, exemplarLabelRequestByteBudget,
		"refused chunked query still wrote %d label-value bytes", payload)
}

func requestFor(queryType string, specs []exemplarSpec) *backend.QueryDataRequest {
	from := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	queries := make([]backend.DataQuery, len(specs))
	for i, spec := range specs {
		queries[i] = spec.query(queryType, from)
	}
	return &backend.QueryDataRequest{Queries: queries}
}

func chunkRequestFor(queryType string, specs []exemplarSpec) *backend.QueryChunkedDataRequest {
	from := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	queries := make([]backend.DataQuery, len(specs))
	for i, spec := range specs {
		queries[i] = spec.query(queryType, from)
	}
	return &backend.QueryChunkedDataRequest{Queries: queries}
}

func framesOf(resp *backend.QueryDataResponse) []*data.Frame {
	if resp == nil {
		return nil
	}
	var frames []*data.Frame
	for _, dr := range resp.Responses {
		frames = append(frames, dr.Frames...)
	}
	return frames
}

func labelPayload(frames []*data.Frame) (cols, payload int) {
	for _, frame := range frames {
		if frame == nil {
			continue
		}
		for _, field := range frame.Fields {
			if field.Name == data.TimeSeriesTimeFieldName || field.Name == data.TimeSeriesValueFieldName {
				continue
			}
			cols++
			for i := 0; i < field.Len(); i++ {
				s, ok := field.At(i).(string)
				if ok {
					payload += len(s)
				}
			}
		}
	}
	return cols, payload
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
	mu     sync.Mutex
	frames []*data.Frame
	errors int
}

func (w *captureChunkWriter) WriteFrame(_ context.Context, _ string, _ string, f *data.Frame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.frames = append(w.frames, f)
	return nil
}

func (w *captureChunkWriter) WriteError(_ context.Context, _ string, _ backend.Status, _ error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.errors++
	return nil
}
