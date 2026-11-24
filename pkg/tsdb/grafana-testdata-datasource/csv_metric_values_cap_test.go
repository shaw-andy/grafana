package testdatasource

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/web"
)

// csvMetricPointCap is the server-side bound already used for random-walk
// series. CSV scenarios must apply it even when the client asks for more
// points than that, and they must apply it before splitting the input or
// allocating a column of that length.
const csvMetricPointCap = 10000

// Attacker-controlled maxDataPoints, larger than both the cap and the over-cap
// fixtures, so a fix that trusts this field still expands the input.
const attackerMaxDataPoints = 5_000_000

const overCapPoints = 1_000_000

// extraAllocMargin is room for another copy of the larger JSON payload.
// It is smaller than the pointer slice strings.Split allocates for overCapPoints,
// so counting tokens and then splitting the whole string still fails.
const extraAllocMargin = 4 << 20

func TestCSVMetricValuesPreservesSmallSeries(t *testing.T) {
	svc := ProvideService()

	t.Run("scenario id", func(t *testing.T) {
		assertSmallSeries(t, svc, "", "1,20,90,30,5,0")
	})
	t.Run("query type", func(t *testing.T) {
		assertSmallSeries(t, svc, "csv_metric_values", "1,20,90,30,5,0")
	})
	t.Run("spaces stripped", func(t *testing.T) {
		assertSmallSeries(t, svc, "", "1, 20, 90, 30, 5, 0")
	})
}

func TestCSVMetricValuesExactCap(t *testing.T) {
	svc := ProvideService()
	q := pluginQueryFromBody(t, metricBody(csvMetricQuery("", repeatedToken("1", csvMetricPointCap), "A")))
	resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: []backend.DataQuery{q}})
	require.NoError(t, err)
	require.Equal(t, csvMetricPointCap, rowsFor(resp, "A"))
}

func TestCSVMetricValuesOnePastCapIsNotExpanded(t *testing.T) {
	svc := ProvideService()
	for _, queryType := range []string{"", "csv_metric_values"} {
		t.Run(queryTypeLabel(queryType), func(t *testing.T) {
			q := pluginQueryFromBody(t, metricBody(csvMetricQuery(queryType, repeatedToken("1", csvMetricPointCap+1), "A")))
			resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: []backend.DataQuery{q}})
			requireAtMostCap(t, resp, err)
		})
	}
}

func TestCSVMetricValuesSiblingQuery(t *testing.T) {
	svc := ProvideService()
	body := metricBodyMulti(
		csvMetricQuery("", "1,20,90,30,5,0", "A"),
		csvMetricQuery("", repeatedToken("1", csvMetricPointCap+1), "B"),
	)
	queries := pluginQueriesFromBody(t, body)
	resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: queries})
	if err != nil {
		requireAtMostCap(t, resp, err)
		return
	}
	require.Equal(t, []int64{1, 20, 90, 30, 5, 0}, intSeries(t, resp, "A"))
	requireAtMostCap(t, resp, nil)
}

func TestUncappedCSVScenariosDoNotAllocatePerToken(t *testing.T) {
	svc := ProvideService()
	warmup(t, svc)

	cases := []struct {
		name  string
		build func(n int) map[string]any
	}{
		{
			name: "csv_metric_values scenario id",
			build: func(n int) map[string]any {
				return csvMetricQuery("", repeatedToken("1", n), "A")
			},
		},
		{
			name: "csv_metric_values query type",
			build: func(n int) map[string]any {
				return csvMetricQuery("csv_metric_values", repeatedToken("1", n), "A")
			},
		},
		{
			name: "csv_metric_values non-numeric tokens",
			build: func(n int) map[string]any {
				return csvMetricQuery("csv_metric_values", repeatedToken("a", n), "A")
			},
		},
		{
			name: "server_error_500",
			build: func(n int) map[string]any {
				return csvMetricQuery("server_error_500", repeatedToken("1", n), "A")
			},
		},
		{
			name: "csv_content",
			build: func(n int) map[string]any {
				return map[string]any{
					"refId":         "A",
					"datasource":    map[string]any{"type": "grafana-testdata-datasource", "uid": "testdata"},
					"scenarioId":    "csv_content",
					"queryType":     "csv_content",
					"maxDataPoints": attackerMaxDataPoints,
					"csvContent":    "value\n" + strings.Repeat("1\n", n),
					"intervalMs":    1000,
				}
			},
		},
		{
			name: "predictable_csv_wave",
			build: func(n int) map[string]any {
				return map[string]any{
					"refId":         "A",
					"datasource":    map[string]any{"type": "grafana-testdata-datasource", "uid": "testdata"},
					"scenarioId":    "predictable_csv_wave",
					"queryType":     "predictable_csv_wave",
					"maxDataPoints": attackerMaxDataPoints,
					"intervalMs":    1000,
					"csvWave": []any{map[string]any{
						"timeStep":  int64(1),
						"valuesCSV": repeatedToken("1", n),
						"name":      "wave",
					}},
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			small := pluginQueryFromBody(t, metricBody(tc.build(csvMetricPointCap)))
			_, _, smallAlloc := expandAndEncode(svc, []backend.DataQuery{small})

			huge := pluginQueryFromBody(t, metricBody(tc.build(overCapPoints)))
			resp, err, hugeAlloc := expandAndEncode(svc, []backend.DataQuery{huge})

			extra := len(huge.JSON) - len(small.JSON)
			if extra < 0 {
				extra = 0
			}
			limit := smallAlloc + uint64(extra) + extraAllocMargin
			if hugeAlloc > limit {
				t.Fatalf("expanding %d tokens allocated %d bytes; limit is %d (capped baseline %d, extra JSON %d, margin %d)",
					overCapPoints, hugeAlloc, limit, smallAlloc, extra, extraAllocMargin)
			}
			requireAtMostCap(t, resp, err)
		})
	}
}

func TestCSVMetricValuesChunkedQueryCap(t *testing.T) {
	svc := ProvideService()
	warmup(t, svc)

	small := pluginQueryFromBody(t, metricBody(csvMetricQuery("csv_metric_values", repeatedToken("1", csvMetricPointCap), "A")))
	_, _, smallAlloc := expandAndEncodeChunked(svc, small)

	huge := pluginQueryFromBody(t, metricBody(csvMetricQuery("", repeatedToken("1", overCapPoints), "A")))
	frames, err, hugeAlloc := expandAndEncodeChunked(svc, huge)

	extra := len(huge.JSON) - len(small.JSON)
	if extra < 0 {
		extra = 0
	}
	limit := smallAlloc + uint64(extra) + extraAllocMargin
	if hugeAlloc > limit {
		t.Fatalf("chunked expansion allocated %d bytes; limit is %d (baseline %d, extra JSON %d)", hugeAlloc, limit, smallAlloc, extra)
	}
	if err != nil {
		return
	}
	for _, f := range frames {
		if f != nil && f.Rows() > csvMetricPointCap {
			t.Fatalf("chunked frame expanded to %d points", f.Rows())
		}
	}
}

func assertSmallSeries(t *testing.T, svc *Service, queryType string, input string) {
	t.Helper()
	q := pluginQueryFromBody(t, metricBody(csvMetricQuery(queryType, input, "A")))
	resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: []backend.DataQuery{q}})
	require.NoError(t, err)
	require.Equal(t, []int64{1, 20, 90, 30, 5, 0}, intSeries(t, resp, "A"))
}

func csvMetricQuery(queryType string, stringInput string, refID string) map[string]any {
	if refID == "" {
		refID = "A"
	}
	scenario := "csv_metric_values"
	q := map[string]any{
		"refId":         refID,
		"datasource":    map[string]any{"type": "grafana-testdata-datasource", "uid": "testdata"},
		"scenarioId":    scenario,
		"stringInput":   stringInput,
		"maxDataPoints": attackerMaxDataPoints,
		"intervalMs":    1000,
	}
	if queryType != "" {
		q["queryType"] = queryType
		q["scenarioId"] = queryType
	}
	return q
}

func metricBody(query map[string]any) []byte {
	return metricBodyMulti(query)
}

func metricBodyMulti(queries ...map[string]any) []byte {
	payload := map[string]any{
		"from":    "0",
		"to":      "3600000",
		"queries": queries,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return body
}

// pluginQueryFromBody binds a /api/ds/query body the way QueryMetricsV2 does,
// then copies queryType, maxDataPoints, and the query JSON the way
// parseMetricRequest does before the plugin runs.
func pluginQueryFromBody(t *testing.T, body []byte) backend.DataQuery {
	t.Helper()
	queries := pluginQueriesFromBody(t, body)
	require.Len(t, queries, 1)
	return queries[0]
}

func pluginQueriesFromBody(t *testing.T, body []byte) []backend.DataQuery {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodPost, "/api/ds/query", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	var dto dtos.MetricRequest
	require.NoError(t, web.Bind(httpReq, &dto))
	require.NotEmpty(t, dto.Queries)

	out := make([]backend.DataQuery, 0, len(dto.Queries))
	for _, q := range dto.Queries {
		modelJSON, err := q.MarshalJSON()
		require.NoError(t, err)
		out = append(out, backend.DataQuery{
			RefID:         q.Get("refId").MustString("A"),
			QueryType:     q.Get("queryType").MustString(""),
			MaxDataPoints: q.Get("maxDataPoints").MustInt64(100),
			Interval:      time.Duration(q.Get("intervalMs").MustInt64(1000)) * time.Millisecond,
			JSON:          modelJSON,
			TimeRange: backend.TimeRange{
				From: time.Unix(0, 0).UTC(),
				To:   time.Unix(3600, 0).UTC(),
			},
		})
	}
	return out
}

func expandAndEncode(svc *Service, queries []backend.DataQuery) (*backend.QueryDataResponse, error, uint64) {
	var resp *backend.QueryDataResponse
	var err error
	alloc := minAllocs(2, func() {
		resp, err = svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: queries})
		if err == nil && resp != nil {
			var buf bytes.Buffer
			encErr := json.NewEncoder(&buf).Encode(resp)
			if encErr != nil {
				err = encErr
			}
		}
	})
	return resp, err, alloc
}

type captureChunkWriter struct {
	frames []*data.Frame
}

func (w *captureChunkWriter) WriteFrame(_ context.Context, _ string, _ string, f *data.Frame) error {
	w.frames = append(w.frames, f)
	return nil
}

func (w *captureChunkWriter) WriteError(_ context.Context, _ string, _ backend.Status, _ error) error {
	return nil
}

func expandAndEncodeChunked(svc *Service, q backend.DataQuery) ([]*data.Frame, error, uint64) {
	var frames []*data.Frame
	var err error
	alloc := minAllocs(2, func() {
		w := &captureChunkWriter{}
		err = svc.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{
			Queries: []backend.DataQuery{q},
		}, w)
		frames = w.frames
		if err == nil {
			var buf bytes.Buffer
			for _, f := range frames {
				encErr := json.NewEncoder(&buf).Encode(f)
				if encErr != nil {
					err = encErr
					return
				}
			}
		}
	})
	return frames, err, alloc
}

func minAllocs(n int, fn func()) uint64 {
	var min uint64
	for i := 0; i < n; i++ {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		fn()
		runtime.ReadMemStats(&after)
		delta := after.TotalAlloc - before.TotalAlloc
		if i == 0 || delta < min {
			min = delta
		}
	}
	return min
}

func warmup(t *testing.T, svc *Service) {
	t.Helper()
	q := pluginQueryFromBody(t, metricBody(csvMetricQuery("", "1,2,3", "A")))
	_, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{Queries: []backend.DataQuery{q}})
	require.NoError(t, err)
}

func requireAtMostCap(t *testing.T, resp *backend.QueryDataResponse, err error) {
	t.Helper()
	if err != nil {
		return
	}
	require.NotNil(t, resp)
	for refID, dr := range resp.Responses {
		for _, f := range dr.Frames {
			if f != nil && f.Rows() > csvMetricPointCap {
				t.Fatalf("ref %s expanded to %d points; cap is %d", refID, f.Rows(), csvMetricPointCap)
			}
		}
	}
}

func rowsFor(resp *backend.QueryDataResponse, refID string) int {
	if resp == nil {
		return 0
	}
	n := 0
	for _, f := range resp.Responses[refID].Frames {
		if f != nil {
			n += f.Rows()
		}
	}
	return n
}

func intSeries(t *testing.T, resp *backend.QueryDataResponse, refID string) []int64 {
	t.Helper()
	require.NotNil(t, resp)
	dr := resp.Responses[refID]
	require.NoError(t, dr.Error)
	require.Len(t, dr.Frames, 1)
	field := dr.Frames[0].Fields[1]
	out := make([]int64, field.Len())
	for i := 0; i < field.Len(); i++ {
		v, ok := field.ConcreteAt(i)
		require.True(t, ok)
		out[i] = v.(int64)
	}
	return out
}

func repeatedToken(token string, n int) string {
	if n <= 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(n * (len(token) + 1))
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(token)
	}
	return b.String()
}

func queryTypeLabel(queryType string) string {
	if queryType == "" {
		return "scenario id"
	}
	return queryType
}
