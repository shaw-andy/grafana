package expr

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
)

// maxSQLExpressionResultBytes is the most bytes a SQL expression may
// materialize for its result values, summed across every value in the
// frame. The default output limit counts cells, so one cell can otherwise
// be a string as long as the repeat count, and several cells can add up
// past any per-cell clamp. Refusal has to happen before the engine
// allocates that string: building it and then dropping the row still
// exhausts memory.
const maxSQLExpressionResultBytes = 256 << 10

func TestSQLExpressionRejectsOversizedResultBeforeAllocation(t *testing.T) {
	// Steady-state cost of a tiny expression, so the budget is not dominated
	// by the first call into the SQL engine.
	_, _ = runSQLExpression(t, "SELECT 1 AS n", nil)
	baseline := allocatedDuring(func() {
		resp, err := runSQLExpression(t, "SELECT 'ok' AS s", nil)
		require.NoError(t, err)
		require.NoError(t, resp.Responses["A"].Error)
	})
	// A query that stays within the cap may copy a result of that size a
	// few times. A query that asks for more must be refused before those
	// bytes are allocated, so the budget stays a small multiple of the cap
	// and far below the multi-megabyte strings these statements request.
	budget := baseline + uint64(maxSQLExpressionResultBytes)*4

	type tc struct {
		name   string
		sql    string
		inputs map[string]backend.DataResponse
	}
	cases := []tc{
		{name: "repeat literal", sql: "SELECT REPEAT('A', 2000000) AS s"},
		{name: "repeat addition", sql: "SELECT REPEAT('A', 1000000 + 1000000) AS s"},
		{name: "repeat pow", sql: "SELECT REPEAT('A', POW(10, 6) * 2) AS s"},
		{name: "repeat nested", sql: "SELECT REPEAT(REPEAT('A', 2048), 1024) AS s"},
		{name: "repeat subquery", sql: "SELECT REPEAT('A', (SELECT 2000000)) AS s"},
		{name: "concat of repeats", sql: "SELECT CONCAT(REPEAT('A', 1000000), REPEAT('B', 1000000)) AS s"},
		{name: "replace expands repeat", sql: "SELECT REPLACE(REPEAT('A', 200000), 'A', 'BBBBB') AS s"},
		{name: "regexp_replace expands repeat", sql: "SELECT REGEXP_REPLACE(REPEAT('A', 150000), 'A', 'BB') AS s"},
		{name: "json_array of repeat", sql: "SELECT JSON_ARRAY(REPEAT('A', 2000000)) AS s"},
		{name: "elt of repeat", sql: "SELECT ELT(1, REPEAT('A', 300000)) AS s"},
		{name: "quote of repeat", sql: "SELECT QUOTE(REPEAT('A', 300000)) AS s"},
		{name: "group_concat of repeat", sql: "SELECT GROUP_CONCAT(REPEAT('A', 2000000) SEPARATOR '') AS s"},
		{
			name:   "repeat count from input column",
			sql:    "SELECT REPEAT('A', n) AS s FROM A",
			inputs: int64Input("n", 2_000_000),
		},
		{
			name:   "repeat count computed from input column",
			sql:    "SELECT REPEAT('A', n * 1000) AS s FROM A",
			inputs: int64Input("n", 2_000),
		},
		{
			name: "repeat across rows under the cell cap",
			sql: `WITH RECURSIVE nums AS (
				SELECT 1 AS n
				UNION ALL
				SELECT n + 1 FROM nums WHERE n < 4
			)
			SELECT REPEAT('A', 200000) AS s FROM nums`,
		},
		{
			name: "recursive concat doubling",
			sql: `WITH RECURSIVE s AS (
				SELECT CAST('A' AS CHAR(1)) AS v
				UNION ALL
				SELECT CONCAT(v, v) FROM s WHERE CHAR_LENGTH(v) < 400000
			)
			SELECT v FROM s ORDER BY CHAR_LENGTH(v) DESC LIMIT 1`,
		},
		{
			name: "recursive replace doubling",
			sql: `WITH RECURSIVE s AS (
				SELECT CAST('A' AS CHAR(1)) AS v
				UNION ALL
				SELECT REPLACE(v, 'A', 'AA') FROM s WHERE CHAR_LENGTH(v) < 400000
			)
			SELECT v FROM s ORDER BY CHAR_LENGTH(v) DESC LIMIT 1`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Less(t, len(c.sql), int(setting.DefaultSQLExpressionQueryLengthLimit),
				"query must stay under the query-length limit; that limit is not the bound under test")

			var resp *backend.QueryDataResponse
			var err error
			delta := allocatedDuring(func() {
				resp, err = runSQLExpression(t, c.sql, c.inputs)
			})
			assertResultWithinByteCap(t, err, resp)
			require.Lessf(t, delta, budget,
				"query allocated %d bytes (budget %d, baseline %d); the result was built before it was refused",
				delta, budget, baseline)
		})
	}
}

func TestSQLExpressionSmallResultStillRuns(t *testing.T) {
	resp, err := runSQLExpression(t, "SELECT 'ok' AS s", nil)
	require.NoError(t, err)
	require.NoError(t, resp.Responses["A"].Error)
	require.Equal(t, "ok", resp.Responses["A"].Frames[0].Fields[0].At(0))

	resp, err = runSQLExpression(t, "SELECT REPEAT('A', 8) AS s", nil)
	require.NoError(t, err)
	if resp.Responses["A"].Error != nil {
		require.ErrorContains(t, resp.Responses["A"].Error, "not in the allowed list")
		return
	}
	require.Equal(t, "AAAAAAAA", resp.Responses["A"].Frames[0].Fields[0].At(0))
}

func TestSQLExpressionInputColumnIsReadable(t *testing.T) {
	resp, err := runSQLExpression(t, "SELECT n AS n FROM A", int64Input("n", 2_000_000))
	require.NoError(t, err)
	require.NoError(t, resp.Responses["B"].Error)
	require.Equal(t, 1, resp.Responses["B"].Frames[0].Rows())
	got, err := resp.Responses["B"].Frames[0].Fields[0].NullableFloatAt(0)
	if err != nil {
		raw := resp.Responses["B"].Frames[0].Fields[0].At(0)
		require.EqualValues(t, 2_000_000, raw)
		return
	}
	require.NotNil(t, got)
	require.Equal(t, float64(2_000_000), *got)
}

func assertResultWithinByteCap(t *testing.T, err error, resp *backend.QueryDataResponse) {
	t.Helper()
	if err != nil || resp == nil {
		return
	}
	total := 0
	for _, r := range resp.Responses {
		if r.Error != nil {
			continue
		}
		for _, frame := range r.Frames {
			if frame == nil {
				continue
			}
			for _, field := range frame.Fields {
				for i := 0; i < field.Len(); i++ {
					total += sqlValueBytes(field.At(i))
				}
			}
		}
	}
	if total > maxSQLExpressionResultBytes {
		t.Errorf("result is %d bytes, above the %d byte cap", total, maxSQLExpressionResultBytes)
	}
}

func sqlValueBytes(v any) int {
	switch x := v.(type) {
	case string:
		return len(x)
	case *string:
		if x == nil {
			return 0
		}
		return len(*x)
	case json.RawMessage:
		return len(x)
	case []byte:
		return len(x)
	default:
		return 0
	}
}

func int64Input(field string, n int64) map[string]backend.DataResponse {
	frame := data.NewFrame("", data.NewField(field, nil, []int64{n}))
	return map[string]backend.DataResponse{
		"A": {Frames: data.Frames{frame}},
	}
}

func runSQLExpression(t *testing.T, expression string, inputs map[string]backend.DataResponse) (*backend.QueryDataResponse, error) {
	t.Helper()
	if inputs == nil {
		inputs = map[string]backend.DataResponse{}
	}
	escaped, err := json.Marshal(expression)
	require.NoError(t, err)

	refID := "A"
	queries := []Query{}
	if len(inputs) > 0 {
		refID = "B"
		queries = append(queries, Query{
			RefID: "A",
			DataSource: &datasources.DataSource{
				OrgID: 1,
				UID:   "test",
				Type:  "test",
			},
			JSON: json.RawMessage(`{ "datasource": { "uid": "test", "type": "test" }, "refId": "A" }`),
			TimeRange: AbsoluteTimeRange{
				From: time.Unix(0, 0),
				To:   time.Unix(1, 0),
			},
		})
	}
	queries = append(queries, Query{
		RefID:      refID,
		DataSource: dataSourceModel(),
		JSON: json.RawMessage(fmt.Sprintf(
			`{ "datasource": { "uid": "__expr__", "type": "__expr__"}, "type": "sql", "expression": %s }`,
			escaped,
		)),
		TimeRange: AbsoluteTimeRange{
			From: time.Unix(0, 0),
			To:   time.Unix(1, 0),
		},
	})

	s, req := newMockQueryService(inputs, queries)
	s.cfg = productionExpressionSettings()
	s.features = featuremgmt.WithFeatures(featuremgmt.FlagSqlExpressions)
	return s.TransformData(t.Context(), time.Now(), req)
}

func productionExpressionSettings() *setting.Cfg {
	cfg := setting.NewCfg()
	cfg.ExpressionsEnabled = true
	cfg.SQLExpressionCellLimit = setting.DefaultSQLExpressionCellLimit
	cfg.SQLExpressionOutputCellLimit = setting.DefaultSQLExpressionOutputCellLimit
	cfg.SQLExpressionTimeout = setting.DefaultSQLExpressionTimeout
	cfg.SQLExpressionQueryLengthLimit = setting.DefaultSQLExpressionQueryLengthLimit
	cfg.MathExpressionMemoryLimit = 1 << 30
	return cfg
}

func allocatedDuring(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}
