package expr

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/expr/mathexp"
	"github.com/grafana/grafana/pkg/expr/metrics"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/dsquerierclient"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	testdatasource "github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource"
)

func newTestDataExpressionService(t *testing.T, cfg *setting.Cfg) *Service {
	t.Helper()
	features := featuremgmt.WithFeatures()
	tracer := tracing.InitializeTracerForTest()
	return &Service{
		cfg:          cfg,
		dataService:  testdatasource.ProvideService(),
		pCtxProvider: &fakePluginContextProvider{},
		features:     features,
		tracer:       tracer,
		metrics:      metrics.NewSSEMetrics(nil),
		converter: &ResultConverter{
			Features: features,
			Tracer:   tracer,
		},
		qsDatasourceClientBuilder: dsquerierclient.NewNullQSDatasourceClientBuilder(),
	}
}

func testDataSource() *datasources.DataSource {
	return &datasources.DataSource{
		ID:   1,
		UID:  "testdata",
		Name: "TestData",
		Type: datasources.DS_TESTDATA,
	}
}

func viewer() *user.SignedInUser {
	return &user.SignedInUser{UserID: 1, OrgID: 1, OrgRole: org.RoleViewer}
}

func randomWalkQuery(refID string, seriesCount int, labels string) Query {
	body := map[string]any{
		"refId":       refID,
		"scenarioId":  "random_walk",
		"seriesCount": seriesCount,
		// Wider than the one-second time range, so each series has one point.
		"intervalMs": int64(time.Hour / time.Millisecond),
	}
	if labels != "" {
		body["labels"] = labels
	}
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return Query{
		RefID:         refID,
		TimeRange:     AbsoluteTimeRange{From: time.Unix(0, 0), To: time.Unix(1, 0)},
		DataSource:    testDataSource(),
		JSON:          raw,
		Interval:      time.Hour,
		QueryType:     "random_walk",
		MaxDataPoints: 1,
	}
}

func mathQuery(expression string) Query {
	raw, err := json.Marshal(map[string]any{
		"type":       "math",
		"expression": expression,
	})
	if err != nil {
		panic(err)
	}
	return Query{
		RefID:      "C",
		DataSource: DataSourceModel(),
		JSON:       raw,
		TimeRange:  AbsoluteTimeRange{From: time.Unix(0, 0), To: time.Unix(1, 0)},
	}
}

func TestMathExpressionFromTestData_pairWalkIsBounded(t *testing.T) {
	cfg, err := setting.NewCfgFromBytes(nil)
	require.NoError(t, err)
	require.True(t, cfg.ExpressionsEnabled)
	require.Equal(t, int64(1<<30), cfg.MathExpressionMemoryLimit)

	svc := newTestDataExpressionService(t, cfg)
	ctx := context.Background()

	t.Run("omitted labels are rewritten to equal-length names", func(t *testing.T) {
		frames := queryTestDataFrames(t, randomWalkQuery("A", 3, ""))
		require.Len(t, frames, 3)
		for _, frame := range frames {
			require.Equal(t, 1, frame.Rows(), "interval wider than the time range yields one point")
		}
		_, results, err := svc.converter.Convert(ctx, datasources.DS_TESTDATA, frames)
		require.NoError(t, err)
		require.Len(t, results.Values, 3)
		names := map[string]struct{}{}
		for _, value := range results.Values {
			labels := value.GetLabels()
			require.Len(t, labels, 1)
			name := labels["__name__"]
			require.NotEmpty(t, name)
			names[name] = struct{}{}
		}
		require.Len(t, names, 3)
	})

	t.Run("explicit labels of equal length are preserved", func(t *testing.T) {
		frames := queryTestDataFrames(t, randomWalkQuery("A", 2, `{a="$seriesIndex"}`))
		_, results, err := svc.converter.Convert(ctx, datasources.DS_TESTDATA, frames)
		require.NoError(t, err)
		require.Len(t, results.Values, 2)
		require.Equal(t, data.Labels{"a": "0"}, results.Values[0].GetLabels())
		require.Equal(t, data.Labels{"a": "1"}, results.Values[1].GetLabels())
	})

	for _, tc := range []struct {
		name   string
		labels [2]string
	}{
		{name: "omitted labels", labels: [2]string{"", ""}},
		{name: "distinct label keys", labels: [2]string{`{a="$seriesIndex"}`, `{b="$seriesIndex"}`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const seriesCount = 6000
			queries := []Query{
				randomWalkQuery("A", seriesCount, tc.labels[0]),
				randomWalkQuery("B", seriesCount, tc.labels[1]),
			}
			// Baseline is the same two datasource queries, including frame
			// conversion, with no math node. The added expression must not
			// then spend time proportional to the product of the series counts.
			baseStart := time.Now()
			baseResp, err := svc.TransformData(ctx, time.Unix(2, 0), &Request{User: viewer(), Queries: queries})
			require.NoError(t, err)
			baseline := time.Since(baseStart)
			require.Len(t, baseResp.Responses["A"].Frames, seriesCount)
			require.Len(t, baseResp.Responses["B"].Frames, seriesCount)

			start := time.Now()
			resp, err := svc.TransformData(ctx, time.Unix(2, 0), &Request{
				User:    viewer(),
				Queries: append(append([]Query{}, queries...), mathQuery("$A + $B")),
			})
			elapsed := time.Since(start)
			require.NoError(t, err)
			require.NotNil(t, resp)

			ceiling := baseline + 250*time.Millisecond
			var mathErr error
			if got, ok := resp.Responses["C"]; ok {
				mathErr = got.Error
			}
			if elapsed > ceiling {
				t.Fatalf("TestData %s plus $A + $B took %s (queries alone %s, ceiling %s, math err=%v); the binary node visited every series pair", tc.name, elapsed, baseline, ceiling, mathErr)
			}
		})
	}
}

func TestMathExpression_canceledContextStopsBinaryEvaluation(t *testing.T) {
	// A handful of matching series is under any input cap that still permits
	// ordinary expressions, and it is under the default memory limit. The
	// context is already canceled, so evaluation has to stop before the pair
	// walk instead of returning the sum.
	labels := func(i int) data.Labels { return data.Labels{"id": string(rune('a' + i))} }
	values := make(mathexp.Values, 4)
	for i := range values {
		values[i] = mathexp.NewSeries("s", labels(i), 1)
		value := float64(i + 1)
		values[i].(mathexp.Series).SetPoint(0, time.Unix(1, 0), &value)
	}
	cmd, err := NewMathCommand("C", "$A + $B", 1<<30)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = cmd.Execute(ctx, time.Unix(1, 0), mathexp.Vars{
		"A": mathexp.Results{Values: values},
		"B": mathexp.Results{Values: values},
	}, tracing.InitializeTracerForTest(), nil)
	require.ErrorIs(t, err, context.Canceled)
}

func TestConverter_unlabeledPrometheusFramesReachBinaryMath(t *testing.T) {
	// Datasource types outside the name-fixing list keep empty labels, and
	// empty labels match every series on the other side. The default limit
	// has to reject that product before every pair is visited.
	const n = 16000
	frames := make(data.Frames, n)
	for i := range frames {
		frames[i] = data.NewFrame("",
			data.NewField("time", nil, []time.Time{time.Unix(1, 0)}),
			data.NewField("value", nil, []*float64{new(1.0)}),
		)
	}
	features := featuremgmt.WithFeatures()
	converter := &ResultConverter{Features: features, Tracer: tracing.InitializeTracerForTest()}
	_, left, err := converter.Convert(context.Background(), datasources.DS_PROMETHEUS, frames)
	require.NoError(t, err)
	require.Len(t, left.Values, n)
	require.Empty(t, left.Values[0].GetLabels())

	cfg, err := setting.NewCfgFromBytes(nil)
	require.NoError(t, err)
	cmd, err := NewMathCommand("C", "$A + $B", cfg.MathExpressionMemoryLimit)
	require.NoError(t, err)
	require.Equal(t, int64(1<<30), cmd.memoryLimit)

	start := time.Now()
	_, err = cmd.Execute(context.Background(), time.Unix(1, 0), mathexp.Vars{
		"A": left,
		"B": left,
	}, tracing.InitializeTracerForTest(), nil)
	elapsed := time.Since(start)
	if elapsed > time.Second || err == nil {
		t.Fatalf("unlabeled prometheus series addition took %s (err=%v); the default memory limit was applied only after every pair was visited", elapsed, err)
	}
}

func queryTestDataFrames(t *testing.T, query Query) data.Frames {
	t.Helper()
	resp, err := testdatasource.ProvideService().QueryData(context.Background(), &backend.QueryDataRequest{
		Queries: []backend.DataQuery{{
			RefID: query.RefID,
			TimeRange: backend.TimeRange{
				From: time.Unix(0, 0),
				To:   time.Unix(1, 0),
			},
			Interval:      time.Hour,
			MaxDataPoints: 1,
			QueryType:     query.QueryType,
			JSON:          query.JSON,
		}},
	})
	require.NoError(t, err)
	got := resp.Responses[query.RefID]
	require.NoError(t, got.Error)
	return got.Frames
}

// Ensure the test datasource handler satisfies the expression data service.
var _ backend.QueryDataHandler = (*testdatasource.Service)(nil)
