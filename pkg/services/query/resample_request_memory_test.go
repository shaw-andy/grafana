package query

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/expr"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/datasources"
	fakeDatasources "github.com/grafana/grafana/pkg/services/datasources/fakes"
	"github.com/grafana/grafana/pkg/services/dsquerierclient"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/plugincontext"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tsdb/grafanads"
)

// Resample output length is the query time range divided by the caller-chosen
// window (pkg/expr/mathexp/resample.go), independent of how short the input
// series is. The graph executor keeps every node's result until the request
// finishes. Math expressions already consult setting.Cfg.MathExpressionMemoryLimit
// (default 1 GiB). These tests require that same configured budget to bound the
// resample series retained for one /api/ds/query request.
//
// The budget is the sum, across resample outputs the executor keeps, of
//
//	points * (size of time.Time + size of a *float64)
//
// where points is int(range/window)+1, the length Series.Resample allocates.
// Caller-supplied maxDataPoints, intervalMs, window, and from/to cannot raise
// the budget. A single series whose size is under the budget must still succeed.
// Several series that each fit must be refused when their sum does not.
// The check has to use the time range resample actually samples. QueryDataNew
// lets each query carry its own time range; a check of only the top-level
// from/to, followed by sampling the per-query range, still fails these tests.
// Refusing after the output series has been allocated also fails.

func TestResampleExpressionsStayWithinRequestMemoryBudget(t *testing.T) {
	// Warm the plugin and expression paths so later allocation deltas are the series.
	warmup := newResampleHarness(t, 1<<30, false)
	_, err := warmup.service.QueryData(context.Background(), viewerWithBuiltinQueryGrant(), false, resampleRequest(t, time.Second, "1s", 1, false))
	require.NoError(t, err)

	t.Run("series under the budget succeeds and is longer than the input", func(t *testing.T) {
		const span = 2 * time.Second
		points := resamplePoints(span, time.Millisecond)
		// One series of this length is far under the default 1 GiB budget.
		h := newResampleHarness(t, 1<<30, false)
		resp, err := h.service.QueryData(context.Background(), viewerWithBuiltinQueryGrant(), false, resampleRequest(t, span, "1ms", 1, false))
		require.NoError(t, err)
		require.False(t, requestRefused(nil, resp))
		out := frameLen(t, resp, "R0")
		in := frameLen(t, resp, "A")
		require.Equal(t, points, out)
		require.Less(t, in, out/10, "resample output followed the input length instead of range/window")
	})

	t.Run("one resample larger than the budget is refused before it is allocated", func(t *testing.T) {
		const span = 200 * time.Second
		points := resamplePoints(span, time.Millisecond)
		lower := minSeriesBytes(points)
		require.Greater(t, lower, int64(1<<20))

		small := int64(64 << 10)
		require.Less(t, small, lower/2)

		assertBudget(t, span, "1ms", 1, false, false, small, lower)
	})

	for _, grouped := range []bool{false, true} {
		t.Run(fmt.Sprintf("resamples retained together sseGroupByDatasource=%v", grouped), func(t *testing.T) {
			const (
				span  = 2 * time.Second
				nodes = 8
			)
			points := resamplePoints(span, time.Millisecond)
			lower := minSeriesBytes(points)
			// Half the nodes fit, all of them do not. Each individual series fits.
			budget := lower*int64(nodes)/2 + lower
			require.Greater(t, lower, int64(0))
			require.Less(t, lower, budget)
			require.Greater(t, lower*int64(nodes), budget)

			assertBudget(t, span, "1ms", nodes, false, grouped, budget, lower)
		})
	}

	t.Run("per-query time range is the range that is sampled", func(t *testing.T) {
		const span = 200 * time.Second
		points := resamplePoints(span, time.Millisecond)
		lower := minSeriesBytes(points)
		// Top-level from/to is a zero-length range. The query time range is span.
		// A check that only looks at the top-level range allows the request and
		// then Series.Resample allocates `points`.
		small := int64(64 << 10)
		assertBudget(t, span, "1ms", 1, true, false, small, lower)
	})
}

// assertBudget runs the same request twice. With the default 1 GiB budget the
// resample must succeed and produce resamplePoints(span, window) points, which
// is what the current code allocates. With budget it must refuse, keep retained
// series bytes at or below the budget, and allocate at least half a series less
// than the successful run.
func assertBudget(t *testing.T, span time.Duration, window string, nodes int, perQueryRange, grouped bool, budget, oneSeries int64) {
	t.Helper()
	user := viewerWithBuiltinQueryGrant()
	req := resampleRequest(t, span, window, nodes, perQueryRange)

	high := newResampleHarness(t, 1<<30, grouped)
	query := high.service.QueryData
	if perQueryRange {
		// X-Query-V2. Each query's timeRange is the range resample samples.
		query = high.service.QueryDataNew
	}
	var highResp *backend.QueryDataResponse
	var highErr error
	highAlloc := allocOf(func() {
		highResp, highErr = query(context.Background(), user, false, req)
	})
	require.NoError(t, highErr)
	require.False(t, requestRefused(nil, highResp))
	wantPoints := resamplePoints(span, time.Millisecond)
	for i := 0; i < nodes; i++ {
		require.Equal(t, wantPoints, frameLen(t, highResp, fmt.Sprintf("R%d", i)))
	}
	require.Greater(t, minSeriesBytes(wantPoints*nodes), budget)

	low := newResampleHarness(t, budget, grouped)
	if perQueryRange {
		query = low.service.QueryDataNew
	} else {
		query = low.service.QueryData
	}
	var lowResp *backend.QueryDataResponse
	var lowErr error
	lowAlloc := allocOf(func() {
		lowResp, lowErr = query(context.Background(), user, false, req)
	})
	retained := retainedSeriesBytes(lowResp)
	require.LessOrEqualf(t, retained, budget, "retained %d bytes of resample series, budget %d, lowAlloc %d, highAlloc %d", retained, budget, lowAlloc, highAlloc)
	require.Truef(t, requestRefused(lowErr, lowResp), "over-budget resample request succeeded (retained %d, lowAlloc %d, highAlloc %d)", retained, lowAlloc, highAlloc)
	// Bytes the successful run allocates beyond the budget. A refusal that still
	// allocates the over-budget series stays within half of that excess of the
	// successful run.
	full := uint64(oneSeries) * uint64(nodes)
	over := full - uint64(budget)
	require.Greaterf(t, highAlloc, lowAlloc+over/2, "refused only after allocating the series (low %d, high %d, over budget %d)", lowAlloc, highAlloc, over)
}

func TestDSQueryRouteAllowsViewerBuiltinDatasourceQuery(t *testing.T) {
	// /api/ds/query authorizes EvalPermission(datasources:query) with no scope.
	// A Viewer whose only query grant is the built-in Grafana datasource scope
	// satisfies that check. A principal with no datasources:query grant does not.
	viewer := map[string][]string{
		datasources.ActionQuery: {datasources.ScopePrefix + grafanads.DatasourceUID},
	}
	require.True(t, accesscontrol.EvalPermission(datasources.ActionQuery).Evaluate(viewer))
	require.False(t, accesscontrol.EvalPermission(datasources.ActionQuery).Evaluate(map[string][]string{}))
	require.False(t, accesscontrol.EvalPermission(datasources.ActionQuery).Evaluate(map[string][]string{
		datasources.ActionRead: {datasources.ScopePrefix + grafanads.DatasourceUID},
	}))
	require.Equal(t, org.RoleViewer, org.RoleType(identity.RoleViewer))
}

type resampleHarness struct {
	service *ServiceImpl
}

func newResampleHarness(t *testing.T, memoryLimit int64, groupByDatasource bool) *resampleHarness {
	t.Helper()
	cfg := setting.NewCfg()
	cfg.ExpressionsEnabled = true
	cfg.MathExpressionMemoryLimit = memoryLimit

	var toggles []any
	if groupByDatasource {
		toggles = append(toggles, featuremgmt.FlagSseGroupByDatasource)
	}
	features := featuremgmt.WithFeatures(toggles...)

	graf := grafanads.ProvideService(nil, features)
	client := &grafanaQueryClient{svc: graf}
	pCtx := plugincontext.ProvideService(
		cfg,
		nil,
		&pluginstore.FakePluginStore{
			PluginList: []pluginstore.Plugin{{JSONData: plugins.JSONData{ID: "grafana"}}},
		},
		&fakeDatasources.FakeCacheService{},
		&fakeDatasources.FakeDataSourceService{},
		nil,
		pluginconfig.NewFakePluginRequestConfigProvider(),
	)
	exprSvc := expr.ProvideService(
		cfg,
		client,
		pCtx,
		features,
		nil,
		tracing.NewNoopTracerService(),
		dsquerierclient.NewNullQSDatasourceClientBuilder(),
	)
	svc := ProvideService(
		cfg,
		&fakeDataSourceCache{},
		exprSvc,
		&validations.OSSDataSourceRequestValidator{},
		client,
		pCtx,
		dsquerierclient.NewNullQSDatasourceClientBuilder(),
	)
	return &resampleHarness{service: svc}
}

// grafanaQueryClient is the in-process grafana datasource. QueryData is
// grafanads.Service.QueryData, which runs the random-walk scenario.
type grafanaQueryClient struct {
	plugins.Client
	svc *grafanads.Service
}

func (c *grafanaQueryClient) QueryData(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	if req.PluginContext.PluginID != "" && req.PluginContext.PluginID != "grafana" {
		return nil, fmt.Errorf("unexpected plugin %q", req.PluginContext.PluginID)
	}
	return c.svc.QueryData(ctx, req)
}

func viewerWithBuiltinQueryGrant() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  2,
		OrgID:   1,
		OrgRole: identity.RoleViewer,
		Login:   "viewer",
		Permissions: map[int64]map[string][]string{
			1: {
				datasources.ActionQuery: {datasources.ScopePrefix + grafanads.DatasourceUID},
			},
		},
	}
}

// resampleRequest is the /api/ds/query body from the finding: one built-in
// grafana randomWalk plus resample expressions over it. When perQueryRange is
// set, the top-level from/to span is zero and each query carries span itself.
// That is the body QueryDataNew parses when X-Query-V2 is sent.
func resampleRequest(t *testing.T, span time.Duration, window string, nodes int, perQueryRange bool) dtos.MetricRequest {
	t.Helper()
	from := time.UnixMilli(1_700_000_000_000).UTC()
	to := from.Add(span)
	fromMS := strconv.FormatInt(from.UnixMilli(), 10)
	toMS := strconv.FormatInt(to.UnixMilli(), 10)

	topFrom, topTo := fromMS, toMS
	perQuery := ""
	if perQueryRange {
		topFrom = fromMS
		topTo = fromMS
		perQuery = fmt.Sprintf(`,"timeRange":{"from":%q,"to":%q}`, fromMS, toMS)
	}

	raw := make([]string, 0, nodes+1)
	raw = append(raw, fmt.Sprintf(
		`{"refId":"A","datasource":{"type":"grafana","uid":"grafana"},"queryType":"randomWalk","intervalMs":1000,"maxDataPoints":1000000%s}`,
		perQuery,
	))
	for i := 0; i < nodes; i++ {
		raw = append(raw, fmt.Sprintf(
			`{"refId":"R%d","datasource":{"type":"__expr__","uid":"__expr__"},"type":"resample","expression":"$A","window":%q,"downsampler":"mean","upsampler":"pad","maxDataPoints":1000000%s}`,
			i, window, perQuery,
		))
	}
	req := metricRequestWithQueries(t, raw...)
	req.From = topFrom
	req.To = topTo
	return req
}

func resamplePoints(span, window time.Duration) int {
	n := int(float64(span.Nanoseconds()) / float64(window.Nanoseconds()))
	return n + 1
}

func minSeriesBytes(points int) int64 {
	point := int64(unsafe.Sizeof(time.Time{}) + unsafe.Sizeof((*float64)(nil)))
	return int64(points) * point
}

func retainedSeriesBytes(resp *backend.QueryDataResponse) int64 {
	if resp == nil {
		return 0
	}
	points := 0
	for _, r := range resp.Responses {
		for _, frame := range r.Frames {
			if frame == nil || len(frame.Fields) == 0 {
				continue
			}
			points += frame.Fields[0].Len()
		}
	}
	return minSeriesBytes(points)
}

func frameLen(t *testing.T, resp *backend.QueryDataResponse, refID string) int {
	t.Helper()
	require.NotNil(t, resp)
	r, ok := resp.Responses[refID]
	require.Truef(t, ok, "missing ref %s", refID)
	require.NoError(t, r.Error)
	require.NotEmpty(t, r.Frames)
	require.NotEmpty(t, r.Frames[0].Fields)
	return r.Frames[0].Fields[0].Len()
}

func requestRefused(err error, resp *backend.QueryDataResponse) bool {
	if err != nil || resp == nil {
		return true
	}
	for _, r := range resp.Responses {
		if r.Error != nil {
			return true
		}
	}
	return false
}

func allocOf(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}
