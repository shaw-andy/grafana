package expr_test

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/expr"
	"github.com/grafana/grafana/pkg/expr/mathexp"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/services/datasources"
	fakeDatasources "github.com/grafana/grafana/pkg/services/datasources/fakes"
	"github.com/grafana/grafana/pkg/services/dsquerierclient"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/plugincontext"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tsdb/grafanads"
)

// bytesPerResamplePoint is the heap cost of one resample output slot: a
// time.Time (24 bytes) plus a *float64 pointer and the float it addresses
// (8 + 8). This is the same per-point cost math expressions already estimate
// before they run.
const bytesPerResamplePoint int64 = 40

// resampleBudgetAllocSlack is overhead that is not the resample series itself
// (the built-in random walk input, frames, metrics). A refusal that has
// already allocated the resample series is still a failure.
const resampleBudgetAllocSlack int64 = 2 << 20

func TestResampleWithinExpressionMemoryBudgetStillRuns(t *testing.T) {
	limit := int64(8 << 20)
	svc := newGrafanaResampleService(t, limit)
	tr := absoluteRange(10 * time.Second)
	req := viewerResampleRequest(t, tr, []resampleNode{{refID: "B", input: "A", downsampler: "mean", upsampler: "pad"}})

	resp, err, _ := measureTransform(svc, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Responses["A"].Error)
	require.NotEmpty(t, resp.Responses["A"].Frames)
	require.NoError(t, resp.Responses["B"].Error)
	require.NotEmpty(t, resp.Responses["B"].Frames)
	require.LessOrEqual(t, keptResampleBytes(resp), limit)
}

func TestOneResampleOverBudgetIsRejectedBeforeAllocation(t *testing.T) {
	// 200_000 one-second slots is under the 1_000_000 length cap, and larger
	// than a 1 MiB expression memory budget.
	limit := int64(1 << 20)
	span := 200_000 * time.Second
	svc := newGrafanaResampleService(t, limit)
	base := viewerResampleRequest(t, absoluteRange(10*time.Second), []resampleNode{{refID: "B", input: "A", downsampler: "mean", upsampler: "pad"}})
	over := viewerResampleRequest(t, absoluteRange(span), []resampleNode{{refID: "B", input: "A", downsampler: "mean", upsampler: "pad"}})

	_, _, baseAlloc := measureTransform(svc, base)
	resp, err, alloc := measureTransform(svc, over)
	assertResampleWithinBudget(t, limit, baseAlloc, resp, err, alloc)
}

func TestManyResampleNodesShareOneRequestBudget(t *testing.T) {
	// Each node is about 4 MiB estimated, under the 8 MiB budget. Four nodes
	// in one request are not. This is the Viewer request shape: one built-in
	// random walk, many resample expressions, each window 1s.
	limit := int64(8 << 20)
	span := 100_000 * time.Second
	nodes := make([]resampleNode, 4)
	for i := range nodes {
		nodes[i] = resampleNode{refID: fmt.Sprintf("B%d", i+1), input: "A", downsampler: "mean", upsampler: "pad"}
	}

	svc := newGrafanaResampleService(t, limit)
	base := viewerResampleRequest(t, absoluteRange(10*time.Second), nodes[:1])
	over := viewerResampleRequest(t, absoluteRange(span), nodes)

	_, _, baseAlloc := measureTransform(svc, base)
	resp, err, alloc := measureTransform(svc, over)
	assertResampleWithinBudget(t, limit, baseAlloc, resp, err, alloc)
}

func TestExecutePipelineEnforcesResampleBudget(t *testing.T) {
	// Alert evaluation calls BuildPipeline and ExecutePipeline directly, rather
	// than TransformData. The budget has to hold there too.
	limit := int64(8 << 20)
	span := 100_000 * time.Second
	nodes := make([]resampleNode, 4)
	for i := range nodes {
		nodes[i] = resampleNode{refID: fmt.Sprintf("B%d", i+1), input: "A", downsampler: "mean", upsampler: "pad"}
	}

	svc := newGrafanaResampleService(t, limit)
	baseReq := viewerResampleRequest(t, absoluteRange(10*time.Second), nodes[:1])
	overReq := viewerResampleRequest(t, absoluteRange(span), nodes)
	now := time.Unix(1_700_000_000, 0).UTC()

	_, _, baseAlloc := measurePipeline(t, svc, now, baseReq)
	resp, err, alloc := measurePipeline(t, svc, now, overReq)
	assertResampleWithinBudget(t, limit, baseAlloc, resp, err, alloc)
}

func TestChainedResampleSharesOneRequestBudget(t *testing.T) {
	// Each hop is individually under the budget. The chain keeps every hop.
	limit := int64(6 << 20)
	span := 100_000 * time.Second
	nodes := []resampleNode{
		{refID: "B", input: "A", downsampler: "mean", upsampler: "pad"},
		{refID: "C", input: "B", downsampler: "mean", upsampler: "pad"},
		{refID: "D", input: "C", downsampler: "mean", upsampler: "pad"},
	}

	svc := newGrafanaResampleService(t, limit)
	base := viewerResampleRequest(t, absoluteRange(10*time.Second), nodes[:1])
	over := viewerResampleRequest(t, absoluteRange(span), nodes)

	_, _, baseAlloc := measureTransform(svc, base)
	resp, err, alloc := measureTransform(svc, over)
	assertResampleWithinBudget(t, limit, baseAlloc, resp, err, alloc)
}

func TestEveryResampleSamplerSharesTheMemoryBudget(t *testing.T) {
	downsamplers := []string{"sum", "mean", "min", "max", "last"}
	upsamplers := []string{"pad", "backfilling", "fillna"}
	limit := int64(1 << 20)
	span := 200_000 * time.Second

	for _, down := range downsamplers {
		for _, up := range upsamplers {
			t.Run(down+"/"+up, func(t *testing.T) {
				svc := newGrafanaResampleService(t, limit)
				base := viewerResampleRequest(t, absoluteRange(10*time.Second), []resampleNode{{refID: "B", input: "A", downsampler: down, upsampler: up}})
				over := viewerResampleRequest(t, absoluteRange(span), []resampleNode{{refID: "B", input: "A", downsampler: down, upsampler: up}})
				_, _, baseAlloc := measureTransform(svc, base)
				resp, err, alloc := measureTransform(svc, over)
				assertResampleWithinBudget(t, limit, baseAlloc, resp, err, alloc)
			})
		}
	}
}

type resampleNode struct {
	refID       string
	input       string
	downsampler string
	upsampler   string
}

func viewerResampleRequest(t *testing.T, tr expr.AbsoluteTimeRange, nodes []resampleNode) *expr.Request {
	t.Helper()
	queries := []expr.Query{grafanaRandomWalkQuery(tr)}
	for _, n := range nodes {
		queries = append(queries, resampleExprQuery(t, n, tr))
	}
	return &expr.Request{
		OrgId:   1,
		Headers: map[string]string{},
		User:    viewerIdentity(),
		Queries: queries,
	}
}

func grafanaRandomWalkQuery(tr expr.AbsoluteTimeRange) expr.Query {
	return expr.Query{
		RefID:         "A",
		QueryType:     "randomWalk",
		DataSource:    grafanads.DataSourceModel(1),
		TimeRange:     tr,
		Interval:      64 * time.Millisecond,
		MaxDataPoints: 100,
		JSON:          json.RawMessage(`{"refId":"A","datasource":{"type":"grafana","uid":"grafana"},"queryType":"randomWalk"}`),
	}
}

func resampleExprQuery(t *testing.T, n resampleNode, tr expr.AbsoluteTimeRange) expr.Query {
	t.Helper()
	ds, err := expr.DataSourceModelFromNodeType(expr.TypeCMDNode)
	require.NoError(t, err)
	raw := fmt.Sprintf(
		`{"refId":%q,"datasource":{"type":"__expr__","uid":"__expr__"},"type":"resample","expression":"$%s","window":"1s","downsampler":%q,"upsampler":%q}`,
		n.refID, n.input, n.downsampler, n.upsampler,
	)
	return expr.Query{
		RefID:      n.refID,
		DataSource: ds,
		TimeRange:  tr,
		JSON:       json.RawMessage(raw),
	}
}

func absoluteRange(span time.Duration) expr.AbsoluteTimeRange {
	from := time.Unix(1_700_000_000, 0).UTC()
	return expr.AbsoluteTimeRange{From: from, To: from.Add(span)}
}

func viewerIdentity() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  2,
		OrgID:   1,
		OrgRole: identity.RoleViewer,
		Permissions: map[int64]map[string][]string{
			1: {datasources.ActionQuery: {datasources.ScopePrefix + grafanads.DatasourceUID}},
		},
	}
}

// grafanaCoreClient is the in-process dispatch for the built-in grafana
// datasource: the plugin client looks the plugin up by id and calls its
// QueryData handler, which is grafanads.Service.
type grafanaCoreClient struct {
	*pluginfakes.FakePluginClient
	graf *grafanads.Service
}

func (c grafanaCoreClient) QueryData(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	if req == nil || req.PluginContext.PluginID != "grafana" {
		return nil, plugins.ErrPluginNotRegistered
	}
	return c.graf.QueryData(ctx, req)
}

func newGrafanaResampleService(t *testing.T, memoryLimit int64) *expr.Service {
	t.Helper()
	cfg := setting.NewCfg()
	// NewCfg does not read defaults.ini. Production loads this in
	// readExpressionsSettings: expressions are on, and the math memory limit
	// defaults to 1 GiB. The tests set a smaller positive limit so a failure
	// does not allocate gigabytes; resample has to honor whatever positive
	// limit is configured.
	cfg.ExpressionsEnabled = true
	cfg.MathExpressionMemoryLimit = memoryLimit

	features := featuremgmt.WithFeatures()
	grafanaDS := grafanads.ProvideService(nil, features)
	pCtxProvider := plugincontext.ProvideService(
		cfg,
		nil,
		pluginstore.NewFakePluginStore(pluginstore.Plugin{JSONData: plugins.JSONData{ID: "grafana"}}),
		&fakeDatasources.FakeCacheService{},
		&fakeDatasources.FakeDataSourceService{},
		nil,
		pluginconfig.NewFakePluginRequestConfigProvider(),
	)
	return expr.ProvideService(
		cfg,
		grafanaCoreClient{FakePluginClient: &pluginfakes.FakePluginClient{}, graf: grafanaDS},
		pCtxProvider,
		features,
		prometheus.NewRegistry(),
		tracing.NewNoopTracerService(),
		dsquerierclient.NewNullQSDatasourceClientBuilder(),
	)
}

func measureTransform(svc *expr.Service, req *expr.Request) (*backend.QueryDataResponse, error, uint64) {
	var resp *backend.QueryDataResponse
	var err error
	alloc := allocatedDuring(func() {
		resp, err = svc.TransformData(context.Background(), time.Unix(1_700_000_000, 0).UTC(), req)
	})
	return resp, err, alloc
}

func measurePipeline(t *testing.T, svc *expr.Service, now time.Time, req *expr.Request) (*backend.QueryDataResponse, error, uint64) {
	t.Helper()
	var resp *backend.QueryDataResponse
	var err error
	alloc := allocatedDuring(func() {
		var pipeline expr.DataPipeline
		pipeline, err = svc.BuildPipeline(context.Background(), req)
		if err != nil {
			return
		}
		resp, err = svc.ExecutePipeline(context.Background(), now, pipeline)
	})
	return resp, err, alloc
}

func allocatedDuring(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func assertResampleWithinBudget(t *testing.T, limit int64, baseAlloc uint64, resp *backend.QueryDataResponse, err error, alloc uint64) {
	t.Helper()
	kept := keptResampleBytes(resp)
	extra := int64(alloc) - int64(baseAlloc)
	if extra < 0 {
		extra = 0
	}
	require.LessOrEqualf(t, kept, limit,
		"resample output kept in the response is %d bytes, budget is %d (err=%v, allocated beyond baseline=%d)", kept, limit, err, extra)
	// Heap traffic for a series that is built and copied into the response is
	// higher than the 40-byte estimate. 4x the budget still rejects a request
	// that allocates every over-budget series, and fits a request that stops
	// once the estimate reaches the budget.
	require.LessOrEqualf(t, extra, limit*4+resampleBudgetAllocSlack,
		"resample allocated %d bytes beyond a within-budget request before returning (budget %d, err=%v, kept=%d)",
		extra, limit, err, kept)
}

func keptResampleBytes(resp *backend.QueryDataResponse) int64 {
	if resp == nil {
		return 0
	}
	var points int64
	for ref, r := range resp.Responses {
		if ref == "A" {
			continue
		}
		for _, f := range r.Frames {
			points += int64(frameLen(f))
		}
	}
	return points * bytesPerResamplePoint
}

func frameLen(f *data.Frame) int {
	if f == nil || len(f.Fields) == 0 {
		return 0
	}
	return f.Fields[0].Len()
}

// Keep the reducer identifiers referenced so a rename of the supported
// resample reducers fails this file at compile time.
var _ = []mathexp.ReducerID{mathexp.ReducerSum, mathexp.ReducerMean, mathexp.ReducerMin, mathexp.ReducerMax, mathexp.ReducerLast}

var _ plugins.Client = grafanaCoreClient{}
