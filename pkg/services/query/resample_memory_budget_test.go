package query

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/expr"
	"github.com/grafana/grafana/pkg/infra/log"
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
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tsdb/grafanads"
)

// bytesPerResamplePoint matches the math-expression estimate: time.Time is
// 24 bytes and a nullable float is a pointer plus a float64 (16 bytes).
const bytesPerResamplePoint int64 = 40

const resampleBudgetAllocSlack int64 = 2 << 20

func TestQueryDataResampleWithinBudgetStillRunsForViewer(t *testing.T) {
	limit := int64(8 << 20)
	svc := newResampleQueryService(t, limit)
	viewer := viewerWithBuiltinQuery()
	req := resampleMetricRequest(t, 10*time.Second, []resampleSpec{{refID: "B", input: "A", downsampler: "mean", upsampler: "pad"}})

	resp, err, _ := measureQueryData(svc, viewer, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotErrorIs(t, resp.Responses["A"].Error, datasources.ErrDataSourceAccessDenied)
	require.NoError(t, resp.Responses["A"].Error)
	require.NotEmpty(t, resp.Responses["A"].Frames)
	require.NoError(t, resp.Responses["B"].Error)
	require.NotEmpty(t, resp.Responses["B"].Frames)
	require.LessOrEqual(t, keptResampleBytes(resp), limit)

	// QueryMetricsV2 uses QueryDataNew when X-Query-V2 is set. Same parser,
	// with per-query time ranges falling back to the request range.
	respNew, err := svc.QueryDataNew(context.Background(), viewer, true, req)
	require.NoError(t, err)
	require.NoError(t, respNew.Responses["B"].Error)
	require.NotEmpty(t, respNew.Responses["B"].Frames)
}

func TestQueryDataRejectsResampleFanoutBeforeAllocation(t *testing.T) {
	// Four resample nodes of 100_000 one-second slots. Each estimated output
	// is under an 8 MiB budget; together they are not. parseMetricRequest
	// accepts every query, and the expression pipeline keeps each result.
	limit := int64(8 << 20)
	nodes := make([]resampleSpec, 4)
	for i := range nodes {
		nodes[i] = resampleSpec{refID: fmt.Sprintf("B%d", i+1), input: "A", downsampler: "mean", upsampler: "pad"}
	}

	svc := newResampleQueryService(t, limit)
	viewer := viewerWithBuiltinQuery()
	base := resampleMetricRequest(t, 10*time.Second, nodes[:1])
	over := resampleMetricRequest(t, 100_000*time.Second, nodes)

	_, _, baseAlloc := measureQueryData(svc, viewer, base)
	resp, err, alloc := measureQueryData(svc, viewer, over)
	require.NotErrorIs(t, err, datasources.ErrDataSourceAccessDenied)
	assertQueryResampleWithinBudget(t, limit, baseAlloc, resp, err, alloc)
}

func TestQueryDataRejectsChainedResampleBeforeAllocation(t *testing.T) {
	limit := int64(6 << 20)
	nodes := []resampleSpec{
		{refID: "B", input: "A", downsampler: "mean", upsampler: "pad"},
		{refID: "C", input: "B", downsampler: "mean", upsampler: "pad"},
		{refID: "D", input: "C", downsampler: "mean", upsampler: "pad"},
	}
	svc := newResampleQueryService(t, limit)
	viewer := viewerWithBuiltinQuery()
	base := resampleMetricRequest(t, 10*time.Second, nodes[:1])
	over := resampleMetricRequest(t, 100_000*time.Second, nodes)

	_, _, baseAlloc := measureQueryData(svc, viewer, base)
	resp, err, alloc := measureQueryData(svc, viewer, over)
	assertQueryResampleWithinBudget(t, limit, baseAlloc, resp, err, alloc)
}

type resampleSpec struct {
	refID       string
	input       string
	downsampler string
	upsampler   string
}

func resampleMetricRequest(t *testing.T, span time.Duration, nodes []resampleSpec) dtos.MetricRequest {
	t.Helper()
	from := time.Unix(1_700_000_000, 0).UTC()
	to := from.Add(span)
	queries := make([]*simplejson.Json, 0, 1+len(nodes))
	walk, err := simplejson.NewJson([]byte(`{"refId":"A","datasource":{"type":"grafana","uid":"grafana"},"queryType":"randomWalk"}`))
	require.NoError(t, err)
	queries = append(queries, walk)
	for _, n := range nodes {
		raw := fmt.Sprintf(
			`{"refId":%q,"datasource":{"type":"__expr__","uid":"__expr__"},"type":"resample","expression":"$%s","window":"1s","downsampler":%q,"upsampler":%q}`,
			n.refID, n.input, n.downsampler, n.upsampler,
		)
		q, err := simplejson.NewJson([]byte(raw))
		require.NoError(t, err)
		queries = append(queries, q)
	}
	return dtos.MetricRequest{
		From:    strconv.FormatInt(from.UnixMilli(), 10),
		To:      strconv.FormatInt(to.UnixMilli(), 10),
		Queries: queries,
	}
}

func viewerWithBuiltinQuery() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  2,
		OrgID:   1,
		OrgRole: identity.RoleViewer,
		Permissions: map[int64]map[string][]string{
			1: {datasources.ActionQuery: {datasources.ScopePrefix + grafanads.DatasourceUID}},
		},
	}
}

// grafanaCoreClient is the in-process dispatch the plugin client performs for
// the built-in grafana datasource: look the plugin up by id, then call its
// QueryData handler. The handler is grafanads.Service.
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

func newResampleQueryService(t *testing.T, memoryLimit int64) *ServiceImpl {
	t.Helper()
	cfg := setting.NewCfg()
	cfg.ExpressionsEnabled = true
	cfg.MathExpressionMemoryLimit = memoryLimit

	features := featuremgmt.WithFeatures()
	grafanaDS := grafanads.ProvideService(nil, features)
	store := pluginstore.NewFakePluginStore(pluginstore.Plugin{JSONData: plugins.JSONData{ID: "grafana"}})
	pCtxProvider := plugincontext.ProvideService(
		cfg,
		nil,
		store,
		&fakeDatasources.FakeCacheService{},
		&fakeDatasources.FakeDataSourceService{},
		nil,
		pluginconfig.NewFakePluginRequestConfigProvider(),
	)
	exprSvc := expr.ProvideService(
		cfg,
		grafanaCoreClient{FakePluginClient: &pluginfakes.FakePluginClient{}, graf: grafanaDS},
		pCtxProvider,
		features,
		prometheus.NewRegistry(),
		tracing.NewNoopTracerService(),
		dsquerierclient.NewNullQSDatasourceClientBuilder(),
	)
	return &ServiceImpl{
		cfg:                        cfg,
		dataSourceCache:            &fakeDatasources.FakeCacheService{},
		expressionService:          exprSvc,
		dataSourceRequestValidator: validations.ProvideValidator(),
		pluginClient:               grafanaCoreClient{FakePluginClient: &pluginfakes.FakePluginClient{}, graf: grafanaDS},
		pCtxProvider:               pCtxProvider,
		log:                        log.New("query_data"),
		qsDatasourceClientBuilder:  dsquerierclient.NewNullQSDatasourceClientBuilder(),
	}
}

func measureQueryData(svc *ServiceImpl, viewer *user.SignedInUser, req dtos.MetricRequest) (*backend.QueryDataResponse, error, uint64) {
	var resp *backend.QueryDataResponse
	var err error
	alloc := allocatedDuring(func() {
		resp, err = svc.QueryData(context.Background(), viewer, true, req)
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

func assertQueryResampleWithinBudget(t *testing.T, limit int64, baseAlloc uint64, resp *backend.QueryDataResponse, err error, alloc uint64) {
	t.Helper()
	kept := keptResampleBytes(resp)
	extra := int64(alloc) - int64(baseAlloc)
	if extra < 0 {
		extra = 0
	}
	require.LessOrEqualf(t, kept, limit,
		"resample output kept in the response is %d bytes, budget is %d (err=%v)", kept, limit, err)
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
			if f == nil || len(f.Fields) == 0 {
				continue
			}
			points += int64(f.Fields[0].Len())
		}
	}
	return points * bytesPerResamplePoint
}

var _ plugins.Client = grafanaCoreClient{}
