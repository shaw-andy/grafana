package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/gtime"
	"github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/licensing/licensingtest"
	publicdashboards "github.com/grafana/grafana/pkg/services/publicdashboards/internal"
	"github.com/grafana/grafana/pkg/services/publicdashboards/internal/models"
	"github.com/grafana/grafana/pkg/services/publicdashboards/internal/service/intervalv2"
	"github.com/grafana/grafana/pkg/services/query"
	"github.com/grafana/grafana/pkg/tsdb/graphite"
)

// publicDashboardSafeResolution is the fixed bound described on
// getSafeIntervalAndMaxDataPoints. Public dashboard queries must not exceed it.
const publicDashboardSafeResolution = int64(11000)

// coarseIntervalMs is coarser than the safe interval of every range used below.
// 7 days is longer than those ranges, and the safe interval is the range divided
// by publicDashboardSafeResolution, so this interval always takes the branch
// that currently returns the caller maxDataPoints unchanged.
const coarseIntervalMs = int64(7 * 24 * 60 * 60 * 1000)

const attackerMaxDataPoints = int64(50_000_000)

const panelRangeFrom = "2022-09-01T00:00:00.000Z"
const panelRangeTo = "2022-09-01T12:00:00.000Z"

func TestBuildMetricRequest_ClampsMaxDataPointsWhenIntervalIsCoarserThanSafe(t *testing.T) {
	pd := &PublicDashboardServiceImpl{intervalCalculator: intervalv2.NewCalculator()}
	req := attackQueryDTO(attackerMaxDataPoints)

	t.Run("v1 panel queries", func(t *testing.T) {
		dash := v1GraphiteDashboard(t)
		pub := &models.PublicDashboard{TimeSelectionEnabled: false}
		requireCallerIntervalCoarserThanSafe(t, pd, dash, pub, 1, req)

		metricReq, err := pd.buildMetricRequest(dash, pub, 1, req)
		require.NoError(t, err)
		requireCappedQueries(t, metricReq, coarseIntervalMs)
		require.Equal(t, "stats.counters.web.hits", metricReq.Queries[0].Get("target").MustString())
		require.Equal(t, "servers.cpu", metricReq.Queries[1].Get("target").MustString())
	})

	t.Run("v1 query nested in a collapsed row", func(t *testing.T) {
		dash := v1CollapsedRowDashboard(t)
		pub := &models.PublicDashboard{TimeSelectionEnabled: false}
		requireCallerIntervalCoarserThanSafe(t, pd, dash, pub, 4, req)

		metricReq, err := pd.buildMetricRequest(dash, pub, 4, req)
		require.NoError(t, err)
		requireCappedQueries(t, metricReq, coarseIntervalMs)
		require.Equal(t, "collapsed.metric", metricReq.Queries[0].Get("target").MustString())
	})

	t.Run("v2 panel queries", func(t *testing.T) {
		dash := v2GraphiteDashboard()
		pub := &models.PublicDashboard{TimeSelectionEnabled: false}
		requireCallerIntervalCoarserThanSafeV2(t, pd, dash, pub, 4, req)

		metricReq, err := pd.buildMetricRequest(dash, pub, 4, req)
		require.NoError(t, err)
		requireCappedQueries(t, metricReq, coarseIntervalMs)
		require.Equal(t, "v2.metric", metricReq.Queries[0].Get("target").MustString())
		require.Equal(t, "v2.other", metricReq.Queries[1].Get("target").MustString())
	})

	t.Run("time selection uses the caller range and still clamps maxDataPoints", func(t *testing.T) {
		dash := v1GraphiteDashboard(t)
		pub := &models.PublicDashboard{TimeSelectionEnabled: true}
		selected := attackQueryDTO(attackerMaxDataPoints)
		selected.TimeRange = models.TimeRangeDTO{
			From: "2022-08-01T00:00:00.000Z",
			To:   "2022-09-01T00:00:00.000Z",
		}
		requireCallerIntervalCoarserThanSafe(t, pd, dash, pub, 1, selected)

		metricReq, err := pd.buildMetricRequest(dash, pub, 1, selected)
		require.NoError(t, err)

		fromMs, convErr := strconv.ParseInt(metricReq.From, 10, 64)
		require.NoError(t, convErr)
		toMs, convErr := strconv.ParseInt(metricReq.To, 10, 64)
		require.NoError(t, convErr)
		require.Equal(t, time.Date(2022, 8, 1, 0, 0, 0, 0, time.UTC).UnixMilli(), fromMs)
		require.Equal(t, time.Date(2022, 9, 1, 0, 0, 0, 0, time.UTC).UnixMilli(), toMs)
		requireCappedQueries(t, metricReq, coarseIntervalMs)
	})

	t.Run("maxDataPoints at the safe resolution is left unchanged", func(t *testing.T) {
		dash := v1GraphiteDashboard(t)
		pub := &models.PublicDashboard{TimeSelectionEnabled: false}
		atCap := attackQueryDTO(publicDashboardSafeResolution)
		requireCallerIntervalCoarserThanSafe(t, pd, dash, pub, 1, atCap)

		metricReq, err := pd.buildMetricRequest(dash, pub, 1, atCap)
		require.NoError(t, err)
		requireCappedQueries(t, metricReq, coarseIntervalMs)
	})
}

func TestGetQueryDataResponse_DoesNotRunQueriesAboveTheSafeResolution(t *testing.T) {
	dash := v1GraphiteDashboard(t)
	pub := enabledPublicDashboard(dash)
	svc, querySvc := publicDashboardWithFakes(t, dash, pub)

	var executed *dtos.MetricRequest
	querySvc.On("QueryData", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			req := args.Get(3).(dtos.MetricRequest)
			executed = &req
		}).
		Return(&backend.QueryDataResponse{}, nil).
		Maybe()

	var body models.PublicDashboardQueryDTO
	require.NoError(t, json.Unmarshal([]byte(`{"intervalMs":604800000,"maxDataPoints":50000000}`), &body))
	require.Equal(t, attackerMaxDataPoints, body.MaxDataPoints)
	require.Equal(t, coarseIntervalMs, body.IntervalMs)

	_, err := svc.GetQueryDataResponse(context.Background(), false, body, 1, pub.AccessToken)
	if err != nil {
		require.Nil(t, executed, "query execution started before the request was refused")
		return
	}
	require.NotNil(t, executed)
	requireCappedQueries(t, *executed, coarseIntervalMs)
}

func TestGetQueryDataResponse_RunsSavedQueriesAtTheSafeResolution(t *testing.T) {
	dash := v1GraphiteDashboard(t)
	pub := enabledPublicDashboard(dash)
	svc, querySvc := publicDashboardWithFakes(t, dash, pub)

	var got dtos.MetricRequest
	var requester identity.Requester
	querySvc.On("QueryData", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			ctx := args.Get(0).(context.Context)
			require.True(t, identity.IsServiceIdentity(ctx))
			requester = args.Get(1).(identity.Requester)
			got = args.Get(3).(dtos.MetricRequest)
		}).
		Return(&backend.QueryDataResponse{}, nil)

	var body models.PublicDashboardQueryDTO
	require.NoError(t, json.Unmarshal([]byte(`{"intervalMs":604800000,"maxDataPoints":11000}`), &body))

	_, err := svc.GetQueryDataResponse(context.Background(), false, body, 1, pub.AccessToken)
	require.NoError(t, err)
	require.Equal(t, dash.OrgID, requester.GetOrgID())
	requireCappedQueries(t, got, coarseIntervalMs)
	require.Equal(t, "stats.counters.web.hits", got.Queries[0].Get("target").MustString())
}

func TestGraphiteRenderRequest_UsesCappedMaxDataPointsFromPublicDashboard(t *testing.T) {
	pd := &PublicDashboardServiceImpl{intervalCalculator: intervalv2.NewCalculator()}
	dash := v1GraphiteDashboard(t)
	pub := &models.PublicDashboard{TimeSelectionEnabled: false}
	req := attackQueryDTO(attackerMaxDataPoints)
	requireCallerIntervalCoarserThanSafe(t, pd, dash, pub, 1, req)

	metricReq, err := pd.buildMetricRequest(dash, pub, 1, req)
	require.NoError(t, err)

	// Same field copy parseMetricRequest performs before a datasource runs.
	// QueryData (supportLocalTimeRange false) stores maxDataPoints from the
	// query JSON and does not read intervalMs into the Graphite form.
	dataQueries := dataQueriesFromMetricRequest(t, metricReq)
	require.Len(t, dataQueries, 2)
	for _, q := range dataQueries {
		require.Equal(t, time.Duration(coarseIntervalMs)*time.Millisecond, q.Interval)
	}

	type captured struct {
		maxDataPoints string
		path          string
		form          map[string][]string
	}
	seen := make(chan captured, len(dataQueries))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form := map[string][]string{}
		for k, v := range r.Form {
			form[k] = append([]string(nil), v...)
		}
		seen <- captured{maxDataPoints: r.FormValue("maxDataPoints"), path: r.URL.Path, form: form}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"target":"stats.counters.web.hits","datapoints":[[1,1661990400]]}]`))
	}))
	t.Cleanup(server.Close)

	gs := graphite.ProvideService(httpclient.NewProvider(), noop.NewTracerProvider().Tracer("public-dashboard-cap"))
	rsp, err := gs.QueryData(context.Background(), &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{
			DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{URL: server.URL},
			OrgID:                      dash.OrgID,
		},
		Queries: dataQueries,
	})
	require.NoError(t, err)
	require.NotNil(t, rsp)

	for range dataQueries {
		select {
		case got := <-seen:
			require.Contains(t, got.path, "render")
			parsed, convErr := strconv.ParseInt(got.maxDataPoints, 10, 64)
			require.NoError(t, convErr)
			require.Equal(t, publicDashboardSafeResolution, parsed)
			require.NotContains(t, got.form, "interval")
			require.NotContains(t, got.form, "intervalMs")
		default:
			t.Fatal("graphite render request was not sent")
		}
	}
}

func attackQueryDTO(maxDataPoints int64) models.PublicDashboardQueryDTO {
	return models.PublicDashboardQueryDTO{
		IntervalMs:    coarseIntervalMs,
		MaxDataPoints: maxDataPoints,
	}
}

func requireCallerIntervalCoarserThanSafe(t *testing.T, pd *PublicDashboardServiceImpl, dash *dashboards.Dashboard, pub *models.PublicDashboard, panelID int64, req models.PublicDashboardQueryDTO) {
	t.Helper()
	ts := buildTimeSettings(dash, req, pub, panelID)
	requireIntervalCoarserThanSafe(t, pd, ts, req.IntervalMs)
}

func requireCallerIntervalCoarserThanSafeV2(t *testing.T, pd *PublicDashboardServiceImpl, dash *dashboards.Dashboard, pub *models.PublicDashboard, panelID int64, req models.PublicDashboardQueryDTO) {
	t.Helper()
	ts := buildTimeSettingsV2(dash, req, pub, panelID)
	requireIntervalCoarserThanSafe(t, pd, ts, req.IntervalMs)
}

func requireIntervalCoarserThanSafe(t *testing.T, pd *PublicDashboardServiceImpl, ts models.TimeSettings, intervalMs int64) {
	t.Helper()
	dataTimeRange := gtime.NewTimeRange(ts.From, ts.To)
	tr := backend.TimeRange{From: dataTimeRange.GetFromAsTimeUTC(), To: dataTimeRange.GetToAsTimeUTC()}
	safe := pd.intervalCalculator.CalculateSafeInterval(tr, publicDashboardSafeResolution)
	require.Greater(t, intervalMs, safe.Value.Milliseconds(), "caller interval must take the coarse-interval branch")
}

func requireCappedQueries(t *testing.T, metricReq dtos.MetricRequest, intervalMs int64) {
	t.Helper()
	require.NotEmpty(t, metricReq.Queries)
	for _, q := range metricReq.Queries {
		require.Equal(t, publicDashboardSafeResolution, q.Get("maxDataPoints").MustInt64())
		require.Equal(t, intervalMs, q.Get("intervalMs").MustInt64())
	}
}

func dataQueriesFromMetricRequest(t *testing.T, metricReq dtos.MetricRequest) []backend.DataQuery {
	t.Helper()
	timeRange := gtime.NewTimeRange(metricReq.From, metricReq.To)
	out := make([]backend.DataQuery, 0, len(metricReq.Queries))
	for _, query := range metricReq.Queries {
		modelJSON, err := query.MarshalJSON()
		require.NoError(t, err)
		out = append(out, backend.DataQuery{
			TimeRange: backend.TimeRange{
				From: timeRange.GetFromAsTimeUTC(),
				To:   timeRange.GetToAsTimeUTC(),
			},
			RefID:         query.Get("refId").MustString("A"),
			MaxDataPoints: query.Get("maxDataPoints").MustInt64(100),
			Interval:      time.Duration(query.Get("intervalMs").MustInt64(1000)) * time.Millisecond,
			QueryType:     query.Get("queryType").MustString(""),
			JSON:          modelJSON,
		})
	}
	return out
}

func publicDashboardWithFakes(t *testing.T, dash *dashboards.Dashboard, pub *models.PublicDashboard) (*PublicDashboardServiceImpl, *query.FakeQueryService) {
	t.Helper()
	store := publicdashboards.NewFakePublicDashboardStore(t)
	store.On("FindByAccessToken", mock.Anything, pub.AccessToken).Return(pub, nil)

	dashSvc := dashboards.NewFakeDashboardService(t)
	dashSvc.On("GetDashboard", mock.Anything, mock.MatchedBy(func(q *dashboards.GetDashboardQuery) bool {
		return q != nil && q.UID == pub.DashboardUid && q.OrgID == pub.OrgId
	})).Return(dash, nil)

	querySvc := query.NewFakeQueryService(t)
	license := licensingtest.NewFakeLicensing()
	license.On("FeatureEnabled", models.FeaturePublicDashboardsEmailSharing).Return(false)
	svc := &PublicDashboardServiceImpl{
		log:                log.New("publicdashboards.test"),
		intervalCalculator: intervalv2.NewCalculator(),
		store:              store,
		dashboardService:   dashSvc,
		QueryDataService:   querySvc,
		license:            license,
	}
	return svc, querySvc
}

func enabledPublicDashboard(dash *dashboards.Dashboard) *models.PublicDashboard {
	return &models.PublicDashboard{
		Uid:          "pubdash-uid",
		DashboardUid: dash.UID,
		OrgId:        dash.OrgID,
		IsEnabled:    true,
		Share:        models.PublicShareType,
		AccessToken:  "pubdash-test-token",
	}
}

func v1GraphiteDashboard(t *testing.T) *dashboards.Dashboard {
	t.Helper()
	return createTestDashboard(t, "public-graphite", 1, "", false, nil, []any{
		map[string]any{
			"id": 1,
			"targets": []any{
				map[string]any{
					"datasource": map[string]any{"type": "graphite", "uid": "graphite-uid"},
					"refId":      "A",
					"target":     "stats.counters.web.hits",
				},
				map[string]any{
					"datasource": map[string]any{"type": "graphite", "uid": "graphite-uid"},
					"refId":      "B",
					"target":     "servers.cpu",
				},
			},
		},
	})
}

func v1CollapsedRowDashboard(t *testing.T) *dashboards.Dashboard {
	t.Helper()
	return createTestDashboard(t, "public-graphite-row", 1, "", false, nil, []any{
		map[string]any{
			"id":        1,
			"type":      "row",
			"collapsed": true,
			"panels": []any{
				map[string]any{
					"id": 4,
					"targets": []any{
						map[string]any{
							"datasource": map[string]any{"type": "graphite", "uid": "graphite-uid"},
							"refId":      "A",
							"target":     "collapsed.metric",
						},
					},
				},
			},
		},
	})
}

func v2GraphiteDashboard() *dashboards.Dashboard {
	return &dashboards.Dashboard{
		UID:   "v2-graphite",
		OrgID: 1,
		Data: simplejson.NewFromAny(map[string]any{
			"elements": map[string]any{
				"panel-1": map[string]any{
					"spec": map[string]any{
						"id": int64(4),
						"data": map[string]any{
							"spec": map[string]any{
								"queries": []any{
									v2Query("A", "v2.metric"),
									v2Query("B", "v2.other"),
								},
							},
						},
					},
				},
			},
			"timeSettings": map[string]any{
				"from":     panelRangeFrom,
				"to":       panelRangeTo,
				"timezone": "UTC",
			},
		}),
	}
}

func v2Query(refID, target string) map[string]any {
	return map[string]any{
		"spec": map[string]any{
			"query": map[string]any{
				"group": "graphite",
				"spec": map[string]any{
					"refId":  refID,
					"target": target,
					"datasource": map[string]any{
						"type": "graphite",
						"uid":  "graphite-uid",
					},
				},
			},
		},
	}
}
