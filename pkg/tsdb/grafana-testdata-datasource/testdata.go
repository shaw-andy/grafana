package testdatasource

import (
	"context"
	"fmt"
	"maps"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/datasource"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"github.com/grafana/grafana-plugin-sdk-go/backend/resource/httpadapter"
	"github.com/grafana/grafana-plugin-sdk-go/data"

	"github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource/kinds"
	"github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource/sims"
)

// Each random walk series holds up to 10000 points, so this bounds the memory
// one request can make the random walk scenario allocate.
const maxRandomWalkSeries = 100

// ensures that testdata implements all client functions
// var _ plugins.Client = &Service{}

func ProvideService() *Service {
	s := &Service{
		queryMux:  datasource.NewQueryTypeMux(),
		scenarios: map[kinds.TestDataQueryType]*Scenario{},
		frame: data.NewFrame("testdata",
			data.NewField("Time", nil, make([]time.Time, 1)),
			data.NewField("Value", nil, make([]float64, 1)),
			data.NewField("Min", nil, make([]float64, 1)),
			data.NewField("Max", nil, make([]float64, 1)),
		),
		labelFrame: data.NewFrame("labeled",
			data.NewField("labels", nil, make([]string, 1)),
			data.NewField("Time", nil, make([]time.Time, 1)),
			data.NewField("Value", nil, make([]float64, 1)),
		),
		logger: backend.NewLoggerWith("logger", "tsdb.testdata"),
	}

	var err error
	s.sims, err = sims.NewSimulationEngine()
	if err != nil {
		s.logger.Error("Unable to initialize SimulationEngine", "err", err)
	}

	s.registerScenarios()
	s.resourceHandler = httpadapter.New(s.registerRoutes())

	return s
}

var (
	_ backend.QueryDataHandler        = (*Service)(nil)
	_ backend.QueryChunkedDataHandler = (*Service)(nil)
	_ backend.CallResourceHandler     = (*Service)(nil)
	_ backend.AdmissionHandler        = (*Service)(nil)
	_ backend.CollectMetricsHandler   = (*Service)(nil)
)

type Service struct {
	logger          log.Logger
	scenarios       map[kinds.TestDataQueryType]*Scenario
	frame           *data.Frame
	labelFrame      *data.Frame
	queryMux        *datasource.QueryTypeMux
	resourceHandler backend.CallResourceHandler
	sims            *sims.SimulationEngine
}

func (s *Service) QueryData(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	queries, rejected := s.limitRandomWalkSeries(req.Queries)
	if len(rejected) == 0 {
		return s.queryMux.QueryData(ctx, req)
	}

	allowed := *req
	allowed.Queries = queries
	resp, err := s.queryMux.QueryData(ctx, &allowed)
	if err != nil {
		return nil, err
	}
	maps.Copy(resp.Responses, rejected)
	return resp, nil
}

func (s *Service) QueryChunkedData(ctx context.Context, req *backend.QueryChunkedDataRequest, w backend.ChunkedDataWriter) error {
	queries, rejected := s.limitRandomWalkSeries(req.Queries)
	for refID, dr := range rejected {
		if err := w.WriteError(ctx, refID, dr.Status, dr.Error); err != nil {
			return err
		}
	}

	allowed := *req
	allowed.Queries = queries
	return s.queryMux.QueryChunkedData(ctx, &allowed, w)
}

// limitRandomWalkSeries refuses random walk queries once the series they ask
// for, summed over the whole request, would exceed maxRandomWalkSeries. The
// budget is per request rather than per query because the chunked path runs
// every query through its own handler call.
func (s *Service) limitRandomWalkSeries(queries []backend.DataQuery) ([]backend.DataQuery, backend.Responses) {
	remaining := maxRandomWalkSeries
	allowed := make([]backend.DataQuery, 0, len(queries))
	var rejected backend.Responses
	for _, q := range queries {
		count := s.randomWalkSeriesCount(q)
		if count > remaining {
			if rejected == nil {
				rejected = backend.Responses{}
			}
			rejected[q.RefID] = backend.ErrDataResponseWithSource(backend.StatusBadRequest, backend.ErrorSourceDownstream,
				fmt.Sprintf("random walk queries in one request may return at most %d series in total", maxRandomWalkSeries))
			continue
		}
		remaining -= count
		allowed = append(allowed, q)
	}
	return allowed, rejected
}

// randomWalkSeriesCount mirrors the query type routing in queryMux and
// handleFallbackScenario, returning 0 for queries another scenario handles.
func (s *Service) randomWalkSeriesCount(q backend.DataQuery) int {
	model, err := GetJSONModel(q.JSON)
	if err != nil {
		return 0
	}
	scenarioID := kinds.TestDataQueryType(q.QueryType)
	if _, ok := s.scenarios[scenarioID]; !ok {
		scenarioID = model.ScenarioId
	}
	if scenarioID != kinds.TestDataQueryTypeRandomWalk {
		return 0
	}
	return max(model.SeriesCount, 0)
}

func (s *Service) CallResource(ctx context.Context, req *backend.CallResourceRequest, sender backend.CallResourceResponseSender) error {
	return s.resourceHandler.CallResource(ctx, req, sender)
}

func (s *Service) CheckHealth(_ context.Context, _ *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	return &backend.CheckHealthResult{
		Status:  backend.HealthStatusOk,
		Message: "Data source is working",
	}, nil
}

// CollectMetricsHandler handles metric collection.
func (s *Service) CollectMetrics(ctx context.Context, req *backend.CollectMetricsRequest) (*backend.CollectMetricsResult, error) {
	return nil, nil
}
