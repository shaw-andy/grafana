package testdatasource

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"

	"github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource/kinds"
)

// Generated data is built in memory before the response is sent, and every
// query in a request is handled together, so the limits below apply to the
// whole request and not just to each query.
const (
	maxPointsPerSeries  = 10000
	maxCSVWavesPerQuery = 100
	maxSeriesPerRequest = 1000
	maxPointsPerRequest = maxCSVWavesPerQuery * maxPointsPerSeries
)

var (
	errTooManyCSVWaves = fmt.Errorf("predictable CSV wave queries support at most %d waves", maxCSVWavesPerQuery)
	errRequestTooLarge = fmt.Errorf("query exceeds the limit of %d series and %d points per request", maxSeriesPerRequest, maxPointsPerRequest)
)

// RequestBudget tracks how much generated data the queries of one request may
// still allocate.
type RequestBudget struct {
	series int64
	points int64
}

func NewRequestBudget() *RequestBudget {
	return &RequestBudget{series: maxSeriesPerRequest, points: maxPointsPerRequest}
}

// ReserveRandomWalk claims room for the single series RandomWalk builds for query.
func (b *RequestBudget) ReserveRandomWalk(query backend.DataQuery) error {
	return b.reserve(1, seriesPoints(query.TimeRange, query.Interval.Milliseconds()))
}

func (b *RequestBudget) reserve(series, points int64) error {
	if series > b.series || points > b.points {
		return errRequestTooLarge
	}
	b.series -= series
	b.points -= points
	return nil
}

// reserveQuery must resolve the scenario the same way the query mux and
// handleFallbackScenario do, so that the estimate covers the handler that runs.
func (b *RequestBudget) reserveQuery(q backend.DataQuery) error {
	model, err := GetJSONModel(q.JSON)
	if err != nil {
		return err
	}
	scenario := kinds.TestDataQueryType(q.QueryType)
	if scenario == "" {
		scenario = model.ScenarioId
	}

	switch scenario {
	case kinds.TestDataQueryTypePredictableCsvWave:
		if len(model.CsvWave) > maxCSVWavesPerQuery {
			return errTooManyCSVWaves
		}
		var points int64
		for _, wave := range model.CsvWave {
			points += seriesPoints(q.TimeRange, wave.TimeStep*1000)
		}
		return b.reserve(int64(len(model.CsvWave)), points)
	case kinds.TestDataQueryTypeRandomWalk:
		if model.SeriesCount <= 0 {
			return nil
		}
		count := int64(model.SeriesCount)
		if count > b.series {
			return errRequestTooLarge
		}
		return b.reserve(count, count*seriesPoints(q.TimeRange, q.Interval.Milliseconds()))
	default:
		return b.reserve(1, maxPointsPerSeries)
	}
}

// seriesPoints is an upper bound on the points predictableSeries or RandomWalk
// generate for one series stepping stepMs through timeRange.
func seriesPoints(timeRange backend.TimeRange, stepMs int64) int64 {
	if stepMs <= 0 {
		return maxPointsPerSeries
	}
	from := timeRange.From.UnixNano() / int64(time.Millisecond)
	to := timeRange.To.UnixNano() / int64(time.Millisecond)
	span := max(to-from, 0)
	// predictableSeries aligns the first point down to a step boundary, which
	// can add one point before from.
	return min(span/stepMs+2, maxPointsPerSeries)
}

// admitQueries splits queries into those that fit in one request budget and
// error responses for the rest.
func admitQueries(queries []backend.DataQuery) ([]backend.DataQuery, backend.Responses) {
	budget := NewRequestBudget()
	admitted := make([]backend.DataQuery, 0, len(queries))
	var rejected backend.Responses
	for _, q := range queries {
		if err := budget.reserveQuery(q); err != nil {
			if rejected == nil {
				rejected = backend.Responses{}
			}
			rejected[q.RefID] = limitErrorResponse(err)
			continue
		}
		admitted = append(admitted, q)
	}
	return admitted, rejected
}

func limitErrorResponse(err error) backend.DataResponse {
	return backend.ErrDataResponseWithSource(backend.StatusBadRequest, backend.ErrorSourceDownstream, err.Error())
}

func writeRejected(ctx context.Context, w backend.ChunkedDataWriter, rejected backend.Responses) error {
	var errs []error
	for refID, dr := range rejected {
		errs = append(errs, w.WriteError(ctx, refID, dr.Status, dr.Error))
	}
	return errors.Join(errs...)
}
