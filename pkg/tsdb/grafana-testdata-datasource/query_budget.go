package testdatasource

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource/kinds"
)

// maxSeriesPoints is the point ceiling for a single generated series.
const maxSeriesPoints = 10_000

// maxRequestSeriesPoints caps the points generated across every random walk
// series and CSV wave entry in one request.
const maxRequestSeriesPoints = int64(1_000_000)

type queryBudgetKey struct{}

// queryBudget is shared by every scenario handler call made for one request.
// Queries are split across handler calls by query type, by scenario and, on
// the chunked path, one query per concurrent call, so a per-call limit could
// be bypassed by spreading the same work over many queries.
type queryBudget struct {
	usaCells     atomic.Int64
	seriesPoints atomic.Int64
}

func newQueryBudget() *queryBudget {
	b := &queryBudget{}
	b.usaCells.Store(maxUSAResults)
	b.seriesPoints.Store(maxRequestSeriesPoints)
	return b
}

func withQueryBudget(ctx context.Context) context.Context {
	if _, ok := ctx.Value(queryBudgetKey{}).(*queryBudget); ok {
		return ctx
	}
	return context.WithValue(ctx, queryBudgetKey{}, newQueryBudget())
}

// queryBudgetFrom returns the request budget, or a fresh one when a handler is
// called directly without going through Service.
func queryBudgetFrom(ctx context.Context) *queryBudget {
	if b, ok := ctx.Value(queryBudgetKey{}).(*queryBudget); ok {
		return b
	}
	return newQueryBudget()
}

func (b *queryBudget) takeUSACells(n int64) bool {
	return take(&b.usaCells, n)
}

// takeSeries reserves count series of up to pointsPerSeries points each.
func (b *queryBudget) takeSeries(count int64, pointsPerSeries int64) bool {
	if count <= 0 {
		return true
	}
	if count > maxRequestSeriesPoints {
		return false
	}
	return take(&b.seriesPoints, count*pointsPerSeries)
}

func (b *queryBudget) takeCSVWaves(timeRange backend.TimeRange, waves []kinds.CSVWave) bool {
	if int64(len(waves)) > maxRequestSeriesPoints {
		return false
	}
	var points int64
	for _, wave := range waves {
		points += seriesPointCount(timeRange, wave.TimeStep*1000)
	}
	return take(&b.seriesPoints, points)
}

func take(remaining *atomic.Int64, n int64) bool {
	if n < 0 {
		return false
	}
	for {
		cur := remaining.Load()
		if n > cur {
			return false
		}
		if remaining.CompareAndSwap(cur, cur-n) {
			return true
		}
	}
}

// seriesPointCount is an upper bound on the points a generator stepping
// through timeRange by stepMs produces. It is at least one, since an empty
// series is still a frame.
func seriesPointCount(timeRange backend.TimeRange, stepMs int64) int64 {
	if stepMs <= 0 {
		return maxSeriesPoints
	}
	spanMs := timeRange.To.UnixMilli() - timeRange.From.UnixMilli()
	return min(max(spanMs/stepMs+2, 1), maxSeriesPoints)
}

func seriesLimitResponse(series int) backend.DataResponse {
	return backend.ErrDataResponseWithSource(backend.StatusBadRequest, backend.ErrorSourceDownstream,
		fmt.Sprintf("too many series: %d series exceed the limit of %d generated points per request", series, maxRequestSeriesPoints))
}
