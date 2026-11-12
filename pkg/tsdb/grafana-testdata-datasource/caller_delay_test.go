package testdatasource

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource/kinds"
)

// maxCallerSuppliedDelay is the longest a TestData handler may block on a
// duration taken from the request. The flaky-query editor and the slow-query
// scenario both already use 5s as their default; a longer wait is the bug.
//
// The bound is on the time the handler blocks, not on the raw string. For a
// flaky query, flakyQueryDelay can scale queryDelay by up to two when
// queryDelayVariability is 100, so clamping the parsed input and then applying
// jitter can still wait twice this long. The waited duration has to stay
// within the bound.
const maxCallerSuppliedDelay = 5 * time.Second

// capReturnSlack is scheduling room past the cap. A handler that still sleeps
// for an uncapped caller duration does not return inside this window.
const capReturnSlack = 2 * time.Second

// cancelReturnSlack is how quickly a handler must return after the request
// context is cancelled. The cancel happens after the wait has started, so a
// fix that only checks the context and then calls time.Sleep still fails.
const cancelReturnSlack = time.Second

const enteredWait = 500 * time.Millisecond

func TestFlakyQueryCallerDelayIsBoundedAndCancellable(t *testing.T) {
	huge := "1000000h"
	parsed, err := time.ParseDuration(huge)
	require.NoError(t, err)
	require.Greater(t, parsed, maxCallerSuppliedDelay)

	t.Run("scenario id route", func(t *testing.T) {
		t.Parallel()
		mustReturnWithin(t, maxCallerSuppliedDelay+capReturnSlack, func() {
			_, _ = ProvideService().QueryData(context.Background(), flakyQueryRequest("", huge))
		})
	})

	t.Run("scenario id route caps a moderate delay", func(t *testing.T) {
		t.Parallel()
		moderate := "30s"
		parsed, err := time.ParseDuration(moderate)
		require.NoError(t, err)
		require.Greater(t, parsed, maxCallerSuppliedDelay)
		mustReturnWithin(t, maxCallerSuppliedDelay+capReturnSlack, func() {
			_, _ = ProvideService().QueryData(context.Background(), flakyQueryRequest("", moderate))
		})
	})

	t.Run("query type route", func(t *testing.T) {
		t.Parallel()
		mustReturnWithin(t, maxCallerSuppliedDelay+capReturnSlack, func() {
			_, _ = ProvideService().QueryData(context.Background(), flakyQueryRequest(string(kinds.TestDataQueryTypeFlakyQuery), huge))
		})
	})

	t.Run("later query in the same request", func(t *testing.T) {
		t.Parallel()
		req := flakyQueryRequest("", "0s")
		req.Queries = append(req.Queries, flakyQueryRequest("", huge).Queries[0])
		req.Queries[1].RefID = "B"
		mustReturnWithin(t, maxCallerSuppliedDelay+capReturnSlack, func() {
			_, _ = ProvideService().QueryData(context.Background(), req)
		})
	})

	t.Run("cancelled context", func(t *testing.T) {
		t.Parallel()
		mustStopAfterCancel(t, func(ctx context.Context) {
			_, _ = ProvideService().QueryData(ctx, flakyQueryRequest("", huge))
		})
	})

	t.Run("chunked query", func(t *testing.T) {
		t.Parallel()
		req := flakyQueryRequest("", huge)
		mustStopAfterCancel(t, func(ctx context.Context) {
			_ = ProvideService().QueryChunkedData(ctx, &backend.QueryChunkedDataRequest{
				Queries: req.Queries,
			}, nopChunkWriter{})
		})
	})
}

func TestSlowQueryCallerDelayIsBoundedAndCancellable(t *testing.T) {
	huge := "1000000h"
	parsed, err := time.ParseDuration(huge)
	require.NoError(t, err)
	require.Greater(t, parsed, maxCallerSuppliedDelay)

	t.Run("scenario id route", func(t *testing.T) {
		t.Parallel()
		mustReturnWithin(t, maxCallerSuppliedDelay+capReturnSlack, func() {
			_, _ = ProvideService().QueryData(context.Background(), slowQueryRequest("", huge))
		})
	})

	t.Run("query type route", func(t *testing.T) {
		t.Parallel()
		mustReturnWithin(t, maxCallerSuppliedDelay+capReturnSlack, func() {
			_, _ = ProvideService().QueryData(context.Background(), slowQueryRequest(string(kinds.TestDataQueryTypeSlowQuery), huge))
		})
	})

	t.Run("later query in the same request", func(t *testing.T) {
		t.Parallel()
		req := slowQueryRequest("", "0s")
		req.Queries = append(req.Queries, slowQueryRequest("", huge).Queries[0])
		req.Queries[1].RefID = "B"
		mustReturnWithin(t, maxCallerSuppliedDelay+capReturnSlack, func() {
			_, _ = ProvideService().QueryData(context.Background(), req)
		})
	})

	t.Run("cancelled context", func(t *testing.T) {
		t.Parallel()
		mustStopAfterCancel(t, func(ctx context.Context) {
			_, _ = ProvideService().QueryData(ctx, slowQueryRequest("", huge))
		})
	})
}

func TestStreamSpeedIsBoundedAndCancellable(t *testing.T) {
	huge := "1000000h"
	parsed, err := time.ParseDuration(huge)
	require.NoError(t, err)
	require.Greater(t, parsed, maxCallerSuppliedDelay)

	t.Run("resource route", func(t *testing.T) {
		t.Parallel()
		mustReturnWithin(t, maxCallerSuppliedDelay+capReturnSlack, func() {
			_ = ProvideService().CallResource(context.Background(), streamRequest(huge), backend.CallResourceResponseSenderFunc(func(*backend.CallResourceResponse) error {
				return nil
			}))
		})
	})

	t.Run("cancelled context", func(t *testing.T) {
		t.Parallel()
		mustStopAfterCancel(t, func(ctx context.Context) {
			_ = ProvideService().CallResource(ctx, streamRequest(huge), backend.CallResourceResponseSenderFunc(func(*backend.CallResourceResponse) error {
				return nil
			}))
		})
	})
}

func flakyQueryRequest(queryType, queryDelay string) *backend.QueryDataRequest {
	return &backend.QueryDataRequest{
		Queries: []backend.DataQuery{
			{
				RefID:     "A",
				QueryType: queryType,
				TimeRange: backend.TimeRange{
					From: time.Now().Add(-time.Minute),
					To:   time.Now(),
				},
				Interval:      time.Second,
				MaxDataPoints: 10,
				JSON:          []byte(`{"scenarioId":"` + string(kinds.TestDataQueryTypeFlakyQuery) + `","queryDelay":"` + queryDelay + `","queryDelayVariability":0}`),
			},
		},
	}
}

func slowQueryRequest(queryType, stringInput string) *backend.QueryDataRequest {
	return &backend.QueryDataRequest{
		Queries: []backend.DataQuery{
			{
				RefID:     "A",
				QueryType: queryType,
				TimeRange: backend.TimeRange{
					From: time.Now().Add(-time.Minute),
					To:   time.Now(),
				},
				Interval:      time.Second,
				MaxDataPoints: 10,
				JSON:          []byte(`{"scenarioId":"` + string(kinds.TestDataQueryTypeSlowQuery) + `","stringInput":"` + stringInput + `"}`),
			},
		},
	}
}

func streamRequest(speed string) *backend.CallResourceRequest {
	return &backend.CallResourceRequest{
		Path:   "stream",
		Method: http.MethodGet,
		// flush=0 skips the flusher assertion so the wait is the only blocking work.
		// count=1 is one iteration; each iteration's sleep has to stay within the cap.
		URL: "stream?speed=" + speed + "&count=1&flush=0",
	}
}

func mustReturnWithin(t *testing.T, limit time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("handler still blocked after %s; caller-supplied delay was not capped at %s", limit, maxCallerSuppliedDelay)
	}
}

func mustStopAfterCancel(t *testing.T, start func(context.Context)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		start(ctx)
	}()

	// Let the handler enter its wait, then cancel. Checking the context only
	// before the wait still leaves this blocked.
	time.Sleep(enteredWait)
	cancel()

	select {
	case <-done:
	case <-time.After(cancelReturnSlack):
		t.Fatal("handler kept blocking after the request context was cancelled")
	}
}

type nopChunkWriter struct{}

func (nopChunkWriter) WriteFrame(context.Context, string, string, *data.Frame) error { return nil }
func (nopChunkWriter) WriteError(context.Context, string, backend.Status, error) error {
	return nil
}
