package testdatasource

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/genproto/pluginv2"

	"github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource/kinds"
)

// maxSlowQueryDelay is the longest delay a testdata query or resource call may
// apply. The slow-query scenario's own default stringInput is 5s; a longer
// caller-supplied duration must be ignored, not clamped and then slept.
// A within-cap delay must still be interruptible by context cancellation.
const maxSlowQueryDelay = 5 * time.Second

// ignoredDelayLimit is how quickly a call must return when every supplied
// duration is above maxSlowQueryDelay. It is shorter than maxSlowQueryDelay so
// a fix that sleeps the cap still fails.
const ignoredDelayLimit = 750 * time.Millisecond

// attackerDuration parses to a multi-year delay (about 114 years) and is the
// value the slow-query scenario passes to time.Sleep.
const attackerDuration = "1000000h"

func TestTestDataSlowQueryAttackerDurationDoesNotBlock(t *testing.T) {
	parsed := mustParseLongDuration(t, attackerDuration)
	require.Greater(t, parsed, 365*24*time.Hour)

	svc := ProvideService()
	requireReturnsWithin(t, ignoredDelayLimit, func() {
		_, _ = svc.QueryData(context.Background(), slowQueryRequest("", attackerDuration))
	})
}

func TestTestDataSlowQueryExplicitQueryTypeAttackerDurationDoesNotBlock(t *testing.T) {
	mustParseLongDuration(t, attackerDuration)
	svc := ProvideService()
	requireReturnsWithin(t, ignoredDelayLimit, func() {
		_, _ = svc.QueryData(context.Background(), slowQueryRequest(string(kinds.TestDataQueryTypeSlowQuery), attackerDuration))
	})
}

func TestTestDataSlowQueryChunkedAttackerDurationDoesNotBlock(t *testing.T) {
	mustParseLongDuration(t, attackerDuration)
	svc := ProvideService()
	writer := backend.NewChunkedDataWriter(backend.DataFrameFormat_JSON, func(*pluginv2.QueryChunkedDataResponse) error {
		return nil
	})
	requireReturnsWithin(t, ignoredDelayLimit, func() {
		_ = svc.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{
			Queries: slowQueryRequest("", attackerDuration).Queries,
		}, writer)
	})
}

func TestTestDataSlowQueryRepeatedAttackerDurationDoesNotBlock(t *testing.T) {
	mustParseLongDuration(t, attackerDuration)
	svc := ProvideService()
	req := slowQueryRequest("", attackerDuration)
	req.Queries = append(req.Queries, slowQuery("B", "", attackerDuration))
	requireReturnsWithin(t, ignoredDelayLimit, func() {
		_, _ = svc.QueryData(context.Background(), req)
	})
}

func TestTestDataSlowQueryReturnsWhenCanceledDuringSleep(t *testing.T) {
	svc := ProvideService()
	requireStopsWhenCanceled(t, func(ctx context.Context) {
		_, _ = svc.QueryData(ctx, slowQueryRequest("", "4s"))
	})
}

func TestTestDataSlowQueryHonorsDelayWithinCap(t *testing.T) {
	svc := ProvideService()
	started := time.Now()
	_, err := svc.QueryData(context.Background(), slowQueryRequest(string(kinds.TestDataQueryTypeSlowQuery), "300ms"))
	elapsed := time.Since(started)
	require.NoError(t, err)
	require.GreaterOrEqual(t, elapsed, 250*time.Millisecond)
	require.Less(t, elapsed, time.Second)
}

func TestTestDataFlakyQueryAttackerDelayDoesNotBlock(t *testing.T) {
	mustParseLongDuration(t, attackerDuration)
	svc := ProvideService()
	requireReturnsWithin(t, ignoredDelayLimit, func() {
		_, _ = svc.QueryData(context.Background(), flakyQueryRequest("", attackerDuration))
	})
}

func TestTestDataFlakyQueryExplicitQueryTypeAttackerDelayDoesNotBlock(t *testing.T) {
	mustParseLongDuration(t, attackerDuration)
	svc := ProvideService()
	requireReturnsWithin(t, ignoredDelayLimit, func() {
		_, _ = svc.QueryData(context.Background(), flakyQueryRequest(string(kinds.TestDataQueryTypeFlakyQuery), attackerDuration))
	})
}

func TestTestDataFlakyQueryReturnsWhenCanceledDuringSleep(t *testing.T) {
	svc := ProvideService()
	requireStopsWhenCanceled(t, func(ctx context.Context) {
		_, _ = svc.QueryData(ctx, flakyQueryRequest("", "4s"))
	})
}

func TestTestDataStreamResourceAttackerSpeedDoesNotBlock(t *testing.T) {
	mustParseLongDuration(t, attackerDuration)
	svc := ProvideService()
	requireReturnsWithin(t, ignoredDelayLimit, func() {
		_ = svc.CallResource(context.Background(), streamRequest(1, 1, attackerDuration), discardResourceSender())
	})
}

func TestTestDataStreamResourceRepeatedAttackerSpeedDoesNotBlock(t *testing.T) {
	mustParseLongDuration(t, attackerDuration)
	svc := ProvideService()
	// count defaults to 10 when the query omits it. Each iteration sleeps.
	requireReturnsWithin(t, ignoredDelayLimit, func() {
		_ = svc.CallResource(context.Background(), streamRequest(1, 10, attackerDuration), discardResourceSender())
	})
}

func TestTestDataStreamResourceReturnsWhenCanceledDuringSleep(t *testing.T) {
	svc := ProvideService()
	requireStopsWhenCanceled(t, func(ctx context.Context) {
		_ = svc.CallResource(ctx, streamRequest(1, 1, "4s"), discardResourceSender())
	})
}

func mustParseLongDuration(t *testing.T, raw string) time.Duration {
	t.Helper()
	parsed, err := time.ParseDuration(raw)
	require.NoError(t, err)
	require.Greater(t, parsed, maxSlowQueryDelay)
	return parsed
}

func requireReturnsWithin(t *testing.T, limit time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("call still blocked after %s", limit)
	}
}

// requireStopsWhenCanceled cancels only after the call has had time to enter
// its sleep. A context check that runs before time.Sleep, followed by the
// sleep itself, must still fail.
func requireStopsWhenCanceled(t *testing.T, start func(context.Context)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan struct{})
	go func() {
		defer close(done)
		start(ctx)
	}()

	select {
	case <-done:
		t.Fatal("call returned before a within-cap delay could start")
	case <-time.After(500 * time.Millisecond):
	}
	cancel()

	select {
	case <-done:
	case <-time.After(ignoredDelayLimit):
		t.Fatal("call still blocked after the context was canceled")
	}
}

func slowQueryRequest(queryType string, stringInput string) *backend.QueryDataRequest {
	return &backend.QueryDataRequest{
		Queries: []backend.DataQuery{slowQuery("A", queryType, stringInput)},
	}
}

func slowQuery(refID string, queryType string, stringInput string) backend.DataQuery {
	return dataQuery(refID, queryType, fmt.Sprintf(`{"scenarioId":%q,"stringInput":%q}`, kinds.TestDataQueryTypeSlowQuery, stringInput))
}

func flakyQueryRequest(queryType string, queryDelay string) *backend.QueryDataRequest {
	q := dataQuery("A", queryType, fmt.Sprintf(
		`{"scenarioId":%q,"queryDelay":%q,"queryDelayVariability":0}`,
		kinds.TestDataQueryTypeFlakyQuery, queryDelay,
	))
	return &backend.QueryDataRequest{Queries: []backend.DataQuery{q}}
}

func dataQuery(refID string, queryType string, jsonBody string) backend.DataQuery {
	to := time.Unix(1_700_000_000, 0).UTC()
	return backend.DataQuery{
		RefID:         refID,
		QueryType:     queryType,
		Interval:      time.Second,
		MaxDataPoints: 10,
		TimeRange: backend.TimeRange{
			From: to.Add(-5 * time.Minute),
			To:   to,
		},
		JSON: []byte(jsonBody),
	}
}

func streamRequest(start int, count int, speed string) *backend.CallResourceRequest {
	return &backend.CallResourceRequest{
		PluginContext: backend.PluginContext{},
		Method:        http.MethodGet,
		Path:          "stream",
		URL:           fmt.Sprintf("/stream?start=%d&count=%d&speed=%s", start, count, speed),
	}
}

func discardResourceSender() backend.CallResourceResponseSender {
	return backend.CallResourceResponseSenderFunc(func(*backend.CallResourceResponse) error {
		return nil
	})
}
