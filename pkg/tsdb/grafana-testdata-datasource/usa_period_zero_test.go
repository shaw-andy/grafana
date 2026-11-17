package testdatasource

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource/kinds"
)

// usaResultModes are every result shape that computes a value. The empty mode
// and values-as-rows both take the default row path.
var usaResultModes = []string{
	"",
	modeValueAsRow,
	modeValueAsFields,
	modeValueAsLabeledFields,
	modeTimeseries,
	modeTimeseriesWide,
}

// nonPositiveUSAPeriods are duration strings time.ParseDuration accepts as a
// duration of zero nanoseconds or less. Each one is a divisor in getStateValues.
var nonPositiveUSAPeriods = []string{
	"0s",
	"0",
	"0ms",
	"0us",
	"0ns",
	"0m",
	"0h",
	"0h0m0s",
	"0.0s",
	"+0s",
	"-0s",
	"0.9ns",
	"0.5ns",
	"-1ns",
	"-1s",
	"-30m",
}

func TestUSANonPositivePeriodQueryData(t *testing.T) {
	svc := ProvideService()
	for _, mode := range usaResultModes {
		for _, period := range nonPositiveUSAPeriods {
			for _, queryType := range []string{"", string(kinds.TestDataQueryTypeUsa)} {
				mode, period, queryType := mode, period, queryType
				name := "mode=" + mode + "/period=" + period + "/queryType=" + queryType
				t.Run(name, func(t *testing.T) {
					rsp, err := svc.QueryData(context.Background(), usaPeriodRequest(t, mode, period, queryType, "A"))
					requireVisibleQueryError(t, rsp, err, "A")
				})
			}
		}
	}
}

func TestUSANonPositivePeriodDoesNotDropSiblingQuery(t *testing.T) {
	svc := ProvideService()
	rawBad := usaPeriodJSON(t, modeTimeseries, "0s")
	rawGood := usaPeriodJSON(t, modeTimeseries, "30s")
	start := time.Date(2020, time.January, 10, 23, 0, 0, 0, time.UTC)
	rsp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{
		Queries: []backend.DataQuery{
			usaDataQuery("bad", rawBad, "", start),
			usaDataQuery("good", rawGood, "", start),
		},
	})
	// scenarioId dispatch drops a handler-level error, which would hide both
	// the rejection and the sibling query. The bad ref has to carry the error.
	require.NoError(t, err)
	requireVisibleQueryError(t, rsp, nil, "bad")
	requireUSAFrames(t, rsp, "good")
}

func TestUSAPositivePeriodQueryData(t *testing.T) {
	svc := ProvideService()
	for _, mode := range usaResultModes {
		for _, period := range []string{"", "30m", "1s", "1ns"} {
			mode, period := mode, period
			t.Run("mode="+mode+"/period="+period, func(t *testing.T) {
				rsp, err := svc.QueryData(context.Background(), usaPeriodRequest(t, mode, period, "", "A"))
				require.NoError(t, err)
				requireUSAFrames(t, rsp, "A")

				rsp, err = svc.QueryData(context.Background(), usaPeriodRequest(t, mode, period, string(kinds.TestDataQueryTypeUsa), "A"))
				require.NoError(t, err)
				requireUSAFrames(t, rsp, "A")
			})
		}
	}
}

func TestUSANonPositivePeriodQueryChunkedData(t *testing.T) {
	svc := ProvideService()
	for _, mode := range usaResultModes {
		for _, period := range []string{"0s", "0", "0.9ns", "-1s"} {
			for _, queryType := range []string{"", string(kinds.TestDataQueryTypeUsa)} {
				mode, period, queryType := mode, period, queryType
				t.Run("mode="+mode+"/period="+period+"/queryType="+queryType, func(t *testing.T) {
					writer := &captureChunkWriter{}
					q := usaPeriodRequest(t, mode, period, queryType, "A").Queries[0]
					err := svc.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{
						Queries: []backend.DataQuery{q},
					}, writer)
					if err != nil {
						require.Error(t, err)
						return
					}
					require.NotEmpty(t, writer.errs, "chunked query returned no error for period %q", period)
				})
			}
		}
	}
}

func usaPeriodRequest(t *testing.T, mode, period, queryType, refID string) *backend.QueryDataRequest {
	t.Helper()
	start := time.Date(2020, time.January, 10, 23, 0, 0, 0, time.UTC)
	return &backend.QueryDataRequest{
		Queries: []backend.DataQuery{
			usaDataQuery(refID, usaPeriodJSON(t, mode, period), queryType, start),
		},
	}
}

func usaPeriodJSON(t *testing.T, mode, period string) []byte {
	t.Helper()
	body := map[string]any{
		"scenarioId": string(kinds.TestDataQueryTypeUsa),
		"usa": map[string]any{
			"mode":   mode,
			"period": period,
			"fields": []string{"foo"},
			"states": []string{"CA"},
		},
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	return raw
}

func usaDataQuery(refID string, raw []byte, queryType string, start time.Time) backend.DataQuery {
	return backend.DataQuery{
		RefID: refID,
		TimeRange: backend.TimeRange{
			From: start,
			To:   start.Add(10 * time.Second),
		},
		Interval:      time.Second,
		MaxDataPoints: 5,
		QueryType:     queryType,
		JSON:          raw,
	}
}

// requireVisibleQueryError fails when the caller cannot see a failure for refID.
// handleFallbackScenario drops errors returned from the scenario handler, so a
// non-positive period has to be reported on the query response itself (or the
// query mux has to return that error) for the panel or alert to fail normally.
func requireVisibleQueryError(t *testing.T, rsp *backend.QueryDataResponse, err error, refID string) {
	t.Helper()
	if err != nil {
		require.Error(t, err)
		return
	}
	require.NotNil(t, rsp)
	dr, ok := rsp.Responses[refID]
	require.Truef(t, ok, "query %s was dropped instead of returned as an error", refID)
	require.Errorf(t, dr.Error, "query %s", refID)
}

func requireUSAFrames(t *testing.T, rsp *backend.QueryDataResponse, refID string) {
	t.Helper()
	require.NotNil(t, rsp)
	dr, ok := rsp.Responses[refID]
	require.Truef(t, ok, "query %s missing", refID)
	require.NoError(t, dr.Error)
	require.NotEmpty(t, dr.Frames)
	require.NotNil(t, dr.Frames[0])
	require.Greater(t, dr.Frames[0].Rows(), 0)
	for _, frame := range dr.Frames {
		require.NotEmpty(t, frame.Fields)
		for _, field := range frame.Fields {
			require.Equal(t, field.Len(), frame.Rows())
		}
	}
}

type captureChunkWriter struct {
	errs   []error
	frames int
}

func (c *captureChunkWriter) WriteFrame(_ context.Context, _ string, _ string, _ *data.Frame) error {
	c.frames++
	return nil
}

func (c *captureChunkWriter) WriteError(_ context.Context, _ string, _ backend.Status, err error) error {
	c.errs = append(c.errs, err)
	return nil
}
