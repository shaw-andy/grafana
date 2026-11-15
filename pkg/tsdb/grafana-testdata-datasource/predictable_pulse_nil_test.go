package testdatasource

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
)

// Missing or null pulseWave must be rejected. predictablePulse dereferences
// PulseWave immediately, and handlePredictablePulseScenario drops a returned
// error, so the rejection has to show up on the query response (or as an
// error QueryData itself returns). A panic fails the test.
func TestPredictablePulseMissingPulseWaveIsRejected(t *testing.T) {
	s := ProvideService()
	from := time.Unix(1_700_000_000, 0).UTC()
	to := from.Add(5 * time.Minute)

	cases := []struct {
		name      string
		queryType string
		rawJSON   string
	}{
		{
			name:    "scenario id with pulseWave omitted",
			rawJSON: `{"scenarioId":"predictable_pulse","refId":"A"}`,
		},
		{
			name:    "scenario id with pulseWave null",
			rawJSON: `{"scenarioId":"predictable_pulse","refId":"A","pulseWave":null}`,
		},
		{
			name:      "query type with pulseWave omitted",
			queryType: "predictable_pulse",
			rawJSON:   `{"refId":"A"}`,
		},
		{
			name:      "query type with pulseWave null",
			queryType: "predictable_pulse",
			rawJSON:   `{"scenarioId":"predictable_pulse","refId":"A","pulseWave":null}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.QueryData(context.Background(), &backend.QueryDataRequest{
				Queries: []backend.DataQuery{{
					RefID:     "A",
					QueryType: tc.queryType,
					TimeRange: backend.TimeRange{From: from, To: to},
					JSON:      []byte(tc.rawJSON),
				}},
			})
			requirePulseWaveRejected(t, resp, err)
		})
	}
}

func TestPredictablePulseCompletePulseWaveSucceeds(t *testing.T) {
	s := ProvideService()
	from := time.Unix(1_700_000_000, 0).UTC()
	to := from.Add(5 * time.Minute)

	resp, err := s.QueryData(context.Background(), &backend.QueryDataRequest{
		Queries: []backend.DataQuery{{
			RefID: "A",
			TimeRange: backend.TimeRange{
				From: from,
				To:   to,
			},
			JSON: []byte(`{"scenarioId":"predictable_pulse","refId":"A","pulseWave":{"timeStep":60,"onCount":1,"offCount":1,"onValue":2,"offValue":1}}`),
		}},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	dr, ok := resp.Responses["A"]
	require.True(t, ok)
	require.NoError(t, dr.Error)
	require.NotEmpty(t, dr.Frames)
}

// QueryChunkedData runs the same scenario handler on another goroutine.
func TestPredictablePulseMissingPulseWaveChunkedQueryIsRejected(t *testing.T) {
	s := ProvideService()
	from := time.Unix(1_700_000_000, 0).UTC()
	to := from.Add(5 * time.Minute)
	w := &captureChunkedWriter{}

	err := s.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{
		Queries: []backend.DataQuery{{
			RefID:     "A",
			TimeRange: backend.TimeRange{From: from, To: to},
			JSON:      []byte(`{"scenarioId":"predictable_pulse","refId":"A"}`),
		}},
	}, w)
	if err != nil {
		require.Error(t, err)
		return
	}
	require.NotEmpty(t, w.errs)
	require.Empty(t, w.frames)
}

func requirePulseWaveRejected(t *testing.T, resp *backend.QueryDataResponse, err error) {
	t.Helper()
	if err != nil {
		require.Error(t, err)
		return
	}
	require.NotNil(t, resp)
	dr, ok := resp.Responses["A"]
	require.True(t, ok, "missing pulseWave must be reported on the query response")
	require.Error(t, dr.Error)
	require.Empty(t, dr.Frames)
}

type captureChunkedWriter struct {
	frames int
	errs   []error
}

func (c *captureChunkedWriter) WriteFrame(_ context.Context, _ string, _ string, _ *data.Frame) error {
	c.frames++
	return nil
}

func (c *captureChunkedWriter) WriteError(_ context.Context, _ string, _ backend.Status, err error) error {
	c.errs = append(c.errs, err)
	return nil
}
