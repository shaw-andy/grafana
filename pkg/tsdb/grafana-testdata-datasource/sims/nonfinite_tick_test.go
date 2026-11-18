package sims

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"
)

// discardSender satisfies the stream sender used by RunStream. The non-finite
// cases return before any packet is sent.
type discardSender struct{}

func (discardSender) Send(*backend.StreamPacket) error { return nil }

func TestNonFiniteTickRejectedByLookup(t *testing.T) {
	eng, err := NewSimulationEngine()
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		hz   float64
	}{
		{name: "NaN", hz: math.NaN()},
		{name: "positive infinity", hz: math.Inf(1)},
		{name: "negative infinity", hz: math.Inf(-1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := eng.Lookup(simulationState{
				Key: simulationKey{Type: "flight", TickHZ: tc.hz},
			})
			require.Error(t, err)
		})
	}
}

func TestNonFiniteTickSubscribeAndRun(t *testing.T) {
	paths := []string{
		"sim/flight/NaNhz",
		"sim/sine/NaNhz",
		"sim/tank/NaNhz",
		"sim/flight/NaNhz/instance",
		"sim/flight/+Infhz",
		"sim/sine/-Infhz",
		"sim/tank/+Infhz",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			eng, err := NewSimulationEngine()
			require.NoError(t, err)
			sender := backend.NewStreamSender(discardSender{})

			// Run on a fresh engine, then again after SubscribeStream has had a
			// chance to store the simulation. A check that only runs before the
			// simulation is cached must not leave a later RunStream able to tick.
			assertRunRejected(t, eng, sender, path)

			resp, err := eng.SubscribeStream(context.Background(), &backend.SubscribeStreamRequest{Path: path})
			if err == nil {
				require.NotNil(t, resp)
				require.NotEqual(t, backend.SubscribeStreamStatusOK, resp.Status)
			}

			assertRunRejected(t, eng, sender, path)
		})
	}
}

func TestNonFiniteTickHTTPHandlerDoesNotLeaveRunnableSim(t *testing.T) {
	eng, err := NewSimulationEngine()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/sim/flight/NaNhz", nil)
	rr := httptest.NewRecorder()
	eng.GetSimulationHandler(rr, req)

	assertRunRejected(t, eng, backend.NewStreamSender(discardSender{}), "sim/flight/NaNhz")
	require.GreaterOrEqual(t, rr.Code, 400)
	require.NotEqual(t, http.StatusOK, rr.Code)
}

func TestFiniteTickSimulationStillRuns(t *testing.T) {
	eng, err := NewSimulationEngine()
	require.NoError(t, err)

	resp, err := eng.SubscribeStream(context.Background(), &backend.SubscribeStreamRequest{Path: "sim/flight/1hz"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, backend.SubscribeStreamStatusOK, resp.Status)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = eng.RunStream(ctx, &backend.RunStreamRequest{Path: "sim/flight/1hz"}, backend.NewStreamSender(discardSender{}))
	require.ErrorIs(t, err, context.Canceled)

	req := httptest.NewRequest(http.MethodGet, "/sim/flight/1hz", nil)
	rr := httptest.NewRecorder()
	eng.GetSimulationHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
}

func assertRunRejected(t *testing.T, eng *SimulationEngine, sender *backend.StreamSender, path string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	started := time.Now()
	var err error
	require.NotPanics(t, func() {
		err = eng.RunStream(ctx, &backend.RunStreamRequest{Path: path}, sender)
	})
	require.Error(t, err)
	require.NotErrorIs(t, err, context.DeadlineExceeded)
	require.NotErrorIs(t, err, context.Canceled)
	require.Less(t, time.Since(started), 150*time.Millisecond)
}
