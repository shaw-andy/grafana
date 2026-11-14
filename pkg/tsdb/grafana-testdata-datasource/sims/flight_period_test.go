package sims

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"
)

// The divisor used for a flight point is the period converted to whole
// nanoseconds. These tests require that conversion to be rejected at the
// point it is used, including when the period was written into an already
// created simulation after creation-time checks ran.
func TestFlightUseSiteRejectsNonPositivePeriod(t *testing.T) {
	t.Parallel()

	periods := []struct {
		name   string
		period float64
	}{
		{name: "zero", period: 0},
		{name: "negative", period: -5},
		// Positive, but it truncates to a zero nanosecond divisor.
		{name: "subnanosecond", period: 1e-18},
	}

	for i, tc := range periods {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			eng, err := NewSimulationEngine()
			require.NoError(t, err)

			key := simulationKey{Type: "flight", TickHZ: 50, UID: fmt.Sprintf("use-%d", i)}
			sim, err := eng.Lookup(simulationState{Key: key})
			require.NoError(t, err)
			// Installed after Lookup, so a check that only runs while the
			// simulation is created does not cover this read.
			sim.(*flightSim).cfg.Period = tc.period

			mustNotPanic(t, func() {
				_ = sim.GetValues(time.Now())
			})

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			body, err := json.Marshal(map[string]any{
				"sim": simulationQuery{
					simulationState: simulationState{Key: key},
					Last:            true,
				},
			})
			require.NoError(t, err)

			_, err = eng.QueryData(ctx, &backend.QueryDataRequest{
				Queries: []backend.DataQuery{{
					RefID: "A",
					TimeRange: backend.TimeRange{
						From: time.Now().Add(-time.Minute),
						To:   time.Now(),
					},
					JSON: body,
				}},
			})
			require.Error(t, err)

			_, err = eng.SubscribeStream(ctx, &backend.SubscribeStreamRequest{Path: "sim/" + key.String()})
			require.Error(t, err)

			err = eng.RunStream(ctx, &backend.RunStreamRequest{Path: "sim/" + key.String()}, backend.NewStreamSender(nopPacketSender{}))
			require.Error(t, err)
			require.NotErrorIs(t, err, context.DeadlineExceeded)
			require.NotErrorIs(t, err, context.Canceled)
		})
	}
}

func TestFlightSetConfigRejectsNonPositivePeriod(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body map[string]any
	}{
		{name: "zero", body: map[string]any{"period": 0.0}},
		{name: "negative", body: map[string]any{"period": -5.0}},
		{name: "subnanosecond", body: map[string]any{"period": 1e-18}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			eng, err := NewSimulationEngine()
			require.NoError(t, err)
			sim, err := eng.Lookup(simulationState{
				Key: simulationKey{Type: "flight", TickHZ: 10, UID: tc.name},
			})
			require.NoError(t, err)
			require.InDelta(t, 10, flightPeriod(t, sim), 0.001)

			err = sim.SetConfig(tc.body)
			require.Error(t, err)
			require.InDelta(t, 10, flightPeriod(t, sim), 0.001)

			mustNotPanic(t, func() {
				_ = sim.GetValues(time.Now())
			})
		})
	}
}

func flightPeriod(t *testing.T, sim Simulation) float64 {
	t.Helper()
	raw, err := json.Marshal(sim.GetState().Config)
	require.NoError(t, err)
	var cfg struct {
		Period float64 `json:"period"`
	}
	require.NoError(t, json.Unmarshal(raw, &cfg))
	return cfg.Period
}

func mustNotPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("panic: %v", recovered)
		}
	}()
	fn()
}

type nopPacketSender struct{}

func (nopPacketSender) Send(*backend.StreamPacket) error { return nil }
