package sims

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"
)

// Periods that are positive but truncate to a zero integer divisor must be
// refused before a simulation instance is stored. QueryData, SubscribeStream,
// and RunStream all call GetValues on that shared instance.

func TestSineSubMillisecondPeriodIsRefusedBeforeItCanDivideByZero(t *testing.T) {
	for _, period := range []float64{0.0001, 0.000999} {
		t.Run(periodLabel(period), func(t *testing.T) {
			engine := newEngine(t)
			uid := "sine-subms"
			key := simulationKey{Type: "sine", TickHZ: 10, UID: uid}.String()

			resp, err := querySimulation(t, engine, sineQueryJSON(uid, period, true), true)
			requireSimulationRefused(t, resp, err)
			requireSinePeriodNotDivisor(t, engine, key)

			// A range query walks GetValues once per step. Same config, same divisor.
			engine = newEngine(t)
			resp, err = querySimulation(t, engine, sineQueryJSON(uid, period, false), false)
			requireSimulationRefused(t, resp, err)
			requireSinePeriodNotDivisor(t, engine, key)

			requireLiveReadDoesNotUseTruncatedPeriod(t, engine, "sim/"+key, func(sim Simulation) {
				ws, ok := sim.(*waveformSim)
				require.True(t, ok)
				require.GreaterOrEqual(t, ws.cfg.Period*1000, 1.0)
			})
		})
	}
}

func TestSineGetValuesDoesNotDivideByTruncatedPeriod(t *testing.T) {
	// The field is set on the instance directly, after any check that only
	// inspects the incoming query. GetValues still has to refuse the value
	// it is about to use as a divisor.
	sim := &waveformSim{
		cfg:        waveformConfig{Period: 0.0001, Amplitude: 1},
		calculator: sinewaveCalculator,
	}
	var values map[string]any
	require.NotPanics(t, func() {
		values = sim.GetValues(time.UnixMilli(1_700_000_000_000))
	})
	require.NotNil(t, values)
}

func TestSineNonPositivePeriodIsRefused(t *testing.T) {
	for _, period := range []float64{0, -1} {
		t.Run(periodLabel(period), func(t *testing.T) {
			engine := newEngine(t)
			uid := "sine-nonpositive"
			resp, err := querySimulation(t, engine, sineQueryJSON(uid, period, true), true)
			requireSimulationRefused(t, resp, err)
			key := simulationKey{Type: "sine", TickHZ: 10, UID: uid}.String()
			requireSinePeriodNotDivisor(t, engine, key)
		})
	}
}

func TestSineOneMillisecondPeriodStillEvaluates(t *testing.T) {
	engine := newEngine(t)
	uid := "sine-1ms"
	resp, err := querySimulation(t, engine, sineQueryJSON(uid, 0.001, true), true)
	require.NoError(t, err)
	require.NotNil(t, resp)
	frame := resp.Responses["A"].Frames
	require.NotEmpty(t, frame)
	require.Greater(t, frame[0].Rows(), 0)

	key := simulationKey{Type: "sine", TickHZ: 10, UID: uid}.String()
	requireLiveReadDoesNotUseTruncatedPeriod(t, engine, "sim/"+key, func(sim Simulation) {
		ws := sim.(*waveformSim)
		require.InDelta(t, 0.001, ws.cfg.Period, 1e-12)
	})
}

func TestFlightTruncatedPeriodIsRefusedBeforeItCanDivideByZero(t *testing.T) {
	// flightConfig.getNextPoint divides by int64(period * time.Second) with no
	// positive-period guard. Zero and sub-nanosecond periods truncate to 0.
	for _, period := range []float64{0, 1e-10} {
		t.Run(periodLabel(period), func(t *testing.T) {
			engine := newEngine(t)
			uid := "flight-trunc"
			key := simulationKey{Type: "flight", TickHZ: 10, UID: uid}.String()

			resp, err := querySimulation(t, engine, flightQueryJSON(uid, period, true), true)
			requireSimulationRefused(t, resp, err)
			requireFlightPeriodNotDivisor(t, engine, key)

			requireLiveReadDoesNotUseTruncatedPeriod(t, engine, "sim/"+key, func(sim Simulation) {
				fs, ok := sim.(*flightSim)
				require.True(t, ok)
				require.NotEqual(t, int64(0), int64(fs.cfg.Period*float64(time.Second)))
			})
		})
	}
}

func TestFlightGetValuesDoesNotDivideByTruncatedPeriod(t *testing.T) {
	sim := &flightSim{cfg: flightConfig{Period: 1e-10, Radius: 0.01, CenterLat: 1, CenterLng: 2}}
	var values map[string]any
	require.NotPanics(t, func() {
		values = sim.GetValues(time.Unix(1_700_000_000, 0))
	})
	require.NotNil(t, values)
}

func TestFlightResourcePostRejectsTruncatedPeriod(t *testing.T) {
	engine := newEngine(t)
	uid := "flight-post"
	key := simulationKey{Type: "flight", TickHZ: 10, UID: uid}
	_, err := engine.Lookup(simulationState{
		Key:    key,
		Config: map[string]any{"period": 10},
	})
	require.NoError(t, err)

	body := strings.NewReader(`{"period":1e-10}`)
	req := httptest.NewRequest(http.MethodPost, "/sim/"+key.String(), body)
	rec := httptest.NewRecorder()
	require.NotPanics(t, func() {
		engine.GetSimulationHandler(rec, req)
	})
	requireFlightPeriodNotDivisor(t, engine, key.String())
	require.GreaterOrEqual(t, rec.Code, 400)

	require.NotPanics(t, func() {
		_, err = engine.SubscribeStream(context.Background(), &backend.SubscribeStreamRequest{
			Path: "sim/" + key.String(),
		})
	})
	require.NoError(t, err)
}

func newEngine(t *testing.T) *SimulationEngine {
	t.Helper()
	engine, err := NewSimulationEngine()
	require.NoError(t, err)
	return engine
}

func querySimulation(t *testing.T, engine *SimulationEngine, raw []byte, last bool) (*backend.QueryDataResponse, error) {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	interval := time.Second
	if !last {
		interval = 100 * time.Millisecond
	}
	var resp *backend.QueryDataResponse
	var err error
	require.NotPanics(t, func() {
		resp, err = engine.QueryData(context.Background(), &backend.QueryDataRequest{
			Queries: []backend.DataQuery{{
				RefID: "A",
				TimeRange: backend.TimeRange{
					From: now.Add(-time.Minute),
					To:   now,
				},
				Interval:      interval,
				MaxDataPoints: 100,
				JSON:          raw,
			}},
		})
	})
	return resp, err
}

func requireSimulationRefused(t *testing.T, resp *backend.QueryDataResponse, err error) {
	t.Helper()
	if err != nil {
		return
	}
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Responses)
	for refID, r := range resp.Responses {
		require.Error(t, r.Error, "query %s accepted a period that truncates to a zero divisor", refID)
	}
}

func requireSinePeriodNotDivisor(t *testing.T, engine *SimulationEngine, key string) {
	t.Helper()
	sim, ok := engine.running[key]
	if !ok {
		return
	}
	ws, ok := sim.(*waveformSim)
	require.True(t, ok)
	require.GreaterOrEqual(t, ws.cfg.Period*1000, 1.0)
	require.NotPanics(t, func() {
		ws.GetValues(time.UnixMilli(1_700_000_000_000))
	})
}

func requireFlightPeriodNotDivisor(t *testing.T, engine *SimulationEngine, key string) {
	t.Helper()
	sim, ok := engine.running[key]
	if !ok {
		return
	}
	fs, ok := sim.(*flightSim)
	require.True(t, ok)
	require.NotEqual(t, int64(0), int64(fs.cfg.Period*float64(time.Second)))
	require.Greater(t, fs.cfg.Period, 0.0)
	require.NotPanics(t, func() {
		fs.GetValues(time.Unix(1_700_000_000, 0))
	})
}

func requireLiveReadDoesNotUseTruncatedPeriod(t *testing.T, engine *SimulationEngine, path string, check func(Simulation)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	require.NotPanics(t, func() {
		_, err := engine.SubscribeStream(ctx, &backend.SubscribeStreamRequest{Path: path})
		require.NoError(t, err)
		err = engine.RunStream(ctx, &backend.RunStreamRequest{Path: path}, backend.NewStreamSender(discardPackets{}))
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
	sim, err := engine.getSimFromPath(path)
	require.NoError(t, err)
	check(sim)
}

type discardPackets struct{}

func (discardPackets) Send(*backend.StreamPacket) error { return nil }

func sineQueryJSON(uid string, period float64, last bool) []byte {
	return simulationQueryJSON("sine", uid, period, last)
}

func flightQueryJSON(uid string, period float64, last bool) []byte {
	return simulationQueryJSON("flight", uid, period, last)
}

func simulationQueryJSON(kind, uid string, period float64, last bool) []byte {
	lastJSON := "false"
	if last {
		lastJSON = "true"
	}
	// Built as text so the period is the decimal the query carries, not a
	// re-encoded float that might round back over the truncation boundary.
	raw := `{"sim":{"key":{"type":"` + kind + `","tick":10,"uid":"` + uid + `"},"config":{"period":` +
		trimFloat(period) + `},"last":` + lastJSON + `}}`
	return []byte(raw)
}

func trimFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func periodLabel(v float64) string {
	return trimFloat(v)
}
