package sims

import (
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/data"
)

type waveformSim struct {
	key        simulationKey
	cfg        waveformConfig
	calculator func(x float64, cfg *waveformConfig) float64
}

var (
	_ Simulation      = (*waveformSim)(nil)
	_ checkedValueSim = (*waveformSim)(nil)
)

type waveformConfig struct {
	Period    float64 `json:"period"`           // seconds
	Offset    float64 `json:"offset,omitempty"` // Y shift
	Phase     float64 `json:"phase,omitempty"`  // X shift // +- 1 (will scale the )
	Amplitude float64 `json:"amplitude"`        // Y size
	Noise     float64 `json:"noise,omitempty"`  // random noise to add
}

func (s *waveformSim) GetState() simulationState {
	return simulationState{
		Key:    s.key,
		Config: s.cfg,
	}
}

func (s *waveformSim) SetConfig(vals map[string]any) error {
	return updateConfigObjectFromJSON(s.cfg, vals)
}

func (s *waveformSim) NewFrame(size int) *data.Frame {
	frame := data.NewFrameOfFieldTypes("", size,
		data.FieldTypeTime,    // time
		data.FieldTypeFloat64, // value
	)
	frame.Fields[0].Name = data.TimeSeriesTimeFieldName
	frame.Fields[1].Name = data.TimeSeriesValueFieldName
	return frame
}

func (s *waveformSim) GetValues(t time.Time) map[string]any {
	vals, err := s.getCheckedValues(t)
	if err != nil {
		return nil
	}
	return vals
}

func (s *waveformSim) getCheckedValues(t time.Time) (map[string]any, error) {
	cfg := s.cfg
	x := 0.0
	if cfg.Period > 0 {
		periodMS := cfg.Period * 1000
		divisor, err := cfg.periodMillis()
		if err != nil {
			return nil, err
		}
		ms := t.UnixMilli() % divisor
		x = ((float64(ms) / periodMS) * 2 * math.Pi) // 0 >> 2Pi
	}

	v := s.calculator(x, &cfg)

	noise := cfg.Noise
	if noise > 0 {
		gen := rand.New(rand.NewSource(t.UnixMilli())) // consistent for the value
		v += (gen.Float64() * 2.0 * noise) - noise
	}

	return map[string]any{
		data.TimeSeriesTimeFieldName:  t,
		data.TimeSeriesValueFieldName: v,
	}, nil
}

// A period that is not positive is valid and produces a flat line.
func (c *waveformConfig) validate() error {
	if c.Period > 0 {
		_, err := c.periodMillis()
		return err
	}
	return nil
}

// periodMillis returns the period as the whole number of milliseconds that
// GetValues divides by.
func (c *waveformConfig) periodMillis() (int64, error) {
	ms := c.Period * 1000
	// Range check the float itself: converting an out of range float to int64
	// is implementation defined, and a positive period can still truncate to 0.
	if !(ms >= 1 && ms < math.MaxInt64) {
		return 0, fmt.Errorf("invalid waveform period %v: must be at least one millisecond", c.Period)
	}
	return int64(ms), nil
}

func (s *waveformSim) Close() error {
	return nil
}

func newSinewaveInfo() simulationInfo {
	sf := waveformConfig{
		Period:    10,
		Amplitude: 1,
		Offset:    0,
		Phase:     0,
	}

	df := data.NewFrame("")
	df.Fields = append(df.Fields, data.NewField("period", nil, []float64{sf.Period}))
	df.Fields = append(df.Fields, data.NewField("offset", nil, []float64{sf.Offset}))
	df.Fields = append(df.Fields, data.NewField("phase", nil, []float64{sf.Phase}))
	df.Fields = append(df.Fields, data.NewField("amplitude", nil, []float64{sf.Amplitude}))
	df.Fields = append(df.Fields, data.NewField("noise", nil, []float64{sf.Noise}))

	f := data.NewField("period", nil, []float64{sf.Period})
	f.Config = &data.FieldConfig{Unit: "s"} // seconds
	df.Fields = append(df.Fields, f)

	return simulationInfo{
		Type:         "sine",
		Name:         "Sine",
		Description:  "Sinewave generator",
		ConfigFields: df,
		OnlyForward:  false,
		create: func(cfg simulationState) (Simulation, error) {
			s := &waveformSim{
				key:        cfg.Key,
				cfg:        sf, // default value
				calculator: sinewaveCalculator,
			}
			err := updateConfigObjectFromJSON(&s.cfg, cfg.Config) // override any fields
			if err == nil {
				err = s.cfg.validate()
			}
			return s, err
		},
	}
}

func sinewaveCalculator(x float64, cfg *waveformConfig) float64 {
	return (math.Sin(x) * cfg.Amplitude) + cfg.Offset
}
