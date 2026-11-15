package sims

import (
	"fmt"
	"math"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/data"
)

type flightSim struct {
	key simulationKey
	cfg flightConfig
}

var (
	_ Simulation = (*flightSim)(nil)
)

type flightDataPoint struct {
	time     time.Time
	lat      float64 // gps
	lng      float64 // gps
	heading  float64 // degree
	altitude float64 // above ground
}

type flightConfig struct {
	CenterLat   float64 `json:"centerLat"`
	CenterLng   float64 `json:"centerLng"`
	Radius      float64 `json:"radius"`
	AltitudeMin float64 `json:"altitudeMin"`
	AltitudeMax float64 `json:"altitudeMax"`
	Period      float64 `json:"period"` // angular speed (seconds)
}

func (s *flightSim) GetState() simulationState {
	return simulationState{
		Key:    s.key,
		Config: s.cfg,
	}
}

func (s *flightSim) SetConfig(vals map[string]any) error {
	cfg := s.cfg
	if err := updateConfigObjectFromJSON(&cfg, vals); err != nil {
		return err
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	s.cfg = cfg
	return nil
}

// periodNanos converts the period to the integer divisor used by getNextPoint.
// Periods that truncate to zero nanoseconds or overflow int64 are refused.
func periodNanos(period float64) (int64, bool) {
	ns := period * float64(time.Second)
	if !(ns >= 1 && ns < math.MaxInt64) {
		return 0, false
	}
	return int64(ns), true
}

func (f *flightConfig) validate() error {
	if _, ok := periodNanos(f.Period); !ok {
		return fmt.Errorf("invalid period %g: must be at least one nanosecond", f.Period)
	}
	return nil
}

func (s *flightSim) NewFrame(size int) *data.Frame {
	frame := data.NewFrameOfFieldTypes("", size,
		data.FieldTypeTime,    // time
		data.FieldTypeFloat64, // lat
		data.FieldTypeFloat64, // lng
		data.FieldTypeFloat64, // heading
		data.FieldTypeFloat64, // altitude
	)
	frame.Fields[0].Name = "time"
	frame.Fields[1].Name = "lat"
	frame.Fields[2].Name = "lng"
	frame.Fields[3].Name = "heading"
	frame.Fields[4].Name = "altitude"
	return frame
}

func (s *flightSim) GetValues(t time.Time) map[string]any {
	p := s.cfg.getNextPoint(t)

	return map[string]any{
		"time":     p.time,
		"lat":      p.lat,
		"lng":      p.lng,
		"heading":  p.heading,
		"altitude": p.altitude,
	}
}

func (s *flightSim) Close() error {
	return nil
}

func newFlightSimInfo() simulationInfo {
	sf := flightConfig{
		CenterLat:   37.83, // San francisco
		CenterLng:   -122.42487,
		Radius:      0.01, // raw gps degrees
		AltitudeMin: 350,
		AltitudeMax: 400,
		Period:      10, //model.Get("period").MustFloat64(10),
	}

	df := data.NewFrame("")
	df.Fields = append(df.Fields, data.NewField("centerLat", nil, []float64{sf.CenterLat}))
	df.Fields = append(df.Fields, data.NewField("centerLng", nil, []float64{sf.CenterLng}))
	df.Fields = append(df.Fields, data.NewField("radius", nil, []float64{sf.Radius}))
	df.Fields = append(df.Fields, data.NewField("altitudeMin", nil, []float64{sf.AltitudeMin}))
	df.Fields = append(df.Fields, data.NewField("altitudeMax", nil, []float64{sf.AltitudeMax}))

	f := data.NewField("period", nil, []float64{sf.Period})
	f.Config = &data.FieldConfig{Unit: "s"} // seconds
	df.Fields = append(df.Fields, f)

	return simulationInfo{
		Type:         "flight",
		Name:         "Flight",
		Description:  "simple circling airplain",
		ConfigFields: df,
		OnlyForward:  false,
		create: func(cfg simulationState) (Simulation, error) {
			s := &flightSim{
				key: cfg.Key,
				cfg: sf, // default value
			}
			if err := updateConfigObjectFromJSON(&s.cfg, cfg.Config); err != nil { // override any fields
				return nil, err
			}
			if err := s.cfg.validate(); err != nil {
				return nil, err
			}
			return s, nil
		},
	}
}

func (f *flightConfig) getNextPoint(t time.Time) flightDataPoint {
	per := 0.0
	if periodNS, ok := periodNanos(f.Period); ok {
		ms := t.UnixNano() % periodNS
		per = float64(ms) / float64(periodNS)
	}
	rad := per * 2.0 * math.Pi // 0 >> 2Pi
	delta := f.AltitudeMax - f.AltitudeMin

	return flightDataPoint{
		time:     t,
		lat:      f.CenterLat + math.Sin(rad)*f.Radius,
		lng:      f.CenterLng + math.Cos(rad)*f.Radius,
		heading:  (rad * 180) / math.Pi,         // (math.Atanh(rad) * 180.0) / math.Pi, // in degrees
		altitude: f.AltitudeMin + (delta * per), // clif
	}
}
