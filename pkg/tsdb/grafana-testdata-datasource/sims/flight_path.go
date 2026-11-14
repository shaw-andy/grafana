package sims

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/data"
)

type flightSim struct {
	key simulationKey

	// cfg is shared by every query and stream using this key, and SetConfig
	// can replace it while a stream is reading it.
	mu  sync.RWMutex
	cfg flightConfig
}

var (
	_ Simulation      = (*flightSim)(nil)
	_ checkedValueSim = (*flightSim)(nil)
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

func (s *flightSim) config() flightConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *flightSim) GetState() simulationState {
	return simulationState{
		Key:    s.key,
		Config: s.config(),
	}
}

func (s *flightSim) SetConfig(vals map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cfg
	if err := updateConfigObjectFromJSON(&next, vals); err != nil {
		return err
	}
	if err := next.validate(); err != nil {
		return err
	}
	s.cfg = next
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
	vals, err := s.getCheckedValues(t)
	if err != nil {
		return nil
	}
	return vals
}

func (s *flightSim) getCheckedValues(t time.Time) (map[string]any, error) {
	cfg := s.config()
	p, err := cfg.getNextPoint(t)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"time":     p.time,
		"lat":      p.lat,
		"lng":      p.lng,
		"heading":  p.heading,
		"altitude": p.altitude,
	}, nil
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
			err := updateConfigObjectFromJSON(&s.cfg, cfg.Config) // override any fields
			if err == nil {
				err = s.cfg.validate()
			}
			return s, err
		},
	}
}

func (f *flightConfig) validate() error {
	_, err := f.periodNanos()
	return err
}

// periodNanos returns the period as the whole number of nanoseconds that
// getNextPoint divides by.
func (f *flightConfig) periodNanos() (int64, error) {
	ns := f.Period * float64(time.Second)
	// Range check the float itself: converting an out of range float to int64
	// is implementation defined, and a positive period can still truncate to 0.
	if !(ns >= 1 && ns < math.MaxInt64) {
		return 0, fmt.Errorf("invalid flight period %v: must be a positive number of seconds of at least one nanosecond", f.Period)
	}
	return int64(ns), nil
}

func (f *flightConfig) getNextPoint(t time.Time) (flightDataPoint, error) {
	periodNS, err := f.periodNanos()
	if err != nil {
		return flightDataPoint{}, err
	}
	ms := t.UnixNano() % periodNS
	per := float64(ms) / float64(periodNS)
	rad := per * 2.0 * math.Pi // 0 >> 2Pi
	delta := f.AltitudeMax - f.AltitudeMin

	return flightDataPoint{
		time:     t,
		lat:      f.CenterLat + math.Sin(rad)*f.Radius,
		lng:      f.CenterLng + math.Cos(rad)*f.Radius,
		heading:  (rad * 180) / math.Pi,         // (math.Atanh(rad) * 180.0) / math.Pi, // in degrees
		altitude: f.AltitudeMin + (delta * per), // clif
	}, nil
}
