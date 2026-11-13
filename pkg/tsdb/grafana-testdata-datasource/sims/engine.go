package sims

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"github.com/grafana/grafana-plugin-sdk-go/data"
)

var (
	_ backend.StreamHandler    = (*SimulationEngine)(nil)
	_ backend.QueryDataHandler = (*SimulationEngine)(nil)
)

type SimulationEngine struct {
	logger log.Logger

	// Lookup by Type
	registry map[string]simulationInfo

	// The running instances
	running map[string]Simulation

	// Number of active RunStream calls per simulation key
	streaming map[string]int

	// safe changes
	mutex sync.Mutex
}

// The simulation key (type, tick and uid) comes from the subscribed channel
// path, so every distinct key would otherwise start another ticking stream.
const maxStreamingSimulations = 20

func (s *SimulationEngine) register(info simulationInfo) error {
	if info.create == nil {
		return fmt.Errorf("invalid simulation -- missing create function: %s", info.Type)
	}
	if info.Type == "" {
		return fmt.Errorf("missing type")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	_, ok := s.registry[info.Type]
	if ok {
		return fmt.Errorf("already registered")
	}

	s.registry[info.Type] = info
	return nil
}

type simulationInitializer = func() simulationInfo

func NewSimulationEngine() (*SimulationEngine, error) {
	s := &SimulationEngine{
		registry:  make(map[string]simulationInfo),
		running:   make(map[string]Simulation),
		streaming: make(map[string]int),
		logger:    backend.NewLoggerWith("logger", "tsdb.sims"),
	}
	// Initialize each type
	initializers := []simulationInitializer{
		newFlightSimInfo,
		newSinewaveInfo,
		newTankSimInfo,
	}

	for _, init := range initializers {
		err := s.register(init())
		if err != nil {
			return s, err
		}
	}
	return s, nil
}

func (s *SimulationEngine) Lookup(info simulationState) (Simulation, error) {
	hz := info.Key.TickHZ
	if hz < (1 / 60.0) {
		return nil, fmt.Errorf("frequency is too slow")
	}
	if hz > 50 {
		return nil, fmt.Errorf("frequency is too fast")
	}
	if info.Key.Type == "" {
		return nil, fmt.Errorf("missing simulation type")
	}

	key := info.Key.String()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	v, ok := s.running[key]
	if ok {
		return v, nil
	}

	t, ok := s.registry[info.Key.Type]
	if !ok {
		return nil, fmt.Errorf("unknown simulation type")
	}

	v, err := t.create(info)
	if err == nil {
		s.running[key] = v
	}
	return v, err
}

type simulationQuery struct {
	simulationState
	Last   bool `json:"last"`
	Stream bool `json:"stream"`
}

type dumbQueryQrapper struct {
	Sim simulationQuery `json:"sim"`
}

func (s *SimulationEngine) QueryData(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	resp := backend.NewQueryDataResponse()

	for _, q := range req.Queries {
		wrap := &dumbQueryQrapper{}
		err := json.Unmarshal(q.JSON, wrap)
		if err != nil {
			return nil, fmt.Errorf("failed to parse query json: %v", err)
		}
		sq := wrap.Sim
		if sq.Key.TickHZ == 0 {
			sq.Key.TickHZ = 10
		}

		sim, err := s.Lookup(sq.simulationState)
		if err != nil {
			return nil, fmt.Errorf("error fetching simulation: %v", err)
		}

		if sim == nil {
			return nil, fmt.Errorf("invalid simulation: %v", sq)
		}

		frame := sim.NewFrame(0)
		if sq.Last {
			v := sim.GetValues(q.TimeRange.To)
			appendFrameRow(frame, v)
		} else {
			timeWalkerMs := q.TimeRange.From.UnixNano() / int64(time.Millisecond)
			to := q.TimeRange.To.UnixNano() / int64(time.Millisecond)
			stepMillis := q.Interval.Milliseconds()

			maxPoints := min(q.MaxDataPoints*2, 10000)
			for i := int64(0); i < maxPoints && timeWalkerMs < to; i++ {
				t := time.UnixMilli(timeWalkerMs).UTC()
				vals := sim.GetValues(t)
				if vals != nil { // nil is returned when you ask for an invalid time
					appendFrameRow(frame, vals)
				}
				timeWalkerMs += stepMillis
			}
		}

		if sq.Stream && req.PluginContext.DataSourceInstanceSettings != nil {
			uid := req.PluginContext.DataSourceInstanceSettings.UID
			frame.Meta = &data.FrameMeta{
				Channel: fmt.Sprintf("ds/%s/sim/%s", uid, sim.GetState().Key.String()),
			}
		}

		respD := resp.Responses[q.RefID]
		respD.Frames = append(respD.Frames, frame)
		resp.Responses[q.RefID] = respD
	}

	return resp, nil
}

func (s *SimulationEngine) getSimFromPath(path string) (Simulation, error) {
	key, err := parseSimKey(path)
	if err != nil {
		return nil, err
	}
	return s.Lookup(simulationState{
		Key: key,
	})
}

func parseSimKey(path string) (simulationKey, error) {
	idx := strings.Index(path, "sim/")
	if idx >= 0 {
		path = path[idx+4:]
	}

	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return simulationKey{}, fmt.Errorf("missing frequency")
	}
	if !strings.HasSuffix(parts[1], "hz") {
		return simulationKey{}, fmt.Errorf("invalid path frequency.  Expecting `hz` suffix")
	}
	hz, err := strconv.ParseFloat(strings.TrimSuffix(parts[1], "hz"), 64)
	if err != nil {
		return simulationKey{}, fmt.Errorf("error parsing frequency from: %s", parts[1])
	}
	if len(parts) == 2 {
		parts = append(parts, "") // empty UID
	}

	key := simulationKey{
		Type:   parts[0],
		TickHZ: hz,
		UID:    parts[2],
	}
	if path != key.String() {
		return simulationKey{}, fmt.Errorf("path should match: %s", key.String())
	}
	return key, nil
}

func (s *SimulationEngine) canStream(key string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	_, ok := s.streaming[key]
	return ok || len(s.streaming) < maxStreamingSimulations
}

func (s *SimulationEngine) acquireStream(key string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, ok := s.streaming[key]; !ok && len(s.streaming) >= maxStreamingSimulations {
		return false
	}
	s.streaming[key]++
	return true
}

func (s *SimulationEngine) releaseStream(key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.streaming[key]--
	if s.streaming[key] <= 0 {
		delete(s.streaming, key)
	}
}

func (s *SimulationEngine) GetSimulationHandler(rw http.ResponseWriter, req *http.Request) {
	var result any
	path := req.URL.Path
	if path == "/sims" {
		v := make([]simulationInfo, 0, len(s.registry))
		for _, value := range s.registry {
			v = append(v, value)
		}
		result = v
	} else if strings.HasPrefix(path, "/sim/") {
		sim, err := s.getSimFromPath(path)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusNotFound)
			return
		}

		// With a POST, update the values
		if req.Method == "POST" {
			body, err := getBodyFromRequest(req)
			if err == nil {
				err = sim.SetConfig(body)
			}
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}
		}
		result = sim.GetState()
	}

	bytes, err := json.Marshal(&result)
	if err != nil {
		s.logger.Error("Failed to marshal response body to JSON", "error", err)
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	if _, err := rw.Write(bytes); err != nil {
		s.logger.Error("Failed to write response", "error", err)
	}
}

func (s *SimulationEngine) SubscribeStream(ctx context.Context, req *backend.SubscribeStreamRequest) (*backend.SubscribeStreamResponse, error) {
	key, err := parseSimKey(req.Path) // includes sim
	if err != nil {
		return nil, err
	}
	if !s.canStream(key.String()) {
		return &backend.SubscribeStreamResponse{
			Status: backend.SubscribeStreamStatusPermissionDenied,
		}, nil
	}
	sim, err := s.Lookup(simulationState{Key: key})
	if err != nil {
		return nil, err
	}

	frame := sim.NewFrame(1)
	setFrameRow(frame, 0, sim.GetValues(time.Now()))
	initial, err := backend.NewInitialFrame(frame, data.IncludeAll)

	return &backend.SubscribeStreamResponse{
		Status:      backend.SubscribeStreamStatusOK,
		InitialData: initial,
	}, err
}

func (s *SimulationEngine) RunStream(ctx context.Context, req *backend.RunStreamRequest, sender *backend.StreamSender) error {
	simKey, err := parseSimKey(req.Path) // includes sim
	if err != nil {
		return err
	}
	sim, err := s.Lookup(simulationState{Key: simKey})
	if err != nil {
		return err
	}

	key := simKey.String()
	if !s.acquireStream(key) {
		// Returning nil, not an error, so the stream manager stops this stream
		// instead of retrying it while the channel has subscribers.
		s.logger.Warn("Too many streaming simulations, not starting stream", "path", req.Path)
		return nil
	}
	defer s.releaseStream(key)

	frequency := 1.0 / sim.GetState().Key.TickHZ
	ticker := time.NewTicker(time.Duration(frequency * float64(time.Second)))
	defer ticker.Stop()

	mode := data.IncludeDataOnly

	frame := sim.NewFrame(1)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case t := <-ticker.C:
			setFrameRow(frame, 0, sim.GetValues(t))
			err := sender.SendFrame(frame, mode)
			if err != nil {
				return err
			}
		}
	}
}

func (s *SimulationEngine) PublishStream(_ context.Context, req *backend.PublishStreamRequest) (*backend.PublishStreamResponse, error) {
	return &backend.PublishStreamResponse{
		Status: backend.PublishStreamStatusPermissionDenied,
	}, nil
}
