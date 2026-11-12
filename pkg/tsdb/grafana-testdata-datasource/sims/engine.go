package sims

import (
	"container/list"
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

	// Recency and active stream count for each key in running
	live map[string]*liveSimulation
	// Keys in running, most recently used at the front
	lru *list.List

	// safe changes
	mutex sync.Mutex
}

// Simulation keys come from query JSON, resource paths and stream paths, so the
// number of retained simulations and the size of each key must stay bounded.
const (
	liveSimulationLimit = 32
	simulationUIDLimit  = 128
)

type liveSimulation struct {
	elem    *list.Element
	streams int
}

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
		registry: make(map[string]simulationInfo),
		running:  make(map[string]Simulation),
		live:     make(map[string]*liveSimulation),
		lru:      list.New(),
		logger:   backend.NewLoggerWith("logger", "tsdb.sims"),
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
	return s.lookup(info, false)
}

// lookup returns the running simulation for info.Key, creating it if needed.
// When stream is true the simulation is pinned against eviction until
// releaseStream is called with the returned simulation.
func (s *SimulationEngine) lookup(info simulationState, stream bool) (Simulation, error) {
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
	if len(info.Key.UID) > simulationUIDLimit {
		return nil, fmt.Errorf("simulation uid is longer than %d bytes", simulationUIDLimit)
	}

	key := info.Key.String()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if v, ok := s.running[key]; ok {
		entry := s.live[key]
		s.lru.MoveToFront(entry.elem)
		if stream {
			entry.streams++
		}
		return v, nil
	}

	t, ok := s.registry[info.Key.Type]
	if !ok {
		return nil, fmt.Errorf("unknown simulation type")
	}

	if len(s.running) >= liveSimulationLimit && !s.evictLeastRecentlyUsed() {
		return nil, fmt.Errorf("too many running simulations")
	}

	v, err := t.create(info)
	if err != nil {
		return nil, err
	}
	entry := &liveSimulation{elem: s.lru.PushFront(key)}
	if stream {
		entry.streams = 1
	}
	s.running[key] = v
	s.live[key] = entry
	return v, nil
}

// evictLeastRecentlyUsed removes the least recently used simulation that has no
// active stream. It must be called with the mutex held.
func (s *SimulationEngine) evictLeastRecentlyUsed() bool {
	for e := s.lru.Back(); e != nil; e = e.Prev() {
		key := e.Value.(string)
		if s.live[key].streams > 0 {
			continue
		}
		s.removeLocked(key)
		return true
	}
	return false
}

func (s *SimulationEngine) removeLocked(key string) {
	sim := s.running[key]
	s.lru.Remove(s.live[key].elem)
	delete(s.live, key)
	delete(s.running, key)
	if err := sim.Close(); err != nil {
		s.logger.Warn("Failed to close simulation", "key", key, "error", err)
	}
}

func (s *SimulationEngine) releaseStream(key string, sim Simulation) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.running[key] != sim {
		return
	}
	entry := s.live[key]
	entry.streams--
	if entry.streams <= 0 {
		s.removeLocked(key)
	}
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

func parseSimulationPath(path string) (simulationKey, error) {
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

func (s *SimulationEngine) getSimFromPath(path string) (Simulation, error) {
	key, err := parseSimulationPath(path)
	if err != nil {
		return nil, err
	}
	return s.Lookup(simulationState{
		Key: key,
	})
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
		key, err := parseSimulationPath(path)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusNotFound)
			return
		}

		// With a POST, update the values. The body is parsed and passed to create
		// so an invalid config never leaves a new simulation behind.
		state := simulationState{Key: key}
		var body map[string]any
		if req.Method == "POST" {
			body, err = getBodyFromRequest(req)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}
			state.Config = body
		}

		sim, err := s.Lookup(state)
		if err != nil {
			status := http.StatusNotFound
			if body != nil {
				status = http.StatusBadRequest
			}
			http.Error(rw, err.Error(), status)
			return
		}
		if body != nil {
			if err := sim.SetConfig(body); err != nil {
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
	sim, err := s.getSimFromPath(req.Path) // includes sim
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
	key, err := parseSimulationPath(req.Path) // includes sim
	if err != nil {
		return err
	}
	sim, err := s.lookup(simulationState{Key: key}, true)
	if err != nil {
		return err
	}
	defer s.releaseStream(key.String(), sim)

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
