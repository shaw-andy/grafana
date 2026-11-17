package managedstream

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana-plugin-sdk-go/live"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/live/model"
	"github.com/grafana/grafana/pkg/services/live/orgchannel"
)

var (
	logger = log.New("live.managed_stream")
)

// If message comes from a plugin:
// 	* it's simply sent to local subscribers without any additional steps
//  * if there is RULE then may be processed in some way
//  * important to keep a message in the original channel
// 	* client subscribed to ds/<UID>/xxx
//
// What we want to build:
// 	* Stream scope not hardcoded and determined by the caller
// 	* So it's possible to use managed stream from plugins
// 	* The problem is HA – at moment several plugins on different nodes publish same messages
// 	* Can use in-memory managed stream for plugins with local subscribers publish, use HA-managed stream for HTTP/WS
// 	* Eventually maintain a single connection with a plugin over a channel leader selection.

// Runner keeps Stream per Grafana live "namespace", which lives inside a scope.
type Runner struct {
	mu             sync.RWMutex
	streams        map[string]map[string]*Stream
	publisher      model.ChannelPublisher
	localPublisher LocalPublisher
	frameCache     FrameCache
}

type LocalPublisher interface {
	PublishLocal(channel string, data []byte) error
}

// NewRunner creates new Runner.
func NewRunner(publisher model.ChannelPublisher, localPublisher LocalPublisher, frameCache FrameCache) *Runner {
	return &Runner{
		publisher:      publisher,
		localPublisher: localPublisher,
		streams:        map[string]map[string]*Stream{},
		frameCache:     frameCache,
	}
}

func (r *Runner) GetManagedChannels(ns string) ([]*ManagedChannel, error) {
	activeChannels, err := r.frameCache.GetActiveChannels(ns)
	if err != nil {
		return []*ManagedChannel{}, fmt.Errorf("error getting active managed stream paths: %v", err)
	}
	channels := make([]*ManagedChannel, 0, len(activeChannels))
	for ch, schema := range activeChannels {
		managedChannel := &ManagedChannel{
			Channel: ch,
			Data:    schema,
		}
		// Enrich with minute rate.
		channel, _ := live.ParseChannel(managedChannel.Channel)
		prefix := channel.Scope + "/" + channel.Namespace
		r.mu.RLock()
		namespaceStream, ok := r.streams[ns][prefix]
		r.mu.RUnlock()
		if ok {
			managedChannel.MinuteRate = namespaceStream.minuteRate(channel.Path)
		}
		channels = append(channels, managedChannel)
	}

	// Hardcode sample streams
	frameJSON, err := data.FrameToJSON(data.NewFrame("testdata",
		data.NewField("Time", nil, make([]time.Time, 0)),
		data.NewField("Value", nil, make([]float64, 0)),
		data.NewField("Min", nil, make([]float64, 0)),
		data.NewField("Max", nil, make([]float64, 0)),
	), data.IncludeSchemaOnly)
	if err == nil {
		channels = append(channels, &ManagedChannel{
			Channel:    "plugin/testdata/random-2s-stream",
			Data:       frameJSON,
			MinuteRate: 30,
		}, &ManagedChannel{
			Channel:    "plugin/testdata/random-flakey-stream",
			Data:       frameJSON,
			MinuteRate: 150,
		}, &ManagedChannel{
			Channel:    "plugin/testdata/random-labeled-stream",
			Data:       frameJSON,
			MinuteRate: 250,
		}, &ManagedChannel{
			Channel:    "plugin/testdata/random-20Hz-stream",
			Data:       frameJSON,
			MinuteRate: 1200,
		})
	}

	sort.Slice(channels, func(i, j int) bool {
		return channels[i].Channel < channels[j].Channel
	})

	return channels, nil
}

// GetOrCreateStream -- for now this will create new manager for each key.
// Eventually, the stream behavior will need to be configured explicitly.
// Returns ErrStreamLimitExceeded when the namespace already holds
// MaxStreamsPerNamespace streams and none has been idle for IdleEvictionTimeout.
func (r *Runner) GetOrCreateStream(ns string, scope string, stream string) (*Stream, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	streams, ok := r.streams[ns]
	if !ok {
		streams = map[string]*Stream{}
	}
	prefix := scope + "/" + stream
	if s, ok := streams[prefix]; ok {
		return s, nil
	}
	if !makeStreamRoom(streams, time.Now()) {
		return nil, ErrStreamLimitExceeded
	}
	s := NewStream(ns, scope, stream, r.publisher, r.localPublisher, r.frameCache)
	streams[prefix] = s
	r.streams[ns] = streams
	return s, nil
}

// GetStream returns the registered stream, or an unregistered one when none
// exists. Use it on read paths such as subscribe, which must not register
// streams on behalf of callers that cannot push to them.
func (r *Runner) GetStream(ns string, scope string, stream string) *Stream {
	r.mu.RLock()
	s, ok := r.streams[ns][scope+"/"+stream]
	r.mu.RUnlock()
	if ok {
		return s
	}
	return NewStream(ns, scope, stream, r.publisher, r.localPublisher, r.frameCache)
}

func makeStreamRoom(streams map[string]*Stream, now time.Time) bool {
	if len(streams) < MaxStreamsPerNamespace {
		return true
	}
	var oldestPrefix string
	var oldest int64
	found := false
	for prefix, s := range streams {
		lastPush := s.lastPush.Load()
		if !found || lastPush < oldest {
			oldestPrefix, oldest, found = prefix, lastPush, true
		}
	}
	if !found || now.Sub(time.Unix(0, oldest)) < IdleEvictionTimeout {
		return false
	}
	delete(streams, oldestPrefix)
	return true
}

// Stream holds the state of a managed stream.
type Stream struct {
	ns             string // k8s namespace, maps to org id / stack id in grafana
	scope          string
	stream         string // within a scope, maps to the Grafana live "namespace"
	publisher      model.ChannelPublisher
	localPublisher LocalPublisher
	frameCache     FrameCache
	rateMu         sync.RWMutex
	rates          map[string][60]rateEntry
	// lastPush is the UnixNano time of creation or of the last successful push.
	lastPush atomic.Int64
}

type rateEntry struct {
	time  uint32
	count int32
}

// ManagedChannel represents a managed stream.
type ManagedChannel struct {
	Channel    string          `json:"channel"`
	MinuteRate int64           `json:"minute_rate"`
	Data       json.RawMessage `json:"data"`
}

// NewStream creates new NewStream.
func NewStream(ns string, scope string, stream string, publisher model.ChannelPublisher, localPublisher LocalPublisher, schemaUpdater FrameCache) *Stream {
	s := &Stream{
		ns:             ns,
		scope:          scope,
		stream:         stream,
		publisher:      publisher,
		localPublisher: localPublisher,
		frameCache:     schemaUpdater,
		rates:          map[string][60]rateEntry{},
	}
	s.lastPush.Store(time.Now().UnixNano())
	return s
}

// Push sends frame to the stream and saves it for later retrieval by subscribers.
// * Saves the entire frame to cache.
// * If schema has been changed sends entire frame to channel, otherwise only data.
// * If publishing a new or changed schema fails, the cached frame is dropped so
// the next push sends the full frame again.
func (s *Stream) Push(ctx context.Context, path string, frame *data.Frame) error {
	jsonFrameCache, err := data.FrameToJSONCache(frame)
	if err != nil {
		return err
	}

	// The channel this will be posted into.
	channel := live.Channel{Scope: s.scope, Namespace: s.stream, Path: path}.String()

	isUpdated, err := s.frameCache.Update(ctx, s.ns, channel, jsonFrameCache)
	if err != nil {
		logger.Error("Error updating managed stream schema", "error", err)
		return err
	}

	// When the schema has not changed, just send the data.
	include := data.IncludeDataOnly
	if isUpdated {
		// When the schema has been changed, send all.
		include = data.IncludeAll
	}
	frameJSON := jsonFrameCache.Bytes(include)

	logger.Debug("Publish data to channel", "channel", channel, "dataLength", len(frameJSON))
	if s.scope == live.ScopeDatasource || s.scope == live.ScopePlugin {
		err = s.localPublisher.PublishLocal(orgchannel.PrependK8sNamespace(s.ns, channel), frameJSON)
	} else {
		err = s.publisher(s.ns, channel, frameJSON)
	}
	if err != nil {
		if isUpdated {
			if delErr := s.frameCache.Delete(ctx, s.ns, channel); delErr != nil {
				logger.Error("Error removing unpublished frame from cache", "error", delErr, "channel", channel)
			}
		}
		return err
	}
	now := time.Now()
	s.lastPush.Store(now.UnixNano())
	s.incRate(path, now.Unix())
	return nil
}

func (s *Stream) incRate(path string, nowUnix int64) {
	s.rateMu.Lock()
	pathRate, ok := s.rates[path]
	if !ok {
		if len(s.rates) >= MaxChannelsPerNamespace {
			s.pruneRatesLocked(nowUnix)
		}
		if len(s.rates) >= MaxChannelsPerNamespace {
			s.rateMu.Unlock()
			return
		}
		pathRate = [60]rateEntry{}
	}
	now := time.Unix(nowUnix, 0)
	slot := now.Second() % 60
	if pathRate[slot].time != uint32(nowUnix) {
		pathRate[slot].count = 0
	}
	pathRate[slot].time = uint32(nowUnix)
	pathRate[slot].count += 1
	s.rates[path] = pathRate
	s.rateMu.Unlock()
}

// pruneRatesLocked drops paths with no pushes in the last minute; they no
// longer contribute to minuteRate.
func (s *Stream) pruneRatesLocked(nowUnix int64) {
	for path, pathRate := range s.rates {
		active := false
		for _, val := range pathRate {
			if int64(val.time) > nowUnix-60 {
				active = true
				break
			}
		}
		if !active {
			delete(s.rates, path)
		}
	}
}

func (s *Stream) minuteRate(path string) int64 {
	var total int64
	s.rateMu.RLock()
	defer s.rateMu.RUnlock()
	pathRate, ok := s.rates[path]
	if !ok {
		return 0
	}
	for _, val := range pathRate {
		if val.time > uint32(time.Now().Unix()-60) {
			total += int64(val.count)
		}
	}
	return total
}

func (s *Stream) GetHandlerForPath(_ string) (model.ChannelHandler, error) {
	return s, nil
}

func (s *Stream) OnSubscribe(ctx context.Context, u identity.Requester, e model.SubscribeEvent) (model.SubscribeReply, backend.SubscribeStreamStatus, error) {
	reply := model.SubscribeReply{}
	frameJSON, ok, err := s.frameCache.GetFrame(ctx, u.GetNamespace(), e.Channel)
	if err != nil {
		return reply, 0, err
	}
	if ok {
		reply.Data = frameJSON
	}
	return reply, backend.SubscribeStreamStatusOK, nil
}

func (s *Stream) OnPublish(_ context.Context, _ identity.Requester, _ model.PublishEvent) (model.PublishReply, backend.PublishStreamStatus, error) {
	return model.PublishReply{}, backend.PublishStreamStatusPermissionDenied, nil
}
