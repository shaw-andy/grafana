package managedstream

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/data"

	"github.com/grafana/grafana/pkg/infra/log"
)

// MemoryFrameCache ...
type MemoryFrameCache struct {
	mu     sync.RWMutex
	frames map[string]map[string]*cachedFrame
	log    log.Logger
}

// NewMemoryFrameCache ...
func NewMemoryFrameCache() *MemoryFrameCache {
	return &MemoryFrameCache{
		frames: map[string]map[string]*cachedFrame{},
		log:    log.New("live.memoryframecache"),
	}
}

func (c *MemoryFrameCache) GetActiveChannels(ns string) (map[string]json.RawMessage, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	frames, ok := c.frames[ns]
	if !ok {
		return nil, nil
	}
	return activeChannels(frames), nil
}

func (c *MemoryFrameCache) GetFrame(ctx context.Context, ns string, channel string) (json.RawMessage, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cached, ok := c.frames[ns][channel]
	var raw json.RawMessage
	if ok {
		raw = cached.frame.Bytes(data.IncludeAll)
	}
	c.log.Debug("Cache get",
		"ns", ns,
		"channel", channel,
		"length", len(raw),
	)
	return raw, ok, nil
}

func (c *MemoryFrameCache) Update(ctx context.Context, ns string, channel string, jsonFrame data.FrameJSONCache) (bool, error) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	frames, ok := c.frames[ns]
	if !ok {
		frames = map[string]*cachedFrame{}
	}
	cached, exists := frames[channel]
	if !exists && !makeRoom(frames, now) {
		return false, ErrChannelLimitExceeded
	}
	c.frames[ns] = frames
	schemaUpdated := !exists || !cached.frame.SameSchema(&jsonFrame)
	frames[channel] = &cachedFrame{frame: jsonFrame, updatedAt: now}
	c.log.Debug("Cache update",
		"ns", ns,
		"channel", channel,
		"length", len(jsonFrame.Bytes(data.IncludeAll)),
	)
	return schemaUpdated, nil
}

func (c *MemoryFrameCache) Delete(_ context.Context, ns string, channel string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	frames, ok := c.frames[ns]
	if !ok {
		return nil
	}
	delete(frames, channel)
	if len(frames) == 0 {
		delete(c.frames, ns)
	}
	return nil
}
