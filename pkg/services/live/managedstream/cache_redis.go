package managedstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/grafana/grafana-plugin-sdk-go/data"

	"github.com/grafana/grafana/pkg/services/live/orgchannel"
)

// RedisFrameCache ...
type RedisFrameCache struct {
	mu          sync.RWMutex
	redisClient *redis.Client
	frames      map[string]map[string]*cachedFrame
	keyPrefix   string
}

// NewRedisFrameCache ...
func NewRedisFrameCache(redisClient *redis.Client, keyPrefix string) *RedisFrameCache {
	return &RedisFrameCache{
		keyPrefix:   keyPrefix,
		frames:      map[string]map[string]*cachedFrame{},
		redisClient: redisClient,
	}
}

func (c *RedisFrameCache) GetActiveChannels(ns string) (map[string]json.RawMessage, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	frames, ok := c.frames[ns]
	if !ok {
		return nil, nil
	}
	return activeChannels(frames), nil
}

func (c *RedisFrameCache) GetFrame(ctx context.Context, ns string, channel string) (json.RawMessage, bool, error) {
	key := c.getCacheKey(orgchannel.PrependK8sNamespace(ns, channel))
	cmd := c.redisClient.HGetAll(ctx, key)
	result, err := cmd.Result()
	if err != nil {
		return nil, false, err
	}
	if len(result) == 0 {
		return nil, false, nil
	}
	return json.RawMessage(result["frame"]), true, nil
}

const (
	frameCacheTTL = 7 * 24 * time.Hour
)

// reserve claims a slot for channel in the local map before it is written to
// Redis, so the namespace limit also bounds the keys written to Redis.
func (c *RedisFrameCache) reserve(ns string, channel string) (*cachedFrame, error) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	frames, ok := c.frames[ns]
	if !ok {
		frames = map[string]*cachedFrame{}
	}
	if existing, ok := frames[channel]; ok {
		if !existing.pending {
			existing.updatedAt = now
		}
		return nil, nil
	}
	if !makeRoom(frames, now) {
		return nil, ErrChannelLimitExceeded
	}
	c.frames[ns] = frames
	reservation := &cachedFrame{updatedAt: now, pending: true}
	frames[channel] = reservation
	return reservation, nil
}

func (c *RedisFrameCache) release(ns string, channel string, reservation *cachedFrame) {
	if reservation == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.frames[ns][channel] == reservation {
		c.deleteLocked(ns, channel)
	}
}

func (c *RedisFrameCache) commit(ns string, channel string, jsonFrame data.FrameJSONCache) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	frames, ok := c.frames[ns]
	if !ok {
		frames = map[string]*cachedFrame{}
	}
	if _, ok := frames[channel]; !ok && !makeRoom(frames, now) {
		return
	}
	c.frames[ns] = frames
	frames[channel] = &cachedFrame{frame: jsonFrame, updatedAt: now}
}

func (c *RedisFrameCache) deleteLocked(ns string, channel string) {
	frames, ok := c.frames[ns]
	if !ok {
		return
	}
	delete(frames, channel)
	if len(frames) == 0 {
		delete(c.frames, ns)
	}
}

func (c *RedisFrameCache) Update(ctx context.Context, ns string, channel string, jsonFrame data.FrameJSONCache) (bool, error) {
	reservation, err := c.reserve(ns, channel)
	if err != nil {
		return false, err
	}

	schemaUpdated, err := c.updateRedis(ctx, ns, channel, jsonFrame)
	if err != nil {
		c.release(ns, channel, reservation)
		return false, err
	}
	c.commit(ns, channel, jsonFrame)
	return schemaUpdated, nil
}

func (c *RedisFrameCache) updateRedis(ctx context.Context, ns string, channel string, jsonFrame data.FrameJSONCache) (bool, error) {
	stringSchema := string(jsonFrame.Bytes(data.IncludeSchemaOnly))

	key := c.getCacheKey(orgchannel.PrependK8sNamespace(ns, channel))

	var mapReply *redis.MapStringStringCmd
	replies, err := c.redisClient.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		mapReply = pipe.HGetAll(ctx, key)
		pipe.HMSet(ctx, key, map[string]string{
			"schema": stringSchema,
			"frame":  string(jsonFrame.Bytes(data.IncludeAll)),
		})
		pipe.Expire(ctx, key, frameCacheTTL)
		return nil
	})
	if err != nil {
		return false, err
	}
	if len(replies) == 0 {
		return false, errors.New("no replies in response")
	}
	if mapReply.Err() != nil {
		return false, fmt.Errorf("error getting existing frame from redis: %w", mapReply.Err())
	}

	result, err := mapReply.Result()
	if err != nil {
		return false, err
	}
	if len(result) == 0 {
		return true, nil
	}
	return result["schema"] != stringSchema, nil
}

func (c *RedisFrameCache) Delete(ctx context.Context, ns string, channel string) error {
	c.mu.Lock()
	c.deleteLocked(ns, channel)
	c.mu.Unlock()
	key := c.getCacheKey(orgchannel.PrependK8sNamespace(ns, channel))
	return c.redisClient.Del(ctx, key).Err()
}

func (c *RedisFrameCache) getCacheKey(channelID string) string {
	return c.keyPrefix + ".managed_stream." + channelID
}
