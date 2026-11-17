package managedstream

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/data"
)

const (
	// MaxStreamsPerNamespace is the number of managed streams kept per namespace.
	MaxStreamsPerNamespace = 32
	// MaxChannelsPerNamespace is the number of channel frames kept per namespace.
	MaxChannelsPerNamespace = 64
	// MaxFramesPerPush is the number of frames a single push request may produce.
	MaxFramesPerPush = 32
	// IdleEvictionTimeout is how long a stream or channel must go without a push
	// before a new one may take its place once the namespace limit is reached.
	IdleEvictionTimeout = 10 * time.Minute
)

var (
	ErrStreamLimitExceeded  = errors.New("managed stream limit exceeded for namespace")
	ErrChannelLimitExceeded = errors.New("managed stream channel limit exceeded for namespace")
)

// FrameCache allows updating frame schema. Returns true is schema not changed.
type FrameCache interface {
	// GetActiveChannels returns active managed stream channels with JSON schema.
	GetActiveChannels(ns string) (map[string]json.RawMessage, error)
	// GetFrame returns full JSON frame for a channel in org.
	GetFrame(ctx context.Context, ns string, channel string) (json.RawMessage, bool, error)
	// Update updates frame cache and returns true if schema changed.
	// Returns ErrChannelLimitExceeded without storing the frame when the
	// namespace has no room for a new channel.
	Update(ctx context.Context, ns string, channel string, frameJson data.FrameJSONCache) (bool, error)
	// Delete removes the frame for a channel in org.
	Delete(ctx context.Context, ns string, channel string) error
}

type cachedFrame struct {
	frame     data.FrameJSONCache
	updatedAt time.Time
	// pending marks a channel reserved while its first write is in flight.
	pending bool
}

// makeRoom ensures frames can take one more channel. When the namespace is
// full, the least recently updated channel is evicted only if it has been idle
// for IdleEvictionTimeout, so active channels cannot be pushed out.
func makeRoom(frames map[string]*cachedFrame, now time.Time) bool {
	if len(frames) < MaxChannelsPerNamespace {
		return true
	}
	var oldestChannel string
	var oldest time.Time
	found := false
	for channel, f := range frames {
		if f.pending {
			continue
		}
		if !found || f.updatedAt.Before(oldest) {
			oldestChannel, oldest, found = channel, f.updatedAt, true
		}
	}
	if !found || now.Sub(oldest) < IdleEvictionTimeout {
		return false
	}
	delete(frames, oldestChannel)
	return true
}

func activeChannels(frames map[string]*cachedFrame) map[string]json.RawMessage {
	info := make(map[string]json.RawMessage, len(frames))
	for k, v := range frames {
		if v.pending {
			continue
		}
		info[k] = v.frame.Bytes(data.IncludeSchemaOnly)
	}
	return info
}
