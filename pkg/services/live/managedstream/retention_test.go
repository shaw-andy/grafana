package managedstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana-plugin-sdk-go/live"
	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/logging"
	"github.com/stretchr/testify/require"
)

// Retention bounds for managed streams. One organization must not be able to
// keep a new stream, channel, or rate entry for every ID it invents.
const (
	maxStreamsPerNamespace  = 32
	maxChannelsPerNamespace = 64
)

func testFrameJSON(t *testing.T, name string) data.FrameJSONCache {
	t.Helper()
	frame := data.NewFrame(name, data.NewField("value", nil, []float64{1}))
	cached, err := data.FrameToJSONCache(frame)
	require.NoError(t, err)
	return cached
}

func TestMemoryFrameCacheRetention(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryFrameCache()

	// Replacing one channel must not accumulate entries.
	frame := testFrameJSON(t, "cpu")
	for range 10 {
		_, err := cache.Update(ctx, "default", "stream/s/cpu", frame)
		require.NoError(t, err)
	}
	channels, err := cache.GetActiveChannels("default")
	require.NoError(t, err)
	require.Len(t, channels, 1)

	// A second organization is counted on its own.
	_, err = cache.Update(ctx, "org-b", "stream/s/cpu", frame)
	require.NoError(t, err)
	_, err = cache.Update(ctx, "org-b", "stream/s/mem", frame)
	require.NoError(t, err)

	for i := 0; i < maxChannelsPerNamespace+8; i++ {
		channel := fmt.Sprintf("stream/s/m%d", i)
		_, err := cache.Update(ctx, "default", channel, testFrameJSON(t, channel))
		if err != nil {
			channels, getErr := cache.GetActiveChannels("default")
			require.NoError(t, getErr)
			_, kept := channels[channel]
			require.Falsef(t, kept, "channel %s was stored after Update failed", channel)
		}
	}

	channels, err = cache.GetActiveChannels("default")
	require.NoError(t, err)
	other, err := cache.GetActiveChannels("org-b")
	require.NoError(t, err)
	require.Len(t, other, 2, "filling one namespace removed another namespace's frames")
	require.LessOrEqualf(t, len(channels), maxChannelsPerNamespace,
		"memory frame cache kept %d channels for one namespace", len(channels))
}

func TestRunnerStreamRetention(t *testing.T) {
	cache := NewMemoryFrameCache()
	runner := NewRunner(func(string, string, []byte) error { return nil }, nil, cache)

	_, err := runner.GetOrCreateStream("org-b", live.ScopeStream, "steady")
	require.NoError(t, err)

	for i := 0; i < maxStreamsPerNamespace+8; i++ {
		streamID := fmt.Sprintf("s%d", i)
		_, err := runner.GetOrCreateStream("default", live.ScopeStream, streamID)
		if err != nil {
			require.NotContainsf(t, runner.streams["default"], live.ScopeStream+"/"+streamID,
				"stream %s kept after GetOrCreateStream failed", streamID)
		}
	}
	require.Contains(t, runner.streams["org-b"], live.ScopeStream+"/steady",
		"creating streams in default removed org-b")
	require.LessOrEqualf(t, len(runner.streams["default"]), maxStreamsPerNamespace,
		"runner kept %d streams for one namespace", len(runner.streams["default"]))
}

func TestRunnerRateRetention(t *testing.T) {
	ctx := context.Background()
	cache := NewMemoryFrameCache()
	runner := NewRunner(func(string, string, []byte) error { return nil }, nil, cache)

	// Paths that already exist must not grow the rate map when pushed again.
	stream, err := runner.GetOrCreateStream("org-b", live.ScopeStream, "steady")
	require.NoError(t, err)
	for range 10 {
		require.NoError(t, stream.Push(ctx, "cpu", data.NewFrame("cpu")))
	}
	require.Len(t, stream.rates, 1)

	for i := 0; i < maxChannelsPerNamespace+8; i++ {
		path := fmt.Sprintf("m%d", i)
		err := stream.Push(ctx, path, data.NewFrame(path))
		if err != nil {
			require.NotContains(t, stream.rates, path, "rate entry kept after Push failed")
			channels, getErr := cache.GetActiveChannels("org-b")
			require.NoError(t, getErr)
			_, kept := channels["stream/steady/"+path]
			require.Falsef(t, kept, "frame %s stored after Push failed", path)
		}
	}
	require.LessOrEqualf(t, len(stream.rates), maxChannelsPerNamespace,
		"rate map kept %d paths", len(stream.rates))
	channels, err := cache.GetActiveChannels("org-b")
	require.NoError(t, err)
	require.LessOrEqualf(t, len(channels), maxChannelsPerNamespace,
		"push kept %d frames", len(channels))
}

func TestPushDropsFrameWhenPublishFails(t *testing.T) {
	cache := NewMemoryFrameCache()
	stream := NewStream("default", live.ScopeStream, "s", func(string, string, []byte) error {
		return errors.New("publish failed")
	}, nil, cache)

	err := stream.Push(context.Background(), "cpu", data.NewFrame("cpu"))
	require.Error(t, err)

	channels, getErr := cache.GetActiveChannels("default")
	require.NoError(t, getErr)
	_, kept := channels["stream/s/cpu"]
	require.False(t, kept, "frame stayed in the cache after publish failed")
	require.Zero(t, stream.minuteRate("cpu"), "rate entry stayed after publish failed")
	require.Empty(t, stream.rates)
}

func TestRedisFrameCacheLocalMapRetention(t *testing.T) {
	logging.Disable()
	ctx := context.Background()
	// No Redis server: Update still writes the process-local map before the
	// client call, and that map is what GetActiveChannels reads.
	client := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:1",
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("redis unavailable")
		},
		DialerRetries:   1,
		MaxRetries:      -1,
		MinRetryBackoff: -1,
	})
	t.Cleanup(func() { _ = client.Close() })

	cache := NewRedisFrameCache(client, "test")
	keptOnError := 0
	for i := 0; i < maxChannelsPerNamespace+8; i++ {
		channel := fmt.Sprintf("stream/s/m%d", i)
		_, err := cache.Update(ctx, "default", channel, testFrameJSON(t, channel))
		if err != nil {
			channels, getErr := cache.GetActiveChannels("default")
			require.NoError(t, getErr)
			if _, kept := channels[channel]; kept {
				keptOnError++
			}
		}
	}
	require.Zero(t, keptOnError, "redis frame cache kept %d channels after Update failed", keptOnError)

	channels, err := cache.GetActiveChannels("default")
	require.NoError(t, err)
	require.LessOrEqualf(t, len(channels), maxChannelsPerNamespace,
		"redis frame cache local map kept %d channels", len(channels))
}
