package pipeline

import (
	"context"
	"fmt"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana-plugin-sdk-go/live"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/live/managedstream"
)

const maxManagedStreamOutputChannels = 64

func TestManagedStreamFrameOutputRetention(t *testing.T) {
	ctx := context.Background()
	cache := managedstream.NewMemoryFrameCache()
	runner := managedstream.NewRunner(func(string, string, []byte) error { return nil }, nil, cache)
	output := NewManagedStreamFrameOutput(runner)

	for i := 0; i < maxManagedStreamOutputChannels+8; i++ {
		path := fmt.Sprintf("m%d", i)
		_, err := output.OutputFrame(ctx, Vars{
			NS:     "default",
			Scope:  live.ScopeStream,
			Stream: fmt.Sprintf("s%d", i),
			Path:   path,
		}, data.NewFrame(path))
		if err != nil {
			channels, getErr := cache.GetActiveChannels("default")
			require.NoError(t, getErr)
			_, kept := channels[fmt.Sprintf("stream/s%d/%s", i, path)]
			require.Falsef(t, kept, "frame stored after OutputFrame failed")
		}
	}

	channels, err := cache.GetActiveChannels("default")
	require.NoError(t, err)
	require.LessOrEqualf(t, len(channels), maxManagedStreamOutputChannels,
		"managed stream output kept %d channels", len(channels))
}
