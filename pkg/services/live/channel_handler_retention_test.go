package live

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/user"
)

const maxCachedChannelHandlers = 64

func TestChannelHandlerRetention(t *testing.T) {
	g, err := setupLiveService(nil, t)
	require.NoError(t, err)

	// Subscribe resolves the stream scope through GetChannelHandler. Any
	// signed-in user can open /api/live/ws; the handler cache has no cap.
	viewer := &user.SignedInUser{
		UserID:    3,
		OrgID:     1,
		OrgRole:   "Viewer",
		Namespace: "default",
	}

	for i := 0; i < maxCachedChannelHandlers+8; i++ {
		channel := fmt.Sprintf("stream/s%d/cpu", i)
		_, _, err := g.GetChannelHandler(t.Context(), viewer, channel)
		if err != nil {
			_, kept := g.channels[channel]
			require.Falsef(t, kept, "handler for %s cached after GetChannelHandler failed", channel)
		}
	}

	require.LessOrEqualf(t, len(g.channels), maxCachedChannelHandlers,
		"channel handler cache kept %d entries", len(g.channels))
}
