package testdatasource

import (
	"context"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"
)

// Paths the built-in TestData stream handler is allowed to run. Anything else,
// including a numeric suffix on random-20Hz-stream, must be refused before a
// live subscription is accepted.
var supportedTestDataStreamPaths = []string{
	"random-2s-stream",
	"random-flakey-stream",
	"random-labeled-stream",
	"random-20Hz-stream",
}

func TestSubscribeStreamRefusesUnlistedPaths(t *testing.T) {
	svc := ProvideService()
	ctx := context.Background()

	for _, path := range supportedTestDataStreamPaths {
		t.Run(path, func(t *testing.T) {
			resp, err := svc.SubscribeStream(ctx, &backend.SubscribeStreamRequest{Path: path})
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Equal(t, backend.SubscribeStreamStatusOK, resp.Status)
			require.NotNil(t, resp.InitialData)
		})
	}

	refused := []string{
		"random-20Hz-stream-1",
		"random-20Hz-stream-2",
		"random-20Hz-stream-42",
		"random-20Hz-stream-1-extra",
		"prefix-random-20Hz-stream",
		"random-20Hz-streamX",
		"random-2s-stream-1",
		"random-flakey-stream-9",
		"not-a-stream",
		"custom-labeled",
		"sim",
	}
	for _, path := range refused {
		t.Run(path, func(t *testing.T) {
			resp, err := svc.SubscribeStream(ctx, &backend.SubscribeStreamRequest{Path: path})
			if err != nil {
				require.Nil(t, resp)
				return
			}
			require.NotNil(t, resp)
			require.NotEqual(t, backend.SubscribeStreamStatusOK, resp.Status)
		})
	}
}
