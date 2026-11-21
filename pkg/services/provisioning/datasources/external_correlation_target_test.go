package datasources

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProvisioningExternalCorrelationRejectsSessionURL(t *testing.T) {
	for _, target := range []string{"/logout", "/profile/switch-org/2", "//grafana.example/logout", "javascript:alert(1)"} {
		t.Run(target, func(t *testing.T) {
			_, err := makeCreateCorrelationCommand(context.Background(), map[string]any{
				"type":        "external",
				"label":       "View documentation",
				"description": "opens the vendor documentation",
				"config": map[string]any{
					"field": "message",
					"target": map[string]any{
						"url": target,
					},
				},
			}, "loki-uid", "loki", "", 1)
			require.Error(t, err)
		})
	}
}

func TestProvisioningExternalCorrelationAllowsDifferentHost(t *testing.T) {
	cmd, err := makeCreateCorrelationCommand(context.Background(), map[string]any{
		"type":        "external",
		"label":       "View documentation",
		"description": "opens the vendor documentation",
		"config": map[string]any{
			"field": "message",
			"target": map[string]any{
				"url": "https://docs.example.com/guide",
			},
		},
	}, "loki-uid", "loki", "", 1)
	require.NoError(t, err)
	require.Equal(t, "https://docs.example.com/guide", cmd.Config.Target["url"])
}
