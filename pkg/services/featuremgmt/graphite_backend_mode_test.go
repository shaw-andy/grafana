package featuremgmt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGraphiteBackendModeShipsDisabled(t *testing.T) {
	var expression string
	found := false
	for _, flag := range standardFeatureFlags {
		if flag.Name == FlagGraphiteBackendMode {
			found = true
			expression = flag.Expression
		}
	}
	require.True(t, found)
	require.Equal(t, "false", expression)
}
