package resource

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContainsSearchQuery(t *testing.T) {
	tests := []struct {
		text     string
		expected string
	}{
		{text: "cpu", expected: "*cpu*"},
		{text: "cpu usage", expected: "*cpu usage*"},
		{text: "cpu*usage?", expected: "*cpuusage*"},
		{text: `\*`, expected: `*\*`},
		{text: "*", expected: ""},
		{text: strings.Repeat("?", 100), expected: ""},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			got, err := ContainsSearchQuery(tt.text)
			require.NoError(t, err)
			require.Equal(t, tt.expected, got)
		})
	}

	got, err := ContainsSearchQuery(strings.Repeat("a", MaxSearchTextLength))
	require.NoError(t, err)
	require.Len(t, got, MaxSearchQueryLength)

	_, err = ContainsSearchQuery(strings.Repeat("a", MaxSearchTextLength+1))
	require.ErrorIs(t, err, ErrSearchQueryTooLong)
}

func TestNormalizeSearchQuery(t *testing.T) {
	tests := []struct {
		query    string
		expected string
	}{
		{query: "cpu", expected: "cpu"},
		{query: "cpu*", expected: "cpu*"},
		{query: "*cpu", expected: "*cpu"},
		{query: "*cpu*", expected: "*cpu*"},
		{query: "**cpu**", expected: "*cpu*"},
		{query: "cpu*usage?", expected: "cpuusage"},
		{query: "*a?c?", expected: "*ac"},
		{query: "*", expected: ""},
		{query: strings.Repeat("*", 256), expected: ""},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			got, err := NormalizeSearchQuery(tt.query)
			require.NoError(t, err)
			require.Equal(t, tt.expected, got)
			require.NoError(t, ValidateWildcardPattern(got))
		})
	}

	_, err := NormalizeSearchQuery(strings.Repeat("*", MaxSearchQueryLength+1))
	require.ErrorIs(t, err, ErrSearchQueryTooLong)
}

func TestValidateWildcardPattern(t *testing.T) {
	for _, pattern := range []string{"cpu", "*", "**", "cpu*", "*cpu", "*cpu*"} {
		require.NoError(t, ValidateWildcardPattern(pattern), pattern)
	}
	for _, pattern := range []string{"cpu*usage", "*a*b*", "***", "*cpu?*", strings.Repeat("a", MaxSearchQueryLength+1)} {
		require.Error(t, ValidateWildcardPattern(pattern), pattern)
	}
}
