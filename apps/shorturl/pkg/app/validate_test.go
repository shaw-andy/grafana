package app

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRelativePath(t *testing.T) {
	validPaths := []string{
		"d/TxKARsmGz/new-dashboard?orgId=1",
		"mock/path?test=true",
		"d/abc123/my-dashboard",
		"explore?left=...",
		"alerting/list",
	}

	for _, p := range validPaths {
		t.Run("valid: "+p, func(t *testing.T) {
			err := validateRelativePath(p)
			assert.NoError(t, err)
		})
	}

	t.Run("rejects absolute path", func(t *testing.T) {
		err := validateRelativePath("/absolute/path")
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrShortURLAbsolutePath))
	})

	t.Run("rejects path traversal", func(t *testing.T) {
		err := validateRelativePath("path/../etc/passwd")
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrShortURLInvalidPath))
	})

	t.Run("rejects protocol-relative URL", func(t *testing.T) {
		err := validateRelativePath("//evil.com/path")
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrShortURLInvalidPath))
	})

	t.Run("rejects backslash prefix", func(t *testing.T) {
		err := validateRelativePath(`\evil.com`)
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrShortURLInvalidPath))
	})

	t.Run("rejects http:// URL", func(t *testing.T) {
		err := validateRelativePath("http://evil.com")
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrShortURLInvalidPath))
	})

	t.Run("rejects https:// URL", func(t *testing.T) {
		err := validateRelativePath("https://evil.com/path")
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrShortURLInvalidPath))
	})

	t.Run("rejects javascript: scheme", func(t *testing.T) {
		err := validateRelativePath("javascript:alert(1)")
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrShortURLInvalidPath))
	})

	// Same gap as pkg/services/shorturls.ValidateRelativePath: only the literal
	// character sequences "../" and "..\" are rejected. Percent-encoded dots are
	// still dot segments once a browser parses the redirect.
	encodedDotPaths := []string{
		"..",
		"%2e%2e",
		"%2e%2e/other-app/action",
		"%2E%2E/other-app/action",
		"%2e./other-app/action",
		".%2e/other-app/action",
		"d/%2e%2e/%2e%2e/other-app/action",
		"%2e%2e%2fother-app/action",
		"..%2fother-app/action",
		"  %2e%2e/other-app/action",
		"%2e%2e/other-app/action?x=1",
	}
	for _, p := range encodedDotPaths {
		t.Run("rejects encoded dot segment: "+p, func(t *testing.T) {
			err := validateRelativePath(p)
			require.Error(t, err)
			require.True(t, errors.Is(err, ErrShortURLInvalidPath))
		})
	}

	t.Run("accepts a percent-encoded dot that is not a dot segment", func(t *testing.T) {
		err := validateRelativePath("d/foo%2ebar/dashboard")
		assert.NoError(t, err)
	})
}
