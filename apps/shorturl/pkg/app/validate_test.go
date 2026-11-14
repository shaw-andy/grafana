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

	// These are same-server GET routes that change the caller's session or data.
	// A short URL may only navigate to a read-only page.
	sessionChangingPaths := []string{
		"logout",
		"logout?continue=1",
		"  logout",
		"profile/switch-org/2",
		"profile/switch-org/2?foo=1",
		"user/auth-tokens/rotate",
		"user/auth-tokens/rotate?redirectTo=/",
		"api/snapshots-delete/example-delete-key",
		"user/email/update?code=example",
		"api/user/invite/complete",
	}
	for _, p := range sessionChangingPaths {
		t.Run("rejects session-changing path: "+p, func(t *testing.T) {
			err := validateRelativePath(p)
			require.Error(t, err)
		})
	}
}
