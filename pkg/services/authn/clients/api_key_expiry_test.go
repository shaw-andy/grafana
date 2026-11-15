package clients

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/apikey"
)

func TestValidateApiKeyHonorsStoredUnixExpiry(t *testing.T) {
	saID := int64(1)
	notRevoked := false

	// A stored expiry one second past a one-day lifetime is still in the future,
	// so API-key authentication accepts the key. The day-limit check is what
	// must refuse to store that expiry.
	stillValid := time.Now().Add(24*time.Hour + time.Second).Unix()
	err := validateApiKey(1, &apikey.APIKey{
		OrgID:            1,
		ServiceAccountId: &saID,
		IsRevoked:        &notRevoked,
		Expires:          &stillValid,
	})
	require.NoError(t, err)

	expired := time.Now().Add(-time.Second).Unix()
	err = validateApiKey(1, &apikey.APIKey{
		OrgID:            1,
		ServiceAccountId: &saID,
		IsRevoked:        &notRevoked,
		Expires:          &expired,
	})
	require.ErrorIs(t, err, errAPIKeyExpired)
}
