package loginattemptimpl

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/loginattempt"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
)

func TestService_ReserveUser(t *testing.T) {
	const maxInvalidLoginAttempts = 5

	testCases := []struct {
		name                      string
		loginAttempts             int64
		disableProtection         bool
		disableUsernameProtection bool
		expected                  bool
		expectedErr               error
	}{
		{
			name:          "Should be valid when brute force protection enabled and user login attempt count is less than max",
			loginAttempts: maxInvalidLoginAttempts - 1,
			expected:      true,
			expectedErr:   nil,
		},
		{
			name:          "Should be invalid when brute force protection enabled and user login attempt count equals max",
			loginAttempts: maxInvalidLoginAttempts,
			expected:      false,
			expectedErr:   nil,
		},
		{
			name:          "Should be invalid when brute force protection enabled and user login attempt count is greater than max",
			loginAttempts: maxInvalidLoginAttempts + 1,
			expected:      false,
			expectedErr:   nil,
		},

		{
			name:              "Should be valid when brute force protection disabled and user login attempt count is less than max",
			loginAttempts:     maxInvalidLoginAttempts - 1,
			disableProtection: true,
			expected:          true,
			expectedErr:       nil,
		},
		{
			name:              "Should be valid when brute force protection disabled and user login attempt count equals max",
			loginAttempts:     maxInvalidLoginAttempts,
			disableProtection: true,
			expected:          true,
			expectedErr:       nil,
		},
		{
			name:              "Should be valid when brute force protection disabled and user login attempt count is greater than max",
			loginAttempts:     maxInvalidLoginAttempts + 1,
			disableProtection: true,
			expected:          true,
			expectedErr:       nil,
		},
		{
			name:                      "Should be valid when brute force username protection disabled and user login attempt count is less than max",
			loginAttempts:             maxInvalidLoginAttempts - 1,
			disableUsernameProtection: true,
			expected:                  true,
			expectedErr:               nil,
		},
		{
			name:                      "Should be valid when brute force username protection disabled and user login attempt count equals max",
			loginAttempts:             maxInvalidLoginAttempts,
			disableUsernameProtection: true,
			expected:                  true,
			expectedErr:               nil,
		},
		{
			name:                      "Should be valid when brute force username protection disabled and user login attempt count is greater than max",
			loginAttempts:             maxInvalidLoginAttempts + 1,
			disableUsernameProtection: true,
			expected:                  true,
			expectedErr:               nil,
		},
		{
			name:                      "Should be valid when both brute force protections disabled and user login attempt count is less than max",
			loginAttempts:             maxInvalidLoginAttempts - 1,
			disableProtection:         true,
			disableUsernameProtection: true,
			expected:                  true,
			expectedErr:               nil,
		},
		{
			name:                      "Should be valid when both brute force protections disabled and user login attempt count equals max",
			loginAttempts:             maxInvalidLoginAttempts,
			disableProtection:         true,
			disableUsernameProtection: true,
			expected:                  true,
			expectedErr:               nil,
		},
		{
			name:                      "Should be valid when both brute force protections disabled and user login attempt count is greater than max",
			loginAttempts:             maxInvalidLoginAttempts + 1,
			disableProtection:         true,
			disableUsernameProtection: true,
			expected:                  true,
			expectedErr:               nil,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := setting.NewCfg()
			cfg.BruteForceLoginProtectionMaxAttempts = maxInvalidLoginAttempts
			cfg.DisableBruteForceLoginProtection = tt.disableProtection
			cfg.DisableUsernameLoginProtection = tt.disableUsernameProtection
			cfg.DisableIPAddressLoginProtection = true
			service := &Service{
				store: fakeStore{
					// the count includes the attempt being reserved
					ExpectedCount: tt.loginAttempts + 1,
				},
				cfg: cfg,
			}

			_, err := service.Reserve(context.Background(), "test", "192.168.1.1")
			if tt.expected {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, loginattempt.ErrTooManyUserAttempts)
			}
		})
	}
}

func TestIntegrationUserLoginAttempts(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	ctx := context.Background()
	cfg := setting.NewCfg()
	cfg.DisableBruteForceLoginProtection = false
	cfg.DisableUsernameLoginProtection = false
	cfg.DisableIPAddressLoginProtection = true
	cfg.BruteForceLoginProtectionMaxAttempts = 5
	db := db.InitTestDB(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	service := ProvideService(db, cfg, nil)

	// reserve multiple login attempts with different uppercases, they all should be counted as the same user
	for _, username := range []string{"admin", "Admin", "aDmin", "adMin", "admIn"} {
		_, err := service.Reserve(ctx, username, "[::1]")
		assert.NoError(t, err)
	}

	// the attempt over the limit is rejected and not recorded
	_, err := service.Reserve(ctx, "admIN", "[::1]")
	assert.ErrorIs(t, err, loginattempt.ErrTooManyUserAttempts)

	count, err := service.store.GetUserLoginAttemptCount(ctx, GetUserLoginAttemptCountQuery{Username: "admin"})
	assert.Nil(t, err)
	assert.Equal(t, int64(5), count)

	// a released attempt no longer counts towards the limit
	id, err := service.Reserve(ctx, "other", "[::1]")
	assert.NoError(t, err)
	assert.NoError(t, service.Release(ctx, id))
	count, err = service.store.GetUserLoginAttemptCount(ctx, GetUserLoginAttemptCountQuery{Username: "other"})
	assert.Nil(t, err)
	assert.Equal(t, int64(0), count)
}

func TestService_ReserveIPAddress(t *testing.T) {
	const maxInvalidLoginAttempts = 5

	testCases := []struct {
		name                string
		loginAttempts       int64
		disableProtection   bool
		disableIPProtection bool
		expected            bool
		expectedErr         error
	}{
		{
			name:          "Should be valid when brute force protection enabled and IP address login attempt count is less than max",
			loginAttempts: maxInvalidLoginAttempts - 1,
			expected:      true,
			expectedErr:   nil,
		},
		{
			name:          "Should be invalid when brute force protection enabled and IP address login attempt count equals max",
			loginAttempts: maxInvalidLoginAttempts,
			expected:      false,
			expectedErr:   nil,
		},
		{
			name:          "Should be invalid when brute force protection enabled and IP address login attempt count is greater than max",
			loginAttempts: maxInvalidLoginAttempts + 1,
			expected:      false,
			expectedErr:   nil,
		},
		{
			name:              "Should be valid when brute force protection disabled and IP address login attempt count is less than max",
			loginAttempts:     maxInvalidLoginAttempts - 1,
			disableProtection: true,
			expected:          true,
			expectedErr:       nil,
		},
		{
			name:              "Should be valid when brute force protection disabled and IP address login attempt count equals max",
			loginAttempts:     maxInvalidLoginAttempts,
			disableProtection: true,
			expected:          true,
			expectedErr:       nil,
		},
		{
			name:              "Should be valid when brute force protection disabled and IP address login attempt count is greater than max",
			loginAttempts:     maxInvalidLoginAttempts + 1,
			disableProtection: true,
			expected:          true,
			expectedErr:       nil,
		},
		{
			name:                "Should be valid when IP brute force protection disabled and IP address login attempt count is less than max",
			loginAttempts:       maxInvalidLoginAttempts - 1,
			disableIPProtection: true,
			expected:            true,
			expectedErr:         nil,
		},
		{
			name:                "Should be valid when IP brute force protection disabled and IP address login attempt count equals max",
			loginAttempts:       maxInvalidLoginAttempts,
			disableIPProtection: true,
			expected:            true,
			expectedErr:         nil,
		},
		{
			name:                "Should be valid when IP brute force protection disabled and IP address login attempt count is greater than max",
			loginAttempts:       maxInvalidLoginAttempts + 1,
			disableIPProtection: true,
			expected:            true,
			expectedErr:         nil,
		},
		{
			name:                "Should be valid when both brute force protections disabled and IP address login attempt count is less than max",
			loginAttempts:       maxInvalidLoginAttempts - 1,
			disableProtection:   true,
			disableIPProtection: true,
			expected:            true,
			expectedErr:         nil,
		},
		{
			name:                "Should be valid when both brute force protections disabled and IP address login attempt count equals max",
			loginAttempts:       maxInvalidLoginAttempts,
			disableProtection:   true,
			disableIPProtection: true,
			expected:            true,
			expectedErr:         nil,
		},
		{
			name:                "Should be valid when both brute force protections disabled and IP address login attempt count is greater than max",
			loginAttempts:       maxInvalidLoginAttempts + 1,
			disableProtection:   true,
			disableIPProtection: true,
			expected:            true,
			expectedErr:         nil,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := setting.NewCfg()
			cfg.BruteForceLoginProtectionMaxAttempts = maxInvalidLoginAttempts
			cfg.DisableBruteForceLoginProtection = tt.disableProtection
			cfg.DisableIPAddressLoginProtection = tt.disableIPProtection
			cfg.DisableUsernameLoginProtection = true
			service := &Service{
				store: fakeStore{
					// the count includes the attempt being reserved
					ExpectedCount: tt.loginAttempts + 1,
				},
				cfg: cfg,
			}

			_, err := service.Reserve(context.Background(), "test", "192.168.1.1")
			if tt.expected {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, loginattempt.ErrTooManyIPAttempts)
			}
		})
	}
}

func TestIntegrationIPLoginAttempts(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	ctx := context.Background()
	cfg := setting.NewCfg()
	cfg.DisableBruteForceLoginProtection = false
	cfg.DisableIPAddressLoginProtection = false
	cfg.BruteForceLoginProtectionMaxAttempts = 3
	db := db.InitTestDB(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	service := ProvideService(db, cfg, nil)

	for _, a := range []struct{ username, ip string }{
		{"user1", "192.168.1.1"},
		{"user2", "10.0.0.123"},
		{"user3", "192.168.1.1"},
		{"user4", "[::1]"},
		{"user5", "192.168.1.1"},
	} {
		_, err := service.Reserve(ctx, a.username, a.ip)
		assert.NoError(t, err)
	}

	// the attempt over the limit is rejected and not recorded
	_, err := service.Reserve(ctx, "user6", "192.168.1.1")
	assert.ErrorIs(t, err, loginattempt.ErrTooManyIPAttempts)

	count, err := service.store.GetIPLoginAttemptCount(ctx, GetIPLoginAttemptCountQuery{IPAddress: "192.168.1.1"})
	assert.Nil(t, err)
	assert.Equal(t, int64(3), count)
}

// TestIPv6AddressSupport verifies that various IPv6 address formats can be stored properly with the new column length, testing various IPv6 address formats that could be encountered.
// This test validates that the ip_address column length is sufficient for IPv6 addresses
func TestIntegrationIPv6AddressSupport(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	ctx := context.Background()
	cfg := setting.NewCfg()
	cfg.DisableBruteForceLoginProtection = false
	cfg.DisableIPAddressLoginProtection = false
	cfg.BruteForceLoginProtectionMaxAttempts = 5

	// Use controlled time like other tests to avoid timestamp conversion issues
	testTime := time.Date(2023, 10, 22, 8, 0, 0, 0, time.UTC)
	store := &xormStore{
		db:  db.InitTestDB(t), //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
		now: func() time.Time { return testTime },
	}
	service := &Service{
		store:  store,
		cfg:    cfg,
		logger: log.New("test.login_attempt"),
	}

	// Test various IPv6 address formats that should be supported
	ipv6Addresses := []string{
		"::1",           // loopback (3 chars)
		"2001:db8::1",   // shortened (12 chars)
		"[::1]",         // bracketed loopback (5 chars)
		"[2001:db8::1]", // bracketed shortened (14 chars)
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334",   // full IPv6 (39 chars)
		"[2001:0db8:85a3:0000:0000:8a2e:0370:7334]", // bracketed full IPv6 (41 chars)
		"2001:db8:85a3:8d3:1319:8a2e:370:7348",      // mixed case (34 chars)
		"[2001:db8:85a3:8d3:1319:8a2e:370:7348]",    // bracketed mixed (36 chars)
		"aaaa:79c0:647:bd00:4c59:2f13:3da6:aaaa",    // from the GitHub issue (35 chars)
		"[aaaa:79c0:647:bd00:4c59:2f13:3da6:aaaa]",  // bracketed from issue (37 chars)
	}

	for i, ipAddress := range ipv6Addresses {
		t.Run("IPv6_Address_"+ipAddress, func(t *testing.T) {
			username := fmt.Sprintf("testuser%d", i)

			// Verify that the address length is within our new limit of 50 characters
			assert.LessOrEqual(t, len(ipAddress), 50, "IP address should fit in VARCHAR(50)")

			// Test that we can reserve login attempts with this IPv6 address
			_, err := service.Reserve(ctx, username, ipAddress)
			assert.NoError(t, err, "Should be able to reserve login attempt with IPv6 address: %s", ipAddress)

			// Verify that the login attempt was stored correctly
			count, err := store.GetIPLoginAttemptCount(ctx, GetIPLoginAttemptCountQuery{
				IPAddress: ipAddress,
				Since:     testTime.Add(-time.Minute * 5),
			})
			assert.NoError(t, err, "Should be able to query login attempts for IPv6 address: %s", ipAddress)
			assert.Equal(t, int64(1), count, "Should have 1 login attempt for IPv6 address: %s", ipAddress)
		})
	}
}

var _ store = new(fakeStore)

type fakeStore struct {
	ExpectedErr         error
	ExpectedCount       int64
	ExpectedDeletedRows int64
}

func (f fakeStore) GetUserLoginAttemptCount(ctx context.Context, query GetUserLoginAttemptCountQuery) (int64, error) {
	return f.ExpectedCount, f.ExpectedErr
}

func (f fakeStore) GetIPLoginAttemptCount(ctx context.Context, query GetIPLoginAttemptCountQuery) (int64, error) {
	return f.ExpectedCount, f.ExpectedErr
}

func (f fakeStore) CreateLoginAttempt(ctx context.Context, command CreateLoginAttemptCommand) (loginattempt.LoginAttempt, error) {
	return loginattempt.LoginAttempt{}, f.ExpectedErr
}

func (f fakeStore) DeleteOldLoginAttempts(ctx context.Context, command DeleteOldLoginAttemptsCommand) (int64, error) {
	return f.ExpectedDeletedRows, f.ExpectedErr
}

func (f fakeStore) DeleteLoginAttempts(ctx context.Context, command DeleteLoginAttemptsCommand) error {
	return f.ExpectedErr
}

func (f fakeStore) DeleteLoginAttempt(ctx context.Context, id int64) error {
	return f.ExpectedErr
}
