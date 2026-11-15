package serviceaccounttoken

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	claims "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/configprovider"
	settingsvc "github.com/grafana/grafana/pkg/services/setting"
	"github.com/grafana/grafana/pkg/setting"
)

func TestValidateExpirationRejectsSameUTCDateOverflow(t *testing.T) {
	// 2026-01-01 00:00:01 UTC. A one-day cap ends 2026-01-02 00:00:01 UTC.
	// Flooring both instants to UTC midnight makes that the same calendar date
	// as an expiry as late as 2026-01-02 23:59:59 UTC.
	now := time.Date(2026, time.January, 1, 0, 0, 1, 0, time.UTC)
	const day = int64(24 * 60 * 60)

	tests := []struct {
		name             string
		expiresInSeconds int64
		settings         expirationSettings
		wantError        bool
	}{
		{
			name:             "one day limit rejects one second past the duration",
			expiresInSeconds: day + 1,
			settings:         expirationSettings{apiKeyMaxSecondsToLive: -1, saTokenExpirationDays: 1},
			wantError:        true,
		},
		{
			name:             "one day limit rejects an expiry later on the cap's UTC date",
			expiresInSeconds: int64(time.Date(2026, time.January, 2, 23, 59, 59, 0, time.UTC).Sub(now) / time.Second),
			settings:         expirationSettings{apiKeyMaxSecondsToLive: -1, saTokenExpirationDays: 1},
			wantError:        true,
		},
		{
			name:             "one day limit accepts exactly one day",
			expiresInSeconds: day,
			settings:         expirationSettings{apiKeyMaxSecondsToLive: -1, saTokenExpirationDays: 1},
		},
		{
			name:             "one day limit accepts one second under the duration",
			expiresInSeconds: day - 1,
			settings:         expirationSettings{apiKeyMaxSecondsToLive: -1, saTokenExpirationDays: 1},
		},
		{
			name:             "seven day limit rejects one second past the duration",
			expiresInSeconds: 7*day + 1,
			settings:         expirationSettings{apiKeyMaxSecondsToLive: -1, saTokenExpirationDays: 7},
			wantError:        true,
		},
		{
			name:             "day limit rejects same-date overflow when the api key max is higher",
			expiresInSeconds: day + 1,
			settings:         expirationSettings{apiKeyMaxSecondsToLive: 3 * day, saTokenExpirationDays: 1},
			wantError:        true,
		},
		{
			name:             "api key max still rejects a lifetime the day limit would allow",
			expiresInSeconds: day + 1,
			settings:         expirationSettings{apiKeyMaxSecondsToLive: 3600, saTokenExpirationDays: 2},
			wantError:        true,
		},
		{
			name:             "unset day limit allows a lifetime past one day",
			expiresInSeconds: day + 1,
			settings:         expirationSettings{apiKeyMaxSecondsToLive: -1, saTokenExpirationDays: -1},
		},
		{
			name:             "zero day limit allows a lifetime past one day",
			expiresInSeconds: day + 1,
			settings:         expirationSettings{apiKeyMaxSecondsToLive: -1, saTokenExpirationDays: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExpiration(tt.expiresInSeconds, tt.settings, now)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateExpirationUsesUTCDateNotLocalDate(t *testing.T) {
	// 10:00 at UTC+14 is 20:00 the previous UTC day. One day later at 23:59:59 UTC
	// is still the same UTC date as now+24h, and is more than 24 hours away.
	loc := time.FixedZone("UTC+14", 14*60*60)
	now := time.Date(2026, time.January, 1, 10, 0, 0, 0, loc)
	expiresAt := time.Date(2026, time.January, 1, 23, 59, 59, 0, time.UTC)
	seconds := int64(expiresAt.Sub(now) / time.Second)
	require.Greater(t, seconds, int64(24*60*60))

	err := validateExpiration(seconds, expirationSettings{
		apiKeyMaxSecondsToLive: -1,
		saTokenExpirationDays:  1,
	}, now)
	require.Error(t, err)
}

func TestHandleCreateRejectsSameUTCDateOverflow(t *testing.T) {
	waitOutUTCDateBoundary(t)

	const day = int64(24 * 60 * 60)
	cases := []struct {
		name     string
		days     int
		seconds  int64
		provider *fakeConfigProvider
		settings *fakeSettingService
	}{
		{
			name:    "config provider one day limit and unset api key max",
			days:    1,
			seconds: day + 1,
			provider: &fakeConfigProvider{cfg: &setting.Cfg{
				ApiKeyMaxSecondsToLive:    -1,
				SATokenExpirationDayLimit: 1,
			}},
		},
		{
			name:    "config provider one day limit and higher api key max",
			days:    1,
			seconds: day + 1,
			provider: &fakeConfigProvider{cfg: &setting.Cfg{
				ApiKeyMaxSecondsToLive:    3 * day,
				SATokenExpirationDayLimit: 1,
			}},
		},
		{
			name:    "config provider seven day limit",
			days:    7,
			seconds: 7*day + 1,
			provider: &fakeConfigProvider{cfg: &setting.Cfg{
				ApiKeyMaxSecondsToLive:    -1,
				SATokenExpirationDayLimit: 7,
			}},
		},
		{
			name:    "setting service one day limit",
			days:    1,
			seconds: day + 1,
			settings: &fakeSettingService{settings: []*settingsvc.Setting{
				{Section: serviceAccountsSection, Key: tokenExpirationDayLimitKey, Value: "1"},
			}},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now().UTC()
			store := &fakeLegacyStore{}
			rest := NewTokensREST(nil, store, noop.NewTracerProvider().Tracer("test"), configProvider(tt.provider), settingService(tt.settings))
			body := fmt.Sprintf(`{"tokenName":"day-limit-overflow","expiresInSeconds":%d}`, tt.seconds)
			req, err := http.NewRequest(http.MethodPost, "/tokens", bytes.NewBufferString(body))
			require.NoError(t, err)
			responder := &fakeResponder{}

			rest.handleCreate(context.Background(), claims.NamespaceInfo{OrgID: 1}, "sa-uid", req, responder)

			if store.createCalled {
				require.NotNil(t, store.expires)
				capAt := before.Add(time.Duration(tt.days) * 24 * time.Hour).Unix()
				assert.LessOrEqual(t, *store.expires, capAt, "stored expiry %d is after the %d-day cap %d", *store.expires, tt.days, capAt)
			}
			assert.False(t, store.createCalled, "over-limit token must not be stored")
			require.Error(t, responder.err)
			assert.True(t, apierrors.IsBadRequest(responder.err))
		})
	}
}

func TestHandleCreateRejectsExpiryLaterOnTheLimitUTCDate(t *testing.T) {
	now := time.Now().UTC()
	const days = 1
	seconds, ok := lifetimeUntilLateOnLimitUTCDate(now, days, 30*time.Minute)
	if !ok {
		t.Skip("less than 30 minutes left in the UTC day; the one-second overflow cases cover this clock")
	}

	before := time.Now().UTC()
	store := &fakeLegacyStore{}
	rest := NewTokensREST(nil, store, noop.NewTracerProvider().Tracer("test"), &fakeConfigProvider{cfg: &setting.Cfg{
		ApiKeyMaxSecondsToLive:    -1,
		SATokenExpirationDayLimit: days,
	}}, nil)
	body := fmt.Sprintf(`{"tokenName":"day-limit-same-date","expiresInSeconds":%d}`, seconds)
	req, err := http.NewRequest(http.MethodPost, "/tokens", bytes.NewBufferString(body))
	require.NoError(t, err)
	responder := &fakeResponder{}

	rest.handleCreate(context.Background(), claims.NamespaceInfo{OrgID: 1}, "sa-uid", req, responder)

	if store.createCalled {
		require.NotNil(t, store.expires)
		capAt := before.Add(time.Duration(days) * 24 * time.Hour).Unix()
		assert.LessOrEqual(t, *store.expires, capAt, "stored expiry %d is after the day cap %d", *store.expires, capAt)
	}
	assert.False(t, store.createCalled, "over-limit token must not be stored")
	require.Error(t, responder.err)
	assert.True(t, apierrors.IsBadRequest(responder.err))
}

func configProvider(provider *fakeConfigProvider) configprovider.ConfigProvider {
	if provider == nil {
		return nil
	}
	return provider
}

func settingService(svc *fakeSettingService) settingsvc.Service {
	if svc == nil {
		return nil
	}
	return svc
}

func TestHandleCreateAcceptsLifetimeAtDayLimit(t *testing.T) {
	const day = int64(24 * 60 * 60)
	store := &fakeLegacyStore{}
	rest := NewTokensREST(nil, store, noop.NewTracerProvider().Tracer("test"), &fakeConfigProvider{cfg: &setting.Cfg{
		ApiKeyMaxSecondsToLive:    -1,
		SATokenExpirationDayLimit: 1,
	}}, nil)
	body := fmt.Sprintf(`{"tokenName":"day-limit-exact","expiresInSeconds":%d}`, day)
	req, err := http.NewRequest(http.MethodPost, "/tokens", bytes.NewBufferString(body))
	require.NoError(t, err)
	responder := &fakeResponder{}
	before := time.Now().UTC()

	rest.handleCreate(context.Background(), claims.NamespaceInfo{OrgID: 1}, "sa-uid", req, responder)

	after := time.Now().UTC()
	require.NoError(t, responder.err)
	assert.Equal(t, http.StatusCreated, responder.status)
	require.True(t, store.createCalled)
	require.NotNil(t, store.expires)
	assert.GreaterOrEqual(t, *store.expires, before.Add(24*time.Hour).Unix())
	assert.LessOrEqual(t, *store.expires, after.Add(24*time.Hour).Unix())
}

// lifetimeUntilLateOnLimitUTCDate returns a whole-second lifetime that ends
// margin before the UTC midnight after now+days, and is still longer than
// days*24h. ok is false when that point is not past the cap by at least margin,
// which happens in the last part of the UTC day.
func lifetimeUntilLateOnLimitUTCDate(now time.Time, days int, margin time.Duration) (int64, bool) {
	now = now.UTC()
	if days <= 0 {
		return 0, false
	}
	limit := now.Add(time.Duration(days) * 24 * time.Hour)
	dayEnd := limit.Truncate(24 * time.Hour).Add(24 * time.Hour)
	target := dayEnd.Add(-margin)
	if !target.After(limit.Add(margin)) {
		return 0, false
	}
	seconds := int64(target.Sub(now) / time.Second)
	if seconds <= int64(days)*24*60*60 {
		return 0, false
	}
	return seconds, true
}

// waitOutUTCDateBoundary waits until a lifetime of days*24h+1s cannot fall on
// the UTC date after the capped instant. That only happens in the last few
// seconds of a UTC day, where flooring both times would reject the request for
// a different reason than the duration cap.
func waitOutUTCDateBoundary(t *testing.T) {
	t.Helper()
	now := time.Now().UTC()
	if now.Hour() == 23 && now.Minute() == 59 && now.Second() >= 57 {
		time.Sleep(time.Until(now.Truncate(24 * time.Hour).Add(24 * time.Hour).Add(2 * time.Second)))
	}
}
