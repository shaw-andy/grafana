package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/apikey"
	"github.com/grafana/grafana/pkg/services/serviceaccounts"
	satests "github.com/grafana/grafana/pkg/services/serviceaccounts/tests"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// recordingTokenService records the lifetime the legacy create handler forwards
// after the day-limit check. Only the numeric lifetime is kept.
type recordingTokenService struct {
	*satests.FakeServiceAccountService
	called        bool
	secondsToLive int64
}

func (s *recordingTokenService) AddServiceAccountToken(ctx context.Context, id int64, cmd *serviceaccounts.AddServiceAccountTokenCommand) (*apikey.APIKey, error) {
	s.called = true
	if cmd != nil {
		s.secondsToLive = cmd.SecondsToLive
	}
	return s.FakeServiceAccountService.AddServiceAccountToken(ctx, id, cmd)
}

func TestCreateTokenRejectsSameUTCDateOverflow(t *testing.T) {
	waitOutLegacyUTCDateBoundary(t)

	const day = int64(24 * 60 * 60)
	tests := []struct {
		name    string
		days    int
		seconds int64
		apiMax  int64
	}{
		{
			name:    "one day limit and unset api key max",
			days:    1,
			seconds: day + 1,
			apiMax:  -1,
		},
		{
			name:    "one day limit and api key max above the extra second",
			days:    1,
			seconds: day + 1,
			apiMax:  3 * day,
		},
		{
			name:    "seven day limit and unset api key max",
			days:    7,
			seconds: 7*day + 1,
			apiMax:  -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newRecordingTokenService()
			status, called, seconds := postToken(t, svc, tt.days, tt.apiMax, tt.seconds)

			assert.Equal(t, http.StatusBadRequest, status)
			assert.False(t, called, "over-limit token must not be stored")
			if called {
				assert.LessOrEqual(t, seconds, int64(tt.days)*day, "stored lifetime %d exceeds the %d-day cap", seconds, tt.days)
			}
		})
	}
}

func TestCreateTokenRejectsExpiryLaterOnTheLimitUTCDate(t *testing.T) {
	now := time.Now().UTC()
	const days = 1
	seconds, ok := legacyLifetimeUntilLateOnLimitUTCDate(now, days, 30*time.Minute)
	if !ok {
		t.Skip("less than 30 minutes left in the UTC day; the one-second overflow cases cover this clock")
	}

	svc := newRecordingTokenService()
	status, called, got := postToken(t, svc, days, -1, seconds)

	assert.Equal(t, http.StatusBadRequest, status)
	assert.False(t, called, "over-limit token must not be stored")
	if called {
		assert.LessOrEqual(t, got, int64(days)*24*60*60, "stored lifetime %d exceeds the day cap", got)
	}
}

func TestCreateTokenAcceptsLifetimeAtDayLimit(t *testing.T) {
	const day = int64(24 * 60 * 60)
	svc := newRecordingTokenService()
	status, called, seconds := postToken(t, svc, 1, -1, day)

	assert.Equal(t, http.StatusOK, status)
	assert.True(t, called)
	assert.Equal(t, day, seconds)
}

func TestCreateTokenAllowsLongLifetimeWhenDayLimitDisabled(t *testing.T) {
	const day = int64(24 * 60 * 60)
	for _, days := range []int{0, -1} {
		t.Run(fmt.Sprintf("day limit %d", days), func(t *testing.T) {
			svc := newRecordingTokenService()
			status, called, seconds := postToken(t, svc, days, -1, day+1)

			assert.Equal(t, http.StatusOK, status)
			assert.True(t, called)
			assert.Equal(t, day+1, seconds)
		})
	}
}

func newRecordingTokenService() *recordingTokenService {
	return &recordingTokenService{
		FakeServiceAccountService: &satests.FakeServiceAccountService{
			ExpectedAPIKey: &apikey.APIKey{ID: 1, Name: "test"},
		},
	}
}

func postToken(t *testing.T, svc *recordingTokenService, days int, apiMax int64, seconds int64) (int, bool, int64) {
	t.Helper()
	server := setupTests(t, func(a *ServiceAccountsAPI) {
		a.cfg.ApiKeyMaxSecondsToLive = apiMax
		a.cfg.SATokenExpirationDayLimit = days
		a.service = svc
	})
	body := fmt.Sprintf(`{"name":"day-limit","secondsToLive":%d}`, seconds)
	req := server.NewRequest(http.MethodPost, "/api/serviceaccounts/1/tokens", strings.NewReader(body))
	permissions := []accesscontrol.Permission{{Action: serviceaccounts.ActionWrite, Scope: "serviceaccounts:id:1"}}
	webtest.RequestWithSignedInUser(req, &user.SignedInUser{
		OrgID:       1,
		Permissions: map[int64]map[string][]string{1: accesscontrol.GroupScopesByActionContext(context.Background(), permissions)},
	})
	res, err := server.SendJSON(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	return res.StatusCode, svc.called, svc.secondsToLive
}

func legacyLifetimeUntilLateOnLimitUTCDate(now time.Time, days int, margin time.Duration) (int64, bool) {
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

func waitOutLegacyUTCDateBoundary(t *testing.T) {
	t.Helper()
	now := time.Now().UTC()
	if now.Hour() == 23 && now.Minute() == 59 && now.Second() >= 57 {
		time.Sleep(time.Until(now.Truncate(24 * time.Hour).Add(24 * time.Hour).Add(2 * time.Second)))
	}
}
