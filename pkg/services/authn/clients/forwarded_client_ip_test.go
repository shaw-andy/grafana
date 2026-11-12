package clients

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/loginattempt/loginattemptimpl"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	// TCP peer of the attacker's connection. Forwarding headers must not replace it
	// when that peer is not a configured trusted proxy. These tests configure none.
	lockoutPeerAddr = "203.0.113.10:4242"
	lockoutPeerIP   = "203.0.113.10"

	// Obvious non-secret. Authentication is rejected before this value is checked.
	passwordPlaceholder = "placeholder"
)

// rejectingPasswordClient fails authentication. When rewriteRealIP is set, it changes
// X-Real-IP after the IP lockout check and before the failed attempt is recorded.
type rejectingPasswordClient struct {
	rewriteRealIP string
}

func (c rejectingPasswordClient) AuthenticatePassword(_ context.Context, r *authn.Request, _, _ string) (*authn.Identity, error) {
	if c.rewriteRealIP != "" && r != nil && r.HTTPRequest != nil {
		r.HTTPRequest.Header.Set("X-Real-IP", c.rewriteRealIP)
	}
	return nil, errIdentityNotFound
}

type loginAttemptRow struct {
	Username  string `xorm:"username"`
	IPAddress string `xorm:"ip_address"`
}

func testLoginAttempts(t *testing.T, disableUsernameProtection bool, inner authn.PasswordClient) (*Password, db.DB) {
	t.Helper()

	sqlStore := db.NewTestStore(t)
	cfg := setting.NewCfg()
	cfg.DisableBruteForceLoginProtection = false
	cfg.DisableUsernameLoginProtection = disableUsernameProtection
	cfg.DisableIPAddressLoginProtection = false
	cfg.BruteForceLoginProtectionMaxAttempts = 2

	attempts := loginattemptimpl.ProvideService(sqlStore, cfg, nil)
	return ProvidePassword(attempts, tracing.InitializeTracerForTest(), inner), sqlStore
}

func forwardedLoginRequest(peerAddr, realIP, forwardedFor, username string, basic bool) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(fmt.Sprintf(`{"user":%q,"password":%q}`, username, passwordPlaceholder)))
	req.RemoteAddr = peerAddr
	req.Header.Set("Content-Type", "application/json")
	if realIP != "" {
		req.Header.Set("X-Real-IP", realIP)
	}
	if forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", forwardedFor)
	}
	if basic {
		req.SetBasicAuth(username, passwordPlaceholder)
	}
	return req
}

func recordedLoginAttempts(t *testing.T, store db.DB) []loginAttemptRow {
	t.Helper()
	var rows []loginAttemptRow
	err := store.WithDbSession(context.Background(), func(sess *db.Session) error {
		return sess.Table("login_attempt").Cols("username", "ip_address").Find(&rows)
	})
	require.NoError(t, err)
	return rows
}

func requireAttemptsRecordedAsPeer(t *testing.T, rows []loginAttemptRow, wantUsers ...string) {
	t.Helper()
	require.Len(t, rows, len(wantUsers))
	gotUsers := map[string]int{}
	for _, row := range rows {
		require.Equal(t, lockoutPeerIP, row.IPAddress, "login attempt for %s was stored under a forwarding header", row.Username)
		gotUsers[row.Username]++
	}
	for _, user := range wantUsers {
		require.Equal(t, 1, gotUsers[user])
	}
}

// TestUntrustedForwardingHeadersDoNotBypassIPLoginLockout submits wrong passwords
// from one TCP connection while rotating X-Real-IP and X-Forwarded-For. IP lockout
// must count the TCP peer, so the attempt after the limit is blocked and every
// stored address is that peer.
func TestUntrustedForwardingHeadersDoNotBypassIPLoginLockout(t *testing.T) {
	t.Run("form login rotates X-Real-IP across usernames", func(t *testing.T) {
		passwordClient, store := testLoginAttempts(t, false, rejectingPasswordClient{})
		form := ProvideForm(passwordClient)
		users := []string{"user-a", "user-b"}
		spoofed := []string{"198.51.100.1", "198.51.100.2"}

		for i, user := range users {
			req := forwardedLoginRequest(lockoutPeerAddr, spoofed[i], "198.51.100.50", user, false)
			_, err := form.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
			require.ErrorIs(t, err, errPasswordAuthFailed)
			require.NotErrorIs(t, err, errPasswordClientTooManyLoginAttempts)
		}
		requireAttemptsRecordedAsPeer(t, recordedLoginAttempts(t, store), users...)

		req := forwardedLoginRequest(lockoutPeerAddr, "198.51.100.3", "198.51.100.51", "user-c", false)
		_, err := form.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
		require.ErrorIs(t, err, errPasswordClientTooManyLoginAttempts)
		requireAttemptsRecordedAsPeer(t, recordedLoginAttempts(t, store), users...)
	})

	t.Run("basic login rotates X-Forwarded-For across usernames", func(t *testing.T) {
		passwordClient, store := testLoginAttempts(t, false, rejectingPasswordClient{})
		basic := ProvideBasic(passwordClient)
		users := []string{"user-d", "user-e"}
		spoofed := []string{"198.51.100.4, 198.51.100.40", "198.51.100.5, 198.51.100.41"}

		for i, user := range users {
			req := forwardedLoginRequest(lockoutPeerAddr, "", spoofed[i], user, true)
			_, err := basic.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
			require.ErrorIs(t, err, errPasswordAuthFailed)
			require.NotErrorIs(t, err, errPasswordClientTooManyLoginAttempts)
		}
		requireAttemptsRecordedAsPeer(t, recordedLoginAttempts(t, store), users...)

		req := forwardedLoginRequest(lockoutPeerAddr, "", "198.51.100.6, 203.0.113.10", "user-f", true)
		_, err := basic.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
		require.ErrorIs(t, err, errPasswordClientTooManyLoginAttempts)
		requireAttemptsRecordedAsPeer(t, recordedLoginAttempts(t, store), users...)
	})

	t.Run("one username keeps guessing when username lockout is disabled", func(t *testing.T) {
		passwordClient, store := testLoginAttempts(t, true, rejectingPasswordClient{})
		form := ProvideForm(passwordClient)
		const user = "one-account"
		spoofed := []string{"198.51.100.11", "198.51.100.12"}

		for _, ip := range spoofed {
			req := forwardedLoginRequest(lockoutPeerAddr, ip, "", user, false)
			_, err := form.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
			require.ErrorIs(t, err, errPasswordAuthFailed)
			require.NotErrorIs(t, err, errPasswordClientTooManyLoginAttempts)
		}
		rows := recordedLoginAttempts(t, store)
		require.Len(t, rows, len(spoofed))
		for _, row := range rows {
			require.Equal(t, user, row.Username)
			require.Equal(t, lockoutPeerIP, row.IPAddress)
		}

		req := forwardedLoginRequest(lockoutPeerAddr, "198.51.100.13", "", user, false)
		_, err := form.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
		require.ErrorIs(t, err, errPasswordClientTooManyLoginAttempts)
	})
}

// TestForwardingHeaderChangedBetweenIPCheckAndRecordIsNotCounted exhausts the
// address in the original forwarding header, then changes that header after the
// lockout check returns. The check and the stored attempt must both use the TCP
// peer, so a second read of the header cannot count or allow a different address.
func TestForwardingHeaderChangedBetweenIPCheckAndRecordIsNotCounted(t *testing.T) {
	const (
		checkedHeader   = "198.51.100.1"
		rewrittenHeader = "198.51.100.77"
		forwardedFor    = "198.51.100.88"
		freshUser       = "fresh-user"
	)

	sqlStore := db.NewTestStore(t)
	cfg := setting.NewCfg()
	cfg.DisableBruteForceLoginProtection = false
	cfg.DisableUsernameLoginProtection = false
	cfg.DisableIPAddressLoginProtection = false
	cfg.BruteForceLoginProtectionMaxAttempts = 2
	attempts := loginattemptimpl.ProvideService(sqlStore, cfg, nil)
	for range 2 {
		require.NoError(t, attempts.Add(context.Background(), "seed-user", checkedHeader))
	}

	passwordClient := ProvidePassword(attempts, tracing.InitializeTracerForTest(), rejectingPasswordClient{rewriteRealIP: rewrittenHeader})
	form := ProvideForm(passwordClient)
	req := forwardedLoginRequest(lockoutPeerAddr, checkedHeader, forwardedFor, freshUser, false)
	_, err := form.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
	require.ErrorIs(t, err, errPasswordAuthFailed)
	require.NotErrorIs(t, err, errPasswordClientTooManyLoginAttempts)

	var fresh, rewritten, seeded int
	for _, row := range recordedLoginAttempts(t, sqlStore) {
		switch {
		case row.Username == freshUser:
			fresh++
			require.Equal(t, lockoutPeerIP, row.IPAddress)
		case row.IPAddress == rewrittenHeader:
			rewritten++
		case row.Username == "seed-user" && row.IPAddress == checkedHeader:
			seeded++
		default:
			t.Fatalf("unexpected login attempt %+v", row)
		}
	}
	require.Equal(t, 1, fresh)
	require.Equal(t, 0, rewritten)
	require.Equal(t, 2, seeded)
}
