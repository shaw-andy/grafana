package clients

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/loginattempt/loginattemptimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
)

// Placeholders only. The correct value is hashed with the real encoder and
// compared by the real password client.
const (
	burstUsername        = "admin"
	burstCorrectPassword = "placeholder-correct"
	burstWrongPassword   = "placeholder-wrong"
	burstPasswordSalt    = "placeholder-salt"
	burstAdminUserID     = int64(42)
	burstClientIP        = "203.0.113.10:9"
)

// TestPasswordLoginBurstBypassesAttemptLimit is the spec for the attempt-limit
// race. It fails while a burst can pass the limit, and passes once a burst cannot.
//
// Each attempt is held inside the password client until every attempt has either
// entered that client or returned. Production hashes the password in that client,
// after the failure count is read and before a failure row is inserted, so the
// held attempts have not recorded a failure yet. Reading the count again before
// calling the client still sees that same total. The attempt has to be reserved
// under a per-user lock (and a per-IP lock when the IP counter is enabled)
// before the client runs.
func TestPasswordLoginBurstBypassesAttemptLimit(t *testing.T) {
	const maxAttempts = 5
	const extraAttempts = 8

	hashed, err := util.EncodePassword(burstCorrectPassword, burstPasswordSalt)
	require.NoError(t, err)

	admin := &user.User{
		ID:       burstAdminUserID,
		Login:    burstUsername,
		Password: user.Password(hashed),
		Salt:     burstPasswordSalt,
		IsAdmin:  true,
	}

	tests := []struct {
		name               string
		usernameProtection bool
		ipProtection       bool
		basic              bool
	}{
		{
			name:               "form login with the default username limit",
			usernameProtection: true,
			ipProtection:       false,
		},
		{
			name:               "basic auth with the default username limit",
			usernameProtection: true,
			ipProtection:       false,
			basic:              true,
		},
		{
			name:         "form login with the ip limit",
			ipProtection: true,
		},
		{
			name:         "basic auth with the ip limit",
			ipProtection: true,
			basic:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := db.NewTestStore(t)
			cfg := setting.NewCfg()
			cfg.DisableBruteForceLoginProtection = false
			cfg.DisableUsernameLoginProtection = !tt.usernameProtection
			cfg.DisableIPAddressLoginProtection = !tt.ipProtection
			cfg.BruteForceLoginProtectionMaxAttempts = maxAttempts
			attempts := loginattemptimpl.ProvideService(store, cfg, nil)

			tracer := tracing.InitializeTracerForTest()
			userService := &usertest.FakeUserService{ExpectedUser: admin}
			release := make(chan struct{})
			var releaseOnce sync.Once
			letPasswordChecksFinish := func() {
				releaseOnce.Do(func() { close(release) })
			}
			var started atomic.Int32
			passwordClient := ProvidePassword(attempts, tracer, &gatingPasswordClient{
				next:    ProvideGrafana(setting.NewCfg(), userService, tracer),
				release: release,
				started: &started,
			})

			var entry func(password string) (*authn.Identity, error)
			if tt.basic {
				basic := ProvideBasic(passwordClient)
				entry = func(password string) (*authn.Identity, error) {
					return basic.Authenticate(context.Background(), burstBasicRequest(t, password))
				}
			} else {
				form := ProvideForm(passwordClient)
				entry = func(password string) (*authn.Identity, error) {
					return form.Authenticate(context.Background(), burstFormRequest(t, password))
				}
			}

			total := maxAttempts + extraAttempts
			results := make([]burstResult, total)
			var finished atomic.Int32
			var wg sync.WaitGroup
			wg.Add(total)
			for i := 0; i < total; i++ {
				password := burstWrongPassword
				if i == 0 {
					password = burstCorrectPassword
				}
				go func(i int, password string) {
					defer wg.Done()
					defer finished.Add(1)
					identity, err := entry(password)
					results[i] = burstResult{identity: identity, err: err}
				}(i, password)
			}

			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) && int(started.Load()+finished.Load()) < total {
				time.Sleep(time.Millisecond)
			}
			require.Equal(t, total, int(started.Load()+finished.Load()),
				"attempts did not all reach password verification or return; started %d finished %d",
				started.Load(), finished.Load())

			// Snapshot before releasing the gate. Releasing lets the real hash
			// finish and, on a failure, inserts the attempt row.
			passwordChecks := int(started.Load())
			letPasswordChecksFinish()
			wg.Wait()

			correct := results[0]
			if passwordChecks > maxAttempts {
				require.NotNilf(t, correct.identity,
					"matching password was not accepted; error %v", correct.err)
				require.Equal(t, fmt.Sprint(burstAdminUserID), correct.identity.ID)
				t.Fatalf("password verification started %d times with limit %d, and the matching password was accepted as user %s (administrator account %s)",
					passwordChecks, maxAttempts, correct.identity.ID, burstUsername)
			}
			require.Equal(t, maxAttempts, passwordChecks)
			if correct.identity != nil {
				require.Equal(t, fmt.Sprint(burstAdminUserID), correct.identity.ID)
			}
		})
	}
}

type burstResult struct {
	identity *authn.Identity
	err      error
}

// gatingPasswordClient blocks where the real password client hashes the password.
type gatingPasswordClient struct {
	next    authn.PasswordClient
	release <-chan struct{}
	started *atomic.Int32
}

func (g *gatingPasswordClient) AuthenticatePassword(ctx context.Context, r *authn.Request, username, password string) (*authn.Identity, error) {
	g.started.Add(1)
	<-g.release
	return g.next.AuthenticatePassword(ctx, r, username, password)
}

func burstFormRequest(t *testing.T, password string) *authn.Request {
	t.Helper()
	body := fmt.Sprintf(`{"user":%q,"password":%q}`, burstUsername, password)
	req, err := http.NewRequest(http.MethodPost, "http://grafana.example/login", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = burstClientIP
	return &authn.Request{HTTPRequest: req, OrgID: 1}
}

func burstBasicRequest(t *testing.T, password string) *authn.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://grafana.example/api/user", nil)
	require.NoError(t, err)
	req.SetBasicAuth(burstUsername, password)
	req.RemoteAddr = burstClientIP
	return &authn.Request{HTTPRequest: req, OrgID: 1}
}
