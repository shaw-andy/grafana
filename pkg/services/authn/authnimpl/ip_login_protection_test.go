package authnimpl

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/apimachinery/errutil"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/loginattempt"
	"github.com/grafana/grafana/pkg/services/loginattempt/loginattemptimpl"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// Password checks are reached only after the source address is still under the
// attempt limit. These tests fail while a default install skips that limit.
func TestIntegrationOneAddressCannotSprayEveryAccount(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	t.Run("shipped defaults", func(t *testing.T) {
		assertOneAddressCannotSpray(t, loadLoginCfg(t, false))
	})
	t.Run("ip protection key absent", func(t *testing.T) {
		assertOneAddressCannotSpray(t, loadLoginCfg(t, true))
	})
}

func TestIntegrationUsernameLoginProtectionStillBlocksThatAccount(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	h := newLoginHarness(t, loadLoginCfg(t, false))
	limit := int(h.cfg.BruteForceLoginProtectionMaxAttempts)
	const wrongPassword = "placeholder-wrong"

	for i := 0; i < limit; i++ {
		// A different source address each time, so this lock is the username
		// limit and not the address limit.
		ip := fmt.Sprintf("192.0.2.%d", 40+i)
		h.reject(t, h.adminLogin, wrongPassword, ip, authn.ClientForm)
	}

	calls := *h.passwordCalls
	sessions := len(h.sessions)
	_, err := h.login(t, h.adminLogin, h.password, "192.0.2.90", authn.ClientForm)
	require.Error(t, err)
	require.Equal(t, "password-auth.failed", grafanaMessageID(t, err))
	require.Equal(t, calls, *h.passwordCalls)
	require.Len(t, h.sessions, sessions)

	// Other names are still attempted. The username limit does not cover them.
	h.reject(t, "other-account", wrongPassword, "192.0.2.91", authn.ClientForm)
}

func assertOneAddressCannotSpray(t *testing.T, cfg *setting.Cfg) {
	t.Helper()
	require.False(t, cfg.DisableBruteForceLoginProtection)
	require.False(t, cfg.DisableUsernameLoginProtection)
	require.False(t, cfg.DisableLoginForm)
	require.False(t, cfg.DisableLogin)
	require.True(t, cfg.BasicAuthEnabled)
	require.Equal(t, int64(5), cfg.BruteForceLoginProtectionMaxAttempts)

	h := newLoginHarness(t, cfg)
	const attacker = "203.0.113.10"
	const other = "203.0.113.20"
	const wrongPassword = "placeholder-wrong"
	limit := int(cfg.BruteForceLoginProtectionMaxAttempts)

	for i := 0; i < limit-1; i++ {
		client := authn.ClientForm
		if i%2 == 1 {
			client = authn.ClientBasic
		}
		h.reject(t, fmt.Sprintf("spray-user-%d", i), wrongPassword, attacker, client)
	}

	// The address is still under the limit, so the administrator password works
	// and a session is issued for that user.
	identity := h.accept(t, attacker, authn.ClientForm)
	require.Equal(t, h.adminID, identity.SessionToken.UserId)
	h.assertSessionCookie(t, identity)

	h.reject(t, "spray-user-last", wrongPassword, attacker, authn.ClientBasic)
	require.Equal(t, int64(limit), h.ipAttempts(t, attacker))

	// Further tries from this address stop before any password client runs,
	// including a password that would otherwise be accepted, and they do not
	// record another attempt or open a session.
	calls := *h.passwordCalls
	attempts := h.ipAttempts(t, attacker)
	sessions := len(h.sessions)
	for _, client := range []string{authn.ClientForm, authn.ClientBasic} {
		_, err := h.login(t, h.adminLogin, h.password, attacker, client)
		require.Error(t, err)
		require.Equal(t, "login-attempt.blocked", grafanaMessageID(t, err))
	}
	_, err := h.svc.Authenticate(context.Background(), &authn.Request{HTTPRequest: loginRequest(t, h.adminLogin, h.password, attacker, true)})
	require.Error(t, err)
	require.Equal(t, "login-attempt.blocked", grafanaMessageID(t, err))
	require.Equal(t, calls, *h.passwordCalls)
	require.Equal(t, attempts, h.ipAttempts(t, attacker))
	require.Len(t, h.sessions, sessions)

	// A different address is not blocked by the first client's attempts.
	otherIdentity := h.accept(t, other, authn.ClientBasic)
	require.Equal(t, h.adminID, otherIdentity.SessionToken.UserId)
	require.True(t, h.sessions[len(h.sessions)-1].ClientIP.Equal(net.ParseIP(other)))

	require.False(t, cfg.DisableBruteForceLoginProtection)
	require.False(t, cfg.DisableUsernameLoginProtection)
	require.False(t, cfg.DisableIPAddressLoginProtection)
	require.Equal(t, int64(5), cfg.BruteForceLoginProtectionMaxAttempts)
}

type loginHarness struct {
	cfg           *setting.Cfg
	store         *sqlstore.SQLStore
	svc           *Service
	adminID       int64
	adminLogin    string
	password      string
	passwordCalls *int
	sessions      []*auth.CreateTokenCommand
}

func newLoginHarness(t *testing.T, cfg *setting.Cfg) *loginHarness {
	t.Helper()
	const placeholderPassword = "placeholder-password"
	const placeholderSalt = "placeholder-salt"

	hashed, err := util.EncodePassword(placeholderPassword, placeholderSalt)
	require.NoError(t, err)

	adminID := int64(1)
	admin := &user.User{
		ID:       adminID,
		Login:    strings.ToLower(cfg.AdminUser),
		Password: user.Password(hashed),
		Salt:     placeholderSalt,
		IsAdmin:  true,
	}
	users := &usertest.FakeUserService{
		GetByLoginFn: func(_ context.Context, query *user.GetUserByLoginQuery) (*user.User, error) {
			if strings.ToLower(query.LoginOrEmail) == admin.Login {
				return admin, nil
			}
			return nil, user.ErrUserNotFound
		},
	}

	store := db.NewTestStore(t)
	attempts := loginattemptimpl.ProvideService(store, cfg, nil)
	tracer := tracing.InitializeTracerForTest()
	calls := 0
	// The first password client is the gate every later client sits behind,
	// including Grafana's own user and LDAP.
	passwordClient := clients.ProvidePassword(attempts, tracer, &recordingPasswordClient{
		calls: &calls,
		next:  clients.ProvideGrafana(cfg, users, tracer),
	})

	h := &loginHarness{
		cfg:           cfg,
		store:         store,
		adminID:       adminID,
		adminLogin:    cfg.AdminUser,
		password:      placeholderPassword,
		passwordCalls: &calls,
	}
	tokens := &authtest.FakeUserAuthTokenService{
		CreateTokenProvider: func(_ context.Context, cmd *auth.CreateTokenCommand) (*auth.UserToken, error) {
			h.sessions = append(h.sessions, cmd)
			return &auth.UserToken{UserId: cmd.User.ID, UnhashedToken: "placeholder-session"}, nil
		},
	}
	h.svc = setupTests(t, func(svc *Service) {
		svc.cfg = cfg
		svc.sessionService = tokens
		svc.RegisterClient(clients.ProvideForm(passwordClient))
		svc.RegisterClient(clients.ProvideBasic(passwordClient))
	})
	return h
}

func (h *loginHarness) login(t *testing.T, username, password, ip, client string) (*authn.Identity, error) {
	t.Helper()
	basic := client == authn.ClientBasic
	return h.svc.Login(context.Background(), client, &authn.Request{
		HTTPRequest: loginRequest(t, username, password, ip, basic),
	})
}

func (h *loginHarness) reject(t *testing.T, username, password, ip, client string) {
	t.Helper()
	before := len(h.sessions)
	identity, err := h.login(t, username, password, ip, client)
	require.Error(t, err)
	require.Nil(t, identity)
	require.Equal(t, "password-auth.failed", grafanaMessageID(t, err))
	require.Len(t, h.sessions, before)
}

func (h *loginHarness) accept(t *testing.T, ip, client string) *authn.Identity {
	t.Helper()
	before := len(h.sessions)
	identity, err := h.login(t, h.adminLogin, h.password, ip, client)
	require.NoError(t, err)
	require.NotNil(t, identity)
	require.NotNil(t, identity.SessionToken)
	require.Len(t, h.sessions, before+1)
	cmd := h.sessions[len(h.sessions)-1]
	require.Equal(t, h.adminID, cmd.User.ID)
	require.True(t, cmd.ClientIP.Equal(net.ParseIP(ip)))
	return identity
}

func (h *loginHarness) assertSessionCookie(t *testing.T, identity *authn.Identity) {
	t.Helper()
	req := loginRequest(t, h.adminLogin, h.password, "203.0.113.10", false)
	rec := httptest.NewRecorder()
	resp := authn.HandleLoginResponse(req, rec, h.cfg, identity, func(target string) (string, error) {
		return target, nil
	}, featuremgmt.WithFeatures())
	require.Equal(t, http.StatusOK, resp.Status())
	found := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == h.cfg.LoginCookieName && cookie.Value != "" {
			found = true
		}
	}
	require.True(t, found, "login response did not set %s", h.cfg.LoginCookieName)
}

func (h *loginHarness) ipAttempts(t *testing.T, ip string) int64 {
	t.Helper()
	var n int64
	err := h.store.WithDbSession(context.Background(), func(sess *sqlstore.DBSession) error {
		var countErr error
		n, countErr = sess.Where("ip_address = ?", ip).Count(&loginattempt.LoginAttempt{})
		return countErr
	})
	require.NoError(t, err)
	return n
}

func loginRequest(t *testing.T, username, password, ip string, basic bool) *http.Request {
	t.Helper()
	var req *http.Request
	if basic {
		req = httptest.NewRequest(http.MethodGet, "/login", nil)
		req.SetBasicAuth(username, password)
	} else {
		body := fmt.Sprintf(`{"user":%q,"password":%q}`, username, password)
		req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.RemoteAddr = ip + ":12345"
	req.Header.Del("X-Real-IP")
	req.Header.Del("X-Forwarded-For")
	return req
}

func grafanaMessageID(t *testing.T, err error) string {
	t.Helper()
	var ge errutil.Error
	require.ErrorAs(t, err, &ge)
	return ge.MessageID
}

type recordingPasswordClient struct {
	calls *int
	next  authn.PasswordClient
}

func (c *recordingPasswordClient) AuthenticatePassword(ctx context.Context, r *authn.Request, username, password string) (*authn.Identity, error) {
	*c.calls++
	return c.next.AuthenticatePassword(ctx, r, username, password)
}

func loadLoginCfg(t *testing.T, stripIPKey bool) *setting.Cfg {
	t.Helper()
	t.Setenv("GF_SECURITY_DISABLE_BRUTE_FORCE_LOGIN_PROTECTION", "")
	t.Setenv("GF_SECURITY_DISABLE_USERNAME_LOGIN_PROTECTION", "")
	t.Setenv("GF_SECURITY_DISABLE_IP_ADDRESS_LOGIN_PROTECTION", "")
	t.Setenv("GF_SECURITY_BRUTE_FORCE_LOGIN_PROTECTION_MAX_ATTEMPTS", "")

	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	shipped := filepath.Join(root, "conf", "defaults.ini")

	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, "conf"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "data", "log"), 0o755))
	target := filepath.Join(home, "conf", "defaults.ini")
	if stripIPKey {
		parsed, err := ini.Load(shipped)
		require.NoError(t, err)
		parsed.Section("security").DeleteKey("disable_ip_address_login_protection")
		require.NoError(t, parsed.SaveTo(target))
	} else {
		body, err := os.ReadFile(shipped)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(target, body, 0o644))
	}

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{HomePath: home, Config: target}))
	require.NotEmpty(t, cfg.AdminUser)
	require.NotEmpty(t, cfg.LoginCookieName)
	return cfg
}
