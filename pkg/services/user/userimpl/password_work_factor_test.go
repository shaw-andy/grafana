package userimpl

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"github.com/grafana/grafana/pkg/infra/serverlock"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/loginattempt/loginattemptimpl"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// placeholderPassword and shortPlaceholderPassword are obvious stand-ins for a
// caller-supplied login password. They are not credentials.
const (
	placeholderPassword      = "PLACEHOLDER"
	shortPlaceholderPassword = "xxxx"
	resetPlaceholderPassword = "PLACEHOLDER-2"
)

// loginPasswordStorageWeakness reports why a stored login password does not
// meet the password-storage parameters these tests require. An empty string
// means the stored value is acceptable.
//
// Acceptable stored values, given the plaintext password and the salt column:
//   - hex of PBKDF2-HMAC-SHA256 at exactly 600000 iterations
//   - pbkdf2-sha256$<iterations>$<hex digest> with iterations in [600000, 2000000],
//     using the salt column as the PBKDF2 salt
//   - an argon2id PHC string, version 19, with m in [19456, 262144] KiB,
//     t in [2, 4], p in [1, 8]
//   - a bcrypt hash with cost in [10, 12]
//
// PBKDF2-HMAC-SHA256 at 10000 iterations is never acceptable. A row that still
// has that hash must be rewritten to an acceptable value when the login form
// accepts the password.
func loginPasswordStorageWeakness(password, salt, stored string) string {
	if stored == "" {
		return "stored login password is empty"
	}
	if n, ok := pbkdf2HexIterations(password, salt, stored, 10_000); ok {
		return "stored login password is PBKDF2-HMAC-SHA256 with 10000 iterations and a " +
			strconv.Itoa(n) + "-byte output. The salt is stored with the hash. " +
			"PBKDF2-HMAC-SHA256 needs at least 600000 iterations; argon2id needs at least 19 MiB, t=2, p=1; bcrypt needs cost 10 or more"
	}
	if passwordStorageAdequate(password, salt, stored) {
		return ""
	}
	return "stored login password does not meet the required password-storage parameters " +
		"(PBKDF2-HMAC-SHA256 at 600000 iterations as hex, or pbkdf2-sha256$<iterations>$<hex> for 600000..2000000, " +
		"or argon2id v=19 with m=19456..262144 t=2..4 p=1..8, or bcrypt cost 10..12)"
}

func passwordStorageAdequate(password, salt, stored string) bool {
	if _, ok := pbkdf2HexIterations(password, salt, stored, 600_000); ok {
		return true
	}
	if pbkdf2SelfDescribing(password, salt, stored) {
		return true
	}
	if argon2idAdequate(password, stored) {
		return true
	}
	return bcryptAdequate(password, stored)
}

func pbkdf2HexIterations(password, salt, stored string, iterations int) (int, bool) {
	digest, err := hex.DecodeString(stored)
	if err != nil || len(digest) == 0 {
		return 0, false
	}
	derived, err := pbkdf2.Key(sha256.New, password, []byte(salt), iterations, len(digest))
	if err != nil {
		return 0, false
	}
	if subtle.ConstantTimeCompare(derived, digest) != 1 {
		return 0, false
	}
	return len(digest), true
}

func pbkdf2SelfDescribing(password, salt, stored string) bool {
	const prefix = "pbkdf2-sha256$"
	if !strings.HasPrefix(stored, prefix) {
		return false
	}
	iterText, digestHex, ok := strings.Cut(stored[len(prefix):], "$")
	if !ok || strings.Contains(digestHex, "$") {
		return false
	}
	iterations, err := strconv.Atoi(iterText)
	if err != nil || iterations < 600_000 || iterations > 2_000_000 {
		return false
	}
	digest, err := hex.DecodeString(digestHex)
	if err != nil || len(digest) == 0 {
		return false
	}
	derived, err := pbkdf2.Key(sha256.New, password, []byte(salt), iterations, len(digest))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(derived, digest) == 1
}

func argon2idAdequate(password, stored string) bool {
	if !strings.HasPrefix(stored, "$argon2id$") {
		return false
	}
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[2] != "v=19" {
		return false
	}
	var memory, timeCost uint32
	var threads uint8
	for _, field := range strings.Split(parts[3], ",") {
		key, val, ok := strings.Cut(field, "=")
		if !ok {
			return false
		}
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return false
		}
		switch key {
		case "m":
			memory = uint32(n)
		case "t":
			timeCost = uint32(n)
		case "p":
			if n > 255 {
				return false
			}
			threads = uint8(n)
		default:
			return false
		}
	}
	if memory < 19*1024 || memory > 256*1024 || timeCost < 2 || timeCost > 4 || threads < 1 || threads > 8 {
		return false
	}
	salt, err := decodeB64(parts[4])
	if err != nil || len(salt) == 0 {
		return false
	}
	sum, err := decodeB64(parts[5])
	if err != nil || len(sum) == 0 {
		return false
	}
	derived := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(sum)))
	return subtle.ConstantTimeCompare(derived, sum) == 1
}

func decodeB64(s string) ([]byte, error) {
	if decoded, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func bcryptAdequate(password, stored string) bool {
	if !strings.HasPrefix(stored, "$2") {
		return false
	}
	cost, err := bcrypt.Cost([]byte(stored))
	if err != nil || cost < 10 || cost > 12 {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) == nil
}

func legacyPBKDF2Hex(password, salt string) (string, error) {
	derived, err := pbkdf2.Key(sha256.New, password, []byte(salt), 10_000, 50)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(derived), nil
}

type passwordFixture struct {
	svc    user.Service
	store  sqlStore
	db     *sqlstore.SQLStore
	cfg    *setting.Cfg
	tracer tracing.Tracer
}

func newPasswordFixture(t *testing.T) passwordFixture {
	t.Helper()
	cfg := setting.NewCfg()
	// Shipped defaults: [auth.basic] password_policy is false, so a
	// four-character password is accepted, and brute-force protection allows
	// five attempts per username. IP protection is disabled.
	cfg.BasicAuthStrongPasswordPolicy = false
	cfg.DisableBruteForceLoginProtection = false
	cfg.DisableUsernameLoginProtection = false
	cfg.DisableIPAddressLoginProtection = true
	cfg.BruteForceLoginProtectionMaxAttempts = 5

	ss := sqlstore.NewTestStore(t, sqlstore.WithCfg(cfg))
	quotaSvc := quotatest.New(false, nil)
	orgSvc, err := orgimpl.ProvideService(legacysql.NewDatabaseProvider(ss), cfg, quotaSvc)
	require.NoError(t, err)
	tracer := tracing.InitializeTracerForTest()
	svc, err := ProvideService(
		legacysql.NewDatabaseProvider(ss), orgSvc, cfg, nil, nil, tracer,
		quotaSvc, supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)
	store := ProvideStore(legacysql.NewDatabaseProvider(ss), cfg)
	return passwordFixture{
		svc:    svc,
		store:  store,
		db:     ss,
		cfg:    cfg,
		tracer: tracer,
	}
}

func (f passwordFixture) createUser(t *testing.T, loginName, password string) *user.User {
	t.Helper()
	created, err := f.svc.Create(context.Background(), &user.CreateUserCommand{
		Login:    loginName,
		Email:    loginName + "@example.com",
		Password: user.Password(password),
	})
	require.NoError(t, err)
	return created
}

func (f passwordFixture) storedUser(t *testing.T, loginName string) *user.User {
	t.Helper()
	stored, err := f.svc.GetByLoginWithPassword(context.Background(), &user.GetUserByLoginQuery{LoginOrEmail: loginName})
	require.NoError(t, err)
	require.NotEmpty(t, stored.Salt, "salt column is empty")
	require.NotEmpty(t, stored.Password, "password column is empty")
	return stored
}

func (f passwordFixture) loginForm(t *testing.T, loginName, password string) *authn.Identity {
	t.Helper()
	// Registration puts the LDAP password client ahead of the Grafana client.
	// With LDAP disabled, that client returns before reading the user table and
	// the password client continues to the Grafana client, which is the one
	// wired here. Login attempts use the real attempt service with the shipped
	// limit of five.
	lock := serverlock.ProvideService(legacysql.NewDatabaseProvider(f.db), f.tracer)
	attempts := loginattemptimpl.ProvideService(f.db, f.cfg, lock)
	grafanaClient := clients.ProvideGrafana(f.cfg, f.svc, f.tracer)
	passwordClient := clients.ProvidePassword(attempts, f.tracer, grafanaClient)
	form := clients.ProvideForm(passwordClient)

	payload, err := json.Marshal(map[string]string{"user": loginName, "password": password})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:443"
	identity, err := form.Authenticate(context.Background(), &authn.Request{HTTPRequest: req, OrgID: 1})
	require.NoError(t, err)
	require.NotNil(t, identity)
	return identity
}

func requireAdequateStorage(t *testing.T, password, salt, stored string) {
	t.Helper()
	if msg := loginPasswordStorageWeakness(password, salt, stored); msg != "" {
		t.Fatal(msg)
	}
}

func TestIntegrationLoginPasswordWorkFactor(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)
	f := newPasswordFixture(t)
	require.NoError(t, user.ValidatePassword(shortPlaceholderPassword, f.cfg))

	t.Run("create_and_form_login", func(t *testing.T) {
		const loginName = "placeholder-create"
		created := f.createUser(t, loginName, shortPlaceholderPassword)
		stored := f.storedUser(t, loginName)
		require.Equal(t, created.ID, stored.ID)
		require.Equal(t, created.Salt, stored.Salt)

		identity := f.loginForm(t, loginName, shortPlaceholderPassword)
		require.Equal(t, strconv.FormatInt(stored.ID, 10), identity.ID)

		requireAdequateStorage(t, shortPlaceholderPassword, stored.Salt, string(stored.Password))
	})

	t.Run("change_password", func(t *testing.T) {
		const loginName = "placeholder-change"
		created := f.createUser(t, loginName, shortPlaceholderPassword)
		old := user.Password(shortPlaceholderPassword)
		next := user.Password(placeholderPassword)
		require.NoError(t, f.svc.Update(context.Background(), &user.UpdateUserCommand{
			UserID:      created.ID,
			OldPassword: &old,
			Password:    &next,
		}))

		stored := f.storedUser(t, loginName)
		identity := f.loginForm(t, loginName, placeholderPassword)
		require.Equal(t, strconv.FormatInt(stored.ID, 10), identity.ID)
		requireAdequateStorage(t, placeholderPassword, stored.Salt, string(stored.Password))
	})

	t.Run("reset_password", func(t *testing.T) {
		const loginName = "placeholder-reset"
		created := f.createUser(t, loginName, shortPlaceholderPassword)
		// Password reset, the admin password update, and grafana-cli
		// reset-admin-password all call Update with the new password and no
		// old password.
		next := user.Password(resetPlaceholderPassword)
		require.NoError(t, f.svc.Update(context.Background(), &user.UpdateUserCommand{
			UserID:   created.ID,
			Password: &next,
		}))

		stored := f.storedUser(t, loginName)
		identity := f.loginForm(t, loginName, resetPlaceholderPassword)
		require.Equal(t, strconv.FormatInt(stored.ID, 10), identity.ID)
		requireAdequateStorage(t, resetPlaceholderPassword, stored.Salt, string(stored.Password))
	})

	t.Run("legacy_hash_rehashed_on_login", func(t *testing.T) {
		const loginName = "placeholder-legacy"
		created := f.createUser(t, loginName, placeholderPassword)
		stored := f.storedUser(t, loginName)
		legacy, err := legacyPBKDF2Hex(placeholderPassword, stored.Salt)
		require.NoError(t, err)
		planted := user.Password(legacy)
		require.NoError(t, f.store.Update(context.Background(), &user.UpdateUserCommand{
			UserID:   created.ID,
			Password: &planted,
		}))
		plantedRow := f.storedUser(t, loginName)
		require.Equal(t, legacy, string(plantedRow.Password))

		identity := f.loginForm(t, loginName, placeholderPassword)
		require.Equal(t, strconv.FormatInt(created.ID, 10), identity.ID)

		upgraded := f.storedUser(t, loginName)
		requireAdequateStorage(t, placeholderPassword, upgraded.Salt, string(upgraded.Password))
	})
}
