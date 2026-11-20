package userimpl

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/loginattempt/loginattempttest"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// Placeholders stand in for login passwords. They are not credentials.
const (
	passwordPlaceholder        = "placeholder-password"
	changedPasswordPlaceholder = "placeholder-password-next"
	resetPasswordPlaceholder   = "placeholder-password-reset"
	shortPasswordPlaceholder   = "xxxx"
)

// Legacy verifiers already in the user table are PBKDF2-HMAC-SHA256 with these
// parameters. Login must still accept one and replace it; the parameters are
// not an acceptable cost for a newly stored verifier.
const (
	legacyPBKDF2Iterations = 10000
	legacyPBKDF2KeyLen     = 50
)

// OWASP Password Storage Cheat Sheet work factors for PBKDF2. The algorithm
// and iteration count have to travel with the digest, in PHC form:
//
//	$pbkdf2-sha256$i=<iterations>$<salt>$<digest>
//	$pbkdf2-sha512$i=<iterations>$<salt>$<digest>
//
// Salt and digest are hex, standard base64, or unpadded base64.
const (
	owaspPBKDF2SHA256Iterations = 600_000
	owaspPBKDF2SHA512Iterations = 220_000
)

func TestIntegrationCreatedLoginPasswordUsesOWASPWorkFactor(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	_, svc := setupUserService(t)

	t.Run("four character password", func(t *testing.T) {
		created := createLoginUser(t, svc, "placeholder-short", "placeholder-short@example.com", shortPasswordPlaceholder)
		reloaded, err := svc.GetByID(context.Background(), &user.GetUserByIDQuery{ID: created.ID})
		require.NoError(t, err)
		requireOWASPPasswordVerifier(t, shortPasswordPlaceholder, string(reloaded.Password))
	})

	t.Run("longer password", func(t *testing.T) {
		created := createLoginUser(t, svc, "placeholder-user", "placeholder-user@example.com", passwordPlaceholder)
		reloaded, err := svc.GetByID(context.Background(), &user.GetUserByIDQuery{ID: created.ID})
		require.NoError(t, err)
		requireOWASPPasswordVerifier(t, passwordPlaceholder, string(reloaded.Password))
	})

	t.Run("encode password", func(t *testing.T) {
		encoded, err := util.EncodePassword(passwordPlaceholder, "placeholder-salt")
		require.NoError(t, err)
		requireOWASPPasswordVerifier(t, passwordPlaceholder, encoded)
	})
}

func TestIntegrationChangedAndResetLoginPasswordUsesOWASPWorkFactor(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	_, svc := setupUserService(t)

	t.Run("change", func(t *testing.T) {
		created := createLoginUser(t, svc, "placeholder-change", "placeholder-change@example.com", passwordPlaceholder)
		changed := user.Password(changedPasswordPlaceholder)
		previous := user.Password(passwordPlaceholder)
		err := svc.Update(context.Background(), &user.UpdateUserCommand{
			UserID:      created.ID,
			Password:    &changed,
			OldPassword: &previous,
		})
		require.NoError(t, err)

		reloaded, err := svc.GetByID(context.Background(), &user.GetUserByIDQuery{ID: created.ID})
		require.NoError(t, err)
		requireOWASPPasswordVerifier(t, changedPasswordPlaceholder, string(reloaded.Password))
	})

	t.Run("reset", func(t *testing.T) {
		created := createLoginUser(t, svc, "placeholder-reset", "placeholder-reset@example.com", passwordPlaceholder)
		reset := user.Password(resetPasswordPlaceholder)
		err := svc.Update(context.Background(), &user.UpdateUserCommand{
			UserID:   created.ID,
			Password: &reset,
		})
		require.NoError(t, err)

		reloaded, err := svc.GetByID(context.Background(), &user.GetUserByIDQuery{ID: created.ID})
		require.NoError(t, err)
		requireOWASPPasswordVerifier(t, resetPasswordPlaceholder, string(reloaded.Password))
	})
}

func TestIntegrationLoginUpgradesLegacyLowCostPassword(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	ss, svc := setupUserService(t)
	victim := createLoginUser(t, svc, "placeholder-victim", "placeholder-victim@example.com", passwordPlaceholder)
	bystander := createLoginUser(t, svc, "placeholder-bystander", "placeholder-bystander@example.com", changedPasswordPlaceholder)

	victimRow, err := svc.GetByID(context.Background(), &user.GetUserByIDQuery{ID: victim.ID})
	require.NoError(t, err)
	bystanderRow, err := svc.GetByID(context.Background(), &user.GetUserByIDQuery{ID: bystander.ID})
	require.NoError(t, err)

	installLegacyVerifier(t, ss, victim.ID, passwordPlaceholder, victimRow.Salt)
	bystanderLegacy := installLegacyVerifier(t, ss, bystander.ID, changedPasswordPlaceholder, bystanderRow.Salt)

	req := loginRequest(t, victim.Login, passwordPlaceholder)
	form := newLoginForm(t, svc)
	identity, err := form.Authenticate(context.Background(), &authn.Request{HTTPRequest: req, OrgID: victim.OrgID})
	require.NoError(t, err)
	require.Equal(t, strconv.FormatInt(victim.ID, 10), identity.ID)

	reloaded, err := svc.GetByID(context.Background(), &user.GetUserByIDQuery{ID: victim.ID})
	require.NoError(t, err)
	requireOWASPPasswordVerifier(t, passwordPlaceholder, string(reloaded.Password))

	untouched, err := svc.GetByID(context.Background(), &user.GetUserByIDQuery{ID: bystander.ID})
	require.NoError(t, err)
	require.Equal(t, bystanderLegacy, string(untouched.Password))
}

func TestIntegrationDefaultAdminPasswordUsesOWASPWorkFactor(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	ss, cfg := db.InitTestDBWithCfg(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	sqlstore.SeedDefaultOrgAndUser(t, ss)

	_, svc := createOrgAndUserSvc(t, ss, cfg)
	admin, err := svc.GetByLogin(context.Background(), &user.GetUserByLoginQuery{LoginOrEmail: cfg.AdminUser})
	require.NoError(t, err)
	require.True(t, admin.IsAdmin)
	requireOWASPPasswordVerifier(t, cfg.AdminPassword, string(admin.Password))
}

func setupUserService(t *testing.T) (*sqlstore.SQLStore, user.Service) {
	t.Helper()

	ss, cfg := db.InitTestDBWithCfg(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	cfg.BasicAuthStrongPasswordPolicy = false
	_, svc := createOrgAndUserSvc(t, ss, cfg)
	return ss, svc
}

func createLoginUser(t *testing.T, svc user.Service, login, email, password string) *user.User {
	t.Helper()

	created, err := svc.Create(context.Background(), &user.CreateUserCommand{
		Login:    login,
		Email:    email,
		Password: user.Password(password),
	})
	require.NoError(t, err)
	return created
}

func installLegacyVerifier(t *testing.T, ss *sqlstore.SQLStore, id int64, password, salt string) string {
	t.Helper()

	raw, err := pbkdf2.Key(sha256.New, password, []byte(salt), legacyPBKDF2Iterations, legacyPBKDF2KeyLen)
	require.NoError(t, err)
	legacy := hex.EncodeToString(raw)

	err = ss.WithDbSession(context.Background(), func(sess *sqlstore.DBSession) error {
		_, err := sess.Exec("UPDATE "+ss.Quote("user")+" SET password = ? WHERE id = ?", legacy, id)
		return err
	})
	require.NoError(t, err)
	return legacy
}

func newLoginForm(t *testing.T, svc user.Service) *clients.Form {
	t.Helper()

	tracer := tracing.InitializeTracerForTest()
	grafana := clients.ProvideGrafana(setting.NewCfg(), svc, tracer)
	attempts := loginattempttest.FakeLoginAttemptService{ExpectedValid: true}
	return clients.ProvideForm(clients.ProvidePassword(attempts, tracer, grafana))
}

func loginRequest(t *testing.T, login, password string) *http.Request {
	t.Helper()

	body := `{"user":"` + login + `","password":"` + password + `"}`
	req, err := http.NewRequest(http.MethodPost, "/login", io.NopCloser(strings.NewReader(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:1234"
	return req
}

func requireOWASPPasswordVerifier(t *testing.T, password, stored string) {
	t.Helper()

	if stored == "" {
		t.Fatal("stored login password verifier is empty")
	}
	if passwordVerifierMeetsOWASP(password, stored) {
		return
	}
	t.Fatalf("stored login password verifier is missing a self-describing PBKDF2 cost of at least %d HMAC-SHA256 iterations or %d HMAC-SHA512 iterations", owaspPBKDF2SHA256Iterations, owaspPBKDF2SHA512Iterations)
}

func passwordVerifierMeetsOWASP(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 5 || parts[0] != "" {
		return false
	}

	var minIter int
	var newHash func() hash.Hash
	switch parts[1] {
	case "pbkdf2-sha256":
		minIter = owaspPBKDF2SHA256Iterations
		newHash = sha256.New
	case "pbkdf2-sha512":
		minIter = owaspPBKDF2SHA512Iterations
		newHash = sha512.New
	default:
		return false
	}

	iter, err := strconv.Atoi(strings.TrimPrefix(parts[2], "i="))
	if err != nil || iter < minIter {
		return false
	}

	salts := decodeVerifierMaterial(parts[3])
	digests := decodeVerifierMaterial(parts[4])
	for _, salt := range salts {
		if len(salt) == 0 {
			continue
		}
		for _, digest := range digests {
			if len(digest) < 32 {
				continue
			}
			got, err := pbkdf2.Key(newHash, password, salt, iter, len(digest))
			if err != nil {
				continue
			}
			if subtle.ConstantTimeCompare(got, digest) == 1 {
				return true
			}
		}
	}
	return false
}

func decodeVerifierMaterial(segment string) [][]byte {
	if segment == "" {
		return nil
	}

	seen := map[string]struct{}{}
	add := func(b []byte) [][]byte {
		if len(b) == 0 {
			return nil
		}
		key := string(b)
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}
		return [][]byte{b}
	}

	out := add([]byte(segment))
	if decoded, err := hex.DecodeString(segment); err == nil {
		out = append(out, add(decoded)...)
	}
	if decoded, err := base64.StdEncoding.DecodeString(segment); err == nil {
		out = append(out, add(decoded)...)
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(segment); err == nil {
		out = append(out, add(decoded)...)
	}
	return out
}
