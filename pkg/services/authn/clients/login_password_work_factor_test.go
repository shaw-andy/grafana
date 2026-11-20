package clients

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
)

// OWASP Password Storage Cheat Sheet minimums used as the bar for a fix:
// PBKDF2-HMAC-SHA256 at 600,000 iterations, or Argon2id at one of the listed
// memory/time pairs (m is KiB).
const owaspPBKDF2SHA256Iterations = 600_000

var owaspArgon2idParams = []struct {
	memory uint32
	time   uint32
}{
	{memory: 47104, time: 1},
	{memory: 19456, time: 2},
	{memory: 12288, time: 3},
	{memory: 9216, time: 4},
	{memory: 7168, time: 5},
}

func TestStoredLoginPasswordWorkFactor(t *testing.T) {
	cfg := shippedConfig(t)
	require.False(t, cfg.DisableLogin, "shipped auth.disable_login")
	require.False(t, cfg.DisableLoginForm, "shipped auth.disable_login_form")
	require.True(t, cfg.BasicAuthEnabled, "shipped auth.basic enabled")
	require.False(t, cfg.BasicAuthStrongPasswordPolicy, "shipped auth.basic password_policy")
	require.False(t, cfg.DisableInitAdminCreation, "shipped security.disable_initial_admin_creation")

	// The shipped policy accepts a four-character password. The placeholder is
	// not a credential; it only has to be a password the product will store.
	short := strings.Repeat("a", 4)
	require.NoError(t, user.ValidatePassword(short, cfg))
	require.GreaterOrEqual(t, len(cfg.AdminPassword), 4)

	t.Run("minimum length password", func(t *testing.T) {
		assertLoginHashResistsLowCostSearch(t, short, fourCharacterSearchSpace())
	})

	t.Run("configured admin password", func(t *testing.T) {
		// Initial admin creation hashes this value with EncodePassword and stores
		// the digest next to the salt. The candidate list is that configured value.
		assertLoginHashResistsLowCostSearch(t, cfg.AdminPassword, []string{cfg.AdminPassword})
	})

	t.Run("legacy hash upgraded on login", func(t *testing.T) {
		assertLegacyHashUpgradedOnLogin(t, cfg, short)
	})
}

func assertLoginHashResistsLowCostSearch(t *testing.T, password string, candidates []string) {
	t.Helper()

	salt, err := util.GetRandomString(10)
	require.NoError(t, err)
	require.Len(t, salt, 10)

	fromHash, err := user.Password(password).Hash(salt)
	require.NoError(t, err)
	fromEncode, err := util.EncodePassword(password, salt)
	require.NoError(t, err)
	// User creation, password change, and password reset hash through Password.Hash.
	// Initial admin creation and login verification hash through EncodePassword.
	require.Equal(t, fromEncode, string(fromHash))

	lowCost := lowCostPBKDF2(t, password, salt)
	recovered := false
	for _, candidate := range candidates {
		if lowCostPBKDF2(t, candidate, salt) == fromEncode {
			recovered = true
			break
		}
	}

	if recovered || fromEncode == lowCost || !storedLoginHashIsStrong(fromEncode, password, salt) {
		t.Fatalf("stored login hash matches PBKDF2-HMAC-SHA256 with 10000 iterations and a 50-byte output, so an offline search with the salt stored on the user row recovered the password. New hashes from EncodePassword and Password.Hash must be PBKDF2-HMAC-SHA256 at %d iterations (bare hex only at that count, key length 32, 50, or 64) or a $pbkdf2-sha256$ / $argon2id$ encoding that meets the OWASP minimums, and login verification must accept that encoding", owaspPBKDF2SHA256Iterations)
	}

	svc := &usertest.FakeUserService{
		ExpectedUser: &user.User{ID: 1, Password: fromHash, Salt: salt},
	}
	client := ProvideGrafana(setting.NewCfg(), svc, tracing.InitializeTracerForTest())
	identity, err := client.AuthenticatePassword(context.Background(), &authn.Request{}, "user", password)
	require.NoError(t, err)
	require.NotNil(t, identity)
	require.Equal(t, login.PasswordAuthModule, identity.AuthenticatedBy)

	_, err = client.AuthenticatePassword(context.Background(), &authn.Request{}, "user", strings.Repeat("b", 4))
	require.Error(t, err)
}

func assertLegacyHashUpgradedOnLogin(t *testing.T, cfg *setting.Cfg, password string) {
	t.Helper()

	salt, err := util.GetRandomString(10)
	require.NoError(t, err)
	legacy := lowCostPBKDF2(t, password, salt)

	current, err := util.EncodePassword(password, salt)
	require.NoError(t, err)
	require.Equal(t, legacy, current, "login verification must still understand an existing 10000-iteration hash before the upgrade assertion")

	svc := &recordingUserService{
		FakeUserService: usertest.FakeUserService{
			ExpectedUser: &user.User{ID: 1, Salt: salt, Password: user.Password(legacy)},
		},
		cfg: cfg,
	}
	client := ProvideGrafana(cfg, svc, tracing.InitializeTracerForTest())

	identity, err := client.AuthenticatePassword(context.Background(), &authn.Request{}, "user", password)
	require.NoError(t, err)
	require.NotNil(t, identity)
	require.Equal(t, login.PasswordAuthModule, identity.AuthenticatedBy)
	if svc.upgraded == nil || !storedLoginHashIsStrong(string(*svc.upgraded), password, salt) {
		t.Fatal("password login accepted a legacy PBKDF2-HMAC-SHA256 hash of 10000 iterations and left that hash stored. A successful login must persist a new hash that meets the OWASP work factor")
	}

	_, err = client.AuthenticatePassword(context.Background(), &authn.Request{}, "user", strings.Repeat("b", 4))
	require.Error(t, err)

	identity, err = client.AuthenticatePassword(context.Background(), &authn.Request{}, "user", password)
	require.NoError(t, err)
	require.NotNil(t, identity)
}

// recordingUserService applies the password handling in LegacyService.Update:
// validate, hash with the stored salt, and reject an unchanged hash.
type recordingUserService struct {
	usertest.FakeUserService
	cfg      *setting.Cfg
	upgraded *user.Password
}

func (s *recordingUserService) Update(_ context.Context, cmd *user.UpdateUserCommand) error {
	if cmd == nil || cmd.Password == nil || s.ExpectedUser == nil {
		return nil
	}
	if err := cmd.Password.Validate(s.cfg); err != nil {
		return err
	}
	hashed, err := cmd.Password.Hash(s.ExpectedUser.Salt)
	if err != nil {
		return err
	}
	if hashed == s.ExpectedUser.Password {
		return user.ErrNewPasswordSameAsOld
	}
	s.ExpectedUser.Password = hashed
	pw := hashed
	s.upgraded = &pw
	return nil
}

func fourCharacterSearchSpace() []string {
	const alphabet = "ab"
	out := make([]string, 0, 16)
	var walk func(prefix string)
	walk = func(prefix string) {
		if len(prefix) == 4 {
			out = append(out, prefix)
			return
		}
		for i := 0; i < len(alphabet); i++ {
			walk(prefix + alphabet[i:i+1])
		}
	}
	walk("")
	// Search the real placeholder last so a match is the result of the whole space.
	target := strings.Repeat("a", 4)
	ordered := make([]string, 0, len(out))
	var last string
	for _, candidate := range out {
		if candidate == target {
			last = candidate
			continue
		}
		ordered = append(ordered, candidate)
	}
	if last != "" {
		ordered = append(ordered, last)
	}
	return ordered
}

func lowCostPBKDF2(t *testing.T, password, salt string) string {
	t.Helper()
	derived, err := pbkdf2.Key(sha256.New, password, []byte(salt), 10_000, 50)
	require.NoError(t, err)
	return hex.EncodeToString(derived)
}

func storedLoginHashIsStrong(stored, password, salt string) bool {
	if stored == "" || matchesPBKDF2(stored, password, salt, 10_000, 50) {
		return false
	}
	for _, keyLen := range []int{32, 50, 64} {
		if matchesPBKDF2(stored, password, salt, owaspPBKDF2SHA256Iterations, keyLen) {
			return true
		}
	}
	if matchesModularPBKDF2(stored, password, salt) {
		return true
	}
	return matchesArgon2id(stored, password)
}

func matchesPBKDF2(stored, password, salt string, iterations, keyLen int) bool {
	derived, err := pbkdf2.Key(sha256.New, password, []byte(salt), iterations, keyLen)
	if err != nil {
		return false
	}
	sum, err := hex.DecodeString(stored)
	if err != nil || len(sum) != keyLen {
		return false
	}
	return subtle.ConstantTimeCompare(derived, sum) == 1
}

func matchesModularPBKDF2(stored, password, salt string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[2])
	if err != nil || iterations < owaspPBKDF2SHA256Iterations {
		return false
	}
	saltBytes, err := decodeFlexibleBase64(parts[3])
	if err != nil || string(saltBytes) != salt {
		return false
	}
	digest, err := decodeFlexibleBase64(parts[4])
	if err != nil || len(digest) < 32 {
		return false
	}
	derived, err := pbkdf2.Key(sha256.New, password, saltBytes, iterations, len(digest))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(derived, digest) == 1
}

func matchesArgon2id(stored, password string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	memory, timeCost, threads, ok := parseArgon2Params(parts[3])
	if !ok || !argon2idMeetsOWASP(memory, timeCost) || memory > 64*1024 {
		return false
	}
	salt, err := decodeFlexibleBase64(parts[4])
	if err != nil || len(salt) == 0 {
		return false
	}
	digest, err := decodeFlexibleBase64(parts[5])
	if err != nil || len(digest) < 16 {
		return false
	}
	derived := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(digest)))
	return subtle.ConstantTimeCompare(derived, digest) == 1
}

func argon2idMeetsOWASP(memory, timeCost uint32) bool {
	for _, params := range owaspArgon2idParams {
		if memory >= params.memory && timeCost >= params.time {
			return true
		}
	}
	return false
}

func parseArgon2Params(field string) (memory, timeCost uint32, threads uint8, ok bool) {
	threads = 1
	for _, item := range strings.Split(field, ",") {
		key, value, found := strings.Cut(item, "=")
		if !found {
			return 0, 0, 0, false
		}
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return 0, 0, 0, false
		}
		switch key {
		case "m":
			memory = uint32(parsed)
		case "t":
			timeCost = uint32(parsed)
		case "p":
			if parsed == 0 || parsed > 255 {
				return 0, 0, 0, false
			}
			threads = uint8(parsed)
		default:
			return 0, 0, 0, false
		}
	}
	if memory == 0 || timeCost == 0 || threads == 0 {
		return 0, 0, 0, false
	}
	return memory, timeCost, threads, true
}

func decodeFlexibleBase64(value string) ([]byte, error) {
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

func shippedConfig(t *testing.T) *setting.Cfg {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), "conf", "defaults.ini"))
	require.NoError(t, err)
	cfg, err := setting.NewCfgFromBytes(raw)
	require.NoError(t, err)
	return cfg
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir)
		dir = parent
	}
}
