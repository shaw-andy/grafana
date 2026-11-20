package userimpl

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
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
)

// Same OWASP Password Storage Cheat Sheet bar as the login-client tests.
const owaspPBKDF2SHA256Iterations = 600_000

func TestPasswordChangeAndResetPersistStrongHash(t *testing.T) {
	cfg := shippedConfig(t)
	require.False(t, cfg.BasicAuthStrongPasswordPolicy)

	// Password change (LegacyService.Update with the old password) and password
	// reset (the same Update with only the new password) both persist Password.Hash.
	password := strings.Repeat("a", 4)
	require.NoError(t, user.ValidatePassword(password, cfg))

	salt, err := util.GetRandomString(10)
	require.NoError(t, err)
	previous, err := user.Password(strings.Repeat("b", 4)).Hash(salt)
	require.NoError(t, err)

	store := &captureStore{FakeUserStore: &FakeUserStore{ExpectedUser: &user.User{
		ID:       1,
		Salt:     salt,
		Password: previous,
	}}}
	svc := LegacyService{
		store:  store,
		cfg:    cfg,
		tracer: tracing.InitializeTracerForTest(),
	}

	next := user.Password(password)
	old := user.Password(strings.Repeat("b", 4))
	require.NoError(t, svc.Update(context.Background(), &user.UpdateUserCommand{
		UserID:      1,
		OldPassword: &old,
		Password:    &next,
	}))

	require.NotNil(t, store.updated)
	require.NotNil(t, store.updated.Password)
	stored := string(*store.updated.Password)
	if stored == lowCostPBKDF2(t, password, salt) || !storedLoginHashIsStrong(stored, password, salt) {
		t.Fatalf("password change and password reset persist PBKDF2-HMAC-SHA256 with 10000 iterations and a 50-byte output. The stored hash must use at least %d iterations, or a $pbkdf2-sha256$ / $argon2id$ encoding that meets the OWASP minimums", owaspPBKDF2SHA256Iterations)
	}
}

type captureStore struct {
	*FakeUserStore
	updated *user.UpdateUserCommand
}

func (s *captureStore) Update(_ context.Context, cmd *user.UpdateUserCommand) error {
	copied := *cmd
	if cmd.Password != nil {
		pw := *cmd.Password
		copied.Password = &pw
	}
	s.updated = &copied
	return nil
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
	return matchesModularPBKDF2(stored, password, salt) || matchesArgon2id(stored, password)
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
	minimums := []struct{ memory, time uint32 }{
		{47104, 1},
		{19456, 2},
		{12288, 3},
		{9216, 4},
		{7168, 5},
	}
	for _, params := range minimums {
		if memory >= params.memory && timeCost >= params.time {
			return true
		}
	}
	return false
}

func parseArgon2Params(field string) (memory, timeCost uint32, threads uint8, ok bool) {
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
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir)
		dir = parent
	}
	raw, err := os.ReadFile(filepath.Join(dir, "conf", "defaults.ini"))
	require.NoError(t, err)
	cfg, err := setting.NewCfgFromBytes(raw)
	require.NoError(t, err)
	return cfg
}
