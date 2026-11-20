package sqlstore

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// placeholderPassword is an obvious stand-in for a caller-supplied login
// password. It is not a credential.
const placeholderPassword = "PLACEHOLDER"

func TestIntegrationInitialAdminPasswordWorkFactor(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	store := NewTestStore(t)
	ctx := context.Background()
	var created user.User
	err := store.WithTransactionalDbSession(ctx, func(sess *DBSession) error {
		var createErr error
		created, createErr = store.createUser(ctx, sess, user.CreateUserCommand{
			Login:    "placeholder-admin",
			Email:    "placeholder-admin@example.com",
			Password: user.Password(placeholderPassword),
			IsAdmin:  true,
		})
		return createErr
	})
	require.NoError(t, err)

	var stored user.User
	err = store.WithDbSession(ctx, func(sess *DBSession) error {
		has, getErr := sess.ID(created.ID).Get(&stored)
		if getErr != nil {
			return getErr
		}
		if !has {
			t.Fatal("admin user row was not stored")
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, stored.Salt, "salt column is empty")
	require.NotEmpty(t, stored.Password, "password column is empty")
	require.Equal(t, created.Salt, stored.Salt)

	if msg := loginPasswordStorageWeakness(placeholderPassword, stored.Salt, string(stored.Password)); msg != "" {
		t.Fatal(msg)
	}
}

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
