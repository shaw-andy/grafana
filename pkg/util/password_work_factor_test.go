package util

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// placeholderPassword is an obvious stand-in for a caller-supplied login
// password. It is not a credential.
const placeholderPassword = "PLACEHOLDER"

// loginPasswordStorageWeakness reports why a stored login password does not
// meet the password-storage parameters these tests require. An empty string
// means the stored value is acceptable.
//
// Acceptable stored values, given the plaintext password and the salt column:
//   - lowercase or mixed-case hex of PBKDF2-HMAC-SHA256 at exactly 600000
//     iterations (the OWASP minimum for that algorithm)
//   - pbkdf2-sha256$<iterations>$<hex digest> with iterations in [600000, 2000000],
//     using the salt column as the PBKDF2 salt
//   - an argon2id PHC string, version 19, with m in [19456, 262144] KiB,
//     t in [2, 4], p in [1, 8]
//   - a bcrypt hash with cost in [10, 12]
//
// PBKDF2-HMAC-SHA256 at 10000 iterations is the value EncodePassword uses today
// and is never acceptable, including when an existing row is verified at login.
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

func TestEncodePasswordWorkFactor(t *testing.T) {
	const salt = "placeholdersalt"
	encoded, err := EncodePassword(placeholderPassword, salt)
	if err != nil {
		t.Fatalf("EncodePassword returned an error: %v", err)
	}
	if msg := loginPasswordStorageWeakness(placeholderPassword, salt, encoded); msg != "" {
		t.Fatal(msg)
	}
}
