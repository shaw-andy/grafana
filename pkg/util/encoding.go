package util

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"mime/quotedprintable"
	"strconv"
	"strings"
)

const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// GetRandomString generates a random alphanumeric string of the specified length,
// optionally using only specified characters
func GetRandomString(n int, alphabets ...byte) (string, error) {
	chars := alphanum
	if len(alphabets) > 0 {
		chars = string(alphabets)
	}
	cnt := len(chars)
	max := 255 / cnt * cnt

	bytes := make([]byte, n)

	randread := n * 5 / 4
	randbytes := make([]byte, randread)

	for i := 0; i < n; {
		if _, err := rand.Read(randbytes); err != nil {
			return "", err
		}

		for j := 0; i < n && j < randread; j++ {
			b := int(randbytes[j])
			if b >= max {
				continue
			}

			bytes[i] = chars[b%cnt]
			i++
		}
	}

	return string(bytes), nil
}

const (
	passwordHashPrefix = "pbkdf2-sha256$"
	// PasswordHashIterations follows the OWASP recommendation for PBKDF2-HMAC-SHA256.
	PasswordHashIterations    = 600_000
	maxPasswordHashIterations = 10_000_000
	passwordHashKeyLen        = sha256.Size

	legacyPasswordHashIterations = 10_000
	legacyPasswordHashKeyLen     = 50
)

// EncodePassword hashes a login password with PBKDF2-HMAC-SHA256 and returns
// "pbkdf2-sha256$<iterations>$<hex digest>". The salt is not part of the result.
// Use VerifyPassword to check a password against the result.
func EncodePassword(password string, salt string) (string, error) {
	digest, err := pbkdf2.Key(sha256.New, password, []byte(salt), PasswordHashIterations, passwordHashKeyLen)
	if err != nil {
		return "", err
	}
	return passwordHashPrefix + strconv.Itoa(PasswordHashIterations) + "$" + hex.EncodeToString(digest), nil
}

// VerifyPassword reports whether password matches a stored hash produced by
// EncodePassword, or by the 10000-iteration PBKDF2 encoding used before it.
// needsRehash is true when the password matches but the stored hash is not
// what EncodePassword produces today, and should be replaced.
func VerifyPassword(password, salt, hash string) (ok bool, needsRehash bool) {
	if rest, found := strings.CutPrefix(hash, passwordHashPrefix); found {
		iterText, digestHex, found := strings.Cut(rest, "$")
		if !found {
			return false, false
		}
		iterations, err := strconv.Atoi(iterText)
		if err != nil || iterations < 1 || iterations > maxPasswordHashIterations {
			return false, false
		}
		digest, err := hex.DecodeString(digestHex)
		if err != nil || len(digest) == 0 {
			return false, false
		}
		if !pbkdf2Matches(password, salt, iterations, digest) {
			return false, false
		}
		return true, iterations != PasswordHashIterations || len(digest) != passwordHashKeyLen
	}

	digest, err := hex.DecodeString(hash)
	if err != nil || len(digest) != legacyPasswordHashKeyLen {
		return false, false
	}
	if !pbkdf2Matches(password, salt, legacyPasswordHashIterations, digest) {
		return false, false
	}
	return true, true
}

func pbkdf2Matches(password, salt string, iterations int, digest []byte) bool {
	derived, err := pbkdf2.Key(sha256.New, password, []byte(salt), iterations, len(digest))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(derived, digest) == 1
}

// EncodeAPIKeySecret hashes a server-generated random API key or service
// account token secret. Stored values are looked up by this hash, so the
// output must stay stable. Never use it for user-chosen passwords.
func EncodeAPIKeySecret(secret string, salt string) (string, error) {
	digest, err := pbkdf2.Key(sha256.New, secret, []byte(salt), legacyPasswordHashIterations, legacyPasswordHashKeyLen)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest), nil
}

// GetBasicAuthHeader returns a base64 encoded string from user and password.
func GetBasicAuthHeader(user string, password string) string {
	var userAndPass = user + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(userAndPass))
}

// DecodeBasicAuthHeader decodes user and password from a basic auth header.
func DecodeBasicAuthHeader(header string) (string, string, error) {
	var code string
	parts := strings.SplitN(header, " ", 2)
	if len(parts) == 2 && parts[0] == "Basic" {
		code = parts[1]
	}

	decoded, err := base64.StdEncoding.DecodeString(code)
	if err != nil {
		return "", "", err
	}

	userAndPass := strings.SplitN(string(decoded), ":", 2)
	if len(userAndPass) != 2 {
		return "", "", errors.New("invalid basic auth header")
	}

	return userAndPass[0], userAndPass[1], nil
}

// RandomHex returns a hex encoding of n random bytes.
func RandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// decodeQuotedPrintable decodes quoted-printable UTF-8 string
func DecodeQuotedPrintable(encodedValue string) string {
	decodedBytes, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(encodedValue)))
	if err != nil {
		return encodedValue
	}
	return string(decodedBytes)
}
