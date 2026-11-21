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
	// passwordIterations follows the OWASP recommendation for PBKDF2-HMAC-SHA256.
	passwordIterations = 600_000
	// maxPasswordIterations bounds the work a stored hash can ask for at login.
	maxPasswordIterations = 10_000_000

	legacyPasswordIterations = 10_000
	legacyPasswordKeyLength  = 50
)

// EncodePassword hashes a login password with PBKDF2-HMAC-SHA256 and returns
// it as pbkdf2-sha256$<iterations>$<hex digest>. Use VerifyPassword to check a
// password against the result.
func EncodePassword(password string, salt string) (string, error) {
	digest, err := pbkdf2.Key(sha256.New, password, []byte(salt), passwordIterations, sha256.Size)
	if err != nil {
		return "", err
	}
	return passwordHashPrefix + strconv.Itoa(passwordIterations) + "$" + hex.EncodeToString(digest), nil
}

// VerifyPassword reports whether password matches a hash stored by
// EncodePassword, or by the hex PBKDF2 encoding used before it. needsRehash is
// true when the password matches but the hash should be replaced with the
// result of EncodePassword.
func VerifyPassword(password string, salt string, encoded string) (match bool, needsRehash bool) {
	if rest, ok := strings.CutPrefix(encoded, passwordHashPrefix); ok {
		iterText, digestHex, ok := strings.Cut(rest, "$")
		if !ok {
			return false, false
		}
		iterations, err := strconv.Atoi(iterText)
		if err != nil || iterations < 1 || iterations > maxPasswordIterations {
			return false, false
		}
		digest, err := hex.DecodeString(digestHex)
		if err != nil || len(digest) != sha256.Size {
			return false, false
		}
		derived, err := pbkdf2.Key(sha256.New, password, []byte(salt), iterations, len(digest))
		if err != nil || subtle.ConstantTimeCompare(derived, digest) != 1 {
			return false, false
		}
		return true, iterations != passwordIterations
	}

	digest, err := hex.DecodeString(encoded)
	if err != nil || len(digest) != legacyPasswordKeyLength {
		return false, false
	}
	derived, err := pbkdf2.Key(sha256.New, password, []byte(salt), legacyPasswordIterations, legacyPasswordKeyLength)
	if err != nil || subtle.ConstantTimeCompare(derived, digest) != 1 {
		return false, false
	}
	return true, true
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
