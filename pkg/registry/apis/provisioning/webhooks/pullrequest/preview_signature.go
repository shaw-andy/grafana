package pullrequest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// PreviewURLTTL bounds how long a preview image URL posted to a pull request stays usable.
	PreviewURLTTL = 24 * time.Hour

	// previewClockSkew tolerates clock differences between the replica that
	// signed a URL and the one that serves it.
	previewClockSkew = 5 * time.Minute

	previewExpiresParam   = "exp"
	previewSignatureParam = "sig"
)

var (
	ErrPreviewSignatureMissing = errors.New("missing preview signature")
	ErrPreviewSignatureExpired = errors.New("preview signature expired")
	ErrPreviewSignatureInvalid = errors.New("invalid preview signature")
)

// SignPreviewQuery returns the query parameters that authorize reading one
// preview blob of one repository until expires.
func SignPreviewQuery(key []byte, namespace, name, blobID string, expires time.Time) url.Values {
	exp := strconv.FormatInt(expires.Unix(), 10)
	query := url.Values{}
	query.Set(previewExpiresParam, exp)
	query.Set(previewSignatureParam, hex.EncodeToString(previewMAC(key, namespace, name, blobID, exp)))
	return query
}

// PreviewSignature is the signature carried by a preview image request. It is
// parsed and time-checked before any repository is loaded, then verified
// against the repository key.
type PreviewSignature struct {
	exp string
	mac []byte
}

// ParsePreviewSignature rejects requests without a well-formed signature whose
// expiry is in the past or further in the future than a signer would set.
func ParsePreviewSignature(query url.Values, now time.Time) (PreviewSignature, error) {
	exp := query.Get(previewExpiresParam)
	sig := query.Get(previewSignatureParam)
	if exp == "" || sig == "" {
		return PreviewSignature{}, ErrPreviewSignatureMissing
	}
	expires, err := strconv.ParseInt(exp, 10, 64)
	if err != nil {
		return PreviewSignature{}, ErrPreviewSignatureInvalid
	}
	if now.Unix() > expires {
		return PreviewSignature{}, ErrPreviewSignatureExpired
	}
	if expires > now.Add(PreviewURLTTL+previewClockSkew).Unix() {
		return PreviewSignature{}, ErrPreviewSignatureInvalid
	}
	mac, err := hex.DecodeString(sig)
	if err != nil || len(mac) != sha256.Size {
		return PreviewSignature{}, ErrPreviewSignatureInvalid
	}
	return PreviewSignature{exp: exp, mac: mac}, nil
}

// Verify reports whether the signature was issued with key for exactly this
// namespace, repository, and blob.
func (s PreviewSignature) Verify(key []byte, namespace, name, blobID string) bool {
	if len(key) == 0 || len(s.mac) == 0 {
		return false
	}
	return hmac.Equal(s.mac, previewMAC(key, namespace, name, blobID, s.exp))
}

func previewMAC(key []byte, namespace, name, blobID, exp string) []byte {
	mac := hmac.New(sha256.New, key)
	// NUL cannot appear in any of the fields, so the encoding is unambiguous.
	mac.Write([]byte(strings.Join([]string{namespace, name, blobID, exp}, "\x00")))
	return mac.Sum(nil)
}
