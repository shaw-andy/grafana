package shorturls

import (
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/grafana/grafana/pkg/apimachinery/errutil"
)

var (
	ErrShortURLBadRequest   = errutil.BadRequest("shorturl.bad-request")
	ErrShortURLNotFound     = errutil.NotFound("shorturl.not-found")
	ErrShortURLAbsolutePath = errutil.ValidationFailed("shorturl.absolute-path", errutil.WithPublicMessage("Path should be relative"))
	ErrShortURLInvalidPath  = errutil.ValidationFailed("shorturl.invalid-path", errutil.WithPublicMessage("Invalid short URL path"))
	ErrShortURLInternal     = errutil.Internal("shorturl.internal")
	ErrShortURLConflict     = errutil.Conflict("shorturl.conflict")
)

type ShortUrl struct {
	Id         int64  `json:"-"`
	OrgId      int64  `json:"-"`
	Uid        string `json:"uid"`
	Path       string `json:"path"`
	CreatedBy  int64  `json:"-"`
	CreatedAt  int64  `json:"-"`
	LastSeenAt int64  `json:"lastSeenAt"`
}

// ValidateRelativePath checks that a short URL path is a safe relative path
// that will not redirect to an external domain. It returns an appropriate error
// if the path is invalid, or nil if the path is safe.
// IMPORTANT: This logic is duplicated in apps/shorturl/pkg/app/validate.go — keep both in sync.
func ValidateRelativePath(rawPath string) error {
	p := strings.TrimSpace(rawPath)

	// Reject path traversal (forward and backslash variants)
	if strings.Contains(p, "../") || strings.Contains(p, `..\`) {
		return ErrShortURLInvalidPath.Errorf("path cannot contain '../': %s", p)
	}

	// Reject protocol-relative URLs (//evil.com) before the general absolute path check
	if strings.HasPrefix(p, "//") {
		return ErrShortURLInvalidPath.Errorf("path cannot start with '//': %s", p)
	}

	// Reject backslash-based paths that browsers may interpret as URLs (\\evil.com, \evil.com)
	if strings.HasPrefix(p, `\`) {
		return ErrShortURLInvalidPath.Errorf("path cannot start with backslash: %s", p)
	}

	// Reject URLs containing a scheme (e.g. http://evil.com)
	if strings.Contains(p, "://") {
		return ErrShortURLInvalidPath.Errorf("path cannot contain a URL scheme: %s", p)
	}

	// Parse as URL and reject if it has a scheme (catches scheme:... patterns like javascript:alert(1))
	parsed, err := url.Parse(p)
	if err == nil && parsed.Scheme != "" {
		return ErrShortURLInvalidPath.Errorf("path cannot contain a URL scheme: %s", p)
	}

	// Reject absolute filesystem paths (starts with /)
	if path.IsAbs(p) {
		return ErrShortURLAbsolutePath.Errorf("expected relative path: %s", p)
	}

	if err != nil {
		return ErrShortURLInvalidPath.Errorf("path is not a valid URL path: %s", p)
	}

	// Browsers treat %2e as "." when removing dot segments, so the checks above
	// must also hold for the percent-decoded path.
	decoded := decodePath(parsed.Path)
	if reason := unsafePathReason(decoded); reason != "" {
		return ErrShortURLInvalidPath.Errorf("path cannot contain %s: %s", reason, p)
	}
	if strings.HasPrefix(decoded, "/") {
		return ErrShortURLInvalidPath.Errorf("decoded path cannot start with '/': %s", p)
	}
	if strings.Contains(decoded, "://") {
		return ErrShortURLInvalidPath.Errorf("path cannot contain a URL scheme: %s", p)
	}
	if decodedURL, err := url.Parse(decoded); err == nil && decodedURL.Scheme != "" {
		return ErrShortURLInvalidPath.Errorf("path cannot contain a URL scheme: %s", p)
	}

	return nil
}

// ResolveRedirectURL resolves target against appURL and returns the URL to
// redirect to. It refuses any target that, once a browser has decoded and
// removed its dot segments, would leave appURL's scheme, host or path prefix.
func ResolveRedirectURL(appURL, target string) (string, error) {
	root, err := url.Parse(strings.TrimSuffix(appURL, "/") + "/")
	if err != nil || root.Opaque != "" {
		return "", ErrShortURLInternal.Errorf("invalid app URL: %s", appURL)
	}

	ref, err := url.Parse(target)
	if err != nil || ref.Opaque != "" || ref.User != nil {
		return "", ErrShortURLInvalidPath.Errorf("invalid redirect URL: %s", target)
	}
	if reason := unsafePathReason(decodePath(ref.Path)); reason != "" {
		return "", ErrShortURLInvalidPath.Errorf("redirect URL cannot contain %s: %s", reason, target)
	}

	resolved := root.ResolveReference(ref)
	if !strings.EqualFold(resolved.Scheme, root.Scheme) || !strings.EqualFold(resolved.Host, root.Host) {
		return "", ErrShortURLInvalidPath.Errorf("redirect URL points outside the app URL: %s", target)
	}

	rootPath := root.EscapedPath()
	resolvedPath := resolved.EscapedPath()
	if resolvedPath+"/" != rootPath && !strings.HasPrefix(resolvedPath, rootPath) {
		return "", ErrShortURLInvalidPath.Errorf("redirect URL points outside the app URL: %s", target)
	}

	return resolved.String(), nil
}

// decodePath percent-decodes p until it stops changing, so that encoded dots,
// slashes and backslashes are checked the way any later decoder will see them.
func decodePath(p string) string {
	for {
		next, err := url.PathUnescape(p)
		if err != nil || next == p {
			return p
		}
		p = next
	}
}

// unsafePathReason describes why a decoded path could escape the URL it is
// appended to, or returns "" if it cannot.
func unsafePathReason(decoded string) string {
	for _, r := range decoded {
		if r < 0x20 || r == 0x7f {
			return "control characters"
		}
	}
	if strings.Contains(decoded, `\`) {
		return "a backslash"
	}
	for _, seg := range strings.Split(decoded, "/") {
		if seg == "." || seg == ".." {
			return "dot segments"
		}
	}
	return ""
}

type DeleteShortUrlCommand struct {
	OrgId     int64
	Uid       string
	OlderThan time.Time

	NumDeleted int64
}
