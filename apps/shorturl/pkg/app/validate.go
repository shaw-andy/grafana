package app

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

// Local error definitions to avoid importing the main shorturls package
var (
	ErrShortURLAbsolutePath = fmt.Errorf("path should be relative")
	ErrShortURLInvalidPath  = fmt.Errorf("invalid short URL path")
)

// validateRelativePath checks that a short URL path is a safe relative path
// that will not redirect to an external domain.
func validateRelativePath(rawPath string) error {
	p := strings.TrimSpace(rawPath)

	// IMPORTANT: This logic is duplicated in pkg/services/shorturls/models.go — keep both in sync.
	// Reject path traversal (forward and backslash variants)
	if strings.Contains(p, "../") || strings.Contains(p, `..\`) {
		return fmt.Errorf("%w: %s", ErrShortURLInvalidPath, p)
	}

	// Reject protocol-relative URLs (//evil.com) before the general absolute path check
	if strings.HasPrefix(p, "//") {
		return fmt.Errorf("%w: %s", ErrShortURLInvalidPath, p)
	}

	// Reject backslash-based paths that browsers may interpret as URLs
	if strings.HasPrefix(p, `\`) {
		return fmt.Errorf("%w: %s", ErrShortURLInvalidPath, p)
	}

	// Reject URLs containing a scheme (e.g. http://evil.com)
	if strings.Contains(p, "://") {
		return fmt.Errorf("%w: %s", ErrShortURLInvalidPath, p)
	}

	// Parse as URL and reject if it has a scheme (catches scheme:... patterns like javascript:alert(1))
	parsed, err := url.Parse(p)
	if err == nil && parsed.Scheme != "" {
		return fmt.Errorf("%w: %s", ErrShortURLInvalidPath, p)
	}

	// Reject absolute filesystem paths (starts with /)
	if path.IsAbs(p) {
		return fmt.Errorf("%w: %s", ErrShortURLAbsolutePath, p)
	}

	if err != nil {
		return fmt.Errorf("%w: not a valid URL path: %s", ErrShortURLInvalidPath, p)
	}

	// Browsers treat %2e as "." when removing dot segments, so the checks above
	// must also hold for the percent-decoded path.
	decoded := decodePath(parsed.Path)
	if reason := unsafePathReason(decoded); reason != "" {
		return fmt.Errorf("%w: path cannot contain %s: %s", ErrShortURLInvalidPath, reason, p)
	}
	if strings.HasPrefix(decoded, "/") || strings.Contains(decoded, "://") {
		return fmt.Errorf("%w: %s", ErrShortURLInvalidPath, p)
	}
	if decodedURL, err := url.Parse(decoded); err == nil && decodedURL.Scheme != "" {
		return fmt.Errorf("%w: %s", ErrShortURLInvalidPath, p)
	}

	return nil
}

// resolveRedirectURL resolves target against appURL and returns the URL to
// redirect to. It refuses any target that, once a browser has decoded and
// removed its dot segments, would leave appURL's scheme, host or path prefix.
// IMPORTANT: This logic is duplicated in pkg/services/shorturls/models.go — keep both in sync.
func resolveRedirectURL(appURL, target string) (string, error) {
	root, err := url.Parse(strings.TrimSuffix(appURL, "/") + "/")
	if err != nil || root.Opaque != "" {
		return "", fmt.Errorf("invalid app URL: %s", appURL)
	}

	ref, err := url.Parse(target)
	if err != nil || ref.Opaque != "" || ref.User != nil {
		return "", fmt.Errorf("%w: %s", ErrShortURLInvalidPath, target)
	}
	if reason := unsafePathReason(decodePath(ref.Path)); reason != "" {
		return "", fmt.Errorf("%w: redirect cannot contain %s: %s", ErrShortURLInvalidPath, reason, target)
	}

	resolved := root.ResolveReference(ref)
	if !strings.EqualFold(resolved.Scheme, root.Scheme) || !strings.EqualFold(resolved.Host, root.Host) {
		return "", fmt.Errorf("%w: redirect points outside the app URL: %s", ErrShortURLInvalidPath, target)
	}

	rootPath := root.EscapedPath()
	resolvedPath := resolved.EscapedPath()
	if resolvedPath+"/" != rootPath && !strings.HasPrefix(resolvedPath, rootPath) {
		return "", fmt.Errorf("%w: redirect points outside the app URL: %s", ErrShortURLInvalidPath, target)
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
