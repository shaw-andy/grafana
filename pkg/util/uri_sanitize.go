package util

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

const masking = "hidden"

var sensitiveQueryChecks = map[string]func(key string, urlValues url.Values) bool{
	"auth_token": func(key string, urlValues url.Values) bool {
		return true
	},
	"x-amz-signature": func(key string, urlValues url.Values) bool {
		return true
	},
	"x-goog-signature": func(key string, urlValues url.Values) bool {
		return true
	},
	"sig": func(key string, urlValues url.Values) bool {
		for k := range urlValues {
			if strings.ToLower(k) == "sv" {
				return true
			}
		}
		return false
	},
}

// sensitivePathPrefixes are path segment sequences that are followed by a
// credential, such as a public dashboard access token. Matching is not anchored
// to the start of the path so that a sub-path in a referer is still covered.
var sensitivePathPrefixes = [][]string{
	{"api", "public", "dashboards"},
	{"public-dashboards"},
	{"bootdata"},
}

// SanitizePath masks credentials carried in URL path segments and returns the
// masked path together with the values that were masked.
func SanitizePath(p string) (string, []string) {
	segments := strings.Split(p, "/")

	// Indexes of non-empty segments, so that "//" cannot split a prefix from its credential.
	idx := make([]int, 0, len(segments))
	for i, s := range segments {
		if s != "" {
			idx = append(idx, i)
		}
	}

	var masked []string
	for n := range idx {
		for _, prefix := range sensitivePathPrefixes {
			if n+len(prefix) >= len(idx) || !segmentsMatch(segments, idx[n:n+len(prefix)], prefix) {
				continue
			}
			i := idx[n+len(prefix)]
			if _, err := uuid.Parse(segments[i]); err != nil {
				continue
			}
			masked = append(masked, segments[i])
			segments[i] = masking
		}
	}

	if len(masked) == 0 {
		return p, nil
	}
	return strings.Join(segments, "/"), masked
}

func segmentsMatch(segments []string, idx []int, prefix []string) bool {
	for k, want := range prefix {
		if !strings.EqualFold(segments[idx[k]], want) {
			return false
		}
	}
	return true
}

func SanitizeURI(s string) (string, error) {
	if s == "" {
		return s, nil
	}

	u, err := url.ParseRequestURI(s)
	if err != nil {
		return "", fmt.Errorf("failed to sanitize URL")
	}

	if p, masked := SanitizePath(u.Path); len(masked) > 0 {
		u.Path = p
		u.RawPath = ""
	}

	// strip out sensitive query strings
	urlValues := u.Query()
	for key := range urlValues {
		lk := strings.ToLower(key)
		if checker, ok := sensitiveQueryChecks[lk]; ok {
			if checker(key, urlValues) {
				urlValues.Set(key, masking)
			}
		}
	}
	u.RawQuery = urlValues.Encode()

	return u.String(), nil
}
