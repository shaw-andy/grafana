package util

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

const masking = "hidden"

// credentialRoutes lists route prefixes whose next path segment is a bearer
// credential: anyone holding the URL can use it without signing in to Grafana.
var credentialRoutes = []struct {
	prefix []string
	// static lists literal routes that share the prefix and hold no credential.
	static []string
}{
	{prefix: []string{"api", "public", "dashboards"}},
	{prefix: []string{"public-dashboards"}, static: []string{"list"}},
	{prefix: []string{"bootdata"}},
	{prefix: []string{"api", "snapshots"}},
	{prefix: []string{"api", "snapshots-delete"}},
	{prefix: []string{"dashboard", "snapshot"}},
	{prefix: []string{"dashboard-solo", "snapshot"}},
	{prefix: []string{"invite"}},
	{prefix: []string{"api", "user", "invite"}, static: []string{"complete"}},
	{prefix: []string{"org", "invites"}},
}

// PathCredentials returns the segments of the URL path p that hold a bearer credential.
func PathCredentials(p string) []string {
	segs := strings.Split(p, "/")
	var creds []string
	for _, i := range credentialSegments(segs) {
		creds = append(creds, segs[i])
	}
	return creds
}

// RedactPathCredentials masks the segments of the URL path p that hold a bearer credential.
func RedactPathCredentials(p string) string {
	segs := strings.Split(p, "/")
	idx := credentialSegments(segs)
	if len(idx) == 0 {
		return p
	}
	for _, i := range idx {
		segs[i] = masking
	}
	return strings.Join(segs, "/")
}

// RedactCredentials masks every occurrence of creds in s.
func RedactCredentials(s string, creds []string) string {
	for _, c := range creds {
		if c != "" {
			s = strings.ReplaceAll(s, c, masking)
		}
	}
	return s
}

// credentialSegments returns the indexes of segs that hold a credential. The
// prefix may appear anywhere so that a sub-path or host prefix does not hide it,
// and both the literal and the dot-resolved path are matched so that empty or
// dot segments do not hide it either.
func credentialSegments(segs []string) []int {
	var literal, resolved []int
	for i, s := range segs {
		switch s {
		case "", ".":
		case "..":
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
		default:
			literal = append(literal, i)
			resolved = append(resolved, i)
		}
	}
	return append(matchCredentialRoutes(segs, literal), matchCredentialRoutes(segs, resolved)...)
}

func matchCredentialRoutes(segs []string, idx []int) []int {
	var found []int
	for start := range idx {
		for _, route := range credentialRoutes {
			end := start + len(route.prefix)
			if end >= len(idx) {
				continue
			}
			matched := true
			for j, want := range route.prefix {
				if !strings.EqualFold(segs[idx[start+j]], want) {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
			cred := segs[idx[end]]
			if slices.ContainsFunc(route.static, func(s string) bool { return strings.EqualFold(s, cred) }) {
				continue
			}
			found = append(found, idx[end])
		}
	}
	return found
}

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

func SanitizeURI(s string) (string, error) {
	if s == "" {
		return s, nil
	}

	u, err := url.ParseRequestURI(s)
	if err != nil {
		return "", fmt.Errorf("failed to sanitize URL")
	}

	if redacted := RedactPathCredentials(u.Path); redacted != u.Path {
		u.Path = redacted
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
