package user

import "strings"

// boundedSearchPattern reports whether a free-text query is safe to hand to
// the index. Ordinary contains matching is a single leading and trailing
// asterisk around literal text. Bleve wildcards do not treat '\' as an
// escape, so a prefixed backslash does not make an asterisk or question mark
// literal.
func boundedSearchPattern(pattern string) bool {
	const maxLen = 256
	if len(pattern) > maxLen {
		return false
	}
	if strings.Contains(pattern, "?") {
		return false
	}
	switch strings.Count(pattern, "*") {
	case 0:
		return true
	case 1:
		return strings.HasPrefix(pattern, "*") || strings.HasSuffix(pattern, "*")
	case 2:
		return strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*")
	default:
		return false
	}
}
