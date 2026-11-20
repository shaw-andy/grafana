package team

import "strings"

// boundedSearchPattern reports whether a free-text query is safe to hand to
// the index. A single leading or trailing asterisk is a prefix or suffix.
// Any question mark, or any further asterisk, is another Bleve wildcard.
// A backslash is not an escape.
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
