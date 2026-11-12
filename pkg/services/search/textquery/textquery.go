// Package textquery bounds caller-supplied text before it is sent to the
// unified search index as ResourceSearchRequest.Query.
//
// The index runs any query that contains '*' as a Bleve wildcard pattern, and
// turns a query shorter than three bytes into a prefix pattern. Bleve has no
// escape for '*' or '?' inside a pattern, and its cost grows quickly with the
// number of wildcards and with the pattern length, so caller text must never
// carry its own wildcards and its length is bounded.
package textquery

import (
	"strings"

	"github.com/grafana/grafana/pkg/apimachinery/errutil"
)

// MaxBytes is the longest free-text query a caller may send to the index. The
// search server enforces the same limit on hybrid and vector queries.
const MaxBytes = 1000

// MaxSubstringBytes is the longest text a caller may search for as a substring.
// Substring search runs as a leading-wildcard pattern, whose cost grows with its
// length. Titles, logins, emails and names are stored in columns of at most 255
// bytes in the legacy store.
const MaxSubstringBytes = 255

// shortQueryBytes mirrors the index: a query shorter than this, with no '*',
// is searched as the prefix pattern query+"*".
const shortQueryBytes = 3

var (
	errTooLong  = errutil.BadRequest("search.queryTooLong", errutil.WithPublicMessage("Search query is too long"))
	errWildcard = errutil.BadRequest("search.queryWildcard", errutil.WithPublicMessage("Search query must not contain wildcard characters"))

	wildcardStripper = strings.NewReplacer("*", "", "?", "")
)

// HasWildcard reports whether the index would run q as a wildcard pattern in
// which a caller-supplied '*' or '?' acts as a wildcard.
func HasWildcard(q string) bool {
	return strings.Contains(q, "*") || (len(q) < shortQueryBytes && strings.Contains(q, "?"))
}

// Check returns a bad request error when q is longer than MaxBytes or when the
// index would run it as a caller-supplied wildcard pattern.
func Check(q string) error {
	if len(q) > MaxBytes {
		return errTooLong.Errorf("search query is %d bytes, maximum is %d", len(q), MaxBytes)
	}
	if HasWildcard(q) {
		return errWildcard.Errorf("search query contains a wildcard character")
	}
	return nil
}

// CheckSubstring returns a bad request error when q is longer than
// MaxSubstringBytes.
func CheckSubstring(q string) error {
	if len(q) > MaxSubstringBytes {
		return errTooLong.Errorf("substring search query is %d bytes, maximum is %d", len(q), MaxSubstringBytes)
	}
	return nil
}

// StripWildcards removes '*' and '?' from text that is about to be wrapped in a
// substring pattern such as "*"+q+"*".
func StripWildcards(q string) string {
	return wildcardStripper.Replace(q)
}
