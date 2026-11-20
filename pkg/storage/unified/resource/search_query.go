package resource

import (
	"errors"
	"fmt"
	"strings"
)

// MaxSearchQueryLength is the longest free-text query, wildcards included,
// that search accepts. The index compiles a query containing '*' into an
// automaton whose construction cost grows with the pattern.
const MaxSearchQueryLength = 256

// MaxSearchTextLength is the longest caller text that ContainsSearchQuery
// accepts, leaving room for the '*' it adds on each side.
const MaxSearchTextLength = MaxSearchQueryLength - 2

var ErrSearchQueryTooLong = fmt.Errorf("search query is longer than %d characters", MaxSearchQueryLength)

var errInnerWildcard = errors.New("'*' is only supported at the start or end of a pattern, and '?' is not supported")

// Bleve wildcard patterns have no escape syntax: '\*' still compiles to '.*'.
// The only way to keep these characters from running as wildcards is to drop them.
var wildcardCharRemover = strings.NewReplacer("*", "", "?", "")

// StripSearchWildcards removes the characters a Bleve wildcard treats as
// metacharacters from caller text.
func StripSearchWildcards(text string) string {
	return wildcardCharRemover.Replace(text)
}

// ContainsSearchQuery returns the query that matches text anywhere in a value.
// It returns an empty query, which matches everything, when text holds only
// wildcard characters.
func ContainsSearchQuery(text string) (string, error) {
	if len(text) > MaxSearchTextLength {
		return "", ErrSearchQueryTooLong
	}
	literal := StripSearchWildcards(text)
	if literal == "" {
		return "", nil
	}
	return "*" + literal + "*", nil
}

// NormalizeSearchQuery bounds a caller-supplied free-text query. A single
// leading or trailing '*' is kept as a suffix or prefix match; every other
// '*' and '?' is dropped. It returns an empty query, which matches everything,
// when the query holds only wildcard characters.
func NormalizeSearchQuery(query string) (string, error) {
	if len(query) > MaxSearchQueryLength {
		return "", ErrSearchQueryTooLong
	}
	literal := StripSearchWildcards(query)
	if literal == "" {
		return "", nil
	}
	if strings.HasPrefix(query, "*") {
		literal = "*" + literal
	}
	if strings.HasSuffix(query, "*") {
		literal += "*"
	}
	return literal, nil
}

// ValidateWildcardPattern reports whether pattern is cheap enough to run as a
// Bleve wildcard: within MaxSearchQueryLength, with '*' only at its ends and
// no '?'.
func ValidateWildcardPattern(pattern string) error {
	if len(pattern) > MaxSearchQueryLength {
		return ErrSearchQueryTooLong
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(pattern, "*"), "*")
	if strings.ContainsAny(inner, "*?") {
		return errInnerWildcard
	}
	return nil
}
