package datasources

import (
	"regexp"
	"strings"
)

var reURLScheme = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.\-]*)://`)

// NormalizeURLScheme lowercases the scheme of a data source URL. Browser-access data sources
// hand the stored URL to the frontend as-is, and the frontend must be able to recognise it as
// an absolute URL to another origin regardless of how the scheme was typed.
func NormalizeURLScheme(rawURL string) string {
	loc := reURLScheme.FindStringSubmatchIndex(rawURL)
	if loc == nil {
		return rawURL
	}
	return strings.ToLower(rawURL[:loc[3]]) + rawURL[loc[3]:]
}
