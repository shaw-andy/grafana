package app

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

var ErrInvalidExternalTarget = errors.New("external correlation target must be an absolute http or https URL on a host other than Grafana")

// ValidateExternalTarget checks the url of an external correlation target.
// Explore renders the url as a link on query results that any viewer can follow
// with their session, so it must not point back at Grafana itself (for example
// /logout or /profile/switch-org/:id). grafanaHosts are the hosts Grafana is
// served on, with or without a port; empty entries are ignored.
func ValidateExternalTarget(target map[string]any, grafanaHosts ...string) error {
	raw, ok := target["url"].(string)
	if !ok || raw == "" {
		return fmt.Errorf("%w: url is required", ErrInvalidExternalTarget)
	}
	return ValidateExternalURL(raw, grafanaHosts...)
}

func ValidateExternalURL(raw string, grafanaHosts ...string) error {
	if strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\\") {
		return fmt.Errorf("%w: %q", ErrInvalidExternalTarget, raw)
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	scheme = strings.ToLower(scheme)
	if !ok || (scheme != "http" && scheme != "https") {
		return fmt.Errorf("%w: %q", ErrInvalidExternalTarget, raw)
	}
	authority := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority = rest[:i]
	}
	if strings.Contains(authority, "@") {
		return fmt.Errorf("%w: %q", ErrInvalidExternalTarget, raw)
	}
	// A host built from template variables is only known once Explore
	// interpolates the link, which is where it is checked against Grafana's origin.
	if strings.Contains(authority, "$") {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidExternalTarget, raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: %q", ErrInvalidExternalTarget, raw)
	}
	if u.Opaque != "" || u.User != nil {
		return fmt.Errorf("%w: %q", ErrInvalidExternalTarget, raw)
	}
	host, ok := normalizeHostname(u.Hostname())
	if !ok {
		return fmt.Errorf("%w: %q", ErrInvalidExternalTarget, raw)
	}
	for _, h := range grafanaHosts {
		if h == "" {
			continue
		}
		grafanaHost, ok := normalizeHostname((&url.URL{Host: h}).Hostname())
		if ok && host == grafanaHost {
			return fmt.Errorf("%w: %q", ErrInvalidExternalTarget, raw)
		}
	}
	return nil
}

// HostFromURL returns the host of an absolute URL such as Grafana's root_url,
// or an empty string when it has none.
func HostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// normalizeHostname returns the hostname the way a browser resolves it, so
// spellings such as upper case, a trailing dot or full-width letters compare
// equal to Grafana's own host. It reports false for anything that is not a
// plain DNS name or IP literal.
func normalizeHostname(h string) (string, bool) {
	if h == "" {
		return "", false
	}
	if strings.Contains(h, ":") {
		ip := net.ParseIP(h)
		if ip == nil {
			return "", false
		}
		return ip.String(), true
	}
	if !isASCII(h) {
		ascii, err := idna.Lookup.ToASCII(h)
		if err != nil {
			return "", false
		}
		h = ascii
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" {
		return "", false
	}
	// Browsers parse a host whose last label is a number (2130706433, 0x7f.1,
	// 0177.0.0.1) as IPv4, so only the canonical dotted form is accepted.
	if endsInNumber(h) {
		ip := net.ParseIP(h)
		if ip == nil || ip.To4() == nil || ip.String() != h {
			return "", false
		}
		return h, true
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' && c != '_' {
			return "", false
		}
	}
	return h, true
}

func endsInNumber(h string) bool {
	last := h[strings.LastIndex(h, ".")+1:]
	if last == "" {
		return false
	}
	if strings.HasPrefix(last, "0x") {
		last = last[2:]
		for i := 0; i < len(last); i++ {
			c := last[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			return false
		}
	}
	return true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
