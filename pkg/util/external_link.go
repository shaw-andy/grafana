package util

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// linkHostProfile maps host names the way the WHATWG URL standard does, so that
// look-alike forms such as full-width dots compare equal to the host a browser
// would actually contact.
var linkHostProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.StrictDomainName(false),
	idna.CheckHyphens(false),
)

// ExternalLinkURL reports whether raw is an absolute http or https URL whose
// host differs from the host of every URL in ownURLs, and returns it in
// canonical form. Callers must place the returned value, not raw, in the link.
//
// Relative, protocol-relative and scheme-relative values are rejected because a
// browser resolves them against the current page. Hosts are compared without
// scheme or port because cookies are scoped to the host only, so a link to any
// port or scheme of a Grafana host carries the viewer's session.
func ExternalLinkURL(raw string, ownURLs ...string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Opaque != "" {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	host, ok := canonicalLinkHost(u.Hostname())
	if !ok {
		return "", false
	}
	for _, own := range ownURLs {
		ownURL, err := url.Parse(own)
		if err != nil || ownURL.Hostname() == "" {
			continue
		}
		if ownHost, ok := canonicalLinkHost(ownURL.Hostname()); ok && ownHost == host {
			return "", false
		}
	}
	return u.String(), true
}

func canonicalLinkHost(host string) (string, bool) {
	if host == "" {
		return "", false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String(), true
	}
	ascii, err := linkHostProfile.ToASCII(host)
	if err != nil {
		return "", false
	}
	ascii = strings.TrimRight(ascii, ".")
	if ascii == "" {
		return "", false
	}
	if addr, ok := parseWHATWGIPv4(ascii); ok {
		return addr.String(), true
	}
	return ascii, true
}

// parseWHATWGIPv4 parses the IPv4 forms browsers accept in a host, such as
// "0x7f.1" or "2130706433", so they compare equal to their dotted-decimal form.
func parseWHATWGIPv4(host string) (netip.Addr, bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	nums := make([]uint64, len(parts))
	for i, part := range parts {
		n, ok := parseWHATWGIPv4Number(part)
		if !ok {
			return netip.Addr{}, false
		}
		nums[i] = n
	}
	var ipv4 uint64
	for i, n := range nums[:len(nums)-1] {
		if n > 255 {
			return netip.Addr{}, false
		}
		ipv4 |= n << (8 * (3 - i))
	}
	last := nums[len(nums)-1]
	if last >= 1<<(8*(5-len(nums))) {
		return netip.Addr{}, false
	}
	ipv4 |= last
	return netip.AddrFrom4([4]byte{byte(ipv4 >> 24), byte(ipv4 >> 16), byte(ipv4 >> 8), byte(ipv4)}), true
}

func parseWHATWGIPv4Number(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	switch {
	case len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X"):
		s, base = s[2:], 16
	case len(s) >= 2 && s[0] == '0':
		s, base = s[1:], 8
	}
	if s == "" {
		return 0, true
	}
	n, err := strconv.ParseUint(s, base, 32)
	return n, err == nil
}
