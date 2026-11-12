package repository

import (
	context "context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
)

type ipAddressResolver func(ctx context.Context, host string) ([]net.IPAddr, error)

type URLValidator struct {
	allowlist         Allowlist
	ipAddressResolver ipAddressResolver
}

func NewURLValidator(allowlist Allowlist, ipAddressResolver ipAddressResolver) *URLValidator {
	return &URLValidator{
		allowlist:         allowlist,
		ipAddressResolver: ipAddressResolver,
	}
}

func (v *URLValidator) ValidateURL(
	ctx context.Context,
	rawURL string,
) error {
	host, err := urlHostname(rawURL)
	if err != nil {
		return err
	}

	if v.allowlist.AllowsHost(host) {
		return nil
	}

	if ip := net.ParseIP(host); ip != nil {
		return validateHostIP(host, ip, v.allowlist)
	}

	addrs, err := v.ipAddressResolver(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve URL host %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("URL host %q did not resolve to any IP addresses", host)
	}

	for _, addr := range addrs {
		if err := validateHostIP(host, addr.IP, v.allowlist); err != nil {
			return err
		}
	}
	return nil
}

func urlHostname(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return normalizeHost(parsed.Hostname(), rawURL)
}

func validateHostIP(host string, ip net.IP, allowlist Allowlist) error {
	if isBlockedIP(ip) && !allowlist.AllowsIP(ip) {
		return fmt.Errorf("URL host %q resolves to blocked IP %s", host, ip.String())
	}
	return nil
}

// nonPublicPrefixes are special-purpose ranges that netip's IsGlobalUnicast
// and IsPrivate do not cover. The IPv6 transition ranges are listed because
// they can carry traffic to an embedded IPv4 address.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // shared address space, cloud metadata on some providers
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("192.88.99.0/24"),  // deprecated 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, includes limited broadcast
	netip.MustParsePrefix("::/96"),           // IPv4-compatible
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments, includes Teredo and benchmarking
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4
	netip.MustParsePrefix("3fff::/20"),       // documentation
	netip.MustParsePrefix("5f00::/16"),       // segment routing
	netip.MustParsePrefix("fec0::/10"),       // deprecated site-local
}

func isBlockedIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return true
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
