package repository

import (
	context "context"
	"fmt"
	"net"
	"net/url"
	"sync"
)

type ipAddressResolver func(ctx context.Context, host string) ([]net.IPAddr, error)

type URLValidator struct {
	allowlist         Allowlist
	ipAddressResolver ipAddressResolver

	transportOnce sync.Once
	transport     *pinnedTransport
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
	_, err = v.allowedAddrs(ctx, host)
	return err
}

// allowedAddrs resolves host once and returns its addresses if every one of them is allowed.
// A nil slice without an error means the host is allowlisted by name and may be used as-is.
func (v *URLValidator) allowedAddrs(ctx context.Context, host string) ([]net.IPAddr, error) {
	host, err := normalizeHost(host, host)
	if err != nil {
		return nil, err
	}

	if v.allowlist.AllowsHost(host) {
		return nil, nil
	}

	if ip := net.ParseIP(host); ip != nil {
		if err := validateHostIP(host, ip, v.allowlist); err != nil {
			return nil, err
		}
		return []net.IPAddr{{IP: ip}}, nil
	}

	addrs, err := v.ipAddressResolver(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve URL host %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("URL host %q did not resolve to any IP addresses", host)
	}

	for _, addr := range addrs {
		if err := validateHostIP(host, addr.IP, v.allowlist); err != nil {
			return nil, err
		}
	}
	return addrs, nil
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

func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified()
}
