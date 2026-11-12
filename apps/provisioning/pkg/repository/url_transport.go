package repository

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"syscall"
	"time"
)

var defaultHTTPTransport = sync.OnceValue(func() http.RoundTripper {
	return NewHTTPTransport(Allowlist{})
})

// DefaultHTTPTransport is the transport used for repository URLs when no
// allowlist has been configured. It only connects to public addresses.
func DefaultHTTPTransport() http.RoundTripper {
	return defaultHTTPTransport()
}

// NewHTTPTransport returns a transport for clients that connect to repository
// URLs. It applies the same address rules as URLValidator, but to the address a
// socket actually connects to, so a host name that resolved to a public address
// when the repository was admitted cannot later be pointed at a blocked one.
//
// When a proxy is configured through the environment, the proxy resolves and
// connects to the target instead of this process, so the target is validated
// before the request is handed to the proxy.
func NewHTTPTransport(allowlist Allowlist) http.RoundTripper {
	direct := newBaseTransport()
	direct.DialContext = guardedDialContext(allowlist)

	proxied := newBaseTransport()
	proxied.Proxy = http.ProxyFromEnvironment

	return &guardedTransport{
		validator: NewURLValidator(allowlist, net.DefaultResolver.LookupIPAddr),
		proxy:     http.ProxyFromEnvironment,
		direct:    direct,
		proxied:   proxied,
	}
}

type guardedTransport struct {
	validator *URLValidator
	proxy     func(*http.Request) (*url.URL, error)
	direct    *http.Transport
	proxied   *http.Transport
}

func (t *guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	proxyURL, err := t.proxy(req)
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	if proxyURL == nil {
		return t.direct.RoundTrip(req)
	}
	if err := t.validator.ValidateURL(req.Context(), req.URL.String()); err != nil {
		closeRequestBody(req)
		return nil, err
	}
	return t.proxied.RoundTrip(req)
}

func (t *guardedTransport) CloseIdleConnections() {
	t.direct.CloseIdleConnections()
	t.proxied.CloseIdleConnections()
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

func newBaseTransport() *http.Transport {
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func guardedDialContext(allowlist Allowlist) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		if !allowlist.AllowsHost(host) {
			// Control runs after name resolution for every address the dialer
			// tries, so the check applies to the address being connected to.
			dialer.Control = func(_, address string, _ syscall.RawConn) error {
				addrPort, err := netip.ParseAddrPort(address)
				if err != nil {
					return fmt.Errorf("URL host %q connects to unparsable address %q: %w", host, address, err)
				}
				return validateHostIP(host, addrPort.Addr().WithZone("").AsSlice(), allowlist)
			}
		}
		return dialer.DialContext(ctx, network, addr)
	}
}
