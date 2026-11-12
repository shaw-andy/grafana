package repository

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Transport returns an HTTP transport whose connections only reach addresses the validator allows.
// The target host is resolved once per connection and the connection is made to exactly the
// addresses that passed the check, so a DNS change after validation cannot retarget it.
func (v *URLValidator) Transport() http.RoundTripper {
	v.transportOnce.Do(func() {
		v.transport = newPinnedTransport(v)
	})
	return v.transport
}

type pinnedTransport struct {
	validator *URLValidator
	dialer    *net.Dialer
	direct    *http.Transport
	proxy     func(*http.Request) (*url.URL, error)

	mu      sync.Mutex
	proxied map[proxiedTransportKey]*http.Transport
}

type proxiedTransportKey struct {
	serverName string
	proxy      string
}

func newPinnedTransport(v *URLValidator) *pinnedTransport {
	t := &pinnedTransport{
		validator: v,
		dialer:    &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second},
		proxy:     http.ProxyFromEnvironment,
		proxied:   map[proxiedTransportKey]*http.Transport{},
	}
	t.direct = t.newTransport()
	t.direct.DialContext = t.dialPinned
	return t
}

func (t *pinnedTransport) newTransport() *http.Transport {
	return &http.Transport{
		DialContext:           t.dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func (t *pinnedTransport) dialPinned(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrs, err := t.validator.allowedAddrs(ctx, host)
	if err != nil {
		return nil, err
	}
	if addrs == nil {
		return t.dialer.DialContext(ctx, network, addr)
	}

	var errs []error
	for _, a := range addrs {
		conn, err := t.dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (t *pinnedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	proxyURL, err := t.proxy(req)
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	if proxyURL == nil {
		return t.direct.RoundTrip(req)
	}

	// Through a proxy, the proxy opens the connection to the target, so it is given a validated
	// address rather than a name it would resolve on its own. Hosts allowlisted by name are trusted
	// and passed through unchanged.
	host := req.URL.Hostname()
	addrs, err := t.validator.allowedAddrs(req.Context(), host)
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	if addrs == nil {
		return t.proxiedTransport(proxyURL, "").RoundTrip(req)
	}

	if !canPinThroughProxy(proxyURL.Scheme, req.URL.Scheme) {
		closeRequestBody(req)
		return nil, fmt.Errorf("host %q must be listed in allowed_git_urls to be reached over %s through a %s proxy", host, req.URL.Scheme, proxyURL.Scheme)
	}
	serverName := ""
	if req.URL.Scheme == "https" {
		serverName = host
	}

	port := req.URL.Port()
	if port == "" {
		port = "80"
		if req.URL.Scheme == "https" {
			port = "443"
		}
	}
	pinned := req.Clone(req.Context())
	pinned.URL.Host = net.JoinHostPort(addrs[0].String(), port)
	if pinned.Host == "" {
		pinned.Host = req.URL.Host
	}

	resp, err := t.proxiedTransport(proxyURL, serverName).RoundTrip(pinned)
	if resp != nil {
		resp.Request = req
	}
	return resp, err
}

func (t *pinnedTransport) proxiedTransport(proxyURL *url.URL, serverName string) *http.Transport {
	key := proxiedTransportKey{serverName: serverName, proxy: proxyURL.String()}

	t.mu.Lock()
	defer t.mu.Unlock()
	if transport, ok := t.proxied[key]; ok {
		return transport
	}

	transport := t.newTransport()
	transport.Proxy = http.ProxyURL(proxyURL)
	if serverName != "" {
		transport.TLSClientConfig = &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	}
	t.proxied[key] = transport
	return transport
}

// canPinThroughProxy reports whether the proxy connects to the address in the request URL. An HTTP
// proxy forwarding a plain-HTTP request takes the target from the Host header, which must stay the
// host name, and the TLS settings of an HTTPS proxy would apply to both the proxy and the target.
func canPinThroughProxy(proxyScheme, targetScheme string) bool {
	switch proxyScheme {
	case "socks5", "socks5h":
		return true
	case "http":
		return targetScheme == "https"
	default:
		return false
	}
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}
