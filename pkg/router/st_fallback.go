package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grafana/authlib/types"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sony/gobreaker/v2"
	"golang.org/x/sync/singleflight"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LoaderWithSingleTenantFallback supplies the standalone router's handler for unregistered API groups.
type LoaderWithSingleTenantFallback interface {
	SingleTenantFallback() http.Handler
}

const (
	// Bound stale routing after a rename, move, or deletion; cache hits do not extend this TTL.
	singleTenantCacheTTL = 6 * time.Hour
	// Retry unknown stacks sooner so newly created stacks can become reachable.
	singleTenantNotFoundTTL   = 30 * time.Second
	singleTenantLookupTimeout = 5 * time.Second
)

var errStackHostNotAllowed = errors.New("stack host is not allowed")

type singleTenantHost struct {
	host      *url.URL
	expiresAt time.Time
}

// singleTenantFallback forwards requests without a matching multi-tenant route to
// the single-tenant stack identified by the request namespace. Although this is
// not an ideal routing path, it gives clients a single entry point that will
// resolve ALL /apis requests regardless where they live (MT, or ST)
type singleTenantFallback struct {
	cache         *lru.Cache[int64, singleTenantHost]
	breakerMu     sync.Mutex
	breakers      *lru.Cache[string, *gobreaker.CircuitBreaker[struct{}]]
	lookups       singleflight.Group
	resolveHost   func(context.Context, int64) (string, error)
	discoveryHost *url.URL
	hostAllowlist []string
	// transport reaches the operator-configured discovery host.
	transport *http.Transport
	// stackTransport reaches stack hosts returned by Grafana.com and only dials public addresses.
	stackTransport *http.Transport
}

type singleTenantFallbackOptions struct {
	cacheSize      int
	resolveHost    func(context.Context, int64) (string, error)
	discoveryHost  *url.URL
	hostAllowlist  []string
	transport      *http.Transport
	stackTransport *http.Transport
}

func newSingleTenantFallback(opts singleTenantFallbackOptions) (*singleTenantFallback, error) {
	cache, err := lru.New[int64, singleTenantHost](opts.cacheSize)
	if err != nil {
		return nil, err
	}

	if opts.resolveHost == nil {
		return nil, fmt.Errorf("single-tenant host resolver is required")
	}
	if u := opts.discoveryHost; u != nil && ((u.Scheme != "http" && u.Scheme != "https") || u.Host == "") {
		return nil, fmt.Errorf("single-tenant discovery URL must be an absolute HTTP(S) URL")
	}

	if opts.transport == nil {
		opts.transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	if opts.stackTransport == nil {
		opts.stackTransport = newPublicOnlyTransport()
	}

	// The host cache above has already validated the capacity.
	breakers, _ := lru.New[string, *gobreaker.CircuitBreaker[struct{}]](opts.cacheSize)
	return &singleTenantFallback{
		breakers:       breakers,
		cache:          cache,
		resolveHost:    opts.resolveHost,
		discoveryHost:  opts.discoveryHost,
		hostAllowlist:  normalizeHostAllowlist(opts.hostAllowlist),
		transport:      opts.transport,
		stackTransport: opts.stackTransport,
	}, nil
}

// normalizeHostAllowlist keeps DNS names only; IP literals never match a stack host.
func normalizeHostAllowlist(entries []string) []string {
	var out []string
	for _, entry := range entries {
		entry = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(entry)), ".")
		if entry == "" {
			continue
		}
		if _, err := netip.ParseAddr(entry); err == nil {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func (st *singleTenantFallback) hostAllowed(u *url.URL) bool {
	host := u.Hostname()
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return false
	}
	for _, entry := range st.hostAllowlist {
		if host == entry || strings.HasSuffix(host, "."+entry) {
			return true
		}
	}
	return false
}

// newPublicOnlyTransport resolves each destination once, rejects it when any
// resolved address is non-public, and dials only the addresses it checked, so a
// second lookup cannot move the connection. Proxies are disabled because a proxy
// would resolve the host itself.
func newPublicOnlyTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses for stack host %q", host)
		}
		for _, ip := range ips {
			if !isPublicAddr(ip) {
				return nil, fmt.Errorf("%w: %q resolves to non-public address %s", errStackHostNotAllowed, host, ip)
			}
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	return transport
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
}

func isPublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func (st *singleTenantFallback) cachedHost(stackID int64) (*url.URL, bool) {
	entry, ok := st.cache.Get(stackID)
	return entry.host, ok && time.Now().Before(entry.expiresAt)
}

func (st *singleTenantFallback) hostForNamespace(ctx context.Context, namespace string) (*url.URL, error) {
	info, err := types.ParseNamespace(namespace)
	if err != nil || info.StackID < 1 {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if host, ok := st.cachedHost(info.StackID); ok {
		return host, nil
	}

	result := st.lookups.DoChan(strconv.FormatInt(info.StackID, 10), func() (any, error) {
		return st.lookupHost(ctx, info.StackID)
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-result:
		if result.Err != nil {
			return nil, result.Err
		}
		return result.Val.(*url.URL), nil
	}
}

func (st *singleTenantFallback) lookupHost(ctx context.Context, stackID int64) (*url.URL, error) {
	if host, ok := st.cachedHost(stackID); ok {
		return host, nil
	}
	// One caller cancelling must not cancel the lookup shared by other callers.
	lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), singleTenantLookupTimeout)
	defer cancel()
	host, err := st.resolveHost(lookupCtx, stackID)
	if err != nil {
		return nil, err
	}
	var target *url.URL
	if host != "" {
		target, err = url.Parse(host)
		if err != nil {
			return nil, err
		}
		if (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
			return nil, fmt.Errorf("invalid stack host URL: %q", host)
		}
		if !st.hostAllowed(target) {
			return nil, fmt.Errorf("%w: %q", errStackHostNotAllowed, target.Host)
		}
	}
	ttl := singleTenantCacheTTL
	if target == nil {
		ttl = singleTenantNotFoundTTL
	}
	st.cache.Add(stackID, singleTenantHost{host: target, expiresAt: time.Now().Add(ttl)})
	return target, nil
}

func (st *singleTenantFallback) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/"), "/")
	if len(parts) > 4 && parts[0] == "apis" && parts[1] != "" && parts[2] != "" && parts[3] == "namespaces" && parts[4] != "" {
		namespace := parts[4]
		info, ok := types.AuthInfoFrom(req.Context())
		if !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		// The operator token and the stack's network position are only used for a caller of that stack.
		if info.GetNamespace() != namespace {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		host, err := st.hostForNamespace(req.Context(), namespace)
		if errors.Is(err, errStackHostNotAllowed) {
			http.Error(w, "stack host not allowed", http.StatusBadGateway)
			return
		}
		if err != nil {
			http.Error(w, "stack lookup unavailable", http.StatusServiceUnavailable)
			return
		}
		if host == nil {
			http.NotFound(w, req)
			return
		}
		st.forward(st.stackTransport, host, parts[1], w, req)
		return
	}
	// The discovery host supplies metadata, never tenant resources or mutations.
	if st.discoveryHost != nil && (req.Method == http.MethodGet || req.Method == http.MethodHead) && isSingleTenantDiscoveryPath(req.URL.Path) {
		if _, ok := types.AuthInfoFrom(req.Context()); !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		// Namespaced requests require a nonempty group, so discovery cannot collide with them.
		st.forward(st.transport, st.discoveryHost, "", w, req)
		return
	}
	http.NotFound(w, req)
}

func isSingleTenantDiscoveryPath(path string) bool {
	path = strings.TrimSuffix(path, "/")
	if path == apisPrefix || path == openapiV3Prefix {
		return true
	}
	if rest, ok := strings.CutPrefix(path, apisPrefix+"/"); ok {
		parts := strings.Split(rest, "/")
		return (len(parts) == 1 && parts[0] != "") || (len(parts) == 2 && parts[0] != "" && parts[1] != "")
	}
	_, _, ok := parseOpenAPIGroupVersionPath(path)
	return ok
}

func (st *singleTenantFallback) forward(transport *http.Transport, host *url.URL, group string, w http.ResponseWriter, req *http.Request) {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(host)
		},
		Transport:      newBackendTransport(transport),
		ModifyResponse: rejectBackendRedirects,
	}
	serveThroughBreaker(st.breakerForDestination(host, group), group, proxy, w, req)
}

// ST groups span multiple hosts, so their handler isolates breakers by destination and group.
func (*singleTenantFallback) managesCircuitBreaking() {}

func (st *singleTenantFallback) breakerForDestination(host *url.URL, group string) *gobreaker.CircuitBreaker[struct{}] {
	key := host.Scheme + "://" + host.Host + "#" + group
	st.breakerMu.Lock()
	defer st.breakerMu.Unlock()
	if breaker, ok := st.breakers.Get(key); ok {
		return breaker
	}
	breaker := newGroupBreaker(key)
	st.breakers.Add(key, breaker)
	return breaker
}

// Helper function called when the fallback is directly used as a loader (testing)
func (st *singleTenantFallback) SingleTenantFallback() http.Handler {
	return st
}

// Load implements [RoutesLoader].
func (st *singleTenantFallback) Load(ctx context.Context) ([]Backend, error) {
	if st.discoveryHost == nil {
		return nil, nil
	}
	client := &http.Client{Transport: st.transport, Timeout: singleTenantLookupTimeout}

	groups, err := discoverGroups(ctx, client, st.discoveryHost.String())
	if err != nil {
		return nil, err
	}

	backends := make([]Backend, 0, len(groups))
	for _, group := range groups {
		groupJSON, err := json.Marshal(group)
		if err != nil {
			return nil, fmt.Errorf("fingerprinting single-tenant discovery: %w", err)
		}
		backends = append(backends, &fallbackBackend{
			group: group,
			key:   "st:" + hashHex(string(groupJSON)),
			st:    st,
		})
	}
	return backends, nil
}

func (st *singleTenantFallback) Notify(ctx context.Context) (<-chan struct{}, error) {
	dirty := make(chan struct{}, 1)
	go func() {
		defer close(dirty)
		st.notifyDiscoveryChanges(ctx, dirty)
	}()
	return dirty, nil
}

func (st *singleTenantFallback) notifyDiscoveryChanges(ctx context.Context, dirty chan<- struct{}) {
	if st.discoveryHost == nil {
		<-ctx.Done()
		return
	}
	// Run performs the initial load; periodic signals retry failures and refresh group membership.
	ticker := time.NewTicker(defaultAggregatePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			select {
			case dirty <- struct{}{}:
			default:
			}
		}
	}
}

var (
	_ RoutesLoader = (*singleTenantFallback)(nil)
	_ Backend      = (*fallbackBackend)(nil)
)

type fallbackBackend struct {
	group v1.APIGroup
	key   string
	st    http.Handler
}

// Group implements [Backend].
func (f *fallbackBackend) Group() v1.APIGroup {
	return f.group
}

// Key implements [Backend].
func (f *fallbackBackend) Key() string {
	return f.key
}

// Load implements [Backend].
func (f *fallbackBackend) Load(context.Context) (http.Handler, error) {
	return f.st, nil
}

// The results of this call are cached
func newGComURLResolver(gcomBaseURL string, gcomToken string) func(context.Context, int64) (string, error) {
	// mirroring grafana's pkg/services/gcom
	type instance struct {
		ID   int    `json:"id"`
		Slug string `json:"slug"`
		Name string `json:"name"`
		URL  string `json:"url"`
	}

	return func(ctx context.Context, stackID int64) (string, error) {
		url, err := url.JoinPath(gcomBaseURL, "instances", strconv.FormatInt(stackID, 10))
		if err != nil {
			return "", err
		}

		// #nosec G704 -- the base URL is operator-controlled Grafana configuration and stackID is an integer.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", fmt.Errorf("creating gcom instance request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+gcomToken)
		// #nosec G704 -- req targets the operator-controlled Grafana.com API URL constructed above.
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("fetching gcom instance: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusNotFound {
			return "", nil
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("fetching gcom instance: unexpected status code %d", resp.StatusCode)
		}

		var result instance
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return "", fmt.Errorf("decoding gcom instance: %w", err)
		}
		return result.URL, nil
	}
}
