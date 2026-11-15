//go:build linux

package router

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/gorilla/mux"
	claims "github.com/grafana/authlib/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
)

// Single-tenant instance proxy security contract.
//
// These tests fail while a request can make the fallback dial the URL stored
// for a stack id.
//
// claims.AuthInfo on the request context is the caller identity. Its namespace
// must equal the namespace in the path. The Authorization header is not that
// identity; it is forwarded only after the destination is accepted.
//
// [cloud_router] st_host_allowlist is a comma-separated list of DNS names. A
// host matches an entry when the names are equal, ignoring case, or when the
// host ends in a dot plus that entry. IP literals do not match. Before a dial,
// every resolved address is rejected when it is loopback, link-local, private,
// or unspecified, including IPv4-mapped IPv6. The dial uses the addresses that
// were checked, so a later lookup cannot move the connection onto a rejected
// address. A rejected URL is not cached as a dial target. The operator-token
// lookup does not run for a caller who is not allowed to use that stack.

const (
	securityOperatorToken = "placeholder-operator-token"
	securityCallerHeader  = "Bearer placeholder-caller-authorization"
	securityAllowlistKey  = "st_host_allowlist"
	securityAllowlist     = "allowed.example"
)

func TestSingleTenantFallbackDoesNotProxyDisallowedTargets(t *testing.T) {
	if os.Getenv("ROUTER_ST_NETNS") != "1" {
		reexecSecurityTest(t)
		return
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"} {
		t.Setenv(key, "")
	}

	require.NoError(t, configureLoopbackAddresses())
	dns := newScriptedDNS(map[string][]net.IP{
		"safe.allowed.example.":   {net.ParseIP("203.0.113.10")},
		"a.safe.allowed.example.": {net.ParseIP("203.0.113.10")},
		"stack.allowed.example.":  {net.ParseIP("203.0.113.10"), net.ParseIP("127.0.0.1")},
		"public.example.":         {net.ParseIP("198.51.100.10")},
		"notallowed.example.":     {net.ParseIP("198.51.100.10")},
		"allowed.example.evil.":   {net.ParseIP("198.51.100.10")},
		"loopback.invalid.":       {net.ParseIP("127.0.0.1")},
		"2130706433.":             {net.ParseIP("127.0.0.1")},
		"private.invalid.":        {net.ParseIP("10.1.2.3")},
		"localhost.":              {net.ParseIP("127.0.0.1")},
	})
	prev := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: dns.Dial}
	t.Cleanup(func() { net.DefaultResolver = prev })

	loopback := startCountingServer(t, "127.0.0.1:0")
	loopback2 := startCountingServer(t, "127.0.0.2:0")
	v6Loop := startCountingServer(t, "[::1]:0")
	unspec4 := startCountingServer(t, "0.0.0.0:0")
	unspec6 := startCountingServer(t, "[::]:0")
	priv10 := startCountingServer(t, "10.1.2.3:0")
	priv172 := startCountingServer(t, "172.16.5.5:0")
	priv172end := startCountingServer(t, "172.31.255.5:0")
	priv192 := startCountingServer(t, "192.168.123.45:0")
	link := startCountingServer(t, "169.254.169.254:0")
	linkOther := startCountingServer(t, "169.254.1.1:0")
	ula := startCountingServer(t, "[fc00::1]:0")
	ula2 := startCountingServer(t, "[fd00::1]:0")
	link6 := startCountingServer(t, "[fe80::1%lo]:0")
	doc1 := startCountingServer(t, "203.0.113.10:0")
	doc2 := startCountingServer(t, "198.51.100.10:0")
	for _, srv := range []*countingServer{loopback, loopback2, v6Loop, unspec4, unspec6, priv10, priv172, priv172end, priv192, link, linkOther, ula, ula2, link6, doc1, doc2} {
		requireListenerReachable(t, srv)
	}

	rebindPort := freePort(t, "203.0.113.10")
	rebindPublic := startCountingServer(t, fmt.Sprintf("203.0.113.10:%d", rebindPort))
	rebindPublic.setBody("pinned-body")
	rebindLoop := startCountingServer(t, fmt.Sprintf("127.0.0.1:%d", rebindPort))
	rebindLoop.setBody("rebound-body")
	requireListenerReachable(t, rebindPublic)
	requireListenerReachable(t, rebindLoop)

	direct := func(t *testing.T, rawURL string) (*singleTenantFallback, *atomic.Int32) {
		t.Helper()
		resolve, hits := securityGCom(t, func(int64) string { return rawURL })
		return securityFallback(t, resolve), hits
	}
	postOnly := []string{http.MethodPost}
	allMethods := []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

	t.Run("authenticated caller still cannot dial rejected addresses", func(t *testing.T) {
		cases := []struct {
			name    string
			raw     string
			srv     *countingServer
			methods []string
		}{
			{name: "ipv4 loopback", raw: loopback.URL(), srv: loopback, methods: allMethods},
			{name: "ipv4 loopback other", raw: loopback2.URL(), srv: loopback2, methods: postOnly},
			{name: "ipv6 loopback", raw: v6Loop.URL(), srv: v6Loop, methods: postOnly},
			{name: "ipv4 unspecified", raw: unspec4.URL(), srv: unspec4, methods: postOnly},
			{name: "ipv6 unspecified", raw: unspec6.URL(), srv: unspec6, methods: postOnly},
			{name: "rfc1918 10", raw: priv10.URL(), srv: priv10, methods: postOnly},
			{name: "rfc1918 172.16", raw: priv172.URL(), srv: priv172, methods: postOnly},
			{name: "rfc1918 172.31", raw: priv172end.URL(), srv: priv172end, methods: postOnly},
			{name: "rfc1918 192.168", raw: priv192.URL(), srv: priv192, methods: postOnly},
			{name: "link local metadata", raw: link.URL(), srv: link, methods: postOnly},
			{name: "link local other", raw: linkOther.URL(), srv: linkOther, methods: postOnly},
			{name: "ipv6 unique local", raw: ula.URL(), srv: ula, methods: postOnly},
			{name: "ipv6 unique local fd", raw: ula2.URL(), srv: ula2, methods: postOnly},
			{name: "ipv6 link local", raw: link6.URL(), srv: link6, methods: postOnly},
			{name: "ipv4-mapped loopback", raw: mappedURL(loopback), srv: loopback, methods: postOnly},
			{name: "ipv4-mapped private", raw: mappedURL(priv10), srv: priv10, methods: postOnly},
			{name: "userinfo loopback", raw: withUserinfo(t, loopback.URL()), srv: loopback, methods: postOnly},
			{name: "localhost", raw: swapHost(t, loopback.URL(), "localhost"), srv: loopback, methods: postOnly},
			{name: "hostname resolving to loopback", raw: swapHost(t, loopback.URL(), "loopback.invalid"), srv: loopback, methods: postOnly},
			{name: "decimal name resolving to loopback", raw: swapHost(t, loopback.URL(), "2130706433"), srv: loopback, methods: postOnly},
			{name: "hostname resolving to private", raw: swapHost(t, priv10.URL(), "private.invalid"), srv: priv10, methods: postOnly},
			{name: "literal public address", raw: doc2.URL(), srv: doc2, methods: postOnly},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				for _, method := range tc.methods {
					t.Run(method, func(t *testing.T) {
						st, gcomHits := direct(t, tc.raw)
						before := tc.srv.accepts.Load()
						rec := httptest.NewRecorder()
						req := securityRequest(t, method, "stacks-123", "payload")
						st.ServeHTTP(rec, withStackIdentity(req, "stacks-123"))
						require.Equal(t, before, tc.srv.accepts.Load(), "dialed %s; dns %s", tc.raw, dns.snapshot())
						require.NotContains(t, rec.Body.String(), tc.srv.body)
						require.Greater(t, gcomHits.Load(), int32(0))
					})
				}
			})
		}
	})

	t.Run("https loopback is not dialed", func(t *testing.T) {
		st, _ := direct(t, "https://"+loopback.ln.Addr().String()+"/secret")
		before := loopback.accepts.Load()
		rec := httptest.NewRecorder()
		st.ServeHTTP(rec, withStackIdentity(securityRequest(t, http.MethodGet, "stacks-123", ""), "stacks-123"))
		require.Equal(t, before, loopback.accepts.Load())
	})

	t.Run("allowlisted public host is proxied for the matching stack", func(t *testing.T) {
		raw := swapHost(t, doc1.URL(), "safe.allowed.example")
		st, hits := factoryFallback(t, securityAllowlist, "https://discovery.example.invalid/", func(id int64) string {
			if id == 123 {
				return raw
			}
			return ""
		})
		before := doc1.accepts.Load()
		rec := httptest.NewRecorder()
		st.ServeHTTP(rec, withStackIdentity(securityRequest(t, http.MethodPost, "stacks-123", "payload"), "stacks-123"))
		require.Greater(t, doc1.accepts.Load(), before)
		require.Equal(t, http.StatusCreated, rec.Code)
		require.Equal(t, doc1.body, rec.Body.String())
		require.Greater(t, hits.Load(), int32(0))
		got, ok := doc1.findPath("/apis/example.grafana.app/v1/namespaces/stacks-123/widgets")
		require.True(t, ok)
		require.Equal(t, http.MethodPost, got.method)
		require.Equal(t, "limit=1", got.rawQuery)
		require.Equal(t, "payload", got.body)
		require.Equal(t, securityCallerHeader, got.authorization)
	})

	t.Run("allowlist matches a subdomain", func(t *testing.T) {
		raw := swapHost(t, doc1.URL(), "a.safe.allowed.example")
		st, _ := factoryFallback(t, securityAllowlist, "https://discovery.example.invalid/", func(int64) string { return raw })
		before := doc1.accepts.Load()
		rec := httptest.NewRecorder()
		st.ServeHTTP(rec, withStackIdentity(securityRequest(t, http.MethodGet, "stacks-123", ""), "stacks-123"))
		require.Greater(t, doc1.accepts.Load(), before)
		require.Equal(t, doc1.body, rec.Body.String())
	})

	t.Run("host outside the allowlist is not dialed", func(t *testing.T) {
		for _, host := range []string{"public.example", "notallowed.example", "allowed.example.evil"} {
			t.Run(host, func(t *testing.T) {
				raw := swapHost(t, doc2.URL(), host)
				st, _ := factoryFallback(t, securityAllowlist, "https://discovery.example.invalid/", func(int64) string { return raw })
				before := doc2.accepts.Load()
				rec := httptest.NewRecorder()
				st.ServeHTTP(rec, withStackIdentity(securityRequest(t, http.MethodPost, "stacks-123", "payload"), "stacks-123"))
				require.Equal(t, before, doc2.accepts.Load(), "dialed %s; dns %s", host, dns.snapshot())
				require.NotContains(t, rec.Body.String(), doc2.body)
			})
		}
	})

	t.Run("allowlist does not accept a literal address", func(t *testing.T) {
		st, _ := factoryFallback(t, "198.51.100.10,"+securityAllowlist, "https://discovery.example.invalid/", func(int64) string {
			return doc2.URL()
		})
		before := doc2.accepts.Load()
		rec := httptest.NewRecorder()
		st.ServeHTTP(rec, withStackIdentity(securityRequest(t, http.MethodGet, "stacks-123", ""), "stacks-123"))
		require.Equal(t, before, doc2.accepts.Load())
		require.NotContains(t, rec.Body.String(), doc2.body)
	})

	t.Run("recheck does not follow a later lookup to loopback", func(t *testing.T) {
		raw := fmt.Sprintf("http://stack.allowed.example:%d/rebind", rebindPort)
		st, _ := factoryFallback(t, securityAllowlist, "https://discovery.example.invalid/", func(int64) string { return raw })
		loopBefore := rebindLoop.accepts.Load()
		rec := httptest.NewRecorder()
		st.ServeHTTP(rec, withStackIdentity(securityRequest(t, http.MethodGet, "stacks-123", ""), "stacks-123"))
		require.Equal(t, loopBefore, rebindLoop.accepts.Load(), "connection followed a second lookup to loopback; dns %s", dns.snapshot())
		require.NotContains(t, rec.Body.String(), "rebound-body")
		require.Equal(t, "pinned-body", rec.Body.String())
		require.Greater(t, rebindPublic.accepts.Load(), int32(0))
	})

	t.Run("rejected URL is not cached as a dial target", func(t *testing.T) {
		var raw atomic.Value
		raw.Store(priv10.URL())
		st, gcomHits := factoryFallback(t, securityAllowlist, "https://discovery.example.invalid/", func(int64) string {
			return raw.Load().(string)
		})
		before := priv10.accepts.Load()
		rec := httptest.NewRecorder()
		st.ServeHTTP(rec, withStackIdentity(securityRequest(t, http.MethodGet, "stacks-123", ""), "stacks-123"))
		require.Equal(t, before, priv10.accepts.Load())
		require.Greater(t, gcomHits.Load(), int32(0))

		raw.Store(swapHost(t, doc1.URL(), "safe.allowed.example"))
		safeBefore := doc1.accepts.Load()
		rec = httptest.NewRecorder()
		st.ServeHTTP(rec, withStackIdentity(securityRequest(t, http.MethodGet, "stacks-123", ""), "stacks-123"))
		require.Equal(t, before, priv10.accepts.Load(), "cached rejected URL was dialed")
		require.Greater(t, doc1.accepts.Load(), safeBefore)
		require.Equal(t, doc1.body, rec.Body.String())
	})

	t.Run("identity for one stack does not authorize another", func(t *testing.T) {
		st, gcomHits := factoryFallback(t, securityAllowlist, "https://discovery.example.invalid/", func(id int64) string {
			if id == 111 || id == 222 {
				return swapHost(t, doc1.URL(), "safe.allowed.example")
			}
			return ""
		})
		before := doc1.pathsContaining("stacks-222")
		gcomBefore := gcomHits.Load()
		rec := httptest.NewRecorder()
		st.ServeHTTP(rec, withStackIdentity(securityRequest(t, http.MethodPost, "stacks-222", "payload"), "stacks-111"))
		require.Equal(t, http.StatusForbidden, rec.Code)
		require.Equal(t, before, doc1.pathsContaining("stacks-222"))
		require.Equal(t, gcomBefore, gcomHits.Load())
		require.NotContains(t, rec.Body.String(), doc1.body)

		rec = httptest.NewRecorder()
		st.ServeHTTP(rec, withStackIdentity(securityRequest(t, http.MethodPost, "stacks-111", "payload"), "stacks-111"))
		require.Equal(t, doc1.body, rec.Body.String())
		require.Greater(t, doc1.pathsContaining("stacks-111"), 0)
	})

	t.Run("router mount does not proxy without an identity", func(t *testing.T) {
		var discoveryHits atomic.Int32
		discovery := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			discoveryHits.Add(1)
			_, _ = io.WriteString(w, "discovery-response")
		}))
		t.Cleanup(discovery.Close)
		httpRouter, hits := factoryRouter(t, securityAllowlist, discovery.URL, func(int64) string { return doc1.URL() })
		before := doc1.accepts.Load()
		rec := httptest.NewRecorder()
		httpRouter.ServeHTTP(rec, securityRequest(t, http.MethodPost, "stacks-123", "payload"))
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.NotContains(t, rec.Body.String(), doc1.body)
		require.Equal(t, before, doc1.accepts.Load())
		require.Zero(t, hits.Load())
		require.Zero(t, discoveryHits.Load())

		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(method, func(t *testing.T) {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(method, "/apis/example.grafana.app/v1", nil)
				req.Header.Set("Authorization", securityCallerHeader)
				httpRouter.ServeHTTP(rec, req)
				require.Equal(t, http.StatusUnauthorized, rec.Code)
				require.NotContains(t, rec.Body.String(), "discovery-response")
				require.Zero(t, discoveryHits.Load())
				require.Zero(t, hits.Load())
			})
		}
	})
}

func reexecSecurityTest(t *testing.T) {
	t.Helper()
	cmd := exec.Command("unshare", "--net", "--map-root-user", "--",
		os.Args[0],
		"-test.run", "^TestSingleTenantFallbackDoesNotProxyDisallowedTargets$",
		"-test.v", "-test.count=1", "-test.timeout", "180s",
	)
	cmd.Env = append(os.Environ(), "ROUTER_ST_NETNS=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("single-tenant proxy security checks: %v", err)
	}
}

func securityRequest(t *testing.T, method, namespace, body string) *http.Request {
	t.Helper()
	var reader io.Reader
	if body != "" || method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "/apis/example.grafana.app/v1/namespaces/"+namespace+"/widgets?limit=1", reader)
	req.Header.Set("Authorization", securityCallerHeader)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func withStackIdentity(req *http.Request, namespace string) *http.Request {
	ctx := claims.WithAuthInfo(req.Context(), &identity.StaticRequester{
		Type:      claims.TypeUser,
		UserID:    7,
		UserUID:   "user-7",
		Namespace: namespace,
	})
	return req.WithContext(ctx)
}

func securityGCom(t *testing.T, urlFor func(int64) string) (func(context.Context, int64) (string, error), *atomic.Int32) {
	t.Helper()
	base, hits := securityGComServer(t, urlFor)
	return newGComURLResolver(base, securityOperatorToken), hits
}

func securityGComServer(t *testing.T, urlFor func(int64) string) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+securityOperatorToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/instances/"), 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		raw := urlFor(id)
		if raw == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%d,"url":%q}`, id, raw)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &hits
}

func securityFallback(t *testing.T, resolve func(context.Context, int64) (string, error)) *singleTenantFallback {
	t.Helper()
	st, err := newSingleTenantFallback(singleTenantFallbackOptions{cacheSize: 50, resolveHost: resolve})
	require.NoError(t, err)
	return st
}

func factoryFallback(t *testing.T, allowlist, discovery string, urlFor func(int64) string) (*singleTenantFallback, *atomic.Int32) {
	t.Helper()
	_, st, hits := factoryMount(t, allowlist, discovery, urlFor, false)
	return st, hits
}

func factoryRouter(t *testing.T, allowlist, discovery string, urlFor func(int64) string) (*mux.Router, *atomic.Int32) {
	t.Helper()
	httpRouter, _, hits := factoryMount(t, allowlist, discovery, urlFor, true)
	return httpRouter, hits
}

func factoryMount(t *testing.T, allowlist, discovery string, urlFor func(int64) string, mount bool) (*mux.Router, *singleTenantFallback, *atomic.Int32) {
	t.Helper()
	gcomBase, hits := securityGComServer(t, urlFor)
	cfg := cfgWithCloudRouterSection(t, map[string]string{
		"st_discovery_url":   discovery,
		securityAllowlistKey: allowlist,
	})
	cfg.Target = []string{"router"}
	cfg.GrafanaComAPIURL = gcomBase
	cfg.GrafanaComSSOAPIToken = securityOperatorToken
	loader, err := ProvideCloudRoutesLoaderFactory(cfg, PluginDependencies{})
	require.NoError(t, err)
	cloud, ok := loader.(*cloudLoader)
	require.True(t, ok)
	require.NotNil(t, cloud.singleTenantFallback)
	var httpRouter *mux.Router
	if mount {
		svc, err := ProvideService(cfg, featuremgmt.WithFeatures(), loader, prometheus.NewRegistry())
		require.NoError(t, err)
		httpRouter = mux.NewRouter()
		require.NoError(t, svc.RegisterTargetRoutes(httpRouter, nil))
	}
	return httpRouter, cloud.singleTenantFallback, hits
}

type recordedRequest struct {
	method, path, rawQuery, body, authorization string
}

type countingListener struct {
	net.Listener
	accepts atomic.Int32
}

func (c *countingListener) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil {
		c.accepts.Add(1)
	}
	return conn, err
}

type countingServer struct {
	ln      *countingListener
	body    string
	accepts *atomic.Int32
	mu      sync.Mutex
	reqs    []recordedRequest
}

func startCountingServer(t *testing.T, addr string) *countingServer {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	cl := &countingListener{Listener: ln}
	cs := &countingServer{ln: cl, accepts: &cl.accepts, body: "secret"}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		cs.mu.Lock()
		cs.reqs = append(cs.reqs, recordedRequest{
			method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery,
			body: string(buf), authorization: r.Header.Get("Authorization"),
		})
		body := cs.body
		cs.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, body)
	})}
	go func() { _ = srv.Serve(cl) }()
	t.Cleanup(func() { _ = srv.Close() })
	return cs
}

func (s *countingServer) setBody(body string) {
	s.mu.Lock()
	s.body = body
	s.mu.Unlock()
}

func (s *countingServer) URL() string {
	host := s.ln.Addr().String()
	if strings.Contains(host, "%") {
		host = strings.Replace(host, "%", "%25", 1)
	}
	return "http://" + host
}

func (s *countingServer) findPath(path string) (recordedRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.reqs) - 1; i >= 0; i-- {
		if s.reqs[i].path == path {
			return s.reqs[i], true
		}
	}
	return recordedRequest{}, false
}

func (s *countingServer) pathsContaining(part string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, req := range s.reqs {
		if strings.Contains(req.path, part) {
			n++
		}
	}
	return n
}

func requireListenerReachable(t *testing.T, srv *countingServer) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(srv.URL())
	require.NoError(t, err, "fixture %s", srv.URL())
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode, srv.URL())
	require.Equal(t, srv.body, string(body), srv.URL())
}

func freePort(t *testing.T, ip string) int {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

func swapHost(t *testing.T, raw, host string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(u.Host)
	require.NoError(t, err)
	u.Host = net.JoinHostPort(host, port)
	return u.String()
}

func withUserinfo(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	u.User = url.User("placeholder")
	return u.String()
}

func mappedURL(srv *countingServer) string {
	host, port, err := net.SplitHostPort(srv.ln.Addr().String())
	if err != nil {
		return srv.URL()
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return srv.URL()
	}
	return fmt.Sprintf("http://[::ffff:%s]:%s/", ip.String(), port)
}

func configureLoopbackAddresses() error {
	if err := setLinkUp("lo"); err != nil {
		return err
	}
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	for _, ip := range []string{
		"127.0.0.1", "127.0.0.2", "10.1.2.3", "172.16.5.5", "172.31.255.5",
		"192.168.123.45", "169.254.169.254", "169.254.1.1", "203.0.113.10", "198.51.100.10",
	} {
		if err := addIPv4(net.ParseIP(ip).To4(), iface.Index); err != nil {
			return fmt.Errorf("add %s: %w", ip, err)
		}
	}
	for _, addr := range []struct {
		ip     string
		prefix uint32
	}{
		{"fc00::1", 128},
		{"fd00::1", 128},
		{"fe80::1", 64},
	} {
		if err := addIPv6(net.ParseIP(addr.ip), addr.prefix, iface.Index); err != nil {
			return fmt.Errorf("add %s: %w", addr.ip, err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for _, target := range []string{"[::1]:0", "[fc00::1]:0", "[fd00::1]:0", "[fe80::1%lo]:0", "127.0.0.1:0", "10.1.2.3:0"} {
		for {
			ln, err := net.Listen("tcp", target)
			if err == nil {
				_ = ln.Close()
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("address %s is not usable: %w", target, err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return nil
}

func setLinkUp(name string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var req [40]byte
	copy(req[:], name)
	*(*uint16)(unsafe.Pointer(&req[16])) = syscall.IFF_UP | syscall.IFF_RUNNING | syscall.IFF_LOOPBACK
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		return errno
	}
	return nil
}

func addIPv4(ip net.IP, index int) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	tv := syscall.Timeval{Sec: 2}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	payload := ifaddrMessage(syscall.AF_INET, 32, 0, index)
	payload = append(payload, rtAttr(1, ip)...) // IFA_ADDRESS
	payload = append(payload, rtAttr(2, ip)...) // IFA_LOCAL
	msg := nlMessage(20, 0x01|0x04|0x400, payload)
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	return netlinkAck(fd)
}

func addIPv6(ip net.IP, prefix uint32, index int) error {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var req struct {
		addr   [16]byte
		prefix uint32
		index  int32
	}
	copy(req.addr[:], ip.To16())
	req.prefix = prefix
	req.index = int32(index)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFADDR, uintptr(unsafe.Pointer(&req)))
	if errno != 0 && errno != syscall.EEXIST {
		return errno
	}
	return nil
}

func ifaddrMessage(family, prefix, scope, index int) []byte {
	buf := make([]byte, 8)
	buf[0] = byte(family)
	buf[1] = byte(prefix)
	buf[2] = 0x02 // IFA_F_NODAD
	buf[3] = byte(scope)
	binary.LittleEndian.PutUint32(buf[4:], uint32(index))
	return buf
}

func rtAttr(typ uint16, data []byte) []byte {
	n := 4 + len(data)
	buf := make([]byte, (n+3)&^3)
	binary.LittleEndian.PutUint16(buf[0:], uint16(n))
	binary.LittleEndian.PutUint16(buf[2:], typ)
	copy(buf[4:], data)
	return buf
}

func nlMessage(typ, flags uint16, payload []byte) []byte {
	buf := make([]byte, 16+len(payload))
	binary.LittleEndian.PutUint32(buf[0:], uint32(len(buf)))
	binary.LittleEndian.PutUint16(buf[4:], typ)
	binary.LittleEndian.PutUint16(buf[6:], flags)
	binary.LittleEndian.PutUint32(buf[8:], 1)
	copy(buf[16:], payload)
	return buf
}

func netlinkAck(fd int) error {
	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	if n < 20 {
		return fmt.Errorf("short netlink ack (%d)", n)
	}
	if binary.LittleEndian.Uint16(buf[4:6]) != 2 {
		return fmt.Errorf("netlink type %d", binary.LittleEndian.Uint16(buf[4:6]))
	}
	errno := int32(binary.LittleEndian.Uint32(buf[16:20]))
	if errno == 0 || syscall.Errno(-errno) == syscall.EEXIST {
		return nil
	}
	return syscall.Errno(-errno)
}

type scriptedDNS struct {
	mu      sync.Mutex
	answers map[string][]net.IP
	next    map[string]int
	queries []string
}

func newScriptedDNS(answers map[string][]net.IP) *scriptedDNS {
	return &scriptedDNS{answers: answers, next: map[string]int{}}
}

func (s *scriptedDNS) Dial(_ context.Context, network, _ string) (net.Conn, error) {
	conn := &dnsConn{server: s}
	if strings.HasPrefix(network, "udp") {
		return &dnsPacketConn{dnsConn: conn}, nil
	}
	return conn, nil
}

func (s *scriptedDNS) snapshot() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.queries, ",")
}

func (s *scriptedDNS) answer(q dnsmessage.Message) dnsmessage.Message {
	resp := dnsmessage.Message{Header: dnsmessage.Header{
		ID: q.Header.ID, Response: true, Authoritative: true, RecursionAvailable: true,
	}, Questions: q.Questions}
	if len(q.Questions) == 0 || q.Questions[0].Type != dnsmessage.TypeA {
		return resp
	}
	name := q.Questions[0].Name.String()
	s.mu.Lock()
	s.queries = append(s.queries, name)
	seq := s.answers[name]
	i := s.next[name]
	if len(seq) == 0 {
		s.mu.Unlock()
		resp.Header.RCode = dnsmessage.RCodeNameError
		return resp
	}
	if i >= len(seq) {
		i = len(seq) - 1
	}
	s.next[name] = i + 1
	ip := seq[i].To4()
	s.mu.Unlock()
	if ip == nil {
		resp.Header.RCode = dnsmessage.RCodeServerFailure
		return resp
	}
	var a [4]byte
	copy(a[:], ip)
	resp.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{
			Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 0,
		},
		Body: &dnsmessage.AResource{A: a},
	}}
	return resp
}

type dnsConn struct {
	server *scriptedDNS
	query  dnsmessage.Message
	buf    []byte
}

func (c *dnsConn) Read(b []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	msg := c.server.answer(c.query)
	packed, err := msg.Pack()
	if err != nil {
		return 0, err
	}
	if len(b) < len(packed) {
		return 0, io.ErrShortBuffer
	}
	copy(b, packed)
	return len(packed), nil
}

func (c *dnsConn) Write(b []byte) (int, error) {
	if err := c.query.Unpack(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *dnsConn) Close() error                     { return nil }
func (c *dnsConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *dnsConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *dnsConn) SetDeadline(time.Time) error      { return nil }
func (c *dnsConn) SetReadDeadline(time.Time) error  { return nil }
func (c *dnsConn) SetWriteDeadline(time.Time) error { return nil }

type dnsPacketConn struct{ *dnsConn }

func (c *dnsPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, &net.UDPAddr{}, err
}

func (c *dnsPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }
