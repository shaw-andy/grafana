package proxyutil

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
)

const (
	// UserHeaderName name of the header used when forwarding the Grafana user login.
	UserHeaderName = "X-Grafana-User"
	// IDHeaderName name of the header used when forwarding singed id token of the user
	IDHeaderName = "X-Grafana-Id"
)

// forwardingHeaders are request headers that describe the original client or
// connection. Upstreams that trust Grafana as a proxy read the client address
// from them, so caller-supplied values must never be passed through. Names are
// lowercase with "-" separators; matching also treats "_" as "-" because some
// servers fold both to the same name.
var forwardingHeaders = map[string]struct{}{
	"forwarded":                {},
	"x-forwarded-for":          {},
	"x-forwarded-host":         {},
	"x-forwarded-port":         {},
	"x-forwarded-proto":        {},
	"x-real-ip":                {},
	"x-client-ip":              {},
	"true-client-ip":           {},
	"x-cluster-client-ip":      {},
	"x-original-forwarded-for": {},
}

// PrepareProxyRequest prepares a request for being proxied.
// Removes Origin, Referer and all inbound forwarding headers (Forwarded, X-Forwarded-*, X-Real-IP, ...).
// Set X-Grafana-Referer based on contents of Referer.
// Set X-Forwarded-For to the TCP peer of the request.
func PrepareProxyRequest(req *http.Request) {
	// Set X-Grafana-Referer to correlate access logs to dashboards
	req.Header.Set("X-Grafana-Referer", req.Header.Get("Referer"))

	// Clear Origin and Referer to avoid CORS issues
	req.Header.Del("Origin")
	req.Header.Del("Referer")

	deleteForwardingHeaders(req.Header)

	if req.RemoteAddr != "" {
		remoteAddr, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			remoteAddr = req.RemoteAddr
		}
		req.Header.Set("X-Forwarded-For", remoteAddr)
	}
}

func deleteForwardingHeaders(header http.Header) {
	for name := range header {
		if _, ok := forwardingHeaders[strings.ReplaceAll(strings.ToLower(name), "_", "-")]; ok {
			delete(header, name)
		}
	}
}

// ClearCookieHeader clear cookie header, except for cookies specified to be kept (keepCookiesNames) if not in skipCookiesNames.
func ClearCookieHeader(req *http.Request, keepCookiesNames []string, skipCookiesNames []string) {
	keepCookies := map[string]*http.Cookie{}
	for _, c := range req.Cookies() {
		for _, v := range keepCookiesNames {
			// match all
			if v == "[]" {
				keepCookies[c.Name] = c
				continue
			}

			if before, ok := strings.CutSuffix(v, "[]"); ok {
				// match prefix
				pattern := before
				if strings.HasPrefix(c.Name, pattern) {
					keepCookies[c.Name] = c
				}
			} else {
				// exact match
				if c.Name == v {
					keepCookies[c.Name] = c
				}
			}
		}
	}

	for _, v := range skipCookiesNames {
		delete(keepCookies, v)
	}

	req.Header.Del("Cookie")

	sortedCookies := make([]string, 0, len(keepCookies))
	for name := range keepCookies {
		sortedCookies = append(sortedCookies, name)
	}
	sort.Strings(sortedCookies)

	for _, name := range sortedCookies {
		c := keepCookies[name]
		req.AddCookie(c)
	}
}

// SetViaHeader adds Grafana's reverse proxy to the proxy chain.
// Defined in RFC 9110 7.6.3 https://datatracker.ietf.org/doc/html/rfc9110#name-via
func SetViaHeader(header http.Header, major, minor int) {
	via := fmt.Sprintf("%d.%d grafana", major, minor)
	if old := header.Get("Via"); old != "" {
		via = fmt.Sprintf("%s, %s", via, old)
	}
	header.Set("Via", via)
}

// ApplyUserHeader Set the X-Grafana-User header if needed (and remove if not).
func ApplyUserHeader(sendUserHeader bool, req *http.Request, user identity.Requester) {
	req.Header.Del(UserHeaderName)

	if !sendUserHeader || user == nil || user.IsNil() {
		return
	}

	if user.IsIdentityType(claims.TypeUser, claims.TypeServiceAccount) {
		req.Header.Set(UserHeaderName, user.GetLogin())
	}
}

func ApplyForwardIDHeader(req *http.Request, user identity.Requester) {
	if user == nil || user.IsNil() {
		return
	}

	if token := user.GetIDToken(); token != "" {
		req.Header.Set(IDHeaderName, token)
	}
}
