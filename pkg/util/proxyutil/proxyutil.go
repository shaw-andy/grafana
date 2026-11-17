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

// PrepareProxyRequest prepares a request for being proxied.
// Removes X-Forwarded-Host, X-Forwarded-Port, X-Forwarded-Proto, Origin, Referer headers.
// Set X-Grafana-Referer based on contents of Referer.
// Set X-Forwarded-For headers.
func PrepareProxyRequest(req *http.Request) {
	// Set X-Grafana-Referer to correlate access logs to dashboards
	req.Header.Set("X-Grafana-Referer", req.Header.Get("Referer"))

	// Clear Origin and Referer to avoid CORS issues
	req.Header.Del("Origin")
	req.Header.Del("Referer")

	req.Header.Del("X-Forwarded-Host")
	req.Header.Del("X-Forwarded-Port")
	req.Header.Del("X-Forwarded-Proto")

	if req.RemoteAddr != "" {
		remoteAddr, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			remoteAddr = req.RemoteAddr
		}
		if req.Header.Get("X-Forwarded-For") != "" {
			req.Header.Set("X-Forwarded-For", req.Header.Get("X-Forwarded-For")+", "+remoteAddr)
		} else {
			req.Header.Set("X-Forwarded-For", remoteAddr)
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

// HasDotSegment reports whether p contains a "." or ".." path segment, either
// as given or after any number of rounds of percent-decoding. A proxy path that
// is appended to a configured upstream URL path must not contain dot segments,
// or the upstream can resolve the request outside that path.
//
// Backslashes and ";" path parameters are treated as segment boundaries because
// some upstream servers normalize them that way.
func HasDotSegment(p string) bool {
	for {
		if containsDotSegment(p) {
			return true
		}
		decoded := lenientPathUnescape(p)
		if decoded == p {
			return false
		}
		p = decoded
	}
}

func containsDotSegment(p string) bool {
	for _, segment := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		segment, _, _ = strings.Cut(segment, ";")
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// lenientPathUnescape decodes every valid %XX escape and keeps invalid ones
// as-is, so a stray "%" cannot hide escapes that follow it.
func lenientPathUnescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
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
