package proxyutil

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
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
// Set X-Grafana-Referer based on contents of Referer, without its query string.
// Set X-Forwarded-For headers.
func PrepareProxyRequest(req *http.Request) {
	// Set X-Grafana-Referer to correlate access logs to dashboards
	req.Header.Set("X-Grafana-Referer", RefererWithoutQuery(req.Header.Get("Referer")))

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

// RefererWithoutQuery reduces a Referer value to its scheme, host and path.
// The page query string and fragment can hold dashboard variables or tokens
// that were never meant for the upstream, so they are dropped together with
// any user info. Values that do not parse as a URL are dropped entirely.
func RefererWithoutQuery(referer string) string {
	if referer == "" {
		return ""
	}

	u, err := url.Parse(referer)
	if err != nil || u.Opaque != "" {
		return ""
	}

	stripped := url.URL{
		Scheme:  u.Scheme,
		Host:    u.Host,
		Path:    u.Path,
		RawPath: u.RawPath,
	}
	return stripped.String()
}

// SanitizeRefererHeader replaces the Referer header with RefererWithoutQuery of
// its value, for requests whose headers are handed to a plugin as is.
func SanitizeRefererHeader(header http.Header) {
	referer := RefererWithoutQuery(header.Get("Referer"))
	if referer == "" {
		header.Del("Referer")
		return
	}
	header.Set("Referer", referer)
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
