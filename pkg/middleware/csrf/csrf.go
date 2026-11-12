package csrf

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"

	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
	"github.com/grafana/grafana/pkg/web"
)

type Service interface {
	Middleware() func(http.Handler) http.Handler
	TrustOrigin(origin string)
	AddAdditionalHeaders(headerName string)
	AddSafeEndpoint(endpoint string)
}

type CSRF struct {
	cfg *setting.Cfg

	trustedOrigins map[string]struct{}
	headers        map[string]struct{}
	safeEndpoints  map[string]struct{}
	alwaysCheck    bool
}

func ProvideCSRFFilter(cfg *setting.Cfg) *CSRF {
	c := &CSRF{
		cfg:            cfg,
		trustedOrigins: map[string]struct{}{},
		headers:        map[string]struct{}{},
		safeEndpoints:  map[string]struct{}{},
	}

	additionalHeaders := cfg.SectionWithEnvOverrides("security").Key("csrf_additional_headers").Strings(" ")
	trustedOrigins := cfg.SectionWithEnvOverrides("security").Key("csrf_trusted_origins").Strings(" ")
	c.alwaysCheck = cfg.SectionWithEnvOverrides("security").Key("csrf_always_check").MustBool(false)

	for _, header := range additionalHeaders {
		c.headers[header] = struct{}{}
	}
	for _, origin := range trustedOrigins {
		c.trustedOrigins[origin] = struct{}{}
	}

	return c
}

func (c *CSRF) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e := &errorWithStatus{}

			err := c.check(r)
			if err != nil {
				if !errors.As(err, &e) {
					http.Error(w, fmt.Sprintf("internal server error: expected error type errorWithStatus, got %s. Error: %v", reflect.TypeOf(err), err), http.StatusInternalServerError)
				}
				http.Error(w, err.Error(), e.HTTPStatus)
				return
			}

			ctx := context.WithValue(r.Context(), verifiedKey{}, c.verified(r))
			// Handlers registered with Use continue the chain with the web context's
			// request rather than the one passed to next, so update it in place.
			if wc := web.FromContext(ctx); wc != nil {
				*wc.Req = *wc.Req.WithContext(ctx)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type verifiedKey struct{}

// IsVerified reports whether the CSRF middleware accepted r as allowed to change
// the state of the session it was sent with: r carries no login cookie, or it
// shows that it was sent by a Grafana page. Handlers that change session state
// must check it, because browsers omit Origin on top-level navigations.
func IsVerified(r *http.Request) bool {
	verified, _ := r.Context().Value(verifiedKey{}).(bool)
	return verified
}

func (c *CSRF) verified(r *http.Request) bool {
	if _, err := r.Cookie(c.cfg.LoginCookieName); errors.Is(err, http.ErrNoCookie) {
		return true
	}

	netAddr, err := util.SplitHostPortDefault(r.Host, "", "0")
	if err != nil {
		return false
	}

	if o := r.Header.Get("Origin"); o != "" {
		return c.checkOrigin(r, netAddr, o) == nil
	}

	if r.Header.Get("Sec-Fetch-Site") == "same-origin" {
		return true
	}

	// Browsers send no Sec-Fetch-Site to plain HTTP origins, but do send a
	// same-origin Referer unless the page opted out of it.
	if ref := r.Referer(); ref != "" {
		return c.checkOrigin(r, netAddr, ref) == nil
	}

	return false
}

func (c *CSRF) check(r *http.Request) error {
	// As per RFC 7231/4.2.2 these methods are idempotent:
	// (GET is excluded because it may have side effects in some APIs, and HEAD
	// because every GET route also serves HEAD)
	safeMethods := []string{"OPTIONS", "TRACE"}

	// If the CSRF checks can be skipped.
	if !c.alwaysCheck {
		// If request has no login cookie - skip CSRF checks
		if _, err := r.Cookie(c.cfg.LoginCookieName); errors.Is(err, http.ErrNoCookie) {
			return nil
		}
	}

	// Skip CSRF checks for "safe" methods
	if slices.Contains(safeMethods, r.Method) {
		return nil
	}
	// Skip CSRF checks for "safe" endpoints
	for safeEndpoint := range c.safeEndpoints {
		if r.URL.Path == safeEndpoint {
			return nil
		}
	}
	// Otherwise - verify that Origin matches the server origin
	netAddr, err := util.SplitHostPortDefault(r.Host, "", "0") // we ignore the port
	if err != nil {
		return &errorWithStatus{Underlying: err, HTTPStatus: http.StatusBadRequest}
	}

	o := r.Header.Get("Origin")

	// No Origin header sent, skip CSRF check. Handlers that change session state
	// on such requests must check IsVerified.
	if o == "" {
		return nil
	}

	return c.checkOrigin(r, netAddr, o)
}

// checkOrigin verifies that the host of rawURL, an Origin or Referer value,
// matches the server host or a trusted origin.
func (c *CSRF) checkOrigin(r *http.Request, netAddr util.NetworkAddress, rawURL string) error {
	originURL, err := url.Parse(rawURL)
	if err != nil {
		return &errorWithStatus{Underlying: err, HTTPStatus: http.StatusBadRequest}
	}
	origin := originURL.Hostname()

	trustedOrigin := false
	for h := range c.headers {
		customHost := r.Header.Get(h)
		addr, err := util.SplitHostPortDefault(customHost, "", "0") // we ignore the port
		if err != nil {
			return &errorWithStatus{Underlying: err, HTTPStatus: http.StatusBadRequest}
		}
		if addr.Host == origin {
			trustedOrigin = true
			break
		}
	}

	for o := range c.trustedOrigins {
		if o == origin {
			trustedOrigin = true
			break
		}
	}

	hostnameMatches := origin == netAddr.Host
	if netAddr.Host == "" || !trustedOrigin && !hostnameMatches {
		return &errorWithStatus{Underlying: errors.New("origin not allowed"), HTTPStatus: http.StatusForbidden}
	}

	return nil
}

func (c *CSRF) TrustOrigin(origin string) {
	c.trustedOrigins[origin] = struct{}{}
}

func (c *CSRF) AddAdditionalHeaders(headerName string) {
	c.headers[headerName] = struct{}{}
}

// AddSafeEndpoint is used for endpoints requests to skip CSRF check
func (c *CSRF) AddSafeEndpoint(endpoint string) {
	c.safeEndpoints[endpoint] = struct{}{}
}

type errorWithStatus struct {
	Underlying error
	HTTPStatus int
}

func (e errorWithStatus) Error() string {
	return e.Underlying.Error()
}

func (e errorWithStatus) Unwrap() error {
	return e.Underlying
}
