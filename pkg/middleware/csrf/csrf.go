package csrf

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"

	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
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

			next.ServeHTTP(w, r)
		})
	}
}

func (c *CSRF) check(r *http.Request) error {
	// As per RFC 7231/4.2.2 these methods are idempotent:
	// (GET is excluded because it may have side effects in some APIs)
	safeMethods := []string{"HEAD", "OPTIONS", "TRACE"}

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
	netAddr, err := util.SplitHostPortDefault(r.Host, "", "")
	if err != nil {
		return &errorWithStatus{Underlying: err, HTTPStatus: http.StatusBadRequest}
	}

	o := r.Header.Get("Origin")

	// No Origin header sent, skip CSRF check.
	if o == "" {
		return nil
	}

	originURL, err := url.Parse(o)
	if err != nil {
		return &errorWithStatus{Underlying: err, HTTPStatus: http.StatusBadRequest}
	}
	origin := parseOrigin(originURL)
	appURL, _ := url.Parse(c.cfg.AppURL)

	trustedOrigin := false
	for h := range c.headers {
		addr, err := util.SplitHostPortDefault(r.Header.Get(h), "", "")
		if err != nil {
			return &errorWithStatus{Underlying: err, HTTPStatus: http.StatusBadRequest}
		}
		if origin.servedBy(r, addr, appURL) {
			trustedOrigin = true
			break
		}
	}

	for o := range c.trustedOrigins {
		if origin.host != "" && o == origin.host {
			trustedOrigin = true
			break
		}
	}

	originMatches := origin.equals(parseOrigin(appURL)) || origin.servedBy(r, netAddr, appURL)
	if netAddr.Host == "" || !trustedOrigin && !originMatches {
		return &errorWithStatus{Underlying: errors.New("origin not allowed"), HTTPStatus: http.StatusForbidden}
	}

	return nil
}

type webOrigin struct {
	scheme string
	host   string
	port   string
}

func defaultPort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

func parseOrigin(u *url.URL) webOrigin {
	if u == nil {
		return webOrigin{}
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = defaultPort(scheme)
	}
	return webOrigin{scheme: scheme, host: strings.ToLower(u.Hostname()), port: port}
}

func (o webOrigin) valid() bool {
	return o.host != "" && defaultPort(o.scheme) != ""
}

func (o webOrigin) equals(other webOrigin) bool {
	return o.valid() && o == other
}

// servedBy reports whether o is the origin the browser addressed when it sent r to
// authority, which is the Host header or a trusted header carrying the public host.
func (o webOrigin) servedBy(r *http.Request, authority util.NetworkAddress, appURL *url.URL) bool {
	if !o.valid() || !strings.EqualFold(o.host, authority.Host) {
		return false
	}

	if scheme := servedScheme(r, authority, appURL); scheme != "" {
		port := authority.Port
		if port == "" {
			port = defaultPort(scheme)
		}
		return o.scheme == scheme && o.port == port
	}

	// A host and port can only be served by one listener, so either scheme is that listener.
	if authority.Port != "" {
		return o.port == authority.Port
	}

	// Without a port the browser used the default port of a scheme Grafana cannot
	// determine, so only a default-port origin can match. Fetch Metadata, when sent,
	// tells whether the requesting page is this exact origin rather than the other scheme.
	if o.port != defaultPort(o.scheme) {
		return false
	}
	site := r.Header.Get("Sec-Fetch-Site")
	return site == "" || site == "same-origin"
}

// servedScheme returns the scheme r was served over for authority, or "" when it is unknown.
func servedScheme(r *http.Request, authority util.NetworkAddress, appURL *url.URL) string {
	if r.TLS != nil {
		return "https"
	}
	app := parseOrigin(appURL)
	if !app.valid() || !strings.EqualFold(app.host, authority.Host) {
		return ""
	}
	port := authority.Port
	if port == "" {
		port = defaultPort(app.scheme)
	}
	if port != app.port {
		return ""
	}
	return app.scheme
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
