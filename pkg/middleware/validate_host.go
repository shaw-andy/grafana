package middleware

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

var (
	hostRedirectCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name:      "host_redirect_total",
		Help:      "Number of requests redirected due to host header mismatch",
		Namespace: "grafana",
	})
)

// ValidateHostHeader redirects requests whose Host is a DNS name Grafana has
// not been configured to answer to. A page served from an attacker-controlled
// name can rebind that name to Grafana's address, after which the browser
// treats Grafana's responses as same-origin. It must therefore run before any
// handler that writes a response, including the unauthenticated monitoring
// endpoints, and cannot depend on the request having been authenticated.
func ValidateHostHeader(cfg *setting.Cfg) web.Middleware {
	allowed := newHostAllowlist(cfg)
	logger := log.New("host-validation")
	redirectBase := strings.TrimSuffix(cfg.AppURL, "/")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if allowed.permits(r.Host) {
				next.ServeHTTP(w, r)
				return
			}

			// the normal redirecting logic doesn't work when running as frontend service, since it has no knowledge of the custom domain.
			// instead, we modify the single tenant `/bootdata` call with a 204 response and a header indicating the domain to redirect to
			// this is safe because only the frontend service calls `/bootdata`
			// the redirect is then handled client side.
			// see pkg/services/frontend/index.html
			if r.URL.Path == "/bootdata" {
				w.Header().Set("Redirect-Domain", cfg.Domain)
				w.WriteHeader(http.StatusNoContent)
				return
			}

			hostRedirectCounter.Inc()
			logger.Info("Enforcing Host header", "hosted", r.Host, "expected", cfg.Domain)
			http.Redirect(w, r, redirectBase+r.RequestURI, http.StatusMovedPermanently)
		})
	}
}

type hostAllowlist struct {
	names    map[string]struct{}
	suffixes []string
}

func newHostAllowlist(cfg *setting.Cfg) hostAllowlist {
	a := hostAllowlist{names: map[string]struct{}{}}

	add := func(host string) {
		host = normalizeHost(host)
		if host == "" {
			return
		}
		if suffix, ok := strings.CutPrefix(host, "*."); ok {
			if suffix != "" {
				a.suffixes = append(a.suffixes, "."+suffix)
			}
			return
		}
		a.names[host] = struct{}{}
	}
	addURLHost := func(raw string) {
		if u, err := url.Parse(raw); err == nil {
			add(u.Hostname())
		}
	}

	// localhost resolves without consulting DNS, so an attacker cannot point
	// it at their own page.
	add("localhost")

	add(cfg.Domain)
	addURLHost(cfg.AppURL)
	// The image renderer calls back to Grafana on the callback URL, or on
	// http_addr when no callback URL is set.
	addURLHost(cfg.RendererCallbackUrl)
	if cfg.HTTPAddr != setting.DefaultHTTPAddr {
		add(cfg.HTTPAddr)
	}
	for _, h := range cfg.EnforceDomainAllowedHosts {
		add(h)
	}

	return a
}

func (a hostAllowlist) permits(hostport string) bool {
	host := normalizeHost(hostport)
	// Browsers always send a Host. They only send an IP literal when the page
	// itself was loaded from that address, so it cannot be a rebound name.
	if host == "" {
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if _, ok := a.names[host]; ok {
		return true
	}
	for _, suffix := range a.suffixes {
		if len(host) > len(suffix) && strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func normalizeHost(hostport string) string {
	host := strings.TrimSpace(hostport)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
