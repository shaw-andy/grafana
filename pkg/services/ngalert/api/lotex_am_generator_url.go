package api

import (
	"net/url"
	"strings"

	"github.com/go-openapi/strfmt"

	"github.com/grafana/grafana/pkg/services/datasources"
	apimodels "github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
)

// GeneratorURLAllowedHostsKey is the Alertmanager data source JSON data key that lists the extra hosts,
// as "host" or "host:port", whose generator URLs are returned to clients.
const GeneratorURLAllowedHostsKey = "generatorURLAllowedHosts"

type hostMatcher struct {
	hostname string
	// port is empty when any port matches.
	port string
}

// generatorURLPolicy keeps only the generator URLs of an external Alertmanager that point at a host
// trusted by the data source administrator. Anyone allowed to post alerts to the Alertmanager controls
// generator URLs, and the UI renders them as links, so the URL must not be able to aim a viewer's
// browser at Grafana itself or at an arbitrary site.
type generatorURLPolicy struct {
	allowed     []hostMatcher
	grafanaHost string
}

func newGeneratorURLPolicy(ds *datasources.DataSource, grafanaHost string) generatorURLPolicy {
	policy := generatorURLPolicy{grafanaHost: strings.ToLower(grafanaHost)}
	if u, err := url.Parse(ds.URL); err == nil && u.Hostname() != "" {
		policy.allowed = append(policy.allowed, hostMatcher{
			hostname: strings.ToLower(u.Hostname()),
			port:     effectivePort(u.Scheme, u.Port()),
		})
	}
	if ds.JsonData != nil {
		for _, entry := range ds.JsonData.Get(GeneratorURLAllowedHostsKey).MustStringArray() {
			if m, ok := parseHostMatcher(entry); ok {
				policy.allowed = append(policy.allowed, m)
			}
		}
	}
	return policy
}

func parseHostMatcher(entry string) (hostMatcher, bool) {
	entry = strings.ToLower(strings.TrimSpace(entry))
	if entry == "" || strings.ContainsAny(entry, "/\\@?#%") {
		return hostMatcher{}, false
	}
	u, err := url.Parse("//" + entry)
	if err != nil || u.Hostname() == "" {
		return hostMatcher{}, false
	}
	return hostMatcher{hostname: u.Hostname(), port: u.Port()}, true
}

func (p generatorURLPolicy) sanitize(alerts []*apimodels.GettableAlert) {
	for _, alert := range alerts {
		if alert != nil {
			alert.GeneratorURL = strfmt.URI(p.allow(alert.GeneratorURL.String()))
		}
	}
}

// allow returns the normalized URL when it may be returned to the client, and an empty string otherwise.
func (p generatorURLPolicy) allow(raw string) string {
	if raw == "" {
		return ""
	}
	// Browsers read a backslash as a path separator in http(s) URLs and Go does not, so the two would
	// disagree on the host.
	if strings.Contains(raw, "\\") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Opaque != "" {
		return ""
	}
	hostname := u.Hostname()
	if hostname == "" || !isPlainHost(u.Host) {
		return ""
	}
	hostname = strings.ToLower(hostname)
	port := effectivePort(u.Scheme, u.Port())
	if p.isGrafana(u.Scheme, hostname, port) {
		return ""
	}
	for _, m := range p.allowed {
		if m.hostname == hostname && (m.port == "" || m.port == port) {
			return u.String()
		}
	}
	return ""
}

func (p generatorURLPolicy) isGrafana(scheme, hostname, port string) bool {
	if p.grafanaHost == "" {
		return false
	}
	g, err := url.Parse("//" + p.grafanaHost)
	if err != nil {
		return true
	}
	return g.Hostname() == hostname && effectivePort(scheme, g.Port()) == port
}

func isPlainHost(host string) bool {
	for i := 0; i < len(host); i++ {
		if c := host[i]; c >= 0x80 || c == '%' {
			return false
		}
	}
	return true
}

func effectivePort(scheme, port string) string {
	if port != "" {
		return port
	}
	switch strings.ToLower(scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}
