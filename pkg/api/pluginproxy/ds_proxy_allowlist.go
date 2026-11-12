package pluginproxy

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/grafana/grafana/pkg/services/datasources"
)

var errInvalidProxyPath = errors.New("invalid proxy path")

type upstreamEndpoint struct {
	methods []string
	path    *regexp.Regexp
}

func endpoint(pathPattern string, methods ...string) upstreamEndpoint {
	return upstreamEndpoint{methods: methods, path: regexp.MustCompile(`^(?:` + pathPattern + `)$`)}
}

type upstreamAllowlist []upstreamEndpoint

func (l upstreamAllowlist) allows(method, path string) bool {
	return slices.ContainsFunc(l, func(e upstreamEndpoint) bool {
		return slices.Contains(e.methods, method) && e.path.MatchString(path)
	})
}

var prometheusAllowlist = upstreamAllowlist{
	endpoint(`api/v1/(query|query_range|query_exemplars|series|labels|metadata|format_query|parse_query|rules|alerts)`, http.MethodGet),
	endpoint(`api/v1/label/[^/]+/values`, http.MethodGet),
	endpoint(`api/v1/status/buildinfo`, http.MethodGet),
	endpoint(`api/v1/search/(metric_names|label_names|label_values)`, http.MethodGet),
	endpoint(`rules(/.+)?`, http.MethodGet),
	endpoint(`(prometheus/)?config/v1/rules(/.+)?`, http.MethodGet),
}

var lokiAllowlist = upstreamAllowlist{
	endpoint(`(loki/)?api/v1/(query|query_range|labels|series|tail|patterns|detected_fields|detected_labels|format_query|index/stats|index/volume|index/volume_range|status/buildinfo)`, http.MethodGet),
	endpoint(`(loki/)?api/v1/(label|detected_field)/[^/]+/values`, http.MethodGet),
	endpoint(`(loki/)?api/v1/rules(/.+)?`, http.MethodGet),
	endpoint(`prometheus/api/v1/(rules|alerts)`, http.MethodGet),
	endpoint(`api/prom/rules(/.+)?`, http.MethodGet),
	endpoint(`rules(/.+)?`, http.MethodGet),
}

// upstreamAllowlists lists, per core datasource type, the upstream endpoints the
// proxy forwards when no plugin route matched. A type listed here with no
// endpoints is never proxied: InfluxDB executes write and drop statements sent
// to /query even over GET, and its frontend queries through the backend.
var upstreamAllowlists = map[string]upstreamAllowlist{
	datasources.DS_PROMETHEUS:        prometheusAllowlist,
	datasources.DS_AMAZON_PROMETHEUS: prometheusAllowlist,
	datasources.DS_AZURE_PROMETHEUS:  prometheusAllowlist,
	datasources.DS_LOKI:              lokiAllowlist,
	datasources.DS_INFLUXDB:          {},
	datasources.DS_INFLUXDB_08:       {},
	datasources.DS_GRAPHITE: {
		endpoint(`render|metrics/(find|expand)`, http.MethodGet, http.MethodPost),
		endpoint(`tags/autoComplete/(tags|values)|version|functions|events/get_data`, http.MethodGet),
	},
	datasources.DS_ES: {
		endpoint(``, http.MethodGet),
		endpoint(`([^/]+/)?(_mapping|_field_caps)`, http.MethodGet),
		endpoint(`_msearch`, http.MethodPost),
	},
	datasources.DS_TEMPO: {
		endpoint(`api/(v2/)?search(/tags)?`, http.MethodGet),
		endpoint(`api/(v2/)?search/tag/[^/]+/values`, http.MethodGet),
		endpoint(`api/(v2/)?traces/[^/]+`, http.MethodGet),
		endpoint(`api/metrics/(query|query_range)|api/echo|api/status/buildinfo`, http.MethodGet),
	},
	datasources.DS_JAEGER: {
		endpoint(`api/(v3/)?(services|operations|traces)|api/dependencies`, http.MethodGet),
		endpoint(`api/services/[^/]+/operations`, http.MethodGet),
		endpoint(`api/(v3/)?traces/[^/]+`, http.MethodGet),
	},
	datasources.DS_ZIPKIN: {
		endpoint(`api/v2/(services|spans|remoteServices|traces|dependencies|autocompleteKeys|autocompleteValues)`, http.MethodGet),
		endpoint(`api/v2/trace/[^/]+`, http.MethodGet),
	},
	datasources.DS_OPENTSDB: {
		endpoint(`api/(suggest|aggregators|version|search/lookup|config/filters)`, http.MethodGet),
	},
}

// canonicalUpstreamPath returns the proxy path as the upstream sees it after
// decoding it once. Upstreams and the proxies in front of them may decode more
// than once or normalize dot segments and backslashes, so any path that could
// resolve to a different endpoint than the one checked is rejected.
func canonicalUpstreamPath(proxyPath string) (string, error) {
	decoded, err := url.PathUnescape(strings.TrimPrefix(proxyPath, "/"))
	if err != nil {
		return "", errInvalidProxyPath
	}
	if decoded == "" {
		return "", nil
	}
	if strings.Contains(decoded, `\`) || strings.ContainsFunc(decoded, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", errInvalidProxyPath
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", errInvalidProxyPath
		}
	}

	for current := decoded; ; {
		next, err := url.PathUnescape(current)
		if err != nil || next == current {
			break
		}
		for _, segment := range strings.FieldsFunc(next, func(r rune) bool { return r == '/' || r == '\\' }) {
			if segment == "." || segment == ".." {
				return "", errInvalidProxyPath
			}
		}
		current = next
	}

	return decoded, nil
}
