package api

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/grafana/grafana/pkg/infra/log"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/util"
	"github.com/grafana/grafana/pkg/util/proxyutil"
	"github.com/grafana/grafana/pkg/web"
)

// ssoTokenAllowedPaths are the GCOM paths that should receive the hg-auth token.
var ssoTokenAllowedPaths = []*regexp.Regexp{
	regexp.MustCompile(`^/?plugins$`),
	regexp.MustCompile(`^/?plugins/[^/]+$`),
	regexp.MustCompile(`^/?plugins/[^/]+/entitlement$`),
	regexp.MustCompile(`^/?plugins/[^/]+/versions$`),
	regexp.MustCompile(`^/?plugins/[^/]+/versions/[^/]+$`),
	regexp.MustCompile(`^/?plugins/[^/]+/versions/[^/]+/logos/[^/]+$`),
	regexp.MustCompile(`^/?plugins/[^/]+/versions/[^/]+/images/.+$`),
	regexp.MustCompile(`^/?plugins/[^/]+/versions/[^/]+/insights$`),
	regexp.MustCompile(`^/?dashboards$`),
	regexp.MustCompile(`^/?dashboards/[^/]+$`),
}

func ssoTokenAllowedPath(proxyPath string) bool {
	for _, re := range ssoTokenAllowedPaths {
		if re.MatchString(proxyPath) {
			return true
		}
	}
	return false
}

// cleanGnetProxyPath returns proxyPath in canonical form, relative to the GCOM API URL.
// Paths containing dot segments, in any encoding, are refused rather than resolved: GCOM
// or a proxy in front of it could resolve them to a resource other than the one checked
// against ssoTokenAllowedPaths.
func cleanGnetProxyPath(proxyPath string) (string, bool) {
	for _, segment := range strings.Split(proxyPath, "/") {
		if unsafeGnetPathSegment(segment) {
			return "", false
		}
	}
	return strings.TrimPrefix(path.Clean("/"+proxyPath), "/"), true
}

func unsafeGnetPathSegment(segment string) bool {
	for {
		if strings.ContainsAny(segment, "\\\x00") {
			return true
		}
		name, _, _ := strings.Cut(segment, ";")
		if name == "." || name == ".." {
			return true
		}
		unescaped, err := url.PathUnescape(segment)
		if err != nil || unescaped == segment {
			return false
		}
		segment = unescaped
	}
}

var grafanaComProxyTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	TLSHandshakeTimeout: 10 * time.Second,
}

func ReverseProxyGnetReq(logger log.Logger, proxyPath, version, grafanaComAPIUrl, grafanaComAPIToken string) *httputil.ReverseProxy {
	url, _ := url.Parse(grafanaComAPIUrl)
	proxyPath, validPath := cleanGnetProxyPath(proxyPath)
	attachToken := grafanaComAPIToken != "" && validPath && ssoTokenAllowedPath(proxyPath)

	director := func(req *http.Request) {
		req.URL.Scheme = url.Scheme
		req.URL.Host = url.Host
		req.Host = url.Host

		req.URL.Path = util.JoinURLFragments(url.Path, proxyPath)
		req.URL.RawPath = ""

		// clear cookie headers
		req.Header.Del("Cookie")
		req.Header.Del("Set-Cookie")
		req.Header.Del("Authorization")

		// send the current Grafana version for each request proxied to GCOM
		req.Header.Add("grafana-version", version)

		if attachToken && req.Method == http.MethodGet {
			req.Header.Set("Authorization", "Bearer "+grafanaComAPIToken)
		}
	}

	return proxyutil.NewReverseProxy(logger, director)
}

func (hs *HTTPServer) ProxyGnetRequest(c *contextmodel.ReqContext) {
	proxyPath, ok := cleanGnetProxyPath(web.Params(c.Req)["*"])
	if !ok {
		c.JsonApiErr(http.StatusBadRequest, "Invalid proxy path", nil)
		return
	}
	proxy := ReverseProxyGnetReq(c.Logger, proxyPath, hs.Cfg.BuildVersion, hs.Cfg.GrafanaComAPIURL, hs.Cfg.GrafanaComProxyAPIToken)
	proxy.Transport = grafanaComProxyTransport
	proxy.ServeHTTP(c.Resp, c.Req)
}
