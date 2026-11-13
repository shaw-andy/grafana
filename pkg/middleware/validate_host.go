package middleware

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
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

// HostMatchesDomain reports whether host, ignoring any port, names cfg.Domain.
func HostMatchesDomain(cfg *setting.Cfg, host string) bool {
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	return strings.EqualFold(host, cfg.Domain)
}

func ValidateHostHeader(cfg *setting.Cfg) web.Handler {
	return func(c *contextmodel.ReqContext) {
		// ignore local render calls
		if c.IsRenderCall {
			return
		}

		if !HostMatchesDomain(cfg, c.Req.Host) {
			// the normal redirecting logic doesn't work when running as frontend service, since it has no knowledge of the custom domain.
			// instead, we modify the single tenant `/bootdata` call with a 204 response and a header indicating the domain to redirect to
			// this is safe because only the frontend service calls `/bootdata`
			// the redirect is then handled client side.
			// see pkg/services/frontend/index.html
			if c.Req.URL.Path == "/bootdata" {
				c.Resp.Header().Set("Redirect-Domain", cfg.Domain)
				c.Resp.WriteHeader(204)
				return
			}
			hostRedirectCounter.Inc()
			c.Logger.Info("Enforcing Host header", "hosted", c.Req.Host, "expected", cfg.Domain)
			c.Redirect(strings.TrimSuffix(cfg.AppURL, "/")+c.Req.RequestURI, 301)
			return
		}
	}
}
