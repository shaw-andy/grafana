package httpclientprovider

import (
	"net/http"
	"strings"

	sdkhttpclient "github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/clientmiddleware"
	"github.com/grafana/grafana/pkg/setting"
)

const GrafanaRequestIDHeaderMiddlewareName = "grafana-request-id-header-middleware"

func GrafanaRequestIDHeaderMiddleware(cfg *setting.Cfg, logger log.Logger) sdkhttpclient.Middleware {
	return sdkhttpclient.NamedMiddlewareFunc(GrafanaRequestIDHeaderMiddlewareName, func(opts sdkhttpclient.Options, next http.RoundTripper) http.RoundTripper {
		return sdkhttpclient.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if !clientmiddleware.IsRequestURLInAllowList(req.URL, cfg) {
				logger.Debug("Data source URL not among the allow-listed URLs", "url", req.URL.String())
				return next.RoundTrip(req)
			}

			headers := clientmiddleware.GetGrafanaRequestIDHeaders(inboundRequest(req), cfg, logger)
			for _, name := range clientmiddleware.IPRangeACHeaders {
				for k := range req.Header {
					if strings.EqualFold(k, name) {
						delete(req.Header, k)
					}
				}
			}
			for k, v := range headers {
				req.Header.Set(k, v)
			}

			return next.RoundTrip(req)
		})
	})
}

// inboundRequest returns the user request that req is sent on behalf of, or nil
// when there is none. The outgoing request itself has no TCP peer, unless it is
// a clone of the inbound server request, as made by Grafana's reverse proxies.
func inboundRequest(req *http.Request) *http.Request {
	if inbound := clientmiddleware.InboundRequestFromContext(req.Context()); inbound != nil {
		return inbound
	}
	if req.RemoteAddr != "" {
		return req
	}
	return nil
}
