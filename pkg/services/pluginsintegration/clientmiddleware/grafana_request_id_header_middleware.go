package clientmiddleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/netip"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/grafana/grafana-plugin-sdk-go/backend"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/setting"
)

const GrafanaRequestID = "X-Grafana-Request-Id"
const GrafanaSignedRequestID = "X-Grafana-Signed-Request-Id"
const XRealIPHeader = "X-Real-Ip"
const GrafanaInternalRequest = "X-Grafana-Internal-Request"

// IPRangeACHeaders are the headers Grafana sets for IP range access control.
// Any existing values must be removed before Grafana sets its own, so that a
// caller can never pass one of them through.
var IPRangeACHeaders = []string{GrafanaRequestID, GrafanaSignedRequestID, XRealIPHeader, GrafanaInternalRequest}

// NewHostedGrafanaACHeaderMiddleware creates a new backend.HandlerMiddleware that will
// generate a random request ID, sign it together with the client address and internal flag
// using internal key, and populate X-Grafana-Request-ID with the request ID and
// X-Grafana-Signed-Request-ID with the signature. We can then use this to verify that the request
// is coming from hosted Grafana and is not an external request. This is used for IP range access control.
func NewHostedGrafanaACHeaderMiddleware(cfg *setting.Cfg) backend.HandlerMiddleware {
	return backend.HandlerMiddlewareFunc(func(next backend.Handler) backend.Handler {
		return &HostedGrafanaACHeaderMiddleware{
			BaseHandler: backend.NewBaseHandler(next),
			log:         log.New("ip_header_middleware"),
			cfg:         cfg,
		}
	})
}

type HostedGrafanaACHeaderMiddleware struct {
	backend.BaseHandler
	log log.Logger
	cfg *setting.Cfg
}

func (m *HostedGrafanaACHeaderMiddleware) applyGrafanaRequestIDHeader(ctx context.Context, pCtx backend.PluginContext, h backend.ForwardHTTPHeaders) {
	// if request is not for a datasource, skip the middleware
	if h == nil || pCtx.DataSourceInstanceSettings == nil {
		return
	}

	// Check if the request is for a datasource that is allowed to have the header
	dsURL := pCtx.DataSourceInstanceSettings.URL
	dsBaseURL, err := url.Parse(dsURL)
	if err != nil {
		m.log.Debug("Failed to parse data source URL", "error", err)
		return
	}
	if !IsRequestURLInAllowList(dsBaseURL, m.cfg) {
		m.log.Debug("Data source URL not among the allow-listed URLs", "url", dsBaseURL.String())
		return
	}

	headers := GetGrafanaRequestIDHeaders(InboundRequestFromContext(ctx), m.cfg, m.log)
	for _, k := range IPRangeACHeaders {
		deleteForwardedHTTPHeader(h, k)
	}
	for k, v := range headers {
		h.SetHTTPHeader(k, v)
	}
}

func deleteForwardedHTTPHeader(h backend.ForwardHTTPHeaders, key string) {
	canonical := textproto.CanonicalMIMEHeaderKey(key)
	for hasForwardedHTTPHeader(h, canonical) {
		h.DeleteHTTPHeader(key)
	}
}

func hasForwardedHTTPHeader(h backend.ForwardHTTPHeaders, canonical string) bool {
	for k := range h.GetHTTPHeaders() {
		if textproto.CanonicalMIMEHeaderKey(k) == canonical {
			return true
		}
	}
	return false
}

// InboundRequestFromContext returns the inbound user HTTP request being served
// with ctx, or nil when ctx does not belong to an inbound request.
func InboundRequestFromContext(ctx context.Context) *http.Request {
	reqCtx := contexthandler.FromContext(ctx)
	if reqCtx == nil || reqCtx.Context == nil {
		return nil
	}
	return reqCtx.Req
}

func IsRequestURLInAllowList(url *url.URL, cfg *setting.Cfg) bool {
	for _, allowedURL := range cfg.IPRangeACAllowedURLs {
		// Only look at the scheme and host, ignore the path
		if allowedURL.Host == url.Host && allowedURL.Scheme == url.Scheme {
			return true
		}
	}
	return false
}

// GetGrafanaRequestIDHeaders returns the IP range access control headers for a
// call made on behalf of inbound. inbound must be the request Grafana received
// from the client, not an outgoing request; it is nil only when the call has no
// inbound user request, which is the only case marked as internal.
func GetGrafanaRequestIDHeaders(inbound *http.Request, cfg *setting.Cfg, logger log.Logger) map[string]string {
	// Generate a new Grafana request ID and sign it with the secret key
	uid, err := uuid.NewRandom()
	if err != nil {
		logger.Debug("Failed to generate Grafana request ID", "error", err)
		return nil
	}
	grafanaRequestID := uid.String()

	internal := inbound == nil
	remoteAddress := ""
	if !internal {
		remoteAddress = ClientAddress(inbound, cfg.IPRangeACTrustedProxies)
	}

	signedGrafanaRequestID, err := signIPRangeRequest(cfg.IPRangeACSecretKey, grafanaRequestID, remoteAddress, internal)
	if err != nil {
		logger.Debug("Failed to sign IP range access control header", "error", err)
		return nil
	}

	headers := make(map[string]string)
	headers[GrafanaRequestID] = grafanaRequestID
	headers[GrafanaSignedRequestID] = signedGrafanaRequestID

	if internal {
		headers[GrafanaInternalRequest] = "true"
	} else if remoteAddress != "" {
		headers[XRealIPHeader] = remoteAddress
	}

	return headers
}

// signIPRangeRequest binds the request ID to the client address and the internal
// flag, so that neither can be changed or added without invalidating the signature.
func signIPRangeRequest(secret, requestID, address string, internal bool) (string, error) {
	mac := hmac.New(sha256.New, []byte(secret))
	payload := requestID + "\n" + address + "\n" + strconv.FormatBool(internal)
	if _, err := mac.Write([]byte(payload)); err != nil {
		return "", err
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// ClientAddress returns the client IP of an inbound request. It is the peer of
// the TCP connection. X-Forwarded-For is only followed, from the right, while the
// hop that appended an entry is one of trustedProxies. X-Real-IP is never used,
// since any client can set it. An empty string means the address is unknown.
func ClientAddress(req *http.Request, trustedProxies []netip.Prefix) string {
	addr, ok := parseIP(req.RemoteAddr)
	if !ok {
		return ""
	}

	if len(trustedProxies) > 0 {
		var hops []string
		for _, v := range req.Header.Values("X-Forwarded-For") {
			hops = append(hops, strings.Split(v, ",")...)
		}
		for i := len(hops) - 1; i >= 0 && isTrustedProxy(addr, trustedProxies); i-- {
			next, ok := parseIP(strings.TrimSpace(hops[i]))
			if !ok {
				break
			}
			addr = next
		}
	}

	return addr.String()
}

func parseIP(s string) (netip.Addr, bool) {
	if addrPort, err := netip.ParseAddrPort(s); err == nil {
		return addrPort.Addr().WithZone("").Unmap(), true
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.WithZone("").Unmap(), true
	}
	return netip.Addr{}, false
}

func isTrustedProxy(addr netip.Addr, trustedProxies []netip.Prefix) bool {
	for _, p := range trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (m *HostedGrafanaACHeaderMiddleware) QueryData(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	if req == nil {
		return m.BaseHandler.QueryData(ctx, req)
	}

	m.applyGrafanaRequestIDHeader(ctx, req.PluginContext, req)

	return m.BaseHandler.QueryData(ctx, req)
}

func (m *HostedGrafanaACHeaderMiddleware) QueryChunkedData(ctx context.Context, req *backend.QueryChunkedDataRequest, w backend.ChunkedDataWriter) error {
	if req == nil {
		return m.BaseHandler.QueryChunkedData(ctx, req, w)
	}

	m.applyGrafanaRequestIDHeader(ctx, req.PluginContext, req)

	return m.BaseHandler.QueryChunkedData(ctx, req, w)
}

func (m *HostedGrafanaACHeaderMiddleware) CallResource(ctx context.Context, req *backend.CallResourceRequest, sender backend.CallResourceResponseSender) error {
	if req == nil {
		return m.BaseHandler.CallResource(ctx, req, sender)
	}

	m.applyGrafanaRequestIDHeader(ctx, req.PluginContext, req)

	return m.BaseHandler.CallResource(ctx, req, sender)
}

func (m *HostedGrafanaACHeaderMiddleware) CheckHealth(ctx context.Context, req *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	if req == nil {
		return m.BaseHandler.CheckHealth(ctx, req)
	}

	m.applyGrafanaRequestIDHeader(ctx, req.PluginContext, req)

	return m.BaseHandler.CheckHealth(ctx, req)
}
