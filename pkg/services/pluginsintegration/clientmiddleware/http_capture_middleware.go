package clientmiddleware

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	sdkhttpclient "github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"

	"github.com/grafana/grafana/pkg/infra/httpclient/harcapture"
)

const harCaptureHeader = "X-Grafana-HAR-Capture"

// harResponseRefIDPrefix is the refId prefix of the synthetic responses in which externalized plugins
// return their captured traffic.
const harResponseRefIDPrefix = "__har__"

// NewHTTPCaptureMiddleware creates a backend.HandlerMiddleware that captures HTTP traffic
// for QueryData calls when a harcapture.Buffer is present in the context.
func NewHTTPCaptureMiddleware() backend.HandlerMiddleware {
	return backend.HandlerMiddlewareFunc(func(next backend.Handler) backend.Handler {
		return &HTTPCaptureMiddleware{BaseHandler: backend.NewBaseHandler(next)}
	})
}

type HTTPCaptureMiddleware struct {
	backend.BaseHandler
}

func (m *HTTPCaptureMiddleware) QueryData(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	buf := harcapture.FromContext(ctx)
	if buf == nil {
		return m.BaseHandler.QueryData(ctx, req)
	}

	secrets := datasourceSecrets(req.PluginContext)
	buf.AddSecrets(secrets...)

	// Signal external gRPC plugins via request header.
	if req.Headers == nil {
		req.Headers = map[string]string{}
	}
	req.Headers[harCaptureHeader] = "true"

	ctx = sdkhttpclient.WithContextualMiddleware(ctx, captureMiddleware(buf))

	resp, err := m.BaseHandler.QueryData(ctx, req)
	secretSet := harcapture.SecretSet{}.With(secrets...)
	scrubCapturedResponse(resp, secretSet)
	if err != nil {
		if msg := err.Error(); secretSet.Scrub(msg) != msg {
			err = errors.New(secretSet.Scrub(msg))
		}
	}
	return resp, err
}

func (m *HTTPCaptureMiddleware) QueryChunkedData(ctx context.Context, req *backend.QueryChunkedDataRequest, w backend.ChunkedDataWriter) error {
	buf := harcapture.FromContext(ctx)
	if buf == nil {
		return m.BaseHandler.QueryChunkedData(ctx, req, w)
	}

	buf.AddSecrets(datasourceSecrets(req.PluginContext)...)

	// Signal external gRPC plugins via request header.
	if req.Headers == nil {
		req.Headers = map[string]string{}
	}
	req.Headers[harCaptureHeader] = "true"

	ctx = sdkhttpclient.WithContextualMiddleware(ctx, captureMiddleware(buf))

	return m.BaseHandler.QueryChunkedData(ctx, req, w)
}

// datasourceSecrets returns the credential values Grafana can attach to the datasource's requests:
// every decrypted secure setting (basic-auth password, custom header values, tokens, ...), the
// basic-auth header value built from them, and a password embedded in the datasource URL.
func datasourceSecrets(pCtx backend.PluginContext) []string {
	settings := pCtx.DataSourceInstanceSettings
	if settings == nil {
		return nil
	}
	values := make([]string, 0, len(settings.DecryptedSecureJSONData)+3)
	for _, v := range settings.DecryptedSecureJSONData {
		values = append(values, v)
	}
	if pw := settings.DecryptedSecureJSONData["basicAuthPassword"]; pw != "" {
		values = append(values, base64.StdEncoding.EncodeToString([]byte(settings.BasicAuthUser+":"+pw)))
	}
	if pw := settings.DecryptedSecureJSONData["password"]; pw != "" && settings.User != "" {
		values = append(values, base64.StdEncoding.EncodeToString([]byte(settings.User+":"+pw)))
	}
	if u, err := url.Parse(settings.URL); err == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok && pw != "" {
			values = append(values, pw, base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pw)))
		}
	}
	return values
}

// scrubCapturedResponse removes the datasource's credentials from what an externalized plugin
// returned alongside its capture: the serialized HAR and the stashed query error in its __har__
// frames, and per-refId error text. The plugin serialized these itself, so its redaction cannot be
// relied on.
func scrubCapturedResponse(resp *backend.QueryDataResponse, secrets harcapture.SecretSet) {
	if resp == nil || secrets.Empty() {
		return
	}
	for refID, r := range resp.Responses {
		changed := false
		if r.Error != nil {
			if msg := r.Error.Error(); secrets.Scrub(msg) != msg {
				r.Error = errors.New(secrets.Scrub(msg))
				changed = true
			}
		}
		if strings.HasPrefix(refID, harResponseRefIDPrefix) {
			for _, frame := range r.Frames {
				if frame == nil || frame.Meta == nil {
					continue
				}
				custom, ok := frame.Meta.Custom.(map[string]interface{})
				if !ok {
					continue
				}
				for _, key := range []string{"har", "queryError"} {
					if s, ok := custom[key].(string); ok {
						custom[key] = secrets.Scrub(s)
					}
				}
			}
		}
		if changed {
			resp.Responses[refID] = r
		}
	}
}

// captureMiddleware returns an HTTP client middleware that records every outgoing
// request/response into buf, for core (in-process) plugins.
func captureMiddleware(buf *harcapture.Buffer) sdkhttpclient.Middleware {
	return sdkhttpclient.NamedMiddlewareFunc("http-capture", func(_ sdkhttpclient.Options, next http.RoundTripper) http.RoundTripper {
		return sdkhttpclient.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
			// Buffer the request body before it is consumed by the transport.
			var bodyBytes []byte
			if r.Body != nil {
				var readErr error
				bodyBytes, readErr = io.ReadAll(r.Body)
				_ = r.Body.Close()
				if readErr != nil {
					// Fail the request rather than silently forwarding a truncated body to the
					// datasource; the diagnostics run surfaces the error.
					return nil, fmt.Errorf("har capture: reading request body: %w", readErr)
				}
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}

			started := time.Now()
			resp, err := next.RoundTrip(r)
			elapsed := time.Since(started)

			// Capture every attempt, including transport-level failures (connection refused,
			// timeouts, etc.) where err is non-nil and resp is nil -- those are exactly the
			// requests worth seeing in a diagnostics bundle. Restore the request body first so
			// buildEntry can read it.
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			buf.AddEntry(r, resp, err, started, elapsed)

			return resp, err
		})
	})
}
