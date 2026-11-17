package ofrep

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// upstreamSentinel is the body the stand-in feature service returns for every
// request. A caller must not receive it from a path outside the flags prefix.
const upstreamSentinel = "upstream-sentinel"

// sessionCookieName is Grafana's default login cookie name (conf/defaults.ini).
// The value used in these tests is an obvious placeholder, not a real session.
const sessionCookieName = "grafana_session"

const sessionCookiePlaceholder = "placeholder-session"

const flagsPrefix = "/ofrep/v1/evaluate/flags/"

const probeBody = `{"context":{},"probe":"body-marker"}`

func TestFlagKeyCannotEscapeUpstreamFlagsPrefix(t *testing.T) {
	cases := []struct {
		name       string
		provider   setting.OpenFeatureProviderType
		route      string
		signedIn   bool
		withCookie bool
	}{
		{
			name:     "unauthenticated encoded slash traversal on the grafana router",
			provider: setting.OFREPProviderType,
			route:    "/ofrep/v1/evaluate/flags/..%2F..%2Fadmin",
		},
		{
			name:       "signed-in encoded slash traversal forwards the session cookie",
			provider:   setting.OFREPProviderType,
			route:      "/ofrep/v1/evaluate/flags/..%2F..%2Fadmin",
			signedIn:   true,
			withCookie: true,
		},
		{
			name:     "features-service provider uses the same flag proxy",
			provider: setting.FeaturesServiceProviderType,
			route:    "/ofrep/v1/evaluate/flags/..%2F..%2Fadmin",
		},
		{
			name:     "deprecated namespaced route decodes the flag key the same way",
			provider: setting.OFREPProviderType,
			route:    "/apis/features.grafana.app/v0alpha1/namespaces/stacks-1/ofrep/v1/evaluate/flags/..%2F..%2Fadmin",
		},
		{
			name:     "fully encoded dot segments are unescaped into the flag key",
			provider: setting.OFREPProviderType,
			route:    "/ofrep/v1/evaluate/flags/%2e%2e%2f%2e%2e%2fadmin",
		},
		{
			name:     "a parent segment inside the key is joined out of the prefix",
			provider: setting.OFREPProviderType,
			route:    "/ofrep/v1/evaluate/flags/foo%2F..%2F..%2Fadmin",
		},
		{
			name:     "a bare parent segment walks off the flags prefix",
			provider: setting.OFREPProviderType,
			route:    "/ofrep/v1/evaluate/flags/..",
		},
		{
			name:     "extra parent segments reach the upstream root",
			provider: setting.OFREPProviderType,
			route:    "/ofrep/v1/evaluate/flags/..%2F..%2F..%2F..%2Fadmin",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newRecordingUpstream(t)
			srv := newGrafanaOFREPServer(t, tc.provider, up.URL, tc.signedIn)

			cookie := ""
			if tc.withCookie {
				cookie = sessionCookiePlaceholder
			}
			resp := postOFREP(t, srv.URL+tc.route, cookie)
			up.mu.Lock()
			got := up.got
			up.mu.Unlock()

			if got.called && upstreamEscapesFlagsPrefix(got) {
				t.Fatalf("flag key was proxied outside %s: method=%s path=%q rawPath=%q requestURI=%q body=%q cookie=%q clientStatus=%d clientBody=%q",
					flagsPrefix, got.method, got.path, got.rawPath, got.requestURI, got.body, got.cookie, resp.status, resp.body)
			}
			if !got.called && strings.Contains(resp.body, upstreamSentinel) {
				t.Fatalf("client received upstream body without a recorded upstream request: status=%d body=%q", resp.status, resp.body)
			}
		})
	}
}

func TestLegitimateFlagKeyIsProxiedUnderFlagsPrefix(t *testing.T) {
	up := newRecordingUpstream(t)
	srv := newGrafanaOFREPServer(t, setting.OFREPProviderType, up.URL, false)

	const route = "/ofrep/v1/evaluate/flags/alerting.notifications"
	resp := postOFREP(t, srv.URL+route, "")

	up.mu.Lock()
	got := up.got
	up.mu.Unlock()

	require.True(t, got.called, "legitimate flag evaluation should reach the configured upstream")
	require.False(t, upstreamEscapesFlagsPrefix(got), "legitimate flag path escaped the prefix: path=%q requestURI=%q", got.path, got.requestURI)
	require.Equal(t, http.MethodPost, got.method)
	require.Equal(t, flagsPrefix+"alerting.notifications", path.Clean(got.path))
	require.Contains(t, got.body, "body-marker")
	require.Equal(t, http.StatusTeapot, resp.status)
	require.Contains(t, resp.body, upstreamSentinel)
}

type upstreamHit struct {
	called     bool
	method     string
	path       string
	rawPath    string
	requestURI string
	body       string
	cookie     string
}

type recordingUpstream struct {
	*httptest.Server
	mu  sync.Mutex
	got upstreamHit
}

func newRecordingUpstream(t *testing.T) *recordingUpstream {
	t.Helper()
	up := &recordingUpstream{}
	up.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		up.mu.Lock()
		up.got = upstreamHit{
			called:     true,
			method:     r.Method,
			path:       r.URL.Path,
			rawPath:    r.URL.RawPath,
			requestURI: r.RequestURI,
			body:       string(body),
			cookie:     r.Header.Get("Cookie"),
		}
		up.mu.Unlock()
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, upstreamSentinel)
	}))
	t.Cleanup(up.Close)
	return up
}

func newGrafanaOFREPServer(t *testing.T, provider setting.OpenFeatureProviderType, upstream string, signedIn bool) *httptest.Server {
	t.Helper()
	b := newProxyBuilder(t, provider, upstream)

	rr := routing.ProvideRegister()
	b.RegisterHTTPRoutes(rr)

	m := web.New()
	m.UseMiddleware(reqContextMiddleware(signedIn))

	cfg := setting.NewCfg()
	cfg.LoginCookieName = sessionCookieName
	m.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())

	rr.Register(m)
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return srv
}

func newProxyBuilder(t *testing.T, provider setting.OpenFeatureProviderType, upstream string) *APIBuilder {
	t.Helper()
	u, err := url.Parse(upstream)
	require.NoError(t, err)
	b, err := NewAPIBuilder(provider, u, true, "", nil)
	require.NoError(t, err)
	return b
}

// reqContextMiddleware installs the same request context the Grafana
// ContextHandler installs after authentication. It does not require a login.
// Signed-in requests carry a user id so the OFREP handler treats them as
// authenticated; the session cookie itself stays on the request header.
func reqContextMiddleware(signedIn bool) web.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqCtx := &contextmodel.ReqContext{
				Context:      web.FromContext(r.Context()),
				SignedInUser: &user.SignedInUser{},
				IsSignedIn:   signedIn,
			}
			if signedIn {
				reqCtx.SignedInUser.UserID = 1
			}
			ctx := context.WithValue(r.Context(), ctxkey.Key{}, reqCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type clientResult struct {
	status int
	body   string
}

func postOFREP(t *testing.T, rawURL, cookieValue string) clientResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(probeBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieValue})
	}
	// The reported request sends no Origin header. Leave it unset.

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return clientResult{status: resp.StatusCode, body: string(body)}
}

// upstreamEscapesFlagsPrefix reports whether any path the upstream actually
// observed, once percent-decoded and cleaned, leaves /ofrep/v1/evaluate/flags/<segment>.
func upstreamEscapesFlagsPrefix(got upstreamHit) bool {
	for _, candidate := range []string{got.path, got.rawPath, got.requestURI} {
		if candidate == "" {
			continue
		}
		if pathEscapesFlagsPrefix(candidate) {
			return true
		}
	}
	return false
}

func pathEscapesFlagsPrefix(p string) bool {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	decoded, err := url.PathUnescape(p)
	if err != nil {
		decoded = p
	}
	cleaned := path.Clean(decoded)
	rest, ok := strings.CutPrefix(cleaned, flagsPrefix)
	if !ok || rest == "" || strings.Contains(rest, "/") {
		return true
	}
	return rest == "." || rest == ".."
}
