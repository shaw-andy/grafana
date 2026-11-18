package ofrep

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/server/mux"

	"github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// These tests describe the secure behavior of the OFREP reverse proxy.
// They fail while ProvideService dials the feature service with certificate
// verification disabled and forwards the caller Cookie header.

const (
	// placeholderSession is not a credential. It stands in for the login
	// cookie a signed-in browser would send to the evaluation endpoint.
	placeholderSession = "grafana_session=placeholder-session"
	forgedMarker       = "forged-flag"
	upstreamMarker     = "upstream-flag"
)

func TestProvideServiceProxyRejectsUntrustedFeatureServer(t *testing.T) {
	for _, provider := range []string{"ofrep", "features-service"} {
		t.Run(provider, func(t *testing.T) {
			upstream := newRecordingUpstream(t, true, forgedBulkBody, forgedSingleBody)
			b, rr := provideRemoteOFREP(t, provider, upstream.URL)

			t.Run("grafana routes", func(t *testing.T) {
				srv := webtest.NewServer(t, rr)
				for _, path := range evaluationPaths() {
					t.Run(path, func(t *testing.T) {
						upstream.reset()
						req := srv.NewPostRequest(path, strings.NewReader(`{"context":{"namespace":"stacks-1"}}`))
						req.Header.Set("Cookie", placeholderSession)
						req = webtest.RequestWithSignedInUser(req, &user.SignedInUser{UserID: 1, Namespace: "stacks-1"})
						resp, err := srv.SendJSON(req)
						require.NoError(t, err)
						defer resp.Body.Close()
						body, err := io.ReadAll(resp.Body)
						require.NoError(t, err)
						assertFeatureServerUntrusted(t, upstream, resp.StatusCode, string(body))
					})
				}
			})

			t.Run("apiserver mux", func(t *testing.T) {
				m := mux.NewPathRecorderMux("ofrep-cert-test")
				require.NotPanics(t, func() { b.Setup(m) })
				for _, path := range evaluationPaths() {
					t.Run(path, func(t *testing.T) {
						upstream.reset()
						req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"context":{"namespace":"stacks-1"}}`))
						req.Header.Set("Cookie", placeholderSession)
						req.Header.Set("Content-Type", "application/json")
						req = req.WithContext(types.WithAuthInfo(req.Context(), &identity.StaticRequester{
							Type:      types.TypeUser,
							UserID:    1,
							Namespace: "stacks-1",
						}))
						rec := httptest.NewRecorder()
						m.ServeHTTP(rec, req)
						assertFeatureServerUntrusted(t, upstream, rec.Code, rec.Body.String())
					})
				}
			})
		})
	}
}

func TestProvideServiceProxyStripsCallerCookie(t *testing.T) {
	for _, provider := range []string{"ofrep", "features-service"} {
		t.Run(provider, func(t *testing.T) {
			upstream := newRecordingUpstream(t, false, trustedBulkBody, trustedSingleBody)
			b, rr := provideRemoteOFREP(t, provider, upstream.URL)

			t.Run("grafana routes", func(t *testing.T) {
				srv := webtest.NewServer(t, rr)
				for _, path := range evaluationPaths() {
					t.Run(path, func(t *testing.T) {
						upstream.reset()
						req := srv.NewPostRequest(path, strings.NewReader(`{"context":{"namespace":"stacks-1"}}`))
						req.Header.Set("Cookie", placeholderSession)
						req = webtest.RequestWithSignedInUser(req, &user.SignedInUser{UserID: 1, Namespace: "stacks-1"})
						resp, err := srv.SendJSON(req)
						require.NoError(t, err)
						defer resp.Body.Close()
						body, err := io.ReadAll(resp.Body)
						require.NoError(t, err)
						assertCookieStripped(t, upstream, resp.StatusCode, string(body))
					})
				}
			})

			t.Run("apiserver mux", func(t *testing.T) {
				m := mux.NewPathRecorderMux("ofrep-cookie-test")
				require.NotPanics(t, func() { b.Setup(m) })
				for _, path := range evaluationPaths() {
					t.Run(path, func(t *testing.T) {
						upstream.reset()
						req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"context":{"namespace":"stacks-1"}}`))
						req.Header.Set("Cookie", placeholderSession)
						req.Header.Set("Content-Type", "application/json")
						req = req.WithContext(types.WithAuthInfo(req.Context(), &identity.StaticRequester{
							Type:      types.TypeUser,
							UserID:    1,
							Namespace: "stacks-1",
						}))
						rec := httptest.NewRecorder()
						m.ServeHTTP(rec, req)
						assertCookieStripped(t, upstream, rec.Code, rec.Body.String())
					})
				}
			})
		})
	}
}

func evaluationPaths() []string {
	return []string{
		"/ofrep/v1/evaluate/flags",
		"/ofrep/v1/evaluate/flags/someFlag",
		"/apis/features.grafana.app/v0alpha1/namespaces/stacks-1/ofrep/v1/evaluate/flags",
		"/apis/features.grafana.app/v0alpha1/namespaces/stacks-1/ofrep/v1/evaluate/flags/someFlag",
	}
}

const (
	forgedBulkBody    = `{"flags":[{"key":"forged-flag","value":true,"reason":"ATTACKER","metadata":{"public":true}}]}`
	forgedSingleBody  = `{"key":"forged-flag","value":true,"reason":"ATTACKER","metadata":{"public":true}}`
	trustedBulkBody   = `{"flags":[{"key":"upstream-flag","value":true,"reason":"STATIC","metadata":{"public":true}}]}`
	trustedSingleBody = `{"key":"upstream-flag","value":true,"reason":"STATIC","metadata":{"public":true}}`
)

func assertFeatureServerUntrusted(t *testing.T, upstream *recordingUpstream, status int, body string) {
	t.Helper()
	got := upstream.snapshot()
	require.Zero(t, got.hits, "feature server handled an HTTP request over an untrusted certificate; cookie=%q body=%s", got.cookie, body)
	require.NotContains(t, got.cookie, "placeholder-session")
	require.NotContains(t, got.cookie, "grafana_session")
	require.NotEqual(t, http.StatusOK, status, "caller received a successful evaluation from an untrusted feature server: %s", body)
	require.NotContains(t, body, forgedMarker)
	require.NotContains(t, body, "ATTACKER")
}

func assertCookieStripped(t *testing.T, upstream *recordingUpstream, status int, body string) {
	t.Helper()
	got := upstream.snapshot()
	require.Equal(t, http.StatusOK, status, "evaluation was not proxied: %s", body)
	require.Contains(t, body, upstreamMarker)
	require.Greater(t, got.hits, 0)
	require.Empty(t, got.cookie, "caller Cookie header was forwarded to the feature service")
	require.NotContains(t, got.cookie, "placeholder-session")
}

func provideRemoteOFREP(t *testing.T, provider, upstreamURL string) (*APIBuilder, routing.RouteRegister) {
	t.Helper()
	cfg, err := setting.NewCfgFromBytes([]byte(fmt.Sprintf(`
[feature_toggles.openfeature]
provider = %s
url = %s
`, provider, upstreamURL)))
	require.NoError(t, err)
	rr := routing.NewRouteRegister()
	b, err := ProvideService(cfg, rr)
	require.NoError(t, err)
	return b, rr
}

type recordingUpstream struct {
	URL string

	mu     sync.Mutex
	hits   int
	cookie string
}

func newRecordingUpstream(t *testing.T, tlsServer bool, bulkBody, singleBody string) *recordingUpstream {
	t.Helper()
	u := &recordingUpstream{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hits++
		u.cookie = r.Header.Get("Cookie")
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		body := bulkBody
		if strings.Contains(r.URL.Path, "someFlag") {
			body = singleBody
		}
		_, _ = io.WriteString(w, body)
	})
	var srv *httptest.Server
	if tlsServer {
		srv = httptest.NewTLSServer(handler)
	} else {
		srv = httptest.NewServer(handler)
	}
	t.Cleanup(srv.Close)
	u.URL = srv.URL
	return u
}

func (u *recordingUpstream) reset() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.hits = 0
	u.cookie = ""
}

func (u *recordingUpstream) snapshot() (got struct {
	hits   int
	cookie string
}) {
	u.mu.Lock()
	defer u.mu.Unlock()
	got.hits = u.hits
	got.cookie = u.cookie
	return got
}
