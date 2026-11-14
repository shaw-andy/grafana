package ofrep

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/contexthandler"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
	k8smux "k8s.io/apiserver/pkg/server/mux"
)

// placeholderSessionCookie and placeholderAuthorization are stand-ins for the
// caller's Grafana session cookie and Authorization header. They are not real
// credentials.
const (
	placeholderSessionCookie = "grafana_session=placeholder-session-token"
	placeholderExpiryCookie  = "grafana_session_expiry=placeholder-expiry"
	placeholderAuthorization = "Bearer placeholder-token"
	signedInNamespace        = "stacks-1"
	evaluationBody           = `{"context":{"namespace":"stacks-1","targetingKey":"stacks-1"}}`
	upstreamOKBody           = `{"flags":[{"key":"publicFlag","value":true,"reason":"STATIC","variant":"on","metadata":{"public":true}}]}`
	upstreamSingleOKBody     = `{"key":"myflag","value":true,"reason":"STATIC","variant":"on","metadata":{"public":true}}`
)

type forwardedHeaders struct {
	called        bool
	cookie        string
	authorization string
	path          string
	body          string
}

func newHeaderCaptureServer(t *testing.T, responseBody string) (*httptest.Server, *forwardedHeaders) {
	t.Helper()
	got := &forwardedHeaders{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.called = true
		got.cookie = r.Header.Get("Cookie")
		got.authorization = r.Header.Get("Authorization")
		got.path = r.URL.Path
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		got.body = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, responseBody)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func newRemoteBuilder(t *testing.T, provider setting.OpenFeatureProviderType, upstream string) *APIBuilder {
	t.Helper()
	b := newTestBuilder(t, upstream)
	b.providerType = provider
	return b
}

// signedInBrowserRequest is the request Grafana's page makes on startup: a
// same-origin POST carrying the session cookie. The auth-header list is the
// one ContextHandler stores before the route runs.
func signedInBrowserRequest(t *testing.T, target string, params map[string]string) (*contextmodel.ReqContext, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(evaluationBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://grafana.example")
	req.Header.Set("Referer", "http://grafana.example/")
	req.Header.Set("Cookie", placeholderSessionCookie+"; "+placeholderExpiryCookie)
	req.Header.Set("Authorization", placeholderAuthorization)
	if len(params) > 0 {
		req = web.SetURLParams(req, params)
	}
	req = req.WithContext(contexthandler.WithAuthHTTPHeaders(req.Context(), setting.NewCfg()))

	rec := httptest.NewRecorder()
	c := &contextmodel.ReqContext{
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(http.MethodPost, rec),
		},
		SignedInUser: &user.SignedInUser{
			UserID:    1,
			OrgID:     1,
			Login:     "admin",
			Namespace: signedInNamespace,
		},
		IsSignedIn: true,
	}
	return c, rec
}

func requireCredentialsNotForwarded(t *testing.T, got *forwardedHeaders, status int, wantPath string) {
	t.Helper()
	require.True(t, got.called, "flag evaluation was not proxied to the feature service")
	require.Equal(t, http.StatusOK, status, "proxied evaluation should succeed so the assertion covers a completed forward")
	require.Equal(t, wantPath, got.path)
	require.JSONEq(t, evaluationBody, got.body)
	assert.Empty(t, got.cookie, "Cookie header was forwarded to the feature service")
	assert.Empty(t, got.authorization, "Authorization header was forwarded to the feature service")
}

func TestRemoteProviderDoesNotForwardCallerCredentials(t *testing.T) {
	providers := []setting.OpenFeatureProviderType{
		setting.OFREPProviderType,
		setting.FeaturesServiceProviderType,
	}

	for _, provider := range providers {
		t.Run(string(provider), func(t *testing.T) {
			t.Run("bulk evaluation on the canonical route", func(t *testing.T) {
				upstream, got := newHeaderCaptureServer(t, upstreamOKBody)
				b := newRemoteBuilder(t, provider, upstream.URL)
				c, rec := signedInBrowserRequest(t, "http://grafana.example/ofrep/v1/evaluate/flags", nil)

				b.grafanaHTTPHandler(b.allFlagsHandler)(c)

				requireCredentialsNotForwarded(t, got, rec.Code, ofrepPath)
			})

			t.Run("single flag evaluation on the canonical route", func(t *testing.T) {
				upstream, got := newHeaderCaptureServer(t, upstreamSingleOKBody)
				b := newRemoteBuilder(t, provider, upstream.URL)
				c, rec := signedInBrowserRequest(t, "http://grafana.example/ofrep/v1/evaluate/flags/myflag", map[string]string{
					":flagKey": "myflag",
				})

				b.grafanaHTTPHandler(b.oneFlagHandler)(c)

				requireCredentialsNotForwarded(t, got, rec.Code, ofrepPath+"/myflag")
			})

			t.Run("bulk evaluation on the deprecated namespace route", func(t *testing.T) {
				upstream, got := newHeaderCaptureServer(t, upstreamOKBody)
				b := newRemoteBuilder(t, provider, upstream.URL)
				c, rec := signedInBrowserRequest(t,
					"http://grafana.example/apis/features.grafana.app/v0alpha1/namespaces/"+signedInNamespace+"/ofrep/v1/evaluate/flags",
					map[string]string{":namespace": signedInNamespace},
				)

				b.grafanaHTTPHandler(b.allFlagsHandler)(c)

				requireCredentialsNotForwarded(t, got, rec.Code, ofrepPath)
			})

			t.Run("single flag evaluation on the deprecated namespace route", func(t *testing.T) {
				upstream, got := newHeaderCaptureServer(t, upstreamSingleOKBody)
				b := newRemoteBuilder(t, provider, upstream.URL)
				c, rec := signedInBrowserRequest(t,
					"http://grafana.example/apis/features.grafana.app/v0alpha1/namespaces/"+signedInNamespace+"/ofrep/v1/evaluate/flags/myflag",
					map[string]string{":namespace": signedInNamespace, ":flagKey": "myflag"},
				)

				b.grafanaHTTPHandler(b.oneFlagHandler)(c)

				requireCredentialsNotForwarded(t, got, rec.Code, ofrepPath+"/myflag")
			})

			t.Run("standalone apiserver mux forwards the same request", func(t *testing.T) {
				upstream, got := newHeaderCaptureServer(t, upstreamOKBody)
				b := newRemoteBuilder(t, provider, upstream.URL)
				mux := k8smux.NewPathRecorderMux("ofrep-credential-test")
				b.Setup(mux)

				req := httptest.NewRequest(http.MethodPost, "/ofrep/v1/evaluate/flags", strings.NewReader(evaluationBody))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Cookie", placeholderSessionCookie)
				req.Header.Set("Authorization", placeholderAuthorization)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)

				requireCredentialsNotForwarded(t, got, rec.Code, ofrepPath)
			})
		})
	}
}

func TestLegacyOverrideBypassDoesNotForwardCallerCredentials(t *testing.T) {
	setupOpenFeatureFlag(t, featuremgmt.FlagFeaturesLegacyOverrideLookupBypass, true)

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("single-flag evaluation reached the primary provider; the bypass upstream is the one under test")
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(primary.Close)

	goff, got := newHeaderCaptureServer(t, upstreamSingleOKBody)
	b := newRemoteBuilder(t, setting.FeaturesServiceProviderType, primary.URL)
	goffURL, err := url.Parse(goff.URL)
	require.NoError(t, err)
	b.EnableLegacyOverrideLookupBypass(goffURL, nil)

	c, rec := signedInBrowserRequest(t, "http://grafana.example/ofrep/v1/evaluate/flags/myflag", map[string]string{
		":flagKey": "myflag",
	})
	b.grafanaHTTPHandler(b.oneFlagHandler)(c)

	requireCredentialsNotForwarded(t, got, rec.Code, ofrepPath+"/myflag")
}
