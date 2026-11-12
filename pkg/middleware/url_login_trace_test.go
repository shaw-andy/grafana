package middleware

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/services/auth/jwt"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// placeholderCompactJWT builds a compact JWT whose only claim is a fixed subject.
// The value is an obvious placeholder, not a credential.
func placeholderCompactJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"placeholder-subject"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("placeholder-signature"))
	return header + "." + payload + "." + sig
}

func containsURLLoginValue(raw string, token string) bool {
	if raw == "" || token == "" {
		return false
	}
	escaped := url.QueryEscape(token)
	return strings.Contains(raw, token) || strings.Contains(raw, escaped)
}

// TestURLLoginDoesNotRecordTheQueryValue exercises the document request from the
// attack path: URL login is enabled, the query value authenticates, and the
// server span plus the original request URI must not keep that value.
func TestURLLoginDoesNotRecordTheQueryValue(t *testing.T) {
	t.Parallel()

	token := placeholderCompactJWT()
	headerName := "X-Grafana-JWT"

	cfg := &setting.Cfg{
		JWTAuth: setting.AuthJWTSettings{
			Enabled:         true,
			HeaderName:      headerName,
			URLLogin:        true,
			EmailClaim:      "email",
			UsernameClaim:   "preferred_username",
			SkipOrgRoleSync: true,
			AutoSignUp:      true,
		},
	}
	provider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	jwtService := &jwt.FakeJWTService{
		VerifyProvider: func(context.Context, string) (map[string]any, error) {
			return map[string]any{
				"sub":                "placeholder-subject",
				"email":              "placeholder@example.com",
				"preferred_username": "placeholder-user",
			}, nil
		},
	}
	recorder := tracetest.NewSpanRecorder()
	tracerProvider := trace.NewTracerProvider(trace.WithSpanProcessor(recorder))
	t.Cleanup(func() {
		_ = tracerProvider.Shutdown(context.Background())
	})
	tracer := tracerProvider.Tracer("url-login")
	client := clients.ProvideJWT(
		jwtService,
		connectors.ProvideOrgRoleMapper(provider, &orgtest.FakeOrgService{}),
		cfg,
		tracer,
	)

	var (
		accepted        bool
		authErr         error
		identity        *authn.Identity
		afterRequestURI string
		afterRawQuery   string
	)

	m := web.New()
	m.UseMiddleware(RequestTracing(tracer, ShouldTraceWithExceptions))
	m.Get("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authReq := &authn.Request{HTTPRequest: r, OrgID: 1}
		accepted = client.Test(r.Context(), authReq)
		if accepted {
			identity, authErr = client.Authenticate(r.Context(), authReq)
		}
		afterRequestURI = r.RequestURI
		afterRawQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))

	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)

	target := srv.URL + "/?auth_token=" + url.QueryEscape(token) + "&orgId=1"
	resp, err := srv.Client().Get(target)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.True(t, accepted, "URL login did not accept the query value")
	require.NoError(t, authErr)
	require.NotNil(t, identity)
	require.Equal(t, "placeholder-subject", identity.AuthID)
	require.False(t, containsURLLoginValue(afterRawQuery, token), "parsed query still carried the URL login value after authentication")

	spans := recorder.Ended()
	require.NotEmpty(t, spans, "request produced no spans")
	for _, span := range spans {
		if containsURLLoginValue(span.Name(), token) {
			t.Error("request trace name stored the URL login query value")
		}
		for _, attr := range span.Attributes() {
			if containsURLLoginValue(attr.Value.Emit(), token) {
				t.Errorf("request trace attribute %s stored the URL login query value", string(attr.Key))
			}
		}
	}
	if containsURLLoginValue(afterRequestURI, token) {
		t.Error("original request URI still carried the URL login query value after authentication")
	}
}
