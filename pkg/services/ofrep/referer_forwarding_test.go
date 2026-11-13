package ofrep

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
)

func TestOFREPProxyDoesNotForwardDashboardPageQuery(t *testing.T) {
	const dashboardPageReferer = "https://grafana.example/d/abc/overview?orgId=1&var-region=page-query-value"
	const pageQueryValue = "page-query-value"

	var got *http.Request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	target, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	builder := &APIBuilder{
		logger:    log.New("test"),
		transport: http.DefaultTransport.(*http.Transport).Clone(),
	}
	proxy, err := builder.newProxy("/ofrep/v1/evaluate/flags", "default", target, "test-agent")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "http://grafana.example/apis/features.grafana.app/v0alpha1/namespaces/default/ofrep/v1/evaluate/flags?limit=1", nil)
	req.Header.Set("Referer", dashboardPageReferer)
	req.RemoteAddr = "192.0.2.10:1234"
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, got)
	require.Equal(t, "limit=1", got.URL.RawQuery)
	for name, values := range got.Header {
		for _, value := range values {
			if strings.Contains(value, pageQueryValue) {
				t.Fatalf("OFREP proxy header %s contains the dashboard page query", name)
			}
		}
	}
	require.NotContains(t, got.URL.String(), pageQueryValue)

	forwarded := got.Header.Get("X-Grafana-Referer")
	if forwarded == "" {
		return
	}
	parsed, err := url.Parse(forwarded)
	require.NoError(t, err)
	require.Empty(t, parsed.RawQuery)
	require.NotContains(t, forwarded, "?")
}
