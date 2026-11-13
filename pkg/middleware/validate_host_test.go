package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/setting"
)

func TestValidateHostHeader(t *testing.T) {
	cfg := setting.NewCfg()
	cfg.Domain = "grafana.example.com"
	cfg.AppURL = "https://public.example.com/"
	cfg.HTTPAddr = setting.DefaultHTTPAddr
	cfg.RendererCallbackUrl = "http://renderer-callback:3000/"
	cfg.EnforceDomainAllowedHosts = []string{"proxy.internal", "*.tenants.example.com"}

	handler := ValidateHostHeader(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	serve := func(host, target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Host = host
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	accepted := []string{
		"grafana.example.com",
		"grafana.example.com:3000",
		"GRAFANA.example.com",
		"grafana.example.com.",
		"public.example.com",
		"renderer-callback:3000",
		"proxy.internal",
		"a.tenants.example.com",
		"a.b.tenants.example.com:443",
		"localhost:3000",
		"127.0.0.1:3000",
		"10.1.2.3",
		"[::1]:3000",
		"[fe80::1]",
		"",
	}
	for _, host := range accepted {
		t.Run("accepts "+host, func(t *testing.T) {
			assert.Equal(t, http.StatusOK, serve(host, "/metrics").Code)
		})
	}

	refused := []string{
		"rebind.example",
		"rebind.example:3000",
		"grafana.example.com.rebind.example",
		"evilgrafana.example.com",
		"tenants.example.com",
		"eviltenants.example.com",
		"127.0.0.1.rebind.example",
		"localhost.rebind.example",
		"grafana.example.com:3000:rebind.example",
	}
	for _, host := range refused {
		t.Run("redirects "+host, func(t *testing.T) {
			rec := serve(host, "/api/health?x=1")
			require.Equal(t, http.StatusMovedPermanently, rec.Code)
			assert.Equal(t, "https://public.example.com/api/health?x=1", rec.Header().Get("Location"))
		})
	}

	t.Run("bootdata from a foreign host gets the redirect domain", func(t *testing.T) {
		rec := serve("rebind.example", "/bootdata")
		require.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "grafana.example.com", rec.Header().Get("Redirect-Domain"))
	})
}
