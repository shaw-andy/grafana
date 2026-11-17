package csrf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	// Linkname target for pkg/web handler wrapping. The production server pulls this in through pkg/api.
	_ "github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// sessionCookieName matches the default auth.login_cookie_name.
const sessionCookieName = "grafana_session"

// serverOrigin is the origin Grafana is configured to serve, including the port.
const serverOrigin = "http://grafana.example.com:3000"

func TestCrossPortOriginRejectedBeforeHandler(t *testing.T) {
	t.Parallel()

	// Every method that csrf.check does not skip shares the hostname-only comparison.
	for _, method := range []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodGet,
	} {
		t.Run(method+" cross-port origin does not run the handler", func(t *testing.T) {
			t.Parallel()
			rr, called := serveCSRF(t, csrfRequest{
				method: method,
				target: "/api/user/using/2",
				host:   "grafana.example.com:3000",
				origin: "http://grafana.example.com:8443",
				cookie: true,
			})
			require.Equal(t, http.StatusForbidden, rr.Code)
			require.False(t, called, "state-changing handler ran for a cross-port Origin")
		})
	}

	t.Run("cross-scheme origin does not run the handler", func(t *testing.T) {
		t.Parallel()
		rr, called := serveCSRF(t, csrfRequest{
			method: http.MethodPost,
			target: "/api/user/using/2",
			host:   "grafana.example.com:3000",
			origin: "https://grafana.example.com:3000",
			cookie: true,
		})
		require.Equal(t, http.StatusForbidden, rr.Code)
		require.False(t, called, "state-changing handler ran for a cross-scheme Origin")
	})

	t.Run("ipv6 cross-port origin does not run the handler", func(t *testing.T) {
		t.Parallel()
		rr, called := serveCSRF(t, csrfRequest{
			method: http.MethodPost,
			target: "/api/user/using/2",
			host:   "[::1]:3000",
			origin: "http://[::1]:8443",
			cookie: true,
			appURL: "http://[::1]:3000/",
		})
		require.Equal(t, http.StatusForbidden, rr.Code)
		require.False(t, called, "state-changing handler ran for a cross-port IPv6 Origin")
	})

	t.Run("trusted forwarding header ignores a differing port", func(t *testing.T) {
		t.Parallel()
		rr, called := serveCSRF(t, csrfRequest{
			method:            http.MethodPost,
			target:            "/api/user/using/2",
			host:              "internal.grafana.svc:3000",
			origin:            "http://grafana.example.com:8443",
			cookie:            true,
			forwardedHost:     "grafana.example.com:3000",
			additionalHeaders: "X-Forwarded-Host",
		})
		require.Equal(t, http.StatusForbidden, rr.Code)
		require.False(t, called, "state-changing handler ran when only the forwarding header hostname matched")
	})

	t.Run("same scheme host and port still runs the handler", func(t *testing.T) {
		t.Parallel()
		rr, called := serveCSRF(t, csrfRequest{
			method: http.MethodPost,
			target: "/api/user/using/2",
			host:   "grafana.example.com:3000",
			origin: serverOrigin,
			cookie: true,
		})
		require.Equal(t, http.StatusOK, rr.Code)
		require.True(t, called)
	})

	t.Run("implicit http port matches an explicit port", func(t *testing.T) {
		t.Parallel()
		rr, called := serveCSRF(t, csrfRequest{
			method: http.MethodPost,
			target: "/api/user/using/2",
			host:   "grafana.example.com:80",
			origin: "http://grafana.example.com",
			cookie: true,
			appURL: "http://grafana.example.com/",
		})
		require.Equal(t, http.StatusOK, rr.Code)
		require.True(t, called)
	})

	t.Run("different host stays forbidden", func(t *testing.T) {
		t.Parallel()
		rr, called := serveCSRF(t, csrfRequest{
			method: http.MethodPost,
			target: "/api/user/using/2",
			host:   "grafana.example.com:3000",
			origin: "http://evil.example:3000",
			cookie: true,
		})
		require.Equal(t, http.StatusForbidden, rr.Code)
		require.False(t, called)
	})
}

type csrfRequest struct {
	method            string
	target            string
	host              string
	origin            string
	cookie            bool
	appURL            string
	forwardedHost     string
	additionalHeaders string
}

// serveCSRF sends a request through the same web middleware chain HTTPServer uses:
// the CSRF middleware is registered before the route handler, and a rejection must
// leave the handler uncalled.
func serveCSRF(t *testing.T, in csrfRequest) (*httptest.ResponseRecorder, bool) {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.LoginCookieName = sessionCookieName
	cfg.AppURL = serverOrigin + "/"
	if in.appURL != "" {
		cfg.AppURL = in.appURL
	}
	if in.additionalHeaders != "" {
		section, err := cfg.Raw.NewSection("security")
		require.NoError(t, err)
		_, err = section.NewKey("csrf_additional_headers", in.additionalHeaders)
		require.NoError(t, err)
	}

	called := false
	m := web.New()
	m.UseMiddleware(ProvideCSRFFilter(cfg).Middleware())
	m.Any("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(in.method, in.target, nil)
	req.Host = in.host
	req.Header.Set("Origin", in.origin)
	if in.forwardedHost != "" {
		req.Header.Set("X-Forwarded-Host", in.forwardedHost)
	}
	if in.cookie {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "placeholder-session"})
	}

	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	return rr, called
}
