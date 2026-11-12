package middleware

import (
	"crypto/subtle"
	"net/http"

	"github.com/grafana/grafana/pkg/setting"
)

// MetricsScrapeAuthorized reports whether req may read the metrics endpoints.
// Empty [metrics] basic-auth settings leave the endpoints closed rather than
// open, so a scrape is only served when both are configured and req presents
// matching credentials.
func MetricsScrapeAuthorized(cfg *setting.Cfg, req *http.Request) bool {
	if !cfg.MetricsEndpointEnabled {
		return false
	}

	expectedUser := cfg.MetricsEndpointBasicAuthUsername
	expectedPass := cfg.MetricsEndpointBasicAuthPassword
	if expectedUser == "" || expectedPass == "" {
		return false
	}

	user, pass, ok := req.BasicAuth()
	if !ok {
		return false
	}

	userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(expectedUser))
	passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(expectedPass))
	return userMatch&passMatch == 1
}

// WriteMetricsUnauthorized writes the response for a refused metrics scrape.
func WriteMetricsUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Grafana"`)
	w.WriteHeader(http.StatusUnauthorized)
}

// MetricsScrapeHandler serves next only to requests MetricsScrapeAuthorized
// accepts. It responds 404 when the metrics endpoint is disabled.
func MetricsScrapeHandler(cfg *setting.Cfg, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cfg.MetricsEndpointEnabled {
			http.NotFound(w, r)
			return
		}
		if !MetricsScrapeAuthorized(cfg, r) {
			WriteMetricsUnauthorized(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}
