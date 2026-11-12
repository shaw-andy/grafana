package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/grafana/pkg/setting"
)

func TestMetricsScrapeHandler(t *testing.T) {
	const (
		user = "metrics-user"
		pass = "metrics-password"
	)

	tests := []struct {
		desc           string
		enabled        bool
		cfgUser        string
		cfgPass        string
		reqUser        string
		reqPass        string
		sendBasicAuth  bool
		expectedStatus int
	}{
		{desc: "disabled endpoint", enabled: false, cfgUser: user, cfgPass: pass, reqUser: user, reqPass: pass, sendBasicAuth: true, expectedStatus: http.StatusNotFound},
		{desc: "basic auth not configured", enabled: true, expectedStatus: http.StatusUnauthorized},
		{desc: "basic auth not configured, empty credentials sent", enabled: true, sendBasicAuth: true, expectedStatus: http.StatusUnauthorized},
		{desc: "only username configured", enabled: true, cfgUser: user, reqUser: user, sendBasicAuth: true, expectedStatus: http.StatusUnauthorized},
		{desc: "only password configured", enabled: true, cfgPass: pass, reqPass: pass, sendBasicAuth: true, expectedStatus: http.StatusUnauthorized},
		{desc: "no credentials sent", enabled: true, cfgUser: user, cfgPass: pass, expectedStatus: http.StatusUnauthorized},
		{desc: "wrong password", enabled: true, cfgUser: user, cfgPass: pass, reqUser: user, reqPass: "wrong", sendBasicAuth: true, expectedStatus: http.StatusUnauthorized},
		{desc: "wrong username", enabled: true, cfgUser: user, cfgPass: pass, reqUser: "wrong", reqPass: pass, sendBasicAuth: true, expectedStatus: http.StatusUnauthorized},
		{desc: "matching credentials", enabled: true, cfgUser: user, cfgPass: pass, reqUser: user, reqPass: pass, sendBasicAuth: true, expectedStatus: http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			cfg := &setting.Cfg{
				MetricsEndpointEnabled:           tc.enabled,
				MetricsEndpointBasicAuthUsername: tc.cfgUser,
				MetricsEndpointBasicAuthPassword: tc.cfgPass,
			}
			served := false
			handler := MetricsScrapeHandler(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				served = true
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tc.sendBasicAuth {
				req.SetBasicAuth(tc.reqUser, tc.reqPass)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			assert.Equal(t, tc.expectedStatus, recorder.Code)
			assert.Equal(t, tc.expectedStatus == http.StatusOK, served)
		})
	}
}
