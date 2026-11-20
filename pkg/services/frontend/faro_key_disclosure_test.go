package frontend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/hooks"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// faroIngestKeyPlaceholder is a stand-in for the operator-configured
// [log.frontend] api_key. Tests compare against this name only.
const faroIngestKeyPlaceholder = "placeholder-faro-ingest-key"

const faroCollectorURL = "https://collector.example.test/collect"

// TestFrontendServiceFaroKeyOmittedWhenLoggingDisabled fails while the
// frontend service copies [log.frontend] api_key into the public index HTML
// with frontend logging disabled.
func TestFrontendServiceFaroKeyOmittedWhenLoggingDisabled(t *testing.T) {
	body := renderFrontendIndex(t, false, "/")
	assertFaroKeyAbsent(t, body, false)

	login := renderFrontendIndex(t, false, "/login")
	assertFaroKeyAbsent(t, login, false)
}

// TestFrontendServiceFaroKeyPresentWhenLoggingEnabled keeps the browser ingest
// path: with frontend logging on, the public index still includes the key.
func TestFrontendServiceFaroKeyPresentWhenLoggingEnabled(t *testing.T) {
	body := renderFrontendIndex(t, true, "/")
	assertFaroKeyPresent(t, body)
}

func renderFrontendIndex(t *testing.T, enabled bool, path string) string {
	t.Helper()

	publicDir := setupTestWebAssets(t)
	cfg := &setting.Cfg{
		Raw:            ini.Empty(),
		HTTPPort:       "3000",
		StaticRootPath: publicDir,
		BuildVersion:   "10.3.0",
		GrafanaJavascriptAgent: setting.GrafanaJavascriptAgent{
			Enabled:        enabled,
			ApiKey:         faroIngestKeyPlaceholder,
			CustomEndpoint: faroCollectorURL,
		},
	}

	promRegister := prometheus.NewRegistry()
	service, err := ProvideFrontendService(
		cfg,
		featuremgmt.WithFeatures(),
		promRegister,
		promRegister,
		&licensing.OSSLicensingService{},
		hooks.ProvideService(),
	)
	require.NoError(t, err)

	mux := web.New()
	service.addMiddlewares(mux)
	service.registerRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, path, nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	return recorder.Body.String()
}

func assertFaroKeyAbsent(t *testing.T, body string, wantEnabled bool) {
	t.Helper()
	agent, ok := grafanaJavascriptAgent(t, body)
	require.True(t, ok, "response did not include grafanaJavascriptAgent")
	require.Equal(t, wantEnabled, agent["enabled"])
	require.Equal(t, faroCollectorURL, agent["customEndpoint"])
	got := agentString(agent, "apiKey")
	echoed := strings.Contains(body, faroIngestKeyPlaceholder)
	if got != "" || echoed {
		t.Fatalf("frontend logging api_key was disclosed while enabled=%v (apiKey set=%t, value echoed in body=%t)", agent["enabled"], got != "", echoed)
	}
}

func assertFaroKeyPresent(t *testing.T, body string) {
	t.Helper()
	agent, ok := grafanaJavascriptAgent(t, body)
	require.True(t, ok, "response did not include grafanaJavascriptAgent")
	require.Equal(t, true, agent["enabled"])
	require.Equal(t, faroCollectorURL, agent["customEndpoint"])
	require.Equal(t, faroIngestKeyPlaceholder, agentString(agent, "apiKey"))
}

func grafanaJavascriptAgent(t *testing.T, body string) (map[string]any, bool) {
	t.Helper()
	const marker = `"grafanaJavascriptAgent":`
	idx := strings.Index(body, marker)
	if idx < 0 {
		return nil, false
	}
	dec := json.NewDecoder(strings.NewReader(body[idx+len(marker):]))
	var obj map[string]any
	require.NoError(t, dec.Decode(&obj))
	return obj, true
}

func agentString(agent map[string]any, key string) string {
	value, _ := agent[key].(string)
	return value
}
