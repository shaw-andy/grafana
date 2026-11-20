package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/server"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// faroIngestKeyPlaceholder is a stand-in for the operator-configured
// [log.frontend] api_key. Tests compare against this name only.
const faroIngestKeyPlaceholder = "placeholder-faro-ingest-key"

const faroCollectorURL = "https://collector.example.test/collect"

// Public responses that embed frontend settings. Each one is served without
// a login check, and each one renders the same settings object.
var publicSettingsPaths = []string{
	"/bootdata",
	"/login",
	"/invite/placeholder-code",
	"/dashboard-solo/snapshot/placeholder",
	"/bootdata/00000000-0000-4000-8000-000000000001",
	"/public-dashboards/00000000-0000-4000-8000-000000000001",
}

// TestIntegrationFrontendLoggingKeyOmittedWhenDisabled fails while [log.frontend]
// api_key is copied into boot data and the other public pages even though
// frontend logging is off. It passes once that value is cleared whenever
// enabled is false.
func TestIntegrationFrontendLoggingKeyOmittedWhenDisabled(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	addr := startGrafanaWithFrontendLogging(t, false)

	for _, path := range publicSettingsPaths {
		t.Run("anonymous "+path, func(t *testing.T) {
			status, body := getNoRedirect(t, addr, path, nil)
			require.Equalf(t, http.StatusOK, status, "body: %s", truncate(body, 500))
			assertFaroKeyAbsent(t, body, false)
		})
	}

	t.Run("unauthenticated frontend settings", func(t *testing.T) {
		status, body := getNoRedirect(t, addr, "/api/frontend/settings/", nil)
		require.Equalf(t, http.StatusUnauthorized, status, "body: %s", truncate(body, 500))
		require.NotContains(t, body, faroIngestKeyPlaceholder)
	})
}

// TestIntegrationFrontendLoggingKeyOmittedWhenDisabledForSignedIn covers the
// same settings object on the authenticated index page and /api/frontend/settings.
func TestIntegrationFrontendLoggingKeyOmittedWhenDisabledForSignedIn(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	addr, env := startGrafanaWithFrontendLoggingEnv(t, false)
	testinfra.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		Login:    "viewer",
		Password: "test",
		Email:    "viewer@example.test",
	})
	session := loginUser(t, addr, "viewer", "test")

	for _, path := range []string{"/api/frontend/settings/", "/"} {
		t.Run(path, func(t *testing.T) {
			status, body := getNoRedirect(t, addr, path, session)
			require.Equalf(t, http.StatusOK, status, "body: %s", truncate(body, 500))
			assertFaroKeyAbsent(t, body, false)
		})
	}
}

// TestIntegrationFrontendLoggingKeyPresentWhenEnabled documents the browser
// ingest path: with frontend logging on, the same public responses must still
// carry the key and collector URL the Faro agent sends.
func TestIntegrationFrontendLoggingKeyPresentWhenEnabled(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	addr := startGrafanaWithFrontendLogging(t, true)

	for _, path := range publicSettingsPaths {
		t.Run(path, func(t *testing.T) {
			status, body := getNoRedirect(t, addr, path, nil)
			require.Equalf(t, http.StatusOK, status, "body: %s", truncate(body, 500))
			assertFaroKeyPresent(t, body)
		})
	}
}

func startGrafanaWithFrontendLogging(t *testing.T, enabled bool) string {
	t.Helper()
	addr, _ := startGrafanaWithFrontendLoggingEnv(t, enabled)
	return addr
}

func startGrafanaWithFrontendLoggingEnv(t *testing.T, enabled bool) (string, *server.TestEnv) {
	t.Helper()
	grafDir, cfgPath := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{
		DisableAnonymous: true,
	})
	writeFrontendLoggingConfig(t, cfgPath, enabled)
	return testinfra.StartGrafanaEnv(t, grafDir, cfgPath)
}

func writeFrontendLoggingConfig(t *testing.T, cfgPath string, enabled bool) {
	t.Helper()
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, f.Close())
	}()
	_, err = fmt.Fprintf(f, `
[log.frontend]
enabled = %t
custom_endpoint = %s
api_key = %s
`, enabled, faroCollectorURL, faroIngestKeyPlaceholder)
	require.NoError(t, err)
}

func getNoRedirect(t *testing.T, addr, path string, session *http.Cookie) (int, string) {
	t.Helper()

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s%s", addr, path), nil)
	require.NoError(t, err)
	if session != nil {
		req.AddCookie(session)
	}

	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
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
	require.Truef(t, ok, "response did not include grafanaJavascriptAgent: %s", truncate(body, 500))
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
