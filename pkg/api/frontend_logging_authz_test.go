package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	gokitlog "github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/frontendlogging"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/middleware/loggermw"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// placeholderIngestSecret is an obvious placeholder for log.frontend.api_key.
// The ingest tests never send this value.
const placeholderIngestSecret = "placeholder-ingest-secret"

func TestFrontendLogIngestRejectsUnauthenticatedWrites(t *testing.T) {
	// Faro logging is off unless an operator turns it on. These cases are the
	// enabled server: a client that presents no session and no matching ingest
	// secret must be rejected before any frontend log line is written.
	markers := []string{
		"attacker-error-line",
		"attacker-warn-line",
		"attacker-info-line",
		"attacker-debug-line",
		"attacker-trace-line",
		"attacker-default-line",
		"attacker-measurement",
		"attacker-exception-value",
		"attacker-batch-",
		"attacker-large-",
	}

	t.Run("enabled without credentials", func(t *testing.T) {
		srv, lines := newFrontendLogServer(t, frontendLogServerOpts{
			enabled: true,
			apiKey:  placeholderIngestSecret,
		})
		for _, tc := range []struct {
			name    string
			target  string
			remote  string
			headers map[string]string
			body    any
		}{
			{
				name:    "logs exceptions and measurements from a cookieless client",
				target:  grafanaJavascriptAgentEndpointPath,
				remote:  "203.0.113.10:4242",
				headers: map[string]string{"Origin": "https://evil.example"},
				body:    attackerFrontendEvent(),
			},
			{
				name:   "second client address is not covered by another client's budget",
				target: grafanaJavascriptAgentEndpointPath,
				remote: "203.0.113.11:4242",
				body:   attackerFrontendEvent(),
			},
			{
				name:   "unrecognized session cookie",
				target: grafanaJavascriptAgentEndpointPath,
				remote: "203.0.113.12:4242",
				headers: map[string]string{
					"Cookie": "grafana_session=placeholder-session",
				},
				body: attackerFrontendEvent(),
			},
			{
				name:   "wrong ingest header",
				target: grafanaJavascriptAgentEndpointPath,
				remote: "203.0.113.13:4242",
				headers: map[string]string{
					// Header name the Faro FetchTransport uses for its apiKey option.
					"x-api-key": "placeholder-wrong-secret",
				},
				body: attackerFrontendEvent(),
			},
			{
				name:   "authorization header is not a session",
				target: grafanaJavascriptAgentEndpointPath,
				remote: "203.0.113.14:4242",
				headers: map[string]string{
					"Authorization": "Bearer placeholder-token",
				},
				body: attackerFrontendEvent(),
			},
			{
				name:   "many entries in one body",
				target: grafanaJavascriptAgentEndpointPath,
				remote: "203.0.113.15:4242",
				body:   attackerBatchEvent(30),
			},
			{
				name:   "large log message",
				target: grafanaJavascriptAgentEndpointPath,
				remote: "203.0.113.16:4242",
				body: frontendlogging.FrontendGrafanaJavascriptAgentEvent{
					Logs: []frontendlogging.Log{{
						Message:  "attacker-large-" + strings.Repeat("A", 64*1024),
						LogLevel: frontendlogging.LogLevelError,
					}},
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				before := len(lines.snapshot())
				rec := postFrontendLog(t, srv, tc.target, tc.remote, tc.headers, tc.body)
				written := lines.snapshot()[before:]
				assertRejectedBeforeWrite(t, rec, written, markers)
			})
		}
	})

	t.Run("enabled with empty ingest secret", func(t *testing.T) {
		srv, lines := newFrontendLogServer(t, frontendLogServerOpts{enabled: true})
		rec := postFrontendLog(t, srv, grafanaJavascriptAgentEndpointPath, "203.0.113.20:4242", nil, attackerFrontendEvent())
		assertRejectedBeforeWrite(t, rec, lines.snapshot(), markers)
	})

	t.Run("enabled behind subpath", func(t *testing.T) {
		srv, lines := newFrontendLogServer(t, frontendLogServerOpts{
			enabled:          true,
			apiKey:           placeholderIngestSecret,
			serveFromSubPath: true,
			appSubURL:        "/grafana",
		})
		rec := postFrontendLog(t, srv, "/grafana"+grafanaJavascriptAgentEndpointPath, "203.0.113.21:4242", map[string]string{
			"Origin": "https://evil.example",
		}, attackerFrontendEvent())
		assertRejectedBeforeWrite(t, rec, lines.snapshot(), markers)
	})

	t.Run("disabled writes nothing", func(t *testing.T) {
		srv, lines := newFrontendLogServer(t, frontendLogServerOpts{enabled: false})
		_ = postFrontendLog(t, srv, grafanaJavascriptAgentEndpointPath, "203.0.113.22:4242", nil, attackerFrontendEvent())
		joined := strings.Join(lines.snapshot(), "\n")
		for _, marker := range markers {
			assert.NotContains(t, joined, marker)
		}
	})
}

func assertRejectedBeforeWrite(t *testing.T, rec *httptest.ResponseRecorder, written []string, markers []string) {
	t.Helper()
	joined := strings.Join(written, "\n")
	for _, marker := range markers {
		if strings.Contains(joined, marker) {
			t.Errorf("frontend logger wrote attacker marker %q before the request was refused", marker)
		}
	}
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Errorf("unauthenticated ingest status = %d, want 401 or 403", rec.Code)
	}
	if len(written) != 0 {
		t.Errorf("frontend logger was called %d times for an unauthenticated request", len(written))
	}
}

func attackerFrontendEvent() frontendlogging.FrontendGrafanaJavascriptAgentEvent {
	return frontendlogging.FrontendGrafanaJavascriptAgentEvent{
		Logs: []frontendlogging.Log{
			{Message: "attacker-error-line", LogLevel: frontendlogging.LogLevelError},
			{Message: "attacker-warn-line", LogLevel: frontendlogging.LogLevelWarning},
			{Message: "attacker-info-line", LogLevel: frontendlogging.LogLevelInfo},
			{Message: "attacker-debug-line", LogLevel: frontendlogging.LogLevelDebug},
			{Message: "attacker-trace-line", LogLevel: frontendlogging.LogLevelTrace},
			{Message: "attacker-default-line", LogLevel: "notice"},
		},
		Measurements: []frontendlogging.Measurement{{
			Type:   "attacker-measurement",
			Values: map[string]float64{"CLS": 1},
		}},
		Exceptions: []frontendlogging.Exception{{
			Type:  "AttackerException",
			Value: "attacker-exception-value",
			Stacktrace: &frontendlogging.Stacktrace{
				Frames: []frontendlogging.Frame{{
					Function: "boom",
					Filename: "https://evil.example/stack.js",
					Lineno:   1,
					Colno:    1,
				}},
			},
		}},
	}
}

func attackerBatchEvent(n int) frontendlogging.FrontendGrafanaJavascriptAgentEvent {
	logs := make([]frontendlogging.Log, n)
	for i := range logs {
		logs[i] = frontendlogging.Log{
			Message:  fmt.Sprintf("attacker-batch-%d", i),
			LogLevel: frontendlogging.LogLevelError,
		}
	}
	return frontendlogging.FrontendGrafanaJavascriptAgentEvent{Logs: logs}
}

type frontendLogServerOpts struct {
	enabled          bool
	apiKey           string
	serveFromSubPath bool
	appSubURL        string
}

func newFrontendLogServer(t *testing.T, opts frontendLogServerOpts) (*web.Mux, *logCapture) {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.LoginCookieName = "grafana_session"
	cfg.StaticRootPath = t.TempDir()
	cfg.ServeFromSubPath = opts.serveFromSubPath
	cfg.AppSubURL = opts.appSubURL
	cfg.GrafanaJavascriptAgent.Enabled = opts.enabled
	cfg.GrafanaJavascriptAgent.EndpointRPS = 3
	cfg.GrafanaJavascriptAgent.EndpointBurst = 15
	cfg.GrafanaJavascriptAgent.ApiKey = opts.apiKey

	features := featuremgmt.WithFeatures()
	hs := &HTTPServer{
		log:              log.New("test"),
		web:              web.New(),
		Cfg:              cfg,
		Features:         features,
		tracer:           tracing.NewNoopTracerService(),
		promRegister:     prometheus.NewRegistry(),
		LoggerMiddleware: loggermw.Provide(cfg, features),
		License:          &licensing.OSSLicensingService{Cfg: cfg},
		Csrf:             csrf.ProvideCSRFFilter(cfg),
		ContextHandler: contexthandler.ProvideService(cfg, &authntest.FakeService{
			ExpectedErr: errors.New("unauthenticated"),
		}, features),
	}
	hs.addMiddlewaresAndStaticRoutes()

	capture := &logCapture{}
	original := frontendLogger.GetLogger()
	frontendLogger.Swap(gokitlog.LoggerFunc(capture.Log))
	t.Cleanup(func() {
		frontendLogger.Swap(original)
	})

	return hs.web, capture
}

type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (c *logCapture) Log(keyvals ...any) error {
	var b strings.Builder
	for _, kv := range keyvals {
		b.WriteString(fmt.Sprint(kv))
		b.WriteByte('\n')
	}
	c.mu.Lock()
	c.lines = append(c.lines, b.String())
	c.mu.Unlock()
	return nil
}

func (c *logCapture) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.lines))
	copy(out, c.lines)
	return out
}

func postFrontendLog(t *testing.T, srv http.Handler, target, remote string, headers map[string]string, body any) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remote
	for k, v := range headers {
		if strings.EqualFold(k, "Cookie") {
			req.Header.Set("Cookie", v)
			continue
		}
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}
