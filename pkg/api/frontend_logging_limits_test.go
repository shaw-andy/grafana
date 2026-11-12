package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/frontendlogging"
	httpstatic "github.com/grafana/grafana/pkg/api/static"
	glog "github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// One request may resolve at most this many stack frames, across every
// exception in the body. The accepted body must stay far below web.MaxBindBodyBytes.
const (
	maxResolvedFramesPerRequest = 32
	maxFrontendLogBodyBytes     = 1 << 20
	framesPerAttackRequest      = 200
	attackExceptions            = 40
	framesPerAttackException    = 5
)

func TestFrontendLogDefaultsAreOff(t *testing.T) {
	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: "../../",
		Config:   "../../conf/defaults.ini",
	}))
	require.False(t, cfg.GrafanaJavascriptAgent.Enabled)
	require.Equal(t, 3, cfg.GrafanaJavascriptAgent.EndpointRPS)
	require.Equal(t, 15, cfg.GrafanaJavascriptAgent.EndpointBurst)
}

func TestFrontendLogEndpoint_DisabledIgnoresBody(t *testing.T) {
	rec, logs, nextCalled := postFrontendLog(t, false, agentEvent(oneBundleFrames(1)))
	require.Equal(t, http.StatusAccepted, rec.Code)
	require.Zero(t, strings.Count(logs, "some_source.ts"))
	require.False(t, nextCalled)
}

func TestFrontendLogEndpoint_UnauthenticatedRequestResolvesOneFrame(t *testing.T) {
	rec, logs, nextCalled := postFrontendLog(t, true, agentEvent(oneBundleFrames(1)))
	require.Equal(t, http.StatusAccepted, rec.Code)
	require.Equal(t, 1, strings.Count(logs, "some_source.ts"))
	require.NotContains(t, rec.Body.String(), "auth")
	require.False(t, nextCalled, "request reached the middleware registered after frontend log ingestion")
}

func TestFrontendLogEndpoint_OneRequestDoesNotResolveEveryFrame(t *testing.T) {
	// Forty exceptions of five frames stay under a per-exception cap of 32,
	// so the limit has to cover the whole request. Each filename is the same
	// real bundle with a distinct query string. The shipped rate limit is 3
	// requests per second with a burst of 15, and this is a single request.
	var event frontendlogging.FrontendGrafanaJavascriptAgentEvent
	event.Exceptions = make([]frontendlogging.Exception, attackExceptions)
	for exceptionIdx := range event.Exceptions {
		frames := make([]frontendlogging.Frame, framesPerAttackException)
		for frameIdx := range frames {
			n := exceptionIdx*framesPerAttackException + frameIdx
			frames[frameIdx] = frontendlogging.Frame{
				Function: "fn",
				Filename: fmt.Sprintf("http://grafana.example/public/build/foo.js?uniq=%d", n),
				Lineno:   2,
				Colno:    5,
			}
		}
		event.Exceptions[exceptionIdx] = frontendlogging.Exception{
			Type:       "Error",
			Value:      "boom",
			Timestamp:  time.Unix(0, 0).UTC(),
			Stacktrace: &frontendlogging.Stacktrace{Frames: frames},
		}
	}

	rec, logs, nextCalled := postFrontendLog(t, true, event)
	require.NotEqual(t, http.StatusTooManyRequests, rec.Code)
	require.NotEqual(t, http.StatusUnauthorized, rec.Code)
	require.NotEqual(t, http.StatusForbidden, rec.Code)
	require.False(t, nextCalled)
	require.LessOrEqual(t, strings.Count(logs, "some_source.ts"), maxResolvedFramesPerRequest)
}

func TestFrontendLogEndpoint_RejectsOversizedBodyBeforeParsing(t *testing.T) {
	event := agentEvent(oneBundleFrames(1))
	event.Logs = []frontendlogging.Log{{
		Message:   strings.Repeat("a", maxFrontendLogBodyBytes+64<<10),
		LogLevel:  frontendlogging.LogLevelInfo,
		Timestamp: time.Unix(0, 0).UTC(),
	}}

	body := mustJSON(t, event)
	require.Greater(t, len(body), maxFrontendLogBodyBytes)

	rec, logs, nextCalled := postFrontendLogRaw(t, true, body)
	require.Zero(t, strings.Count(logs, "some_source.ts"), "source map parsed before the oversized body was refused")
	require.GreaterOrEqual(t, rec.Code, 400)
	require.Less(t, rec.Code, 500)
	require.False(t, nextCalled)
}

func TestFrontendLogHandler_DistinctFilesAreCappedPerRequest(t *testing.T) {
	var discard strings.Builder
	captureFrontendLogs(t, &discard)

	mapBytes, err := os.ReadFile(filepath.Join("frontendlogging", "test-data", "foo.js.map"))
	require.NoError(t, err)
	staticRoot := t.TempDir()
	for i := 0; i < framesPerAttackRequest; i++ {
		path := filepath.Join(staticRoot, "build", fmt.Sprintf("file-%d.js.map", i))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, mapBytes, 0o644))
	}

	var reads int
	store := frontendlogging.NewSourceMapStore(&setting.Cfg{StaticRootPath: staticRoot}, &fakePluginStaticRouteResolver{}, func(dir, path string) ([]byte, error) {
		reads++
		return frontendlogging.ReadSourceMapFromFS(dir, path)
	})
	handler := GrafanaJavascriptAgentLogMessageHandler(store)

	frames := make([]frontendlogging.Frame, framesPerAttackRequest)
	for i := range frames {
		frames[i] = frontendlogging.Frame{
			Function: "fn",
			Filename: fmt.Sprintf("http://grafana.example/public/build/file-%d.js", i),
			Lineno:   2,
			Colno:    5,
		}
	}

	m := web.New()
	m.Post("/log-grafana-javascript-agent", func(c *web.Context) {
		handler(&HTTPServer{log: glog.NewNopLogger()}, c)
	})
	req := httptest.NewRequest(http.MethodPost, "/log-grafana-javascript-agent", bytes.NewReader(mustJSON(t, agentEvent(frames))))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	require.LessOrEqual(t, reads, maxResolvedFramesPerRequest)
}

func postFrontendLog(t *testing.T, enabled bool, event frontendlogging.FrontendGrafanaJavascriptAgentEvent) (*httptest.ResponseRecorder, string, bool) {
	t.Helper()
	return postFrontendLogRaw(t, enabled, mustJSON(t, event))
}

func postFrontendLogRaw(t *testing.T, enabled bool, body []byte) (*httptest.ResponseRecorder, string, bool) {
	t.Helper()

	staticRoot := t.TempDir()
	mapBytes, err := os.ReadFile(filepath.Join("frontendlogging", "test-data", "foo.js.map"))
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(staticRoot, "build"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(staticRoot, "build", "foo.js.map"), mapBytes, 0o644))

	cfg := setting.NewCfg()
	cfg.StaticRootPath = staticRoot
	cfg.LoginCookieName = "grafana_session"
	cfg.GrafanaJavascriptAgent.Enabled = enabled
	// Shipped defaults from readGrafanaJavascriptAgentConfig.
	cfg.GrafanaJavascriptAgent.EndpointRPS = 3
	cfg.GrafanaJavascriptAgent.EndpointBurst = 15

	var logs strings.Builder
	captureFrontendLogs(t, &logs)

	hs := &HTTPServer{
		Cfg:                       cfg,
		log:                       glog.NewNopLogger(),
		pluginStaticRouteResolver: &fakePluginStaticRouteResolver{},
		Csrf:                      csrf.ProvideCSRFFilter(cfg),
	}

	var nextCalled bool
	m := web.New()
	m.UseMiddleware(hs.Csrf.Middleware())
	m.Use(httpstatic.Static(filepath.Join(staticRoot, "build"), httpstatic.StaticOptions{Prefix: "public/build"}))
	m.Use(hs.frontendLogEndpoints())
	m.Use(func(c *web.Context) {
		nextCalled = true
		c.Resp.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(c.Resp, "auth")
	})
	m.NotFound(func(c *web.Context) {
		if !c.Resp.Written() {
			c.Resp.WriteHeader(http.StatusUnauthorized)
		}
	})

	req := httptest.NewRequest(http.MethodPost, "/log-grafana-javascript-agent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Hide the length so a check of the header alone cannot see the size.
	req.ContentLength = -1
	req.Header.Del("Content-Length")
	req.Header.Set("Origin", "https://attacker.example")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)
	return rec, logs.String(), nextCalled
}

func agentEvent(frames []frontendlogging.Frame) frontendlogging.FrontendGrafanaJavascriptAgentEvent {
	return frontendlogging.FrontendGrafanaJavascriptAgentEvent{
		Exceptions: []frontendlogging.Exception{{
			Type:       "Error",
			Value:      "boom",
			Timestamp:  time.Unix(0, 0).UTC(),
			Stacktrace: &frontendlogging.Stacktrace{Frames: frames},
		}},
	}
}

func oneBundleFrames(n int) []frontendlogging.Frame {
	frames := make([]frontendlogging.Frame, n)
	for i := range frames {
		frames[i] = frontendlogging.Frame{
			Function: "fn",
			Filename: "http://grafana.example/public/build/foo.js",
			Lineno:   2,
			Colno:    5,
		}
	}
	return frames
}

func mustJSON(t *testing.T, event frontendlogging.FrontendGrafanaJavascriptAgentEvent) []byte {
	t.Helper()
	body, err := json.Marshal(event)
	require.NoError(t, err)
	return body
}

func captureFrontendLogs(t *testing.T, dst io.Writer) {
	t.Helper()
	orig := frontendLogger.GetLogger()
	frontendLogger.Swap(level.NewFilter(log.LoggerFunc(func(keyvals ...any) error {
		for i := 0; i+1 < len(keyvals); i += 2 {
			key, ok := keyvals[i].(string)
			if !ok || key != "stacktrace" {
				continue
			}
			_, _ = io.WriteString(dst, fmt.Sprint(keyvals[i+1]))
			_, _ = io.WriteString(dst, "\n")
		}
		return nil
	}), level.AllowAll()))
	t.Cleanup(func() {
		frontendLogger.Swap(orig)
	})
}
