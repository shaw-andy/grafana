package rendering

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
)

// Bounds a fix must enforce. Keep these identical to the handler tests in
// pkg/api/render_limits_attack_test.go. The HTTP client deadline is the
// timeout multiplied by two (getRequestTimeout).
const (
	maxAcceptedRenderTimeout   = 60 * time.Second
	maxAcceptedImageWidth      = 8192
	maxAcceptedImageHeight     = 8192
	maxAcceptedImageScale      = 4.0
	maxAcceptedRenderBodyBytes = 8 << 20
)

func TestRenderServiceCallerTimeoutAndViewportAreBounded(t *testing.T) {
	h := newServiceHarness(t)
	_, err := h.rs.Render(context.Background(), RenderPNG, Opts{
		CommonOpts: CommonOpts{
			Path:            "d-solo/abc/my-dash?timeout=86400&width=100000000&height=100000000&scale=1000000",
			TimeoutOpts:     TimeoutOpts{Timeout: 24 * time.Hour},
			ConcurrentLimit: 30,
			AuthOpts:        AuthOpts{OrgID: 1, UserID: 42, OrgRole: identity.RoleViewer},
		},
		Width:             100000000,
		Height:            100000000,
		DeviceScaleFactor: 1000000,
	})
	assertServiceBoundedOrRejected(t, h, err)
	require.Equal(t, int32(0), h.rs.inProgressCount.Load())
	h.assertNoOversizedFiles(t)
}

func TestRenderServiceCSVTimeoutIsBounded(t *testing.T) {
	h := newServiceHarness(t)
	_, err := h.rs.RenderCSV(context.Background(), CSVOpts{
		CommonOpts: CommonOpts{
			Path:            "d/csv-export?timeout=86400",
			TimeoutOpts:     TimeoutOpts{Timeout: 24 * time.Hour},
			ConcurrentLimit: 30,
			AuthOpts:        AuthOpts{OrgID: 1, UserID: 42, OrgRole: identity.RoleViewer},
		},
	})
	assertServiceBoundedOrRejected(t, h, err)
	require.Equal(t, int32(0), h.rs.inProgressCount.Load())
	h.assertNoOversizedFiles(t)
}

func TestRenderServiceResponseBodyIsCapped(t *testing.T) {
	const extra = 64 << 10
	for _, rt := range []RenderType{RenderPNG, RenderCSV} {
		t.Run(string(rt), func(t *testing.T) {
			h := newServiceHarness(t)
			h.streamBytes.Store(int64(maxAcceptedRenderBodyBytes + extra))
			var err error
			if rt == RenderCSV {
				_, err = h.rs.RenderCSV(context.Background(), CSVOpts{
					CommonOpts: CommonOpts{
						Path:            "d/csv-export",
						TimeoutOpts:     TimeoutOpts{Timeout: 30 * time.Second},
						ConcurrentLimit: 30,
						AuthOpts:        AuthOpts{OrgID: 1, UserID: 42, OrgRole: identity.RoleViewer},
					},
				})
			} else {
				_, err = h.rs.Render(context.Background(), RenderPNG, Opts{
					CommonOpts: CommonOpts{
						Path:            "d-solo/abc/my-dash",
						TimeoutOpts:     TimeoutOpts{Timeout: 30 * time.Second},
						ConcurrentLimit: 30,
						AuthOpts:        AuthOpts{OrgID: 1, UserID: 42, OrgRole: identity.RoleViewer},
					},
					Width:             800,
					Height:            600,
					DeviceScaleFactor: 1,
				})
			}
			_ = err
			h.assertNoOversizedFiles(t)
		})
	}
}

func TestRenderServiceInRangeTimeoutReachesRenderer(t *testing.T) {
	h := newServiceHarness(t)
	result, err := h.rs.Render(context.Background(), RenderPNG, Opts{
		CommonOpts: CommonOpts{
			Path:            "d-solo/abc/my-dash?timeout=45&width=800&height=600&scale=2",
			TimeoutOpts:     TimeoutOpts{Timeout: 45 * time.Second},
			ConcurrentLimit: 30,
			AuthOpts:        AuthOpts{OrgID: 1, UserID: 42, OrgRole: identity.RoleViewer},
		},
		Width:             800,
		Height:            600,
		DeviceScaleFactor: 2,
	})
	require.NoError(t, err)
	require.NotEmpty(t, result.FilePath)
	calls := h.snapshot()
	require.Len(t, calls, 1)
	require.Equal(t, "45", calls[0].timeout)
	require.Equal(t, "800", calls[0].width)
	require.Equal(t, "600", calls[0].height)
	scale, err := strconv.ParseFloat(calls[0].scale, 64)
	require.NoError(t, err)
	require.InDelta(t, 2, scale, 0.001)
	require.True(t, calls[0].hasDeadline)
	remain := time.Until(calls[0].deadline)
	require.Greater(t, remain, 40*time.Second)
	require.LessOrEqual(t, remain, maxAcceptedRenderTimeout*2+2*time.Second)
}

type observedCall struct {
	timeout         string
	width           string
	height          string
	scale           string
	callbackTimeout string
	callbackWidth   string
	callbackHeight  string
	callbackScale   string
	hasDeadline     bool
	deadline        time.Time
}

type serviceHarness struct {
	cfg          *setting.Cfg
	rs           *RenderingService
	streamBytes  atomic.Int64
	sawOversized atomic.Bool

	mu    sync.Mutex
	calls []observedCall
}

func newServiceHarness(t *testing.T) *serviceHarness {
	t.Helper()
	h := &serviceHarness{}
	renderer := httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(renderer.Close)

	data := t.TempDir()
	cfg := setting.NewCfg()
	cfg.Env = setting.Dev
	cfg.Protocol = setting.HTTPScheme
	cfg.AppURL = "http://grafana.example/"
	cfg.RendererServerUrl = renderer.URL + "/render"
	cfg.RendererCallbackUrl = "http://grafana.example/"
	cfg.RendererAuthToken = "test-renderer-token"
	cfg.RendererConcurrentRequestLimit = 30
	cfg.RendererRenderKeyLifeTime = 5 * time.Minute
	cfg.ImagesDir = filepath.Join(data, "png")
	cfg.PDFsDir = filepath.Join(data, "pdf")
	cfg.CSVsDir = filepath.Join(data, "csv")

	rs, err := ProvideService(cfg, featuremgmt.WithFeatures(featuremgmt.FlagRenderAuthJWT), nil)
	require.NoError(t, err)
	rs.renderAction = rs.renderViaHTTP
	rs.renderCSVAction = rs.renderCSVViaHTTP
	rs.version = "3.12.0"
	rs.netClient.Transport = &recordingTransport{base: rs.netClient.Transport, h: h}
	h.cfg = cfg
	h.rs = rs

	stop := make(chan struct{})
	go h.watch(stop)
	t.Cleanup(func() { close(stop) })
	return h
}

func (h *serviceHarness) serve(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", `attachment; filename="panel.csv"`)
	w.WriteHeader(http.StatusOK)
	if remaining := int(h.streamBytes.Load()); remaining > 0 {
		buf := make([]byte, 32<<10)
		for remaining > 0 {
			n := min(remaining, len(buf))
			_, _ = w.Write(buf[:n])
			remaining -= n
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
		}
		return
	}
	_, _ = w.Write([]byte("png"))
}

func (h *serviceHarness) snapshot() []observedCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]observedCall, len(h.calls))
	copy(out, h.calls)
	return out
}

func (h *serviceHarness) watch(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if h.dirsExceedCap() {
				h.sawOversized.Store(true)
			}
		}
	}
}

func (h *serviceHarness) dirsExceedCap() bool {
	for _, dir := range []string{h.cfg.ImagesDir, h.cfg.PDFsDir, h.cfg.CSVsDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err == nil && info.Size() > maxAcceptedRenderBodyBytes {
				return true
			}
		}
	}
	return false
}

func (h *serviceHarness) assertNoOversizedFiles(t *testing.T) {
	t.Helper()
	require.False(t, h.sawOversized.Load() || h.dirsExceedCap(), "renderer response stored past the size cap")
}

func assertServiceBoundedOrRejected(t *testing.T, h *serviceHarness, err error) {
	t.Helper()
	calls := h.snapshot()
	if len(calls) == 0 {
		require.Error(t, err)
		return
	}
	for _, call := range calls {
		assertAtMostInt(t, call.timeout, int(maxAcceptedRenderTimeout.Seconds()))
		assertAtMostInt(t, call.width, maxAcceptedImageWidth)
		assertAtMostInt(t, call.height, maxAcceptedImageHeight)
		assertAtMostFloat(t, call.scale, maxAcceptedImageScale)
		assertAtMostInt(t, call.callbackTimeout, int(maxAcceptedRenderTimeout.Seconds()))
		assertAtMostInt(t, call.callbackWidth, maxAcceptedImageWidth)
		assertAtMostInt(t, call.callbackHeight, maxAcceptedImageHeight)
		assertAtMostFloat(t, call.callbackScale, maxAcceptedImageScale)
		require.True(t, call.hasDeadline, "renderer request has no deadline")
		remain := time.Until(call.deadline)
		require.LessOrEqual(t, remain, maxAcceptedRenderTimeout*2+2*time.Second, "deadline follows caller timeout")
	}
}

type recordingTransport struct {
	base http.RoundTripper
	h    *serviceHarness
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	q := req.URL.Query()
	call := observedCall{
		timeout: q.Get("timeout"),
		width:   q.Get("width"),
		height:  q.Get("height"),
		scale:   q.Get("deviceScaleFactor"),
	}
	if d, ok := req.Context().Deadline(); ok {
		call.hasDeadline = true
		call.deadline = d
	}
	if parsed, err := url.Parse(q.Get("url")); err == nil {
		cq := parsed.Query()
		call.callbackTimeout = cq.Get("timeout")
		call.callbackWidth = cq.Get("width")
		call.callbackHeight = cq.Get("height")
		call.callbackScale = cq.Get("scale")
	}
	t.h.mu.Lock()
	t.h.calls = append(t.h.calls, call)
	t.h.mu.Unlock()
	return t.base.RoundTrip(req)
}

func assertAtMostInt(t *testing.T, raw string, max int) {
	t.Helper()
	if raw == "" {
		return
	}
	n, err := strconv.Atoi(raw)
	require.NoError(t, err)
	require.LessOrEqual(t, n, max)
}

func assertAtMostFloat(t *testing.T, raw string, max float64) {
	t.Helper()
	if raw == "" {
		return
	}
	n, err := strconv.ParseFloat(raw, 64)
	require.NoError(t, err)
	require.LessOrEqual(t, n, max)
}
