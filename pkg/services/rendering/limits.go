package rendering

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/grafana/grafana/pkg/infra/metrics"
)

func (rs *RenderingService) maxTimeout() time.Duration {
	if rs.Cfg.RendererMaxTimeout > 0 {
		return rs.Cfg.RendererMaxTimeout
	}
	return DefaultMaxTimeout
}

func (rs *RenderingService) maxResponseSize() int64 {
	if rs.Cfg.RendererMaxResponseSize > 0 {
		return rs.Cfg.RendererMaxResponseSize
	}
	return DefaultMaxResponseSize
}

// requestTimeout is the deadline of the HTTP call to the renderer, which is how long a render holds its slot.
func (rs *RenderingService) requestTimeout(opts TimeoutOpts) time.Duration {
	return min(getRequestTimeout(opts), 2*rs.maxTimeout())
}

// boundCommonOpts caps the caller-controlled timeout, including the copy carried in the callback path.
func (rs *RenderingService) boundCommonOpts(opts CommonOpts) (CommonOpts, error) {
	maxTimeout := rs.maxTimeout()
	if opts.Timeout <= 0 || opts.Timeout > maxTimeout {
		opts.Timeout = maxTimeout
	}

	path, err := boundPathQuery(opts.Path, maxTimeout)
	if err != nil {
		return opts, err
	}
	opts.Path = path
	return opts, nil
}

func (rs *RenderingService) boundOpts(opts Opts) (Opts, error) {
	common, err := rs.boundCommonOpts(opts.CommonOpts)
	if err != nil {
		return opts, err
	}
	opts.CommonOpts = common

	opts.Width = min(opts.Width, MaxImageWidth)
	opts.Height = min(opts.Height, MaxImageHeight)
	if opts.Height < 0 {
		// -1 is the only negative height the renderer understands: it requests a full-page render.
		opts.Height = -1
	}

	if math.IsInf(opts.DeviceScaleFactor, 0) || math.IsNaN(opts.DeviceScaleFactor) || opts.DeviceScaleFactor <= 0 {
		opts.DeviceScaleFactor = 1
	}
	opts.DeviceScaleFactor = min(opts.DeviceScaleFactor, MaxDeviceScaleFactor)
	return opts, nil
}

// boundPathQuery caps the timeout and viewport parameters of the callback path, which
// is opened by the renderer, to the same limits as the options sent to the renderer.
// The path is returned unchanged when every value is already within the limits.
func boundPathQuery(path string, maxTimeout time.Duration) (string, error) {
	base, rawQuery, ok := strings.Cut(path, "?")
	if !ok {
		return path, nil
	}

	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", fmt.Errorf("invalid render path query: %w", err)
	}

	limits := []struct {
		key   string
		limit float64
	}{
		{"timeout", math.Floor(maxTimeout.Seconds())},
		{"width", MaxImageWidth},
		{"height", MaxImageHeight},
		{"scale", MaxDeviceScaleFactor},
	}

	changed := false
	for _, l := range limits {
		values := query[l.key]
		for i, v := range values {
			n, err := strconv.ParseFloat(v, 64)
			if err == nil && !math.IsNaN(n) && n <= l.limit {
				continue
			}
			values[i] = strconv.FormatFloat(l.limit, 'f', -1, 64)
			changed = true
		}
	}

	if !changed {
		return path, nil
	}
	return base + "?" + query.Encode(), nil
}

func (rs *RenderingService) inProgressCounter(budget ConcurrencyBudget) *atomic.Int32 {
	if budget == AlertingConcurrencyBudget {
		return &rs.alertingInProgressCount
	}
	return &rs.inProgressCount
}

// acquireSlot counts the render against its concurrency budget and reports whether the
// budget's limit still allows it. The returned release function must always be called.
func (rs *RenderingService) acquireSlot(opts CommonOpts) (func(), bool) {
	counter := rs.inProgressCounter(opts.ConcurrencyBudget)
	count := counter.Add(1)
	rs.updateQueueMetric()

	release := func() {
		counter.Add(-1)
		rs.updateQueueMetric()
	}
	return release, opts.ConcurrentLimit <= 0 || int(count) <= opts.ConcurrentLimit
}

func (rs *RenderingService) updateQueueMetric() {
	metrics.MRenderingQueue.Set(float64(rs.inProgressCount.Load() + rs.alertingInProgressCount.Load()))
}
