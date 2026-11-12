package prometheus

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	sdkhttpclient "github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/apps/dashvalidator/pkg/cache"
	"github.com/grafana/grafana/apps/dashvalidator/pkg/validator"
	"github.com/grafana/grafana/pkg/services/datasources"
)

// maxMetricNamesResponseBytes is the most of a Prometheus
// /api/v1/label/__name__/values body FetchMetrics may buffer.
//
// 32 MiB covers the large metric lists this package already plans for
// (on the order of 1e5–5e5 names) and stops one check from holding an
// unbounded payload. The cap is the fetcher's own limit: it applies when
// the data-proxy response limit is 0, which is the shipped default and
// disables grafana-plugin-sdk-go's ResponseLimitMiddleware, and it still
// applies when that middleware is configured with a higher limit.
// Hitting the cap must return an error. Partial names must not be
// returned or cached.
const maxMetricNamesResponseBytes int64 = 32 << 20

const (
	metricListPrefix = `{"status":"success","data":["`
	metricListSuffix = `"]}`
)

// metricListBody streams a valid Prometheus label-values document of
// exactly total bytes. The single metric name is filled with 'm'.
type metricListBody struct {
	total int64
	off   int64
	read  int64
}

func newMetricListBody(total int64) *metricListBody {
	min := int64(len(metricListPrefix) + len(metricListSuffix) + 1)
	if total < min {
		panic("metric list body shorter than a one-character name")
	}
	return &metricListBody{total: total}
}

func (b *metricListBody) Read(p []byte) (int, error) {
	if b.off >= b.total {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if int64(len(p)) > b.total-b.off {
		p = p[:b.total-b.off]
	}

	prefixLen := int64(len(metricListPrefix))
	suffixAt := b.total - int64(len(metricListSuffix))
	n := 0
	for n < len(p) {
		pos := b.off + int64(n)
		switch {
		case pos < prefixLen:
			end := prefixLen
			if end > b.off+int64(len(p)) {
				end = b.off + int64(len(p))
			}
			n += copy(p[n:], metricListPrefix[pos:end])
		case pos >= suffixAt:
			n += copy(p[n:], metricListSuffix[pos-suffixAt:])
		default:
			end := suffixAt
			if end > b.off+int64(len(p)) {
				end = b.off + int64(len(p))
			}
			fill := int(end - pos)
			for i := 0; i < fill; i++ {
				p[n+i] = 'm'
			}
			n += fill
		}
	}
	b.off += int64(n)
	b.read += int64(n)
	if b.off >= b.total {
		return n, io.EOF
	}
	return n, nil
}

func (b *metricListBody) Close() error { return nil }

// upstream is the Prometheus response the datasource HTTP client returns.
// contentLength -1 is a chunked response with no length header.
type upstream struct {
	calls         int
	path          string
	body          io.ReadCloser
	contentLength int64
}

func (u *upstream) RoundTrip(req *http.Request) (*http.Response, error) {
	u.calls++
	u.path = req.URL.Path
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Header:        make(http.Header),
		Body:          u.body,
		ContentLength: u.contentLength,
		Request:       req,
	}, nil
}

// clientWithDataProxyLimit builds the same response-limit middleware the
// datasource HTTP provider installs, in front of upstream.
// GF_DATAPROXY_RESPONSE_LIMIT is pinned to 0 so an ambient env value cannot
// turn the middleware on. A limit argument of 0 matches conf/defaults.ini.
func clientWithDataProxyLimit(t *testing.T, limit int64, next http.RoundTripper) *http.Client {
	t.Helper()
	t.Setenv("GF_DATAPROXY_RESPONSE_LIMIT", "0")
	rt := sdkhttpclient.ResponseLimitMiddleware(limit).CreateMiddleware(sdkhttpclient.Options{}, next)
	return &http.Client{Transport: rt, Timeout: 30 * time.Second}
}

func TestMetricListBody_IsValidPrometheusDocument(t *testing.T) {
	for _, total := range []int64{
		int64(len(metricListPrefix) + len(metricListSuffix) + 1),
		int64(len(metricListPrefix) + len(metricListSuffix) + 64),
	} {
		body := newMetricListBody(total)
		raw, err := io.ReadAll(body)
		require.NoError(t, err)
		require.Len(t, raw, int(total))
		require.Equal(t, total, body.read)

		var parsed prometheusResponse
		require.NoError(t, json.Unmarshal(raw, &parsed))
		require.Equal(t, "success", parsed.Status)
		require.Len(t, parsed.Data, 1)
		require.Len(t, parsed.Data[0], int(total)-len(metricListPrefix)-len(metricListSuffix))
	}
}

func TestFetchMetrics_DefaultDataProxyLimit_RejectsOversizedMetricList(t *testing.T) {
	const overflow = int64(1 << 20)
	body := newMetricListBody(maxMetricNamesResponseBytes + overflow)
	up := &upstream{body: body, contentLength: -1}
	client := clientWithDataProxyLimit(t, 0, up)

	metrics, err := NewFetcher().FetchMetrics(context.Background(), "prom-ds", "http://prometheus.example", client)

	require.Equal(t, "/api/v1/label/__name__/values", up.path)
	require.Error(t, err)
	require.Empty(t, metrics)
	// The read must stop at the cap. MaxBytesReader consumes one extra
	// byte to detect the overflow; reading the rest of the payload is
	// the bug.
	require.LessOrEqual(t, body.read, maxMetricNamesResponseBytes+1)
	require.Less(t, body.read, body.total)
}

func TestFetchMetrics_DefaultDataProxyLimit_AllowsMetricListAtCap(t *testing.T) {
	body := newMetricListBody(maxMetricNamesResponseBytes)
	up := &upstream{body: body, contentLength: body.total}
	client := clientWithDataProxyLimit(t, 0, up)

	metrics, err := NewFetcher().FetchMetrics(context.Background(), "prom-ds", "http://prometheus.example", client)

	require.NoError(t, err)
	require.Len(t, metrics, 1)
	require.Len(t, metrics[0], int(maxMetricNamesResponseBytes)-len(metricListPrefix)-len(metricListSuffix))
	require.Equal(t, body.total, body.read)
}

func TestFetchMetrics_HighDataProxyLimit_StillRejectsOversizedMetricList(t *testing.T) {
	body := newMetricListBody(maxMetricNamesResponseBytes + (1 << 20))
	up := &upstream{body: body, contentLength: body.total}
	// A data-proxy limit above the metric-list cap must not widen it.
	client := clientWithDataProxyLimit(t, maxMetricNamesResponseBytes*4, up)

	metrics, err := NewFetcher().FetchMetrics(context.Background(), "prom-ds", "http://prometheus.example", client)

	require.Error(t, err)
	require.Empty(t, metrics)
	require.LessOrEqual(t, body.read, maxMetricNamesResponseBytes+1)
	require.Less(t, body.read, body.total)
}

func TestMetricsCache_OversizedMetricList_IsNotRetained(t *testing.T) {
	body := newMetricListBody(maxMetricNamesResponseBytes + (1 << 20))
	up := &upstream{body: body, contentLength: -1}
	client := clientWithDataProxyLimit(t, 0, up)

	metricsCache := cache.NewMetricsCache()
	metricsCache.RegisterProvider(datasources.DS_PROMETHEUS, NewPrometheusProvider(cache.DefaultMetricsCacheTTL))
	require.Equal(t, 5*time.Minute, cache.DefaultMetricsCacheTTL)

	ctx := context.Background()
	const uid = "prom-ds"
	metrics, err := metricsCache.GetMetrics(ctx, 1, datasources.DS_PROMETHEUS, uid, "http://prometheus.example", client)
	require.Error(t, err)
	require.Empty(t, metrics)
	require.Equal(t, 1, up.calls)
	require.LessOrEqual(t, body.read, maxMetricNamesResponseBytes+1)

	// A later check for the same datasource must hit Prometheus again.
	// Caching the oversized body, or a prefix of it, fails this.
	followUp := []byte(`{"status":"success","data":["up"]}`)
	up.body = &namedBody{raw: followUp}
	up.contentLength = int64(len(followUp))

	got, err := metricsCache.GetMetrics(ctx, 1, datasources.DS_PROMETHEUS, uid, "http://prometheus.example", client)
	require.NoError(t, err)
	require.Equal(t, []string{"up"}, got)
	require.Equal(t, 2, up.calls)

	set, err := metricsCache.GetMetricsSet(ctx, 1, datasources.DS_PROMETHEUS, uid, "http://prometheus.example", client)
	require.NoError(t, err)
	require.Equal(t, map[string]bool{"up": true}, set)
	// The legal list is kept as both the slice and the lookup map.
	require.Equal(t, 2, up.calls)
}

func TestValidateQueries_OversizedMetricList_ErrorsAndDoesNotCache(t *testing.T) {
	body := newMetricListBody(maxMetricNamesResponseBytes + (1 << 20))
	up := &upstream{body: body, contentLength: -1}
	client := clientWithDataProxyLimit(t, 0, up)

	metricsCache := cache.NewMetricsCache()
	metricsCache.RegisterProvider(datasources.DS_PROMETHEUS, NewPrometheusProvider(cache.DefaultMetricsCacheTTL))
	v := NewValidator(metricsCache)

	ctx := context.Background()
	ds := validator.Datasource{
		UID:        "prom-ds",
		Type:       datasources.DS_PROMETHEUS,
		URL:        "http://prometheus.example",
		HTTPClient: client,
		OrgID:      1,
	}
	queries := []validator.Query{{
		RefID:     "A",
		QueryText: "up",
	}}

	result, err := v.ValidateQueries(ctx, queries, ds)
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, 1, up.calls)
	require.LessOrEqual(t, body.read, maxMetricNamesResponseBytes+1)
	require.Less(t, body.read, body.total)

	up.body = &namedBody{raw: []byte(`{"status":"success","data":["up"]}`)}
	up.contentLength = int64(len(`{"status":"success","data":["up"]}`))

	result, err = v.ValidateQueries(ctx, queries, ds)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, 1, result.FoundMetrics)
	require.Empty(t, result.MissingMetrics)
	require.Equal(t, 2, up.calls)
}

// namedBody is the small follow-up Prometheus document used after an
// oversized response has been refused.
type namedBody struct {
	raw []byte
	off int
}

func (b *namedBody) Read(p []byte) (int, error) {
	if b.off >= len(b.raw) {
		return 0, io.EOF
	}
	n := copy(p, b.raw[b.off:])
	b.off += n
	if b.off >= len(b.raw) {
		return n, io.EOF
	}
	return n, nil
}

func (b *namedBody) Close() error { return nil }
