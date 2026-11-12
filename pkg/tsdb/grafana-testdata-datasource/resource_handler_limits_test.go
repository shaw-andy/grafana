package testdatasource

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"
)

// Bounds the /stream resource must enforce. CallResource is the entry the
// datasource resource API uses after it copies the query string through, so
// these tests are the contract for that loop: oversized spans and sub-millisecond
// speeds are refused before any stream line is written, and cancelling the
// request context stops a stream the client is still accepting.

const (
	maxAcceptedStreamCount = 1000
	minAcceptedStreamSpeed = time.Millisecond
)

func TestStreamResourceAllowsBoundedRequest(t *testing.T) {
	t.Parallel()

	body, status, err := callStream(context.Background(), "count=3&speed=10ms", false)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "Message #1\nMessage #2\nMessage #3\n", body)
}

func TestStreamResourceRefusesUnboundedInput(t *testing.T) {
	t.Parallel()

	// Each query is one the handler accepts today and then loops over.
	// count=1001 is the first inclusive span above maxAcceptedStreamCount
	// (start defaults to 1). Speeds below minAcceptedStreamSpeed parse as
	// durations and then sleep for a zero or negligible time.
	cases := []struct {
		name  string
		query string
	}{
		{name: "attack count and zero speed", query: "count=2000000000&speed=0s"},
		{name: "attack count json", query: "count=2000000000&speed=0s&format=json"},
		{name: "attack count influx", query: "count=2000000000&speed=0s&format=influx"},
		{name: "count above cap", query: "count=1001&speed=10ms"},
		{name: "count above cap json", query: "count=1001&speed=10ms&format=json"},
		{name: "count above cap influx", query: "count=1001&speed=10ms&format=influx"},
		{name: "count above cap without flush", query: "count=1001&speed=10ms&flush=0"},
		{name: "span above cap", query: "start=-1&count=1000&speed=10ms"},
		{name: "full integer span", query: "start=-9223372036854775808&count=9223372036854775807&speed=10ms"},
		{name: "zero speed", query: "count=5&speed=0s"},
		{name: "zero speed without unit", query: "count=5&speed=0"},
		{name: "negative speed", query: "count=5&speed=-1s"},
		{name: "negative milliseconds", query: "count=5&speed=-5ms"},
		{name: "nanosecond speed", query: "count=5&speed=1ns"},
		{name: "microsecond speed", query: "count=5&speed=1us"},
		{name: "sub millisecond speed", query: "count=5&speed=500us"},
		{name: "json zero speed", query: "count=5&speed=0s&format=json"},
		{name: "influx zero speed", query: "count=5&speed=0s&format=influx"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sender := &recordingSender{blockOnSuccess: true}
			done := make(chan error, 1)
			go func() {
				done <- ProvideService().CallResource(context.Background(), streamResourceRequest(tc.query), sender)
			}()

			select {
			case err := <-done:
				body, status := sender.snapshot()
				require.NoError(t, err)
				require.GreaterOrEqual(t, status, 400, "query %s body %q", tc.query, body)
				require.Less(t, status, 500, "query %s body %q", tc.query, body)
				require.NotContains(t, body, "Message #")
				require.NotContains(t, body, `"message"`)
				require.NotContains(t, body, "measurement,")
				require.Less(t, len(body), 512, "refusal wrote a stream body: %q", body)
			case <-time.After(2 * time.Second):
				body, status := sender.snapshot()
				t.Fatalf("stream handler kept running for %s (status %d, body %q); an inclusive span above %d or a speed below %s must be refused before any stream line is written", tc.query, status, body, maxAcceptedStreamCount, minAcceptedStreamSpeed)
			}
		})
	}
}

func TestStreamResourceStopsWhenRequestContextIsCanceled(t *testing.T) {
	t.Parallel()

	// count=30 at 100ms is inside the caps above (3s if it runs to completion).
	// The sender keeps accepting chunks, which is the connection staying open
	// from the handler's point of view. Cancelling the context is what the
	// HTTP server does when the client goes away; the loop has to notice.
	for _, format := range []string{"", "json", "influx"} {
		t.Run(formatName(format), func(t *testing.T) {
			t.Parallel()

			query := "count=30&speed=100ms"
			if format != "" {
				query += "&format=" + format
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sender := &signalingSender{started: make(chan struct{})}
			svc := ProvideService()
			done := make(chan error, 1)
			go func() {
				done <- svc.CallResource(ctx, streamResourceRequest(query), sender)
			}()

			select {
			case <-sender.started:
			case err := <-done:
				body, status := sender.snapshot()
				t.Fatalf("bounded stream returned before a chunk (status %d, err %v, body %q); count=30 speed=100ms must be accepted", status, err, body)
			case <-time.After(2 * time.Second):
				t.Fatal("bounded stream produced no output")
			}

			cancel()

			select {
			case err := <-done:
				require.NoError(t, err)
				body, status := sender.snapshot()
				require.Equal(t, http.StatusOK, status)
				require.Less(t, strings.Count(body, "\n"), 30, "handler kept iterating after the request context was canceled: %q", body)
			case <-time.After(750 * time.Millisecond):
				body, status := sender.snapshot()
				t.Fatalf("handler still running 750ms after cancel (status %d, lines so far %d)", status, strings.Count(body, "\n"))
			}
		})
	}
}

func formatName(format string) string {
	if format == "" {
		return "plain"
	}
	return format
}

func streamResourceRequest(rawQuery string) *backend.CallResourceRequest {
	// Same shape pluginResourceRequest builds: the wildcard path plus the
	// original raw query, then URL.String() passed to CallResource.
	u := &url.URL{Path: "stream", RawQuery: rawQuery}
	return &backend.CallResourceRequest{
		PluginContext: backend.PluginContext{},
		Path:          u.Path,
		Method:        http.MethodGet,
		URL:           u.String(),
	}
}

func callStream(ctx context.Context, rawQuery string, blockOnSuccess bool) (string, int, error) {
	sender := &recordingSender{blockOnSuccess: blockOnSuccess}
	err := ProvideService().CallResource(ctx, streamResourceRequest(rawQuery), sender)
	body, status := sender.snapshot()
	return body, status, err
}

// recordingSender accepts every chunk. When blockOnSuccess is set, the first
// successful stream body parks the handler inside Send. The park is never
// released: resuming it would let a missing limit run for an attacker-chosen
// count. A handler that refuses does not park, because it does not write a
// 200 body.
type recordingSender struct {
	mu             sync.Mutex
	body           strings.Builder
	status         int
	blockOnSuccess bool
	blocked        bool
}

func (s *recordingSender) Send(resp *backend.CallResourceResponse) error {
	if resp == nil {
		return nil
	}

	s.mu.Lock()
	if resp.Status != 0 {
		s.status = resp.Status
	}
	s.body.Write(resp.Body)
	block := s.blockOnSuccess && s.status >= 200 && s.status < 300 && s.body.Len() > 0 && !s.blocked
	if block {
		s.blocked = true
	}
	s.mu.Unlock()

	if block {
		<-make(chan struct{})
	}
	return nil
}

func (s *recordingSender) snapshot() (string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.body.String(), s.status
}

// signalingSender records the response and closes started on the first body
// bytes, without ever returning an error. Writes succeeding is the stand-in
// for a client that is still reading.
type signalingSender struct {
	mu      sync.Mutex
	body    strings.Builder
	status  int
	started chan struct{}
	once    sync.Once
}

func (s *signalingSender) Send(resp *backend.CallResourceResponse) error {
	if resp == nil {
		return nil
	}
	s.mu.Lock()
	if resp.Status != 0 {
		s.status = resp.Status
	}
	s.body.Write(resp.Body)
	n := s.body.Len()
	s.mu.Unlock()
	if n > 0 {
		s.once.Do(func() { close(s.started) })
	}
	return nil
}

func (s *signalingSender) snapshot() (string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.body.String(), s.status
}
