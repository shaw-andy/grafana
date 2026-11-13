package azuremonitor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"

	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/types"
)

// maxAzureResourceResponseBytes is the most of an upstream body a resource
// call may buffer. 32MiB is the ceiling already used for Azure Monitor metrics
// batch responses. These tests fail while resource routes read past it.
const maxAzureResourceResponseBytes int64 = 32 << 20

const oversizedUpstreamBytes = maxAzureResourceResponseBytes + 2<<20

func TestAzureMonitorResourceRoutesDoNotBufferOversizedUpstream(t *testing.T) {
	t.Run("azure monitor", func(t *testing.T) {
		assertOversizedResourceRejected(t, http.MethodGet, "azuremonitor/subscriptions/sub", nil, false)
	})
	t.Run("log analytics", func(t *testing.T) {
		assertOversizedResourceRejected(t, http.MethodPost, "loganalytics/v1/workspaces/ws/query", []byte(`{"query":"traces"}`), false)
	})
	t.Run("resource graph", func(t *testing.T) {
		assertOversizedResourceRejected(t, http.MethodPost, "resourcegraph/providers/Microsoft.ResourceGraph/resources", []byte(`{"query":"resources"}`), false)
	})
	t.Run("log analytics metadata", func(t *testing.T) {
		assertOversizedResourceRejected(t, http.MethodGet, "loganalytics/workspaces/ws/metadata", nil, false)
	})
	t.Run("log analytics basic logs usage", func(t *testing.T) {
		assertOversizedResourceRejected(t, http.MethodPost, "loganalytics/usage/basiclogs", logsUsageBody(), false)
	})
	t.Run("azure monitor chunked", func(t *testing.T) {
		assertOversizedResourceRejected(t, http.MethodGet, "azuremonitor/subscriptions/sub", nil, true)
	})
	t.Run("parallel azure monitor calls", func(t *testing.T) {
		const calls = 2
		servers := make([]*httptest.Server, calls)
		clients := make([]*http.Client, calls)
		counts := make([]*atomic.Int64, calls)
		hits := make([]*atomic.Int32, calls)
		for i := 0; i < calls; i++ {
			counts[i] = &atomic.Int64{}
			hits[i] = &atomic.Int32{}
			servers[i], clients[i] = oversizedServer(t, counts[i], hits[i], false)
		}
		services := make([]*Service, calls)
		for i := 0; i < calls; i++ {
			services[i] = resourceService(t, servers[i], clients[i])
		}

		errCh := make(chan error, calls)
		var wg sync.WaitGroup
		wg.Add(calls)
		for i := 0; i < calls; i++ {
			go func(i int) {
				defer wg.Done()
				errCh <- callOversized(services[i], http.MethodGet, "azuremonitor/subscriptions/sub", nil, counts[i], hits[i])
			}(i)
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			require.NoError(t, err)
		}
	})
}

func TestAzureMonitorResourceRoutesProxySmallUpstream(t *testing.T) {
	body := []byte(`{"ok":true}`)
	for _, tc := range []struct {
		name   string
		method string
		path   string
		req    []byte
	}{
		{name: "azure monitor", method: http.MethodGet, path: "azuremonitor/subscriptions/sub"},
		{name: "log analytics", method: http.MethodPost, path: "loganalytics/v1/workspaces/ws/query", req: []byte(`{"query":"traces"}`)},
		{name: "resource graph", method: http.MethodPost, path: "resourcegraph/providers/Microsoft.ResourceGraph/resources", req: []byte(`{"query":"resources"}`)},
		{name: "log analytics metadata", method: http.MethodGet, path: "loganalytics/workspaces/ws/metadata"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := body
			if tc.name == "log analytics metadata" {
				upstream = []byte(`{}`)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(upstream)
			}))
			t.Cleanup(srv.Close)

			resp := callResource(t, resourceService(t, srv, srv.Client()), tc.method, tc.path, tc.req)
			require.Equal(t, http.StatusOK, resp.Status)
			if tc.name == "log analytics metadata" {
				require.NotEmpty(t, resp.Body)
				require.Less(t, len(resp.Body), 64*1024)
				return
			}
			require.Equal(t, string(upstream), string(resp.Body))
		})
	}
}

func TestShippedDataProxyResponseLimitCapsBodies(t *testing.T) {
	t.Setenv("GF_DATAPROXY_RESPONSE_LIMIT", "")

	shipped := loadGrafanaConfig(t, readDefaultsINI(t))
	withoutKey := loadGrafanaConfig(t, stripResponseLimit(t, readDefaultsINI(t)))

	for _, tc := range []struct {
		name string
		cfg  *setting.Cfg
	}{
		{name: "defaults.ini", cfg: shipped},
		{name: "response_limit key absent", cfg: withoutKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Length", strconv.FormatInt(oversizedUpstreamBytes, 10))
				_, _ = io.Copy(w, io.LimitReader(repeatReader('a'), oversizedUpstreamBytes))
			}))
			t.Cleanup(srv.Close)

			// Same middleware the shared data-proxy client installs from cfg.ResponseLimit.
			provider := httpclient.NewProvider(httpclient.ProviderOptions{
				Middlewares: []httpclient.Middleware{
					httpclient.ResponseLimitMiddleware(tc.cfg.ResponseLimit),
				},
			})
			client, err := provider.New()
			require.NoError(t, err)
			base := client.Transport
			client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				res, err := base.RoundTrip(req)
				if err != nil || res == nil || res.Body == nil {
					return res, err
				}
				res.Body = &countingReadCloser{ReadCloser: res.Body, n: &got}
				return res, nil
			})

			req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
			require.NoError(t, err)
			res, err := client.Do(req)
			require.NoError(t, err)
			t.Cleanup(func() { _ = res.Body.Close() })

			_, readErr := io.ReadAll(res.Body)
			require.Greater(t, tc.cfg.ResponseLimit, int64(0))
			require.LessOrEqual(t, tc.cfg.ResponseLimit, maxAzureResourceResponseBytes)
			require.ErrorIs(t, readErr, httpclient.ErrResponseBodyTooLarge)
			require.LessOrEqual(t, got.Load(), tc.cfg.ResponseLimit+1)
		})
	}
}

func assertOversizedResourceRejected(t *testing.T, method, path string, reqBody []byte, chunked bool) {
	t.Helper()
	got := &atomic.Int64{}
	hits := &atomic.Int32{}
	srv, client := oversizedServer(t, got, hits, chunked)
	require.NoError(t, callOversized(resourceService(t, srv, client), method, path, reqBody, got, hits))
}

func oversizedServer(t *testing.T, got *atomic.Int64, hits *atomic.Int32, chunked bool) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if chunked {
			// Flush before the rest of the body so the size is not declared up front.
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		} else {
			w.Header().Set("Content-Length", strconv.FormatInt(oversizedUpstreamBytes, 10))
		}
		_, _ = io.Copy(w, jsonStringReader(oversizedUpstreamBytes))
	}))
	t.Cleanup(srv.Close)

	client := srv.Client()
	base := client.Transport
	client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		res, err := base.RoundTrip(req)
		if err != nil || res == nil || res.Body == nil {
			return res, err
		}
		res.Body = &countingReadCloser{ReadCloser: res.Body, n: got}
		return res, nil
	})
	return srv, client
}

func callOversized(s *Service, method, path string, reqBody []byte, got *atomic.Int64, hits *atomic.Int32) error {
	sender := &captureSender{}
	if err := s.CallResource(context.Background(), &backend.CallResourceRequest{
		Path:   path,
		Method: method,
		URL:    path,
		Body:   reqBody,
	}, sender); err != nil {
		return err
	}
	if sender.resp == nil || hits.Load() < 1 {
		return fmt.Errorf("%w: hits=%d", errResourceNotCalled, hits.Load())
	}
	if got.Load() > maxAzureResourceResponseBytes+1 {
		return fmt.Errorf("%w: read %d bytes, status %d, caller body %d bytes", errUpstreamBuffered, got.Load(), sender.resp.Status, sender.body.Len())
	}
	if sender.resp.Status < 400 || sender.resp.Status >= 600 {
		return fmt.Errorf("%w: status %d, read %d bytes", errStatusNotRejected, sender.resp.Status, got.Load())
	}
	if sender.body.Len() >= 64*1024 {
		return fmt.Errorf("%w: caller body %d bytes", errBodyCopied, sender.body.Len())
	}
	return nil
}

var (
	errResourceNotCalled = errString("resource route did not read an upstream response")
	errUpstreamBuffered  = errString("upstream response was buffered past the cap")
	errStatusNotRejected = errString("oversized upstream response was not rejected")
	errBodyCopied        = errString("oversized upstream response was copied to the caller")
)

type errString string

func (e errString) Error() string { return string(e) }

func resourceService(t *testing.T, srv *httptest.Server, client *http.Client) *Service {
	t.Helper()
	s := ProvideService(httpclient.NewProvider())
	svc := types.DatasourceService{URL: srv.URL, HTTPClient: client, Logger: log.DefaultLogger}
	s.im = &fakeInstance{services: map[string]types.DatasourceService{
		azureMonitor:       svc,
		azureLogAnalytics:  svc,
		azureResourceGraph: svc,
	}}
	return s
}

type captureSender struct {
	mu   sync.Mutex
	resp *backend.CallResourceResponse
	body bytes.Buffer
}

func (c *captureSender) Send(resp *backend.CallResourceResponse) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.resp == nil {
		copied := *resp
		c.resp = &copied
	}
	_, _ = c.body.Write(resp.Body)
	return nil
}

func callResource(t *testing.T, s *Service, method, path string, body []byte) *backend.CallResourceResponse {
	t.Helper()
	sender := &captureSender{}
	err := s.CallResource(context.Background(), &backend.CallResourceRequest{
		Path:   path,
		Method: method,
		URL:    path,
		Body:   body,
	}, sender)
	require.NoError(t, err)
	require.NotNil(t, sender.resp)
	sender.resp.Body = append([]byte(nil), sender.body.Bytes()...)
	return sender.resp
}

func logsUsageBody() []byte {
	return []byte(`{"table":"AppTraces","resource":"workspace","queryType":"Azure Log Analytics","from":"0","to":"1000"}`)
}

func readDefaultsINI(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../conf/defaults.ini")
	require.NoError(t, err)
	return raw
}

func stripResponseLimit(t *testing.T, raw []byte) []byte {
	t.Helper()
	re := regexp.MustCompile(`(?m)^response_limit\s*=.*\n`)
	out := re.ReplaceAll(raw, nil)
	require.NotContains(t, string(out), "response_limit")
	require.NotEqual(t, string(raw), string(out))
	return out
}

func loadGrafanaConfig(t *testing.T, raw []byte) *setting.Cfg {
	t.Helper()
	cfg, err := setting.NewCfgFromBytes(raw)
	require.NoError(t, err)
	return cfg
}

// jsonStringReader emits a JSON string of exactly n bytes: a quote, fill, and
// a closing quote. Log Analytics usage decodes the upstream body as JSON, so
// the payload has to be one complete value or the decoder stops early.
func jsonStringReader(n int64) io.Reader {
	if n < 2 {
		return bytes.NewReader([]byte(`""`))
	}
	return io.MultiReader(
		bytes.NewReader([]byte{'"'}),
		io.LimitReader(repeatReader('a'), n-2),
		bytes.NewReader([]byte{'"'}),
	)
}

type repeatReader byte

func (r repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

type countingReadCloser struct {
	io.ReadCloser
	n *atomic.Int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
