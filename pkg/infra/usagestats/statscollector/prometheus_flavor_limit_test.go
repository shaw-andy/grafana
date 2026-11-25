package statscollector

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkhttpclient "github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db/dbtest"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/infra/httpclient/httpclientprovider"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/stats/statstest"
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
)

// buildinfoReadCap is the most of a Prometheus buildinfo body the usage-stats
// collector may pull into the Grafana process, counted after the datasource
// transport has decoded Content-Encoding. The shipped dataproxy response_limit
// is 0 and must not be what enforces this.
const buildinfoReadCap = 64 * 1024

func TestCollectPrometheusFlavors_CapsBuildinfoResponseBody(t *testing.T) {
	// Shipped default is 0, which disables ResponseLimitMiddleware. Pin it so a
	// developer machine with GF_DATAPROXY_RESPONSE_LIMIT set cannot hide the bug.
	t.Setenv("GF_DATAPROXY_RESPONSE_LIMIT", "0")

	const oversized = 256 * 1024
	large := prometheusBuildinfoJSON(t, oversized)
	require.Greater(t, len(large), buildinfoReadCap)

	var gzipped bytes.Buffer
	zw := gzip.NewWriter(&gzipped)
	_, err := zw.Write(large)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.Greater(t, gzipped.Len(), 0)
	require.Less(t, gzipped.Len(), buildinfoReadCap, "compressed fixture must sit under the cap so a full read is the decompressed body")

	const vanillaBody = `{"status":"success","data":{"version":"2.45.0","revision":"","branch":"","buildUser":"","buildDate":"","goVersion":"go1.21.0"}}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/api/v1/status/buildinfo") {
			http.NotFound(w, r)
			return
		}
		switch {
		case strings.Contains(r.URL.Path, "/gzip/"):
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(gzipped.Bytes())
		case strings.Contains(r.URL.Path, "/vanilla/"):
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, vanillaBody)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(large)
		}
	}))
	t.Cleanup(srv.Close)

	accounts := map[string]*bodyAccount{
		"prom-org-1": {},
		"prom-org-2": {},
		"amazon":     {},
		"azure":      {},
	}
	ds := &recordingDatasourceService{
		items: []*datasources.DataSource{
			{
				ID: 1, UID: "prom-org-1", OrgID: 1, Name: "Vanilla", Type: datasources.DS_PROMETHEUS,
				Access: "proxy", URL: srv.URL + "/vanilla",
			},
			{
				ID: 2, UID: "prom-org-2", OrgID: 2, Name: "Plain", Type: datasources.DS_PROMETHEUS,
				Access: "proxy", URL: srv.URL + "/plain",
			},
			{
				ID: 3, UID: "amazon", OrgID: 1, Name: "Amazon", Type: datasources.DS_AMAZON_PROMETHEUS,
				Access: "proxy", URL: srv.URL + "/gzip",
			},
			{
				ID: 4, UID: "azure", OrgID: 2, Name: "Azure", Type: datasources.DS_AZURE_PROMETHEUS,
				Access: "proxy", URL: srv.URL + "/plain",
			},
		},
		accounts: accounts,
	}

	cfg := setting.NewCfg()
	cfg.DataProxyTimeout = 30
	cfg.DataProxyDialTimeout = 10
	cfg.DataProxyKeepAlive = 30
	cfg.DataProxyTLSHandshakeTimeout = 10
	cfg.DataProxyExpectContinueTimeout = 1
	cfg.DataProxyMaxIdleConns = 100
	cfg.DataProxyIdleConnTimeout = 90
	cfg.ResponseLimit = 0
	cfg.DataProxyUserAgent = "Grafana/test"

	prevTimeouts := sdkhttpclient.DefaultTimeoutOptions
	t.Cleanup(func() { sdkhttpclient.DefaultTimeoutOptions = prevTimeouts })

	provider := httpclientprovider.New(cfg, &validations.OSSDataSourceRequestURLValidator{}, tracing.NewNoopTracerService())
	s := createService(
		t,
		cfg,
		dbtest.NewFakeDB(),
		statstest.NewFakeService(),
		withDatasources(ds),
		withHTTPClientProvider(provider),
	)

	stats, err := s.collectPrometheusFlavors(context.Background())
	require.NoError(t, err)

	require.Equal(t, []recordedDatasourceQuery{
		{Type: datasources.DS_PROMETHEUS, OrgID: 0},
		{Type: datasources.DS_AMAZON_PROMETHEUS, OrgID: 0},
		{Type: datasources.DS_AZURE_PROMETHEUS, OrgID: 0},
	}, ds.queries)

	for _, uid := range []string{"prom-org-1", "prom-org-2", "amazon", "azure"} {
		acct := accounts[uid]
		require.Equal(t, int32(1), acct.hits.Load(), uid)
		got := int(acct.n.Load())
		if uid != "prom-org-1" && acct.prefix[0] == 0x1f && acct.prefix[1] == 0x8b {
			t.Errorf("datasource %s buildinfo was still gzip-compressed when the collector read it", uid)
		}
		if got > buildinfoReadCap {
			t.Errorf("datasource %s buildinfo read %d bytes, cap is %d", uid, got, buildinfoReadCap)
		}
	}
	require.Equal(t, len(vanillaBody), int(accounts["prom-org-1"].n.Load()))

	require.Equal(t, int64(1), stats["stats.ds.prometheus.flavor.vanilla.count"])
	require.Equal(t, int64(3), stats["stats.ds.prometheus.flavor.unknown.count"])
}

func prometheusBuildinfoJSON(t *testing.T, versionLen int) []byte {
	t.Helper()
	body := []byte(`{"status":"success","data":{"version":"` + strings.Repeat("x", versionLen) + `"}}`)
	require.True(t, json.Valid(body))
	return body
}

type recordedDatasourceQuery struct {
	Type  string
	OrgID int64
}

// recordingDatasourceService returns every stored datasource when OrgID is unset,
// matching SqlStore.GetDataSourcesByType, and serves them through the caller's
// HTTP provider so the production middleware chain handles the response.
type recordingDatasourceService struct {
	datasources.DataSourceService

	items    []*datasources.DataSource
	accounts map[string]*bodyAccount

	mu      sync.Mutex
	queries []recordedDatasourceQuery
}

func (s *recordingDatasourceService) GetDataSourcesByType(ctx context.Context, query *datasources.GetDataSourcesByTypeQuery) ([]*datasources.DataSource, error) {
	s.mu.Lock()
	s.queries = append(s.queries, recordedDatasourceQuery{Type: query.Type, OrgID: query.OrgID})
	s.mu.Unlock()

	out := make([]*datasources.DataSource, 0, len(s.items))
	for _, ds := range s.items {
		if query.OrgID > 0 && ds.OrgID != query.OrgID {
			continue
		}
		if ds.Type == query.Type {
			out = append(out, ds)
		}
	}
	return out, nil
}

func (s *recordingDatasourceService) GetHTTPTransport(ctx context.Context, ds *datasources.DataSource, provider httpclient.Provider, customMiddlewares ...sdkhttpclient.Middleware) (http.RoundTripper, error) {
	opts := sdkhttpclient.Options{
		Labels: map[string]string{
			"datasource_type": ds.Type,
			"datasource_name": ds.Name,
			"datasource_uid":  ds.UID,
		},
		Timeouts: &sdkhttpclient.TimeoutOptions{
			Timeout:               30 * time.Second,
			DialTimeout:           10 * time.Second,
			KeepAlive:             30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
		},
		Middlewares: customMiddlewares,
	}
	rt, err := provider.GetTransport(opts)
	if err != nil {
		return nil, err
	}
	return accountingTransport{base: rt, acct: s.accounts[ds.UID]}, nil
}

type bodyAccount struct {
	n      atomic.Int64
	hits   atomic.Int32
	mu     sync.Mutex
	filled int
	prefix [2]byte
}

func (a *bodyAccount) addPrefix(p []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, b := range p {
		if a.filled == len(a.prefix) {
			return
		}
		a.prefix[a.filled] = b
		a.filled++
	}
}

type accountingTransport struct {
	base http.RoundTripper
	acct *bodyAccount
}

func (t accountingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.acct.hits.Add(1)
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil || resp.Body == nil {
		return resp, err
	}
	resp.Body = &accountingBody{ReadCloser: resp.Body, acct: t.acct}
	return resp, nil
}

type accountingBody struct {
	io.ReadCloser
	acct *bodyAccount
}

func (b *accountingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.acct.addPrefix(p[:n])
		b.acct.n.Add(int64(n))
	}
	return n, err
}

func withHTTPClientProvider(provider httpclient.Provider) func(*serviceOptions) {
	return func(options *serviceOptions) {
		options.httpClientProvider = provider
	}
}
