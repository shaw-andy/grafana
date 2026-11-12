package loganalytics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-azure-sdk-go/v2/azcredentials"
	"github.com/grafana/grafana-azure-sdk-go/v2/azhttpclient"
	"github.com/grafana/grafana-azure-sdk-go/v2/azsettings"
	"github.com/grafana/grafana-azure-sdk-go/v2/aztokenprovider"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	sdkconfig "github.com/grafana/grafana-plugin-sdk-go/config"

	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/kinds/dataquery"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/types"
)

// Ceilings a traces correlation walk must enforce. The page ceiling matches the
// frontend ARM listing cap (MAX_ARM_PAGES). Resource ids are capped separately
// because one page can list an unbounded resources array.
const (
	maxCorrelationPages     = 50
	maxCorrelationResources = 50

	correlationOperationID  = "op-correlation-1"
	correlationBaseApp      = "/subscriptions/test-sub/resourcegroups/test-rg/providers/microsoft.insights/components/base-app"
	correlationSubscription = "/subscriptions/test-sub"
)

func TestAzureTracesCorrelationPagination(t *testing.T) {
	queryTypes := []string{
		string(dataquery.AzureQueryTypeAzureTraces),
		string(dataquery.AzureQueryTypeTraceExemplar),
	}
	for _, queryType := range queryTypes {
		t.Run(queryType, func(t *testing.T) {
			t.Run("follows each nextLink and keeps every page of resource ids", func(t *testing.T) {
				runCorrelationQuery(t, queryType, correlationScript{
					pages: []correlationPage{
						{resources: []string{componentID("from-page-1")}, next: "/correlation-page/2"},
						{resources: []string{componentID("from-page-2")}, next: "/correlation-page/3"},
						{resources: []string{componentID("from-page-3")}},
					},
					absoluteNext: true,
				}, func(t *testing.T, res correlationResult) {
					require.NoError(t, res.err)
					require.Less(t, res.elapsed, 2*time.Second)
					reqs := res.correlationRequests()
					require.Len(t, reqs, 3)
					require.Contains(t, reqs[0].url, correlationOperationID)
					require.NotContains(t, reqs[0].url, "/correlation-page/")
					require.Contains(t, reqs[1].url, "/correlation-page/2")
					require.Contains(t, reqs[2].url, "/correlation-page/3")
					requireCorrelationAuthorized(t, res)
					requireQueryHasResources(t, res.query, "from-page-1", "from-page-2", "from-page-3")
				})
			})

			t.Run("follows a relative nextLink on the resource manager host", func(t *testing.T) {
				runCorrelationQuery(t, queryType, correlationScript{
					pages: []correlationPage{
						{resources: []string{componentID("from-page-1")}, next: "/correlation-page/2"},
						{resources: []string{componentID("from-relative-page")}},
					},
				}, func(t *testing.T, res correlationResult) {
					require.NoError(t, res.err)
					require.Less(t, res.elapsed, 2*time.Second)
					reqs := res.correlationRequests()
					require.Len(t, reqs, 2)
					require.Contains(t, reqs[1].url, "/correlation-page/2")
					require.Equal(t, res.armHost, reqs[1].host)
					requireCorrelationAuthorized(t, res)
					requireQueryHasResources(t, res.query, "from-page-1", "from-relative-page")
				})
			})

			t.Run("stops within the page cap when nextLink never clears", func(t *testing.T) {
				runCorrelationQuery(t, queryType, correlationScript{
					pages:        neverEndingPages(maxCorrelationPages + 30),
					absoluteNext: true,
				}, func(t *testing.T, res correlationResult) {
					require.NoError(t, res.err)
					require.Less(t, res.elapsed, 2*time.Second)
					reqs := res.correlationRequests()
					require.LessOrEqual(t, len(reqs), maxCorrelationPages)
					require.GreaterOrEqual(t, len(reqs), 2)
					requireCorrelationAuthorized(t, res)
					requireQueryHasResources(t, res.query, "from-page-2")
					requireQueryLacksResources(t, res.query, fmt.Sprintf("from-page-%d", maxCorrelationPages+1))
					require.LessOrEqual(t, strings.Count(res.query.Query, "app('"), maxCorrelationResources)
				})
			})

			t.Run("stops within the page cap when nextLink repeats the original URL", func(t *testing.T) {
				runCorrelationQuery(t, queryType, correlationScript{
					repeatOriginalURL: true,
					pages: []correlationPage{{
						resources: []string{componentID("from-repeated-page")},
					}},
				}, func(t *testing.T, res correlationResult) {
					require.NoError(t, res.err)
					require.Less(t, res.elapsed, 2*time.Second)
					reqs := res.correlationRequests()
					require.LessOrEqual(t, len(reqs), maxCorrelationPages)
					require.NotEmpty(t, reqs)
					for _, req := range reqs {
						require.Contains(t, req.url, correlationOperationID)
						require.NotContains(t, req.url, "evil.example")
					}
					requireCorrelationAuthorized(t, res)
					requireQueryHasResources(t, res.query, "from-repeated-page")
					require.LessOrEqual(t, strings.Count(res.query.Query, "app('"), maxCorrelationResources)
				})
			})

			t.Run("caps resource ids from a single page", func(t *testing.T) {
				ids := make([]string, 200)
				for i := range ids {
					ids[i] = componentID(fmt.Sprintf("from-bulk-%d", i+1))
				}
				runCorrelationQuery(t, queryType, correlationScript{
					pages: []correlationPage{{resources: ids}},
				}, func(t *testing.T, res correlationResult) {
					require.NoError(t, res.err)
					require.Less(t, res.elapsed, 2*time.Second)
					require.Len(t, res.correlationRequests(), 1)
					requireCorrelationAuthorized(t, res)
					kept := strings.Count(res.query.Query, "from-bulk-")
					require.GreaterOrEqual(t, kept, 1)
					require.LessOrEqual(t, kept, maxCorrelationResources)
					require.LessOrEqual(t, strings.Count(res.query.Query, "app('"), maxCorrelationResources)
				})
			})

			foreignLinks := []struct {
				name string
				link func(arm *url.URL) string
			}{
				{
					name: "other host",
					link: func(*url.URL) string { return "https://evil.example/correlation-page/2" },
				},
				{
					name: "resource manager host as a label of another host",
					link: func(arm *url.URL) string {
						return fmt.Sprintf("%s://%s.evil.example/correlation-page/2", arm.Scheme, arm.Hostname())
					},
				},
				{
					name: "same hostname on another port",
					link: func(arm *url.URL) string {
						port := "1"
						if arm.Port() == "1" {
							port = "2"
						}
						return fmt.Sprintf("%s://%s:%s/correlation-page/2", arm.Scheme, arm.Hostname(), port)
					},
				},
				{
					name: "userinfo on another host",
					link: func(*url.URL) string { return "http://placeholder@evil.example/correlation-page/2" },
				},
			}
			for _, foreign := range foreignLinks {
				t.Run("rejects nextLink "+foreign.name, func(t *testing.T) {
					runCorrelationQuery(t, queryType, correlationScript{
						pages: []correlationPage{{
							resources: []string{componentID("from-page-1")},
						}},
						foreignNext: foreign.link,
					}, func(t *testing.T, res correlationResult) {
						require.Less(t, res.elapsed, 2*time.Second)
						reqs := res.correlationRequests()
						require.Len(t, reqs, 1)
						require.Contains(t, reqs[0].url, correlationOperationID)
						for _, req := range res.log.snapshot() {
							require.Equal(t, res.armHost, req.host, "request left the configured resource manager host: %s", req.url)
						}
						if res.err == nil {
							requireQueryLacksResources(t, res.query, "from-evil-page")
						}
					})
				})
			}

			t.Run("stops when the query context is cancelled", func(t *testing.T) {
				runCorrelationQuery(t, queryType, correlationScript{
					pages: []correlationPage{{
						resources: []string{componentID("from-page-1")},
						next:      "/correlation-page/2",
					}},
					absoluteNext: true,
					// Answer one page, then hold the next request until its context ends.
					holdAfter:   1,
					cancelAfter: 2,
				}, func(t *testing.T, res correlationResult) {
					require.Error(t, res.err)
					require.ErrorContains(t, res.err, "context canceled")
					require.Less(t, res.elapsed, 2*time.Second)
					require.Len(t, res.correlationRequests(), 2)
				})
			})

			t.Run("query execution stops while nextLink never clears", func(t *testing.T) {
				runCorrelationExecute(t, queryType, correlationScript{
					pages:        neverEndingPages(maxCorrelationPages + 30),
					absoluteNext: true,
				}, func(t *testing.T, res correlationResult) {
					require.Less(t, res.elapsed, 2*time.Second)
					reqs := res.correlationRequests()
					require.NotEmpty(t, reqs)
					require.LessOrEqual(t, len(reqs), maxCorrelationPages)
					require.Contains(t, reqs[0].url, correlationOperationID)
					requireCorrelationAuthorized(t, res)
					for _, req := range res.log.snapshot() {
						require.Equal(t, res.armHost, req.host)
					}
				})
			})
		})
	}
}

type correlationPage struct {
	resources []string
	// next is a URL path on the resource manager host. Empty ends the walk.
	next string
}

type correlationScript struct {
	pages             []correlationPage
	absoluteNext      bool
	repeatOriginalURL bool
	foreignNext       func(arm *url.URL) string
	// holdAfter answers that many correlation requests, then holds later ones
	// open until the request context ends.
	holdAfter int
	// cancelAfter cancels the query context once this many correlation requests have started.
	cancelAfter int
}

type capturedRequest struct {
	url           string
	host          string
	authorization string
}

type requestLog struct {
	mu   sync.Mutex
	reqs []capturedRequest
}

func (l *requestLog) add(req *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqs = append(l.reqs, capturedRequest{
		url:           req.URL.String(),
		host:          req.URL.Host,
		authorization: req.Header.Get("Authorization"),
	})
}

func (l *requestLog) snapshot() []capturedRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]capturedRequest, len(l.reqs))
	copy(out, l.reqs)
	return out
}

func (l *requestLog) middleware(allowedHost string) httpclient.Middleware {
	return httpclient.NamedMiddlewareFunc("correlation-request-recorder", func(_ httpclient.Options, next http.RoundTripper) http.RoundTripper {
		return httpclient.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			l.add(req)
			if !strings.EqualFold(req.URL.Host, allowedHost) {
				return nil, fmt.Errorf("test transport refused host %q", req.URL.Host)
			}
			return next.RoundTrip(req)
		})
	})
}

type correlationResult struct {
	query   *AzureLogAnalyticsQuery
	err     error
	elapsed time.Duration
	log     *requestLog
	armHost string
}

func (r correlationResult) correlationRequests() []capturedRequest {
	var out []capturedRequest
	for _, req := range r.log.snapshot() {
		if isCorrelationTarget(req.url) {
			out = append(out, req)
		}
	}
	return out
}

func isCorrelationTarget(raw string) bool {
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		decoded = raw
	}
	return strings.Contains(decoded, "/transactions/") || strings.Contains(decoded, "/correlation-page/")
}

type placeholderTokenProvider struct{}

func (placeholderTokenProvider) GetAccessToken(ctx context.Context, scopes []string) (string, error) {
	if ctx == nil || len(scopes) == 0 {
		return "", fmt.Errorf("token request is missing context or scopes")
	}
	return "placeholder", nil
}

func runCorrelationQuery(t *testing.T, queryType string, script correlationScript, check func(t *testing.T, res correlationResult)) {
	t.Helper()
	runCorrelation(t, queryType, script, false, check)
}

func runCorrelationExecute(t *testing.T, queryType string, script correlationScript, check func(t *testing.T, res correlationResult)) {
	t.Helper()
	runCorrelation(t, queryType, script, true, check)
}

func runCorrelation(t *testing.T, queryType string, script correlationScript, execute bool, check func(t *testing.T, res correlationResult)) {
	t.Helper()

	var started chan struct{}
	if script.cancelAfter > 0 {
		started = make(chan struct{}, script.cancelAfter)
	}
	var requests atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requestIsCorrelation(r) {
			writeEmptyLogs(w)
			return
		}
		n := int(requests.Add(1))
		if started != nil {
			started <- struct{}{}
		}
		if script.holdAfter > 0 && n > script.holdAfter {
			<-r.Context().Done()
			return
		}
		writeCorrelationPage(w, r, srv.URL, script, correlationPageNumber(r))
	}))
	t.Cleanup(srv.Close)

	armURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	client, reqLog := newRecordingAzureClient(t, armURL.Host)
	dsInfo := types.DatasourceInfo{
		Services: map[string]types.DatasourceService{
			"Azure Monitor": {URL: srv.URL, HTTPClient: client, Logger: log.NewNullLogger()},
		},
		Settings: types.AzureMonitorSettings{SubscriptionId: "test-sub"},
	}
	ds := &AzureLogAnalyticsDatasource{Logger: log.NewNullLogger()}
	query := correlationDataQuery(t, queryType)

	// The parent deadline is longer than the assertion window so a walk that
	// only ends when the query context is cancelled does not look finished.
	ctx, cancel := correlationContext(queryType)
	defer cancel()
	if script.cancelAfter > 0 {
		go func() {
			for i := 0; i < script.cancelAfter; i++ {
				select {
				case <-started:
				case <-time.After(2 * time.Second):
					return
				}
			}
			cancel()
		}()
	}

	start := time.Now()
	type outcome struct {
		query *AzureLogAnalyticsQuery
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		if execute {
			resp, execErr := ds.ExecuteTimeSeriesQuery(ctx, []backend.DataQuery{query}, dsInfo, client, srv.URL, false)
			if execErr != nil {
				done <- outcome{err: execErr}
				return
			}
			if resp != nil {
				if dataResp, ok := resp.Responses[query.RefID]; ok && dataResp.Error != nil {
					done <- outcome{err: dataResp.Error}
					return
				}
			}
			done <- outcome{}
			return
		}
		built, buildErr := ds.buildQuery(ctx, query, dsInfo, false)
		done <- outcome{query: built, err: buildErr}
	}()

	var res correlationResult
	select {
	case outcome := <-done:
		res = correlationResult{
			query:   outcome.query,
			err:     outcome.err,
			elapsed: time.Since(start),
			log:     reqLog,
			armHost: armURL.Host,
		}
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatalf("correlation walk was still running after 2s (%d requests)", len(reqLog.snapshot()))
	}
	check(t, res)
}

func correlationContext(queryType string) (context.Context, context.CancelFunc) {
	ctx := context.Background()
	if queryType == string(dataquery.AzureQueryTypeTraceExemplar) {
		ctx = sdkconfig.WithGrafanaConfig(ctx, sdkconfig.NewGrafanaCfg(map[string]string{
			"GF_INSTANCE_FEATURE_TOGGLES_ENABLE": "azureMonitorPrometheusExemplars",
		}))
	}
	return context.WithTimeout(ctx, 5*time.Second)
}

func newRecordingAzureClient(t *testing.T, allowedHost string) (*http.Client, *requestLog) {
	t.Helper()
	reqLog := &requestLog{}
	authOpts := azhttpclient.NewAuthOptions(&azsettings.AzureSettings{Cloud: azsettings.AzurePublic})
	authOpts.Scopes([]string{"https://management.azure.com/.default"})
	authOpts.AddTokenProvider(azcredentials.AzureAuthClientSecret, func(*azsettings.AzureSettings, azcredentials.AzureCredentials) (aztokenprovider.AzureTokenProvider, error) {
		return placeholderTokenProvider{}, nil
	})
	clientOpts := httpclient.Options{}
	azhttpclient.AddAzureAuthentication(&clientOpts, authOpts, &azcredentials.AzureClientSecretCredentials{})
	clientOpts.Middlewares = append(clientOpts.Middlewares, reqLog.middleware(allowedHost))
	provider := httpclient.NewProvider(httpclient.ProviderOptions{Timeout: &httpclient.DefaultTimeoutOptions})
	client, err := provider.New(clientOpts)
	require.NoError(t, err)
	return client, reqLog
}

func correlationDataQuery(t *testing.T, queryType string) backend.DataQuery {
	t.Helper()
	traces := map[string]any{
		"resultFormat": string(dataquery.ResultFormatTable),
		"traceTypes":   []string{"trace"},
		"operationId":  correlationOperationID,
	}
	if queryType != string(dataquery.AzureQueryTypeTraceExemplar) {
		traces["resources"] = []string{correlationBaseApp}
	}
	raw, err := json.Marshal(map[string]any{
		"queryType":   queryType,
		"azureTraces": traces,
	})
	require.NoError(t, err)
	from := time.Date(2024, 3, 15, 13, 0, 0, 0, time.UTC)
	return backend.DataQuery{
		RefID:     "A",
		QueryType: queryType,
		TimeRange: backend.TimeRange{From: from, To: from.Add(30 * time.Minute)},
		JSON:      raw,
	}
}

func writeCorrelationPage(w http.ResponseWriter, r *http.Request, armURL string, script correlationScript, page int) {
	var resources []string
	var next *string
	if script.repeatOriginalURL {
		resources = script.pages[0].resources
		original := originalCorrelationURL(armURL, r)
		next = &original
	} else if page-1 >= 0 && page-1 < len(script.pages) {
		current := script.pages[page-1]
		resources = current.resources
		switch {
		case script.foreignNext != nil && page == 1:
			arm, err := url.Parse(armURL)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			link := script.foreignNext(arm)
			next = &link
		case current.next != "":
			link := current.next
			if script.absoluteNext {
				link = armURL + current.next
			}
			next = &link
		}
	} else {
		http.Error(w, "unexpected correlation page", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(AzureCorrelationAPIResponse{
		Properties: AzureCorrelationAPIResponseProperties{
			Resources: resources,
			NextLink:  next,
		},
	})
}

func originalCorrelationURL(armURL string, r *http.Request) string {
	decoded, err := url.PathUnescape(r.URL.String())
	if err != nil {
		decoded = r.URL.String()
	}
	if idx := strings.Index(decoded, "/subscriptions/"); idx >= 0 {
		path := decoded[idx:]
		if cut := strings.Index(path, "?"); cut >= 0 {
			path = path[:cut]
		}
		return armURL + path
	}
	return armURL
}

func writeEmptyLogs(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"tables":[{"name":"PrimaryResult","columns":[{"name":"TimeGenerated","type":"datetime"}],"rows":[]}]}`)
}

func requestIsCorrelation(r *http.Request) bool {
	return isCorrelationTarget(r.URL.RequestURI()) || isCorrelationTarget(r.URL.Path) || isCorrelationTarget(r.URL.String())
}

func correlationPageNumber(r *http.Request) int {
	decoded, err := url.PathUnescape(r.URL.RequestURI() + " " + r.URL.Path + " " + r.URL.String())
	if err != nil {
		decoded = r.URL.RequestURI()
	}
	const marker = "/correlation-page/"
	idx := strings.LastIndex(decoded, marker)
	if idx < 0 {
		return 1
	}
	n := 0
	for _, c := range decoded[idx+len(marker):] {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return 1
	}
	return n
}

func neverEndingPages(n int) []correlationPage {
	pages := make([]correlationPage, n)
	for i := range pages {
		next := ""
		if i+1 < len(pages) {
			next = fmt.Sprintf("/correlation-page/%d", i+2)
		}
		pages[i] = correlationPage{
			resources: []string{componentID(fmt.Sprintf("from-page-%d", i+1))},
			next:      next,
		}
	}
	// The last page still advertises another link so a walk with no cap cannot stop.
	pages[n-1].next = fmt.Sprintf("/correlation-page/%d", n+1)
	return pages
}

func componentID(name string) string {
	return "/subscriptions/test-sub/resourcegroups/test-rg/providers/microsoft.insights/components/" + name
}

func requireCorrelationAuthorized(t *testing.T, res correlationResult) {
	t.Helper()
	reqs := res.correlationRequests()
	require.NotEmpty(t, reqs)
	for _, req := range reqs {
		require.Equal(t, res.armHost, req.host)
		require.Equal(t, "Bearer placeholder", req.authorization)
	}
}

func requireQueryHasResources(t *testing.T, query *AzureLogAnalyticsQuery, names ...string) {
	t.Helper()
	require.NotNil(t, query)
	require.Contains(t, query.Query, correlationOperationID)
	for _, name := range names {
		require.Contains(t, query.Query, name+"')")
	}
	require.LessOrEqual(t, strings.Count(query.Query, "app('"), maxCorrelationResources)
}

func requireQueryLacksResources(t *testing.T, query *AzureLogAnalyticsQuery, names ...string) {
	t.Helper()
	require.NotNil(t, query)
	for _, name := range names {
		require.NotContains(t, query.Query, name+"')")
	}
}
