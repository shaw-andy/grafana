package pluginproxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/oauthtoken"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web"
)

// maxGenericTokenResponseBytes is the largest generic tokenAuth body the proxy
// may read. A larger body, including one sent without Content-Length, must be
// rejected before the rest of it is read.
const maxGenericTokenResponseBytes = 1 << 20

// otherOrgTokenWait is how long another organization's proxy call may block on
// a token fetch that has not returned. It is far below the token client's
// 30s timeout, so a call that shares that fetch's lock fails the test.
const otherOrgTokenWait = 3 * time.Second

func TestGenericTokenAuthProxy_InFlightFetchDoesNotBlockOtherDatasource(t *testing.T) {
	clearTokenCache()
	t.Cleanup(clearTokenCache)

	var releaseSlowOnce sync.Once
	releaseSlow := make(chan struct{})
	release := func() { releaseSlowOnce.Do(func() { close(releaseSlow) }) }

	slowStarted := make(chan struct{})
	var slowStartOnce sync.Once
	var slowMethod, slowContentType string
	slowToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slowMethod = r.Method
		slowContentType = r.Header.Get("Content-Type")
		slowStartOnce.Do(func() { close(slowStarted) })
		<-releaseSlow
		writeChunkedJSON(w, `{"access_token":"slow-token"}`)
	}))
	t.Cleanup(slowToken.Close)

	fastToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeChunkedJSON(w, `{"access_token":"org-b-token","expires_in":3600}`)
	}))
	t.Cleanup(fastToken.Close)

	upstreamHits := make(chan string, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	routes := mustTokenAuthRoutes(t, upstream.URL)
	var wg sync.WaitGroup
	// Release the blocked token server before waiting, and wait before the
	// servers registered above are closed.
	t.Cleanup(func() {
		release()
		wg.Wait()
	})

	// Organization B can complete a token refresh while nothing else is in flight.
	orgBDS := tokenAuthDatasource(22, 2, "org-b", fastToken.URL, upstream.URL)
	warmupRec := httptest.NewRecorder()
	newTokenAuthProxy(t, routes, orgBDS, warmupRec).HandleRequest()
	require.Equal(t, http.StatusOK, warmupRec.Code, warmupRec.Body.String())
	select {
	case auth := <-upstreamHits:
		require.Equal(t, "Bearer org-b-token", auth)
	default:
		t.Fatal("org B proxy did not reach the upstream before the other fetch started")
	}

	// Organization A's datasource points its token URL at a server that does
	// not answer. The proxy call stays inside the token fetch until release.
	orgARec := httptest.NewRecorder()
	orgA := newTokenAuthProxy(t, routes, tokenAuthDatasource(11, 1, "org-a", slowToken.URL, upstream.URL), orgARec)
	wg.Add(1)
	go func() {
		defer wg.Done()
		orgA.HandleRequest()
	}()

	select {
	case <-slowStarted:
	case <-time.After(otherOrgTokenWait):
		t.Fatal("org A token endpoint was not called")
	}
	require.Equal(t, http.MethodPost, slowMethod)
	require.Equal(t, "application/x-www-form-urlencoded", slowContentType)

	// Organization B's cached token, and any refresh of it, must still finish
	// while org A is inside the token HTTP call.
	orgBRec := httptest.NewRecorder()
	orgB := newTokenAuthProxy(t, routes, orgBDS, orgBRec)
	wg.Add(1)
	go func() {
		defer wg.Done()
		orgB.HandleRequest()
	}()

	select {
	case auth := <-upstreamHits:
		require.Equal(t, "Bearer org-b-token", auth)
		require.Equal(t, http.StatusOK, orgBRec.Code, orgBRec.Body.String())
	case <-time.After(otherOrgTokenWait):
		t.Fatalf("org B token refresh did not finish while org A held the token fetch; status=%d body=%s", orgBRec.Code, orgBRec.Body.String())
	}
}

func TestGenericTokenAuthProxy_OversizedChunkedBodyIsRejected(t *testing.T) {
	clearTokenCache()
	t.Cleanup(clearTokenCache)

	upstreamAuth := make(chan string, 4)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	// The vulnerable client forwards the whole token in a request header.
	// Raise the test server's limit so that header is observable instead of
	// rejected by the server before this handler runs.
	upstream.Config.MaxHeaderBytes = 8 << 20
	upstream.Start()
	t.Cleanup(upstream.Close)

	small := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeChunkedJSON(w, `{"access_token":"small-token","expires_in":3600}`)
	}))
	t.Cleanup(small.Close)
	assertChunked(t, small.URL)

	routes := mustTokenAuthRoutes(t, upstream.URL)

	smallRec := httptest.NewRecorder()
	smallProxy := newTokenAuthProxy(t, routes, tokenAuthDatasource(31, 1, "small", small.URL, upstream.URL), smallRec)
	smallProxy.HandleRequest()
	require.Equal(t, http.StatusOK, smallRec.Code, smallRec.Body.String())
	select {
	case auth := <-upstreamAuth:
		require.Equal(t, "Bearer small-token", auth)
	default:
		t.Fatal("proxied request did not reach the upstream")
	}

	// Pause after one byte past the cap, before the JSON value is complete.
	// A reader that keeps going cannot return until the rest is written.
	var releaseOnce sync.Once
	releaseRest := make(chan struct{})
	release := func() { releaseOnce.Do(func() { close(releaseRest) }) }

	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		if flusher != nil {
			flusher.Flush()
		}

		// One byte past the cap, and the JSON string is still open. A reader
		// with no limit blocks in the decode until releaseRest is closed.
		payload := []byte(`{"access_token":"`)
		if len(payload) < maxGenericTokenResponseBytes+1 {
			payload = append(payload, strings.Repeat("b", maxGenericTokenResponseBytes+1-len(payload))...)
		}
		if _, err := w.Write(payload[:maxGenericTokenResponseBytes+1]); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		<-releaseRest
		_, _ = io.WriteString(w, `","expires_in":3600}`)
	}))
	t.Cleanup(oversized.Close)

	routes = mustTokenAuthRoutes(t, upstream.URL)
	overRec := httptest.NewRecorder()
	overProxy := newTokenAuthProxy(t, routes, tokenAuthDatasource(32, 2, "over", oversized.URL, upstream.URL), overRec)

	done := make(chan struct{})
	go func() {
		defer close(done)
		overProxy.HandleRequest()
	}()
	t.Cleanup(func() {
		release()
		<-done
	})

	select {
	case <-done:
	case <-time.After(otherOrgTokenWait):
		t.Fatal("oversized token response was still being read")
	}

	select {
	case auth := <-upstreamAuth:
		require.Empty(t, auth, "oversized token body must not be forwarded")
	default:
		t.Fatal("proxied request did not reach the upstream after the token fetch failed")
	}
	require.NotContains(t, overRec.Body.String(), strings.Repeat("b", 32))
}

func mustTokenAuthRoutes(t *testing.T, upstreamURL string) []*plugins.Route {
	t.Helper()
	raw := fmt.Sprintf(`{
		"id": "token-ds",
		"name": "Token DS",
		"type": "datasource",
		"routes": [{
			"path": "query",
			"method": "GET",
			"url": %q,
			"tokenAuth": {
				"url": "{{.JsonData.tokenUrl}}",
				"params": {"grant_type": "client_credentials"}
			}
		}]
	}`, upstreamURL)
	plugin, err := plugins.ReadPluginJSON(strings.NewReader(raw))
	require.NoError(t, err)
	require.NotNil(t, plugin.Routes[0].TokenAuth)
	require.Empty(t, plugin.Routes[0].AuthType)
	return plugin.Routes
}

func tokenAuthDatasource(id, orgID int64, uid, tokenURL, upstreamURL string) *datasources.DataSource {
	return &datasources.DataSource{
		ID:    id,
		UID:   uid,
		OrgID: orgID,
		Name:  uid,
		Type:  "token-ds",
		URL:   upstreamURL,
		JsonData: simplejson.NewFromAny(map[string]any{
			"tokenUrl": tokenURL,
		}),
		Updated: time.Now(),
		Created: time.Now().Add(-time.Hour),
	}
}

func newTokenAuthProxy(t *testing.T, routes []*plugins.Route, ds *datasources.DataSource, rec *httptest.ResponseRecorder) *DataSourceProxy {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/datasources/proxy/uid/"+ds.UID+"/query", nil)
	reqCtx := &contextmodel.ReqContext{
		Context: &web.Context{Req: req},
		SignedInUser: &user.SignedInUser{
			UserID:  100 + ds.OrgID,
			OrgID:   ds.OrgID,
			OrgRole: org.RoleViewer,
			Login:   "viewer",
		},
	}
	reqCtx.Req = req.WithContext(ctxkey.Set(req.Context(), reqCtx))

	stub := &recordingDSService{transport: http.DefaultTransport, values: map[string]string{}}
	loader, err := NewDataSourceLoader(ds, stub)
	require.NoError(t, err)

	httpCtx := toHTTPContext(t, reqCtx)
	httpCtx.Resp = rec
	proxy, err := NewDataSourceProxy(
		loader,
		routes,
		httpCtx,
		"query",
		&DataSourceProxySettings{},
		nil,
		&oauthtoken.Service{},
		tracing.InitializeTracerForTest(),
		featuremgmt.WithFeatures(),
	)
	require.NoError(t, err)
	return proxy
}

func writeChunkedJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	_, _ = io.WriteString(w, body)
}

func assertChunked(t *testing.T, rawURL string) {
	t.Helper()
	resp, err := http.Get(rawURL) //nolint:gosec // test server URL
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	require.Equal(t, int64(-1), resp.ContentLength)
	require.Contains(t, resp.TransferEncoding, "chunked")
}
