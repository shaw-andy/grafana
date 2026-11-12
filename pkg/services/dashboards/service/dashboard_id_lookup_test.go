package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/grafana/grafana/pkg/api"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/apiserver/client"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	dashboardclient "github.com/grafana/grafana/pkg/services/dashboards/service/client"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/web"
)

// maxIDsPerDashboardUIDLookup is the most ids one GET /api/dashboards/ids/:ids
// request may resolve. A longer comma-separated list must be rejected before
// any dashboard search runs.
const maxIDsPerDashboardUIDLookup = 100

// maxDashboardUIDLookupDeadline is the furthest deadline the lookup may place
// on the context it passes to dashboard search. The handler must return once
// that deadline fires, even when a search call is still blocked.
const maxDashboardUIDLookupDeadline = 30 * time.Second

// TestDashboardIDLookupRejectsOversizedListWithoutSearching is the spec for the
// uncapped id list on GET /api/dashboards/ids/:ids. It fails while every parsed
// id still runs its own search.
func TestDashboardIDLookupRejectsOversizedListWithoutSearching(t *testing.T) {
	ids := make([]string, maxIDsPerDashboardUIDLookup+1)
	for i := range ids {
		ids[i] = strconv.Itoa(i + 1)
	}

	h := newDashboardIDLookupHarness(t, map[string]string{"1": "uid-1"})
	status, body, calls := h.get(t, strings.Join(ids, ","))

	require.Equal(t, http.StatusBadRequest, status, "body: %s searches: %d", body, len(calls))
	require.Empty(t, calls, "oversized id list must be rejected before dashboard search, got %d searches", len(calls))
}

// TestDashboardIDLookupRejectsOversizedTokenListWithoutSearching covers a list
// that does not parse as ids. Splitting and walking it is still work, and the
// request must be rejected before any search.
func TestDashboardIDLookupRejectsOversizedTokenListWithoutSearching(t *testing.T) {
	tokens := make([]string, maxIDsPerDashboardUIDLookup+1)
	for i := range tokens {
		tokens[i] = "nope"
	}

	h := newDashboardIDLookupHarness(t, nil)
	status, body, calls := h.get(t, strings.Join(tokens, ","))

	require.Equal(t, http.StatusBadRequest, status, "body: %s searches: %d", body, len(calls))
	require.Empty(t, calls)
}

// TestDashboardIDLookupResolvesAcceptedIDsInOneSearch requires one search for
// every positive id in an accepted list, including ids that do not exist.
// Non-positive and non-numeric segments are not searched. The caller is a
// Viewer whose only dashboards:read scope is a single dashboard.
func TestDashboardIDLookupResolvesAcceptedIDsInOneSearch(t *testing.T) {
	h := newDashboardIDLookupHarness(t, map[string]string{
		"1": "uid-1",
		"3": "uid-3",
	})
	status, body, calls := h.get(t, "1,2,0,nope,3")

	require.Equal(t, http.StatusOK, status, "body: %s", body)
	require.Len(t, calls, 1, "accepted ids must be resolved by one search, not one search per id")
	require.ElementsMatch(t, []string{"1", "2", "3"}, calls[0].ids)

	var uids []string
	require.NoError(t, json.Unmarshal(body, &uids))
	require.Equal(t, []string{"uid-1", "uid-3"}, uids)
}

// TestDashboardIDLookupTimesOutABlockedSearch requires the search context to
// carry a deadline, and the handler to return after that deadline when the
// search never completes on its own.
func TestDashboardIDLookupTimesOutABlockedSearch(t *testing.T) {
	h := newDashboardIDLookupHarness(t, map[string]string{"1": "uid-1"})
	h.search.block = true

	entered := make(chan context.Context, 1)
	h.search.onSearch = func(ctx context.Context) {
		select {
		case entered <- ctx:
		default:
		}
	}

	done := make(chan struct{})
	go func() {
		resp, err := h.client.Get(h.server.URL + "/api/dashboards/ids/1")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		close(done)
	}()

	var searchCtx context.Context
	select {
	case searchCtx = <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("dashboard search was not called")
	}

	deadline, ok := searchCtx.Deadline()
	require.True(t, ok, "lookup must set a deadline on the context passed to dashboard search")
	remaining := time.Until(deadline)
	require.Greater(t, remaining, time.Duration(0))
	require.LessOrEqual(t, remaining, maxDashboardUIDLookupDeadline)

	select {
	case <-done:
	case <-time.After(remaining + 2*time.Second):
		t.Fatal("handler still running after the lookup deadline")
	}
}

type recordedSearch struct {
	ids []string
}

type countingSearchClient struct {
	client.K8sHandler

	mu       sync.Mutex
	calls    []recordedSearch
	byID     map[string]string
	block    bool
	onSearch func(context.Context)
	release  context.Context
}

func (s *countingSearchClient) GetNamespace(int64) string { return "org-1" }

func (s *countingSearchClient) GetWithPreferredAPIVersion(context.Context, string, int64, metav1.GetOptions, string, ...string) (*unstructured.Unstructured, error) {
	panic("GetWithPreferredAPIVersion is not used by id lookup")
}

func (s *countingSearchClient) Search(ctx context.Context, orgID int64, in *resourcepb.ResourceSearchRequest) (*resourcepb.ResourceSearchResponse, error) {
	ids := dashboardIDsFromSearch(in)
	s.mu.Lock()
	s.calls = append(s.calls, recordedSearch{ids: append([]string(nil), ids...)})
	onSearch := s.onSearch
	block := s.block
	byID := s.byID
	s.mu.Unlock()

	if onSearch != nil {
		onSearch(ctx)
	}
	if block {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.release.Done():
			return nil, context.Canceled
		}
	}

	resp := &resourcepb.ResourceSearchResponse{
		ResultFormat: resourcepb.ResourceSearchRequest_FIELD_VALUES,
		Fields: []*resourcepb.ResourceSearchField{
			{Name: resource.SEARCH_FIELD_TITLE, Type: resourcepb.ResourceSearchField_STRING},
			{Name: resource.SEARCH_FIELD_FOLDER, Type: resourcepb.ResourceSearchField_STRING},
		},
	}
	for _, id := range ids {
		uid, ok := byID[id]
		if !ok {
			continue
		}
		resp.Rows = append(resp.Rows, &resourcepb.ResourceSearchRow{
			Key: &resourcepb.ResourceKey{Namespace: "org-1", Name: uid, Resource: "dashboards"},
			Values: []*resourcepb.ResourceSearchValue{
				{FieldIndex: 0, StringValues: []string{uid}},
				{FieldIndex: 1, StringValues: []string{""}},
			},
		})
	}
	resp.TotalHits = int64(len(resp.Rows))
	_ = orgID
	return resp, nil
}

func (s *countingSearchClient) snapshot() []recordedSearch {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]recordedSearch, len(s.calls))
	copy(out, s.calls)
	return out
}

func dashboardIDsFromSearch(in *resourcepb.ResourceSearchRequest) []string {
	if in == nil || in.Options == nil {
		return nil
	}
	var ids []string
	for _, req := range in.Options.Labels {
		if req.GetKey() == utils.LabelKeyDeprecatedInternalID {
			ids = append(ids, req.GetValues()...)
		}
	}
	return ids
}

type dashboardIDLookupHarness struct {
	server *httptest.Server
	client *http.Client
	search *countingSearchClient
}

func newDashboardIDLookupHarness(t *testing.T, byID map[string]string) *dashboardIDLookupHarness {
	t.Helper()

	release, stop := context.WithCancel(context.Background())

	search := &countingSearchClient{
		byID:    byID,
		release: release,
	}
	svc := &DashboardServiceImpl{k8sclient: search}
	var _ dashboardclient.K8sHandlerWithFallback = search

	hs := &api.HTTPServer{DashboardService: svc}
	viewer := viewerWhoCanReadOneDashboard()

	m := web.New()
	m.Use(func(c *web.Context) {
		reqCtx := &contextmodel.ReqContext{
			Context:      c,
			SignedInUser: viewer,
			IsSignedIn:   true,
			Logger:       log.New("dashboard-id-lookup-test"),
		}
		ctx := identity.WithRequester(ctxkey.Set(c.Req.Context(), reqCtx), viewer)
		c.Req = c.Req.WithContext(ctx)
	})
	// Same route and permission check as pkg/api/api.go.
	m.Get("/api/dashboards/ids/:ids",
		accesscontrol.Middleware(acimpl.ProvideAccessControlTest())(accesscontrol.EvalPermission(dashboards.ActionDashboardsRead)),
		hs.GetDashboardUIDs,
	)

	server := httptest.NewServer(m)
	t.Cleanup(server.Close)
	// Cancel blocked searches before the server waits for handlers to finish.
	t.Cleanup(stop)

	return &dashboardIDLookupHarness{
		server: server,
		client: server.Client(),
		search: search,
	}
}

func (h *dashboardIDLookupHarness) get(t *testing.T, ids string) (int, []byte, []recordedSearch) {
	t.Helper()

	resp, err := h.client.Get(h.server.URL + "/api/dashboards/ids/" + ids)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body, h.search.snapshot()
}

// viewerWhoCanReadOneDashboard is a signed-in Viewer with dashboards:read on
// one dashboard. The route's evaluator takes the action and no scopes, so this
// grant is enough to pass it.
func viewerWhoCanReadOneDashboard() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  7,
		OrgID:   1,
		OrgRole: org.RoleViewer,
		Login:   "viewer",
		Permissions: map[int64]map[string][]string{
			1: {
				dashboards.ActionDashboardsRead: {dashboards.ScopeDashboardsPrefix + "uid-1"},
			},
		},
	}
}
