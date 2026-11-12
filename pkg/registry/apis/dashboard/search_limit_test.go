package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	dashboardapp "github.com/grafana/grafana/apps/dashboard/pkg/apis"
	dashboardv0alpha1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/storage/unified/search"
)

// legacySearchLimit is the maximum the legacy /api/search endpoint accepts.
// Dashboard API search has to refuse anything outside 1..legacySearchLimit
// before it asks the index for a hit window. See pkg/api/search.go.
const legacySearchLimit = 5000

// recordingSearchIndex forwards Search to a real bleve index and counts calls.
// Refusal tests fail when the handler reaches the index at all.
type recordingSearchIndex struct {
	resourcepb.ResourceIndexClient
	resourcepb.ResourceStoreClient
	resourcepb.ResourceStatsClient
	resourcepb.ManagedObjectIndexClient
	resourcepb.BulkStoreClient
	resourcepb.BlobStoreClient
	resourcepb.DiagnosticsClient
	resourcepb.QuotasClient

	idx   resource.ResourceIndex
	calls int
	last  *resourcepb.ResourceSearchRequest
}

func (c *recordingSearchIndex) Search(ctx context.Context, in *resourcepb.ResourceSearchRequest, _ ...grpc.CallOption) (*resourcepb.ResourceSearchResponse, error) {
	c.calls++
	c.last = in
	return c.idx.Search(ctx, nil, in, nil, resource.NewSearchStats("dashboard-search-limit"))
}

func TestDashboardSearchLimitIsCappedBeforeTheIndex(t *testing.T) {
	index := newDashboardSearchIndex(t)
	requester := &user.SignedInUser{Namespace: "default"}

	t.Run("legacy maximum returns every indexed dashboard", func(t *testing.T) {
		client := &recordingSearchIndex{idx: index}
		rr := doDashboardSearch(t, client, requester, "type=dashboard&limit=5000")

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.Equal(t, 1, client.calls)
		require.Equal(t, int64(legacySearchLimit), client.last.Limit)
		require.Equal(t, []string{"alpha", "beta"}, hitNames(t, rr))
		require.ElementsMatch(t, []string{"Alpha Dashboard", "Beta Dashboard"}, hitTitles(t, rr))
	})

	t.Run("limit one above the legacy maximum never reaches the index", func(t *testing.T) {
		client := &recordingSearchIndex{idx: index}
		rr := doDashboardSearch(t, client, requester, "type=dashboard&limit=5001")
		requireSearchRefused(t, rr, client)
	})

	t.Run("platform max int limit never reaches the index", func(t *testing.T) {
		client := &recordingSearchIndex{idx: index}
		rr := doDashboardSearch(t, client, requester, "type=dashboard&limit=2147483647")
		requireSearchRefused(t, rr, client)
	})

	t.Run("limit above max int32 never reaches the index", func(t *testing.T) {
		client := &recordingSearchIndex{idx: index}
		rr := doDashboardSearch(t, client, requester, "type=dashboard&limit=2147483648")
		requireSearchRefused(t, rr, client)
	})

	t.Run("zero limit is refused before the index", func(t *testing.T) {
		client := &recordingSearchIndex{idx: index}
		rr := doDashboardSearch(t, client, requester, "type=dashboard&limit=0")
		requireSearchRefused(t, rr, client)
	})

	t.Run("negative limit is refused before the index", func(t *testing.T) {
		client := &recordingSearchIndex{idx: index}
		rr := doDashboardSearch(t, client, requester, "type=dashboard&limit=-1")
		requireSearchRefused(t, rr, client)
	})

	t.Run("zero limit with a positive offset does not panic and does not search", func(t *testing.T) {
		client := &recordingSearchIndex{idx: index}
		var rr *httptest.ResponseRecorder
		require.NotPanics(t, func() {
			rr = doDashboardSearch(t, client, requester, "type=dashboard&limit=0&offset=1")
		})
		requireSearchRefused(t, rr, client)
	})

	t.Run("unparsed limit with a positive offset does not panic and does not search", func(t *testing.T) {
		client := &recordingSearchIndex{idx: index}
		var rr *httptest.ResponseRecorder
		require.NotPanics(t, func() {
			rr = doDashboardSearch(t, client, requester, "type=dashboard&limit=nope&offset=1")
		})
		requireSearchRefused(t, rr, client)
	})

	t.Run("offset above the legacy maximum never reaches the index", func(t *testing.T) {
		client := &recordingSearchIndex{idx: index}
		rr := doDashboardSearch(t, client, requester, "type=dashboard&limit=10&offset=5001")
		requireSearchRefused(t, rr, client)
	})

	t.Run("negative offset does not panic and never reaches the index", func(t *testing.T) {
		client := &recordingSearchIndex{idx: index}
		var rr *httptest.ResponseRecorder
		require.NotPanics(t, func() {
			rr = doDashboardSearch(t, client, requester, "type=dashboard&limit=10&offset=-1")
		})
		requireSearchRefused(t, rr, client)
	})

	t.Run("page that computes an offset above the legacy maximum never reaches the index", func(t *testing.T) {
		client := &recordingSearchIndex{idx: index}
		// offset = (102-1)*50 = 5050, which is past the legacy maximum.
		rr := doDashboardSearch(t, client, requester, "type=dashboard&limit=50&page=102")
		requireSearchRefused(t, rr, client)
	})

	t.Run("page at the legacy offset maximum still searches", func(t *testing.T) {
		client := &recordingSearchIndex{idx: index}
		// offset = (101-1)*50 = 5000.
		rr := doDashboardSearch(t, client, requester, "type=dashboard&limit=50&page=101")
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.Equal(t, 1, client.calls)
		require.Equal(t, int64(50), client.last.Limit)
		require.Equal(t, int64(legacySearchLimit), client.last.Offset)
	})
}

func requireSearchRefused(t *testing.T, rr *httptest.ResponseRecorder, client *recordingSearchIndex) {
	t.Helper()
	limit := int64(0)
	offset := int64(0)
	if client.last != nil {
		limit = client.last.Limit
		offset = client.last.Offset
	}
	require.Zerof(t, client.calls, "search index ran with limit=%d offset=%d body=%s", limit, offset, rr.Body.String())
	require.Containsf(t, []int{http.StatusBadRequest, http.StatusUnprocessableEntity}, rr.Code, "body=%s", rr.Body.String())
}

func doDashboardSearch(t *testing.T, client *recordingSearchIndex, requester identity.Requester, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	handler := NewSearchHandler(tracing.NewNoopTracerService(), client, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/search?"+rawQuery, nil)
	req = req.WithContext(identity.WithRequester(req.Context(), requester))
	handler.DoSearch(rr, req)
	return rr
}

func hitNames(t *testing.T, rr *httptest.ResponseRecorder) []string {
	t.Helper()
	results := decodeSearchResults(t, rr)
	names := make([]string, 0, len(results.Hits))
	for _, hit := range results.Hits {
		names = append(names, hit.Name)
	}
	return names
}

func hitTitles(t *testing.T, rr *httptest.ResponseRecorder) []string {
	t.Helper()
	results := decodeSearchResults(t, rr)
	titles := make([]string, 0, len(results.Hits))
	for _, hit := range results.Hits {
		titles = append(titles, hit.Title)
	}
	return titles
}

func decodeSearchResults(t *testing.T, rr *httptest.ResponseRecorder) dashboardv0alpha1.SearchResults {
	t.Helper()
	var results dashboardv0alpha1.SearchResults
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &results), rr.Body.String())
	return results
}

func newDashboardSearchIndex(t *testing.T) resource.ResourceIndex {
	t.Helper()
	key := resource.NamespacedResource{
		Namespace: "default",
		Group:     "dashboard.grafana.app",
		Resource:  "dashboards",
	}
	backend, err := search.NewBleveBackend(search.BleveOptions{
		Root:          t.TempDir(),
		FileThreshold: 5,
		SearchFields: resource.NewSearchFieldsRegistry(nil, nil, map[resource.LowerGroupResource]resource.SearchFieldsProvider{
			resource.NewLowerGroupResource(key.Group, key.Resource): resource.NewManifestBackedProvider(dashboardapp.LocalManifest().ManifestData),
		}),
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Stop() })

	ctx := identity.WithRequester(context.Background(), &user.SignedInUser{Namespace: key.Namespace})
	index, err := backend.BuildIndex(ctx, key, 2, "test", func(index resource.ResourceIndex) (int64, error) {
		items := []*resource.BulkIndexItem{
			dashboardDoc(key, "alpha", "Alpha Dashboard"),
			dashboardDoc(key, "beta", "Beta Dashboard"),
		}
		if err := index.BulkIndex(&resource.BulkIndexRequest{Items: items}); err != nil {
			return 0, err
		}
		return 1, nil
	}, nil, false, time.Time{}, 0)
	require.NoError(t, err)
	return index
}

func dashboardDoc(key resource.NamespacedResource, name, title string) *resource.BulkIndexItem {
	return &resource.BulkIndexItem{
		Action: resource.ActionIndex,
		Doc: &resource.IndexableDocument{
			RV:    1,
			Name:  name,
			Title: title,
			Key: &resourcepb.ResourceKey{
				Name:      name,
				Namespace: key.Namespace,
				Group:     key.Group,
				Resource:  key.Resource,
			},
		},
	}
}
