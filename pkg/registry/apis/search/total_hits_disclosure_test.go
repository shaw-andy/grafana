package search

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"k8s.io/apiserver/pkg/endpoints/request"

	authlib "github.com/grafana/authlib/types"
	dashboardapp "github.com/grafana/grafana/apps/dashboard/pkg/apis"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	searchv0 "github.com/grafana/grafana/pkg/apis/search/v0alpha1"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	usearch "github.com/grafana/grafana/pkg/storage/unified/search"
)

// A viewer who can open one dashboard posts a title filter that also names a
// dashboard they cannot open. The search envelope must not report the
// pre-authorization match count.

func TestSearchAPITotalHits_LimitOneDoesNotCountHiddenDashboard(t *testing.T) {
	index := newDisclosureIndex(t)
	require.NoError(t, index.BulkIndex(&resource.BulkIndexRequest{Items: []*resource.BulkIndexItem{
		disclosureItem("team-overview", "Team Overview", "visible"),
		disclosureItem("acquisition-plan", "Acquisition Plan", "secret"),
	}}))

	h := NewHandler(&disclosureIndexClient{
		idx: index,
		ac:  &folderAllowClient{allowed: map[string]bool{"visible": true}},
	}, disclosureFields(), noop.NewTracerProvider().Tracer(""))

	body := `{
		"apiVersion": "` + searchv0.APIVERSION + `",
		"kind": "` + searchv0.KindSearchQuery + `",
		"where": {"filter": {"field": "title", "operator": "In", "values": ["Team Overview", "Acquisition Plan"]}},
		"limit": 1
	}`
	w := postSearch(t, h, body)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var out searchv0.SearchResults
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	require.Len(t, out.Items, 1)
	require.Equal(t, "team-overview", out.Items[0].Resource.Name)
	require.NotEmpty(t, out.Metadata.Continue)

	t.Run("continue", func(t *testing.T) {
		// A continue cursor takes the same unfiltered-total branch. Nothing the
		// viewer may open remains after the first row, so the total is zero.
		continued := `{
			"apiVersion": "` + searchv0.APIVERSION + `",
			"kind": "` + searchv0.KindSearchQuery + `",
			"where": {"filter": {"field": "title", "operator": "In", "values": ["Team Overview", "Acquisition Plan"]}},
			"limit": 1,
			"continue": "` + out.Metadata.Continue + `"
		}`
		w2 := postSearch(t, h, continued)
		require.Equal(t, http.StatusOK, w2.Code, w2.Body.String())
		var page2 searchv0.SearchResults
		require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &page2))
		require.Empty(t, page2.Items)
		require.Equal(t, int64(0), page2.Metadata.TotalHits)
		require.Equal(t, searchv0.TotalHitsAtMost, page2.Metadata.TotalHitsRelation)
	})

	require.Equal(t, int64(1), out.Metadata.TotalHits)
	require.Equal(t, searchv0.TotalHitsAtMost, out.Metadata.TotalHitsRelation)
}

func postSearch(t *testing.T, h *Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/search", strings.NewReader(body))
	viewer := &identity.StaticRequester{
		Type:      authlib.TypeUser,
		UserID:    1,
		Namespace: "default",
		OrgRole:   org.RoleViewer,
	}
	ctx := identity.WithRequester(r.Context(), viewer)
	ctx = request.WithNamespace(ctx, "default")
	w := httptest.NewRecorder()
	h.SearchFor(kindRef{
		group:    "dashboard.grafana.app",
		version:  "v1",
		resource: "dashboards",
		kind:     "Dashboard",
	})(w, r.WithContext(ctx))
	return w
}

func newDisclosureIndex(t *testing.T) resource.ResourceIndex {
	t.Helper()
	key := resource.NamespacedResource{Namespace: "default", Group: "dashboard.grafana.app", Resource: "dashboards"}
	backend, err := usearch.NewBleveBackend(usearch.BleveOptions{
		Root:                 t.TempDir(),
		FileThreshold:        9999,
		PostRankAuthzEnabled: true,
		SearchFields: resource.NewSearchFieldsRegistry(nil, nil, map[resource.LowerGroupResource]resource.SearchFieldsProvider{
			resource.NewLowerGroupResource(key.Group, key.Resource): disclosureFields(),
		}),
	}, nil)
	require.NoError(t, err)
	t.Cleanup(backend.Stop)

	ctx := identity.WithRequester(context.Background(), &identity.StaticRequester{Namespace: "default"})
	index, err := backend.BuildIndex(ctx, key, 2, "test", func(resource.ResourceIndex) (int64, error) {
		return 0, nil
	}, nil, false, time.Time{}, 0)
	require.NoError(t, err)
	return index
}

func disclosureFields() resource.SearchFieldsProvider {
	return resource.NewManifestBackedProvider(dashboardapp.LocalManifest().ManifestData)
}

func disclosureItem(name, title, folder string) *resource.BulkIndexItem {
	return &resource.BulkIndexItem{
		Action: resource.ActionIndex,
		Doc: &resource.IndexableDocument{
			RV:    1,
			Name:  name,
			Title: title,
			Key: &resourcepb.ResourceKey{
				Name: name, Namespace: "default", Group: "dashboard.grafana.app", Resource: "dashboards",
			},
			Folder: folder,
		},
	}
}

// disclosureIndexClient is the ResourceIndexClient the search handler calls.
// Search runs the real index with the viewer's access client.
type disclosureIndexClient struct {
	resourcepb.ResourceIndexClient
	idx resource.ResourceIndex
	ac  authlib.AccessClient
}

func (c *disclosureIndexClient) Search(ctx context.Context, in *resourcepb.ResourceSearchRequest, _ ...grpc.CallOption) (*resourcepb.ResourceSearchResponse, error) {
	return c.idx.Search(ctx, c.ac, in, nil, nil)
}

// folderAllowClient allows a hit only when its folder is in allowed. That is
// the BatchCheck outcome folder permissions produce for a viewer.
type folderAllowClient struct {
	allowed map[string]bool
}

func (c *folderAllowClient) Check(_ context.Context, _ authlib.AuthInfo, _ authlib.CheckRequest, folder string) (authlib.CheckResponse, error) {
	return authlib.CheckResponse{Allowed: c.allowed[folder]}, nil
}

func (c *folderAllowClient) Compile(_ context.Context, _ authlib.AuthInfo, _ authlib.ListRequest) (authlib.ItemChecker, authlib.Zookie, error) {
	return func(_, folder string) bool { return c.allowed[folder] }, authlib.NoopZookie{}, nil
}

func (c *folderAllowClient) BatchCheck(_ context.Context, _ authlib.AuthInfo, req authlib.BatchCheckRequest) (authlib.BatchCheckResponse, error) {
	results := make(map[string]authlib.BatchCheckResult, len(req.Checks))
	for _, item := range req.Checks {
		results[item.CorrelationID] = authlib.BatchCheckResult{Allowed: c.allowed[item.Folder]}
	}
	return authlib.BatchCheckResponse{Results: results}, nil
}
