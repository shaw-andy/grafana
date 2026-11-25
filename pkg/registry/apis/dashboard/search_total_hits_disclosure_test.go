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

	authlib "github.com/grafana/authlib/types"
	dashboardapp "github.com/grafana/grafana/apps/dashboard/pkg/apis"
	dashboardv0alpha1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	usearch "github.com/grafana/grafana/pkg/storage/unified/search"
	"github.com/grafana/grafana/pkg/storage/unified/search/builders"
)

// GET /apis/dashboard.grafana.app/.../search with limit=1 returns totalHits
// straight from the index. A viewer who can see one of two matches must not
// learn that the other dashboard exists.

func TestDoSearchTotalHits_LimitOneDoesNotCountHiddenDashboards(t *testing.T) {
	index := newDashboardDisclosureIndex(t)
	require.NoError(t, index.BulkIndex(&resource.BulkIndexRequest{Items: []*resource.BulkIndexItem{
		dashboardDisclosureItem("team-overview", "Team Overview Plan", "visible"),
		dashboardDisclosureItem("acquisition-plan", "Acquisition Plan", "secret"),
	}}))

	h := &SearchHandler{
		client: &dashboardDisclosureClient{
			idx: index,
			ac:  &dashboardFolderAllow{allowed: map[string]bool{"visible": true}},
		},
		log:    log.New("test"),
		tracer: tracing.NewNoopTracerService(),
	}
	viewer := &user.SignedInUser{Namespace: "default", OrgRole: org.RoleViewer}

	cases := []string{
		"/search?limit=1&type=dashboard&tag=leak",
		"/search?limit=1&type=dashboard&query=plan",
		"/search?limit=1&type=dashboard&panelType=timeseries",
		"/search?limit=1&type=dashboard&dataSourceType=prometheus",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req = req.WithContext(identity.WithRequester(req.Context(), viewer))
			h.DoSearch(rr, req)

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			var out dashboardv0alpha1.SearchResults
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
			require.Len(t, out.Hits, 1, rr.Body.String())
			require.Equal(t, "team-overview", out.Hits[0].Name)
			require.Equal(t, int64(1), out.TotalHits, "totalHits must not include the hidden dashboard")
		})
	}
}

func newDashboardDisclosureIndex(t *testing.T) resource.ResourceIndex {
	t.Helper()
	key := resource.NamespacedResource{Namespace: "default", Group: "dashboard.grafana.app", Resource: "dashboards"}
	backend, err := usearch.NewBleveBackend(usearch.BleveOptions{
		Root:                 t.TempDir(),
		FileThreshold:        9999,
		PostRankAuthzEnabled: true,
		SearchFields: resource.NewSearchFieldsRegistry(nil, nil, map[resource.LowerGroupResource]resource.SearchFieldsProvider{
			resource.NewLowerGroupResource(key.Group, key.Resource): resource.NewManifestBackedProvider(dashboardapp.LocalManifest().ManifestData),
		}),
	}, nil)
	require.NoError(t, err)
	t.Cleanup(backend.Stop)

	ctx := identity.WithRequester(context.Background(), &user.SignedInUser{Namespace: "default"})
	index, err := backend.BuildIndex(ctx, key, 2, "test", func(resource.ResourceIndex) (int64, error) {
		return 0, nil
	}, nil, false, time.Time{}, 0)
	require.NoError(t, err)
	return index
}

func dashboardDisclosureItem(name, title, folder string) *resource.BulkIndexItem {
	return &resource.BulkIndexItem{
		Action: resource.ActionIndex,
		Doc: &resource.IndexableDocument{
			RV:     1,
			Name:   name,
			Title:  title,
			Tags:   []string{"leak"},
			Folder: folder,
			Key: &resourcepb.ResourceKey{
				Name: name, Namespace: "default", Group: "dashboard.grafana.app", Resource: "dashboards",
			},
			Fields: map[string]any{
				builders.DASHBOARD_PANEL_TYPES: []string{"timeseries"},
				builders.DASHBOARD_DS_TYPES:    []string{"prometheus"},
			},
		},
	}
}

type dashboardDisclosureClient struct {
	resourcepb.ResourceIndexClient
	idx resource.ResourceIndex
	ac  authlib.AccessClient
}

func (c *dashboardDisclosureClient) Search(ctx context.Context, in *resourcepb.ResourceSearchRequest, _ ...grpc.CallOption) (*resourcepb.ResourceSearchResponse, error) {
	return c.idx.Search(ctx, c.ac, in, nil, nil)
}

type dashboardFolderAllow struct {
	allowed map[string]bool
}

func (c *dashboardFolderAllow) Check(_ context.Context, _ authlib.AuthInfo, _ authlib.CheckRequest, folder string) (authlib.CheckResponse, error) {
	return authlib.CheckResponse{Allowed: c.allowed[folder]}, nil
}

func (c *dashboardFolderAllow) Compile(_ context.Context, _ authlib.AuthInfo, _ authlib.ListRequest) (authlib.ItemChecker, authlib.Zookie, error) {
	return func(_, folder string) bool { return c.allowed[folder] }, authlib.NoopZookie{}, nil
}

func (c *dashboardFolderAllow) BatchCheck(_ context.Context, _ authlib.AuthInfo, req authlib.BatchCheckRequest) (authlib.BatchCheckResponse, error) {
	results := make(map[string]authlib.BatchCheckResult, len(req.Checks))
	for _, item := range req.Checks {
		results[item.CorrelationID] = authlib.BatchCheckResult{Allowed: c.allowed[item.Folder]}
	}
	return authlib.BatchCheckResponse{Results: results}, nil
}
