package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"

	dashboardapp "github.com/grafana/grafana/apps/dashboard/pkg/apis"
	dashboardv0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/apiserver/client"
	"github.com/grafana/grafana/pkg/services/apiserver/endpoints/request"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/storage/unified/search"
)

// maxDashboardTagFacetTerms is the largest tag facet the dashboard search API
// already accepts. A tags listing has no reason to ask for more.
const maxDashboardTagFacetTerms int64 = 1000

// storedDescriptionMarker is written into each indexed dashboard description.
// The tags handler only needs facet counts, so this payload must not come back
// as a search hit.
const storedDescriptionMarker = "dashboard-tags-stored-payload"

func TestGetDashboardTagsDoesNotMaterializeDashboardDocuments(t *testing.T) {
	cfg := setting.NewCfg()
	const orgID int64 = 1
	namespace := request.GetNamespaceMapper(cfg)(orgID)

	backend, err := search.NewBleveBackend(search.BleveOptions{
		Root:          t.TempDir(),
		FileThreshold: 5,
		SearchFields: resource.NewSearchFieldsRegistry(nil, nil, map[resource.LowerGroupResource]resource.SearchFieldsProvider{
			resource.NewLowerGroupResource(dashboardv0.GROUP, dashboardv0.DASHBOARD_RESOURCE): resource.NewManifestBackedProvider(dashboardapp.LocalManifest().ManifestData),
		}),
	}, nil)
	require.NoError(t, err)
	t.Cleanup(backend.Stop)

	ctx := identity.WithRequester(context.Background(), &user.SignedInUser{Namespace: namespace})
	index, err := backend.BuildIndex(ctx, resource.NamespacedResource{
		Namespace: namespace,
		Group:     dashboardv0.GROUP,
		Resource:  dashboardv0.DASHBOARD_RESOURCE,
	}, 3, "test", func(index resource.ResourceIndex) (int64, error) {
		return 0, nil
	}, nil, false, time.Time{}, 0)
	require.NoError(t, err)

	docs := []struct {
		name string
		tags []string
	}{
		{name: "dash-a", tags: []string{"shared", "only-a"}},
		{name: "dash-b", tags: []string{"shared", "only-b"}},
		{name: "dash-c", tags: []string{"shared"}},
	}
	items := make([]*resource.BulkIndexItem, 0, len(docs))
	for _, doc := range docs {
		items = append(items, &resource.BulkIndexItem{
			Action: resource.ActionIndex,
			Doc: &resource.IndexableDocument{
				RV:          1,
				Name:        doc.name,
				Title:       doc.name,
				Description: storedDescriptionMarker + "-" + doc.name,
				Tags:        doc.tags,
				Key: &resourcepb.ResourceKey{
					Name:      doc.name,
					Namespace: namespace,
					Group:     dashboardv0.GROUP,
					Resource:  dashboardv0.DASHBOARD_RESOURCE,
				},
				Folder: "general",
			},
		})
	}
	require.NoError(t, index.BulkIndex(&resource.BulkIndexRequest{Items: items}))

	// Access is nil on purpose: the authz gRPC client is unset unless
	// authZGRPCServer is enabled, and that flag defaults off. Search then
	// skips the in-searcher permission filter.
	searchClient := &recordingIndexClient{index: index}
	handler := client.NewK8sHandler(
		request.GetNamespaceMapper(cfg),
		schema.GroupVersionResource{Group: dashboardv0.GROUP, Version: dashboardv0.VERSION, Resource: dashboardv0.DASHBOARD_RESOURCE},
		func(context.Context) (*rest.Config, error) { return nil, nil },
		nil,
		searchClient,
	)

	svc := &DashboardServiceImpl{cfg: cfg, k8sclient: tagsHandler{K8sHandler: handler}}
	got, err := svc.GetDashboardTags(ctx, &dashboards.GetDashboardTagsQuery{OrgID: orgID})
	require.NoError(t, err)

	counts := map[string]int{}
	for _, item := range got {
		counts[item.Term] = item.Count
	}
	require.Equal(t, 3, counts["shared"])
	require.Equal(t, 1, counts["only-a"])
	require.Equal(t, 1, counts["only-b"])

	require.NotNil(t, searchClient.got)
	require.NotNil(t, searchClient.resp)
	require.Nil(t, searchClient.resp.Error)
	require.Equal(t, int64(0), searchClient.got.Limit, "tag listing must not request dashboard documents")
	facet, ok := searchClient.got.Facet["tags"]
	require.True(t, ok)
	require.Equal(t, "tags", facet.Field)
	require.Positive(t, facet.Limit)
	require.LessOrEqual(t, facet.Limit, maxDashboardTagFacetTerms)
	require.Empty(t, searchClient.got.Fields)

	require.NotNil(t, searchClient.resp)
	require.Nil(t, searchClient.resp.Error)
	require.Empty(t, searchClient.resp.Rows, "matching dashboards were loaded into the search response and then discarded")
}

type tagsHandler struct {
	client.K8sHandler
}

func (tagsHandler) GetWithPreferredAPIVersion(context.Context, string, int64, v1.GetOptions, string, ...string) (*unstructured.Unstructured, error) {
	return nil, status.Error(codes.Unimplemented, "unused")
}

// recordingIndexClient forwards Search to the real bleve index. Other RPCs are
// unused by GetDashboardTags.
type recordingIndexClient struct {
	index resource.ResourceIndex
	got   *resourcepb.ResourceSearchRequest
	resp  *resourcepb.ResourceSearchResponse
}

func (c *recordingIndexClient) Search(ctx context.Context, in *resourcepb.ResourceSearchRequest, _ ...grpc.CallOption) (*resourcepb.ResourceSearchResponse, error) {
	c.got = &resourcepb.ResourceSearchRequest{
		Limit:  in.Limit,
		Fields: append([]string(nil), in.Fields...),
		Facet:  map[string]*resourcepb.ResourceSearchRequest_Facet{},
	}
	for name, facet := range in.Facet {
		copied := *facet
		c.got.Facet[name] = &copied
	}
	resp, err := c.index.Search(ctx, nil, in, nil, resource.NewSearchStats("dashboard-tags"))
	c.resp = resp
	return resp, err
}

func (c *recordingIndexClient) GetStats(context.Context, *resourcepb.ResourceStatsRequest, ...grpc.CallOption) (*resourcepb.ResourceStatsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unused")
}

func (c *recordingIndexClient) RebuildIndexes(context.Context, *resourcepb.RebuildIndexesRequest, ...grpc.CallOption) (*resourcepb.RebuildIndexesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unused")
}

func (c *recordingIndexClient) VectorSearch(context.Context, *resourcepb.VectorSearchRequest, ...grpc.CallOption) (*resourcepb.VectorSearchResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unused")
}

func (c *recordingIndexClient) HybridSearch(context.Context, *resourcepb.HybridSearchRequest, ...grpc.CallOption) (*resourcepb.HybridSearchResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unused")
}
