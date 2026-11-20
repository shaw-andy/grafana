package search

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

func TestInSearcherFacetQueryCapsDocumentWindow(t *testing.T) {
	// Post-rank authorization is off, which is the default (search_post_rank_authz).
	backend, err := NewBleveBackend(BleveOptions{
		Root:          t.TempDir(),
		FileThreshold: 5,
		SearchFields: resource.NewSearchFieldsRegistry(nil, nil, map[resource.LowerGroupResource]resource.SearchFieldsProvider{
			resource.NewLowerGroupResource("dashboard.grafana.app", "dashboards"): DashboardSearchFieldsProviderForTest(),
		}),
	}, nil)
	require.NoError(t, err)
	t.Cleanup(backend.Stop)

	ctx := identity.WithRequester(context.Background(), &user.SignedInUser{Namespace: "default"})
	index, err := backend.BuildIndex(ctx, resource.NamespacedResource{
		Namespace: "default",
		Group:     "dashboard.grafana.app",
		Resource:  "dashboards",
	}, 0, "test", func(index resource.ResourceIndex) (int64, error) {
		return 0, nil
	}, nil, false, time.Time{}, 0)
	require.NoError(t, err)

	bleveIdx, ok := index.(*bleveIndex)
	require.True(t, ok)
	require.False(t, bleveIdx.postRankAuthzEnabled)

	key := &resourcepb.ResourceKey{
		Namespace: "default",
		Group:     "dashboard.grafana.app",
		Resource:  "dashboards",
	}
	capSize := bleveIdx.postRankAuthz.facetWindowSize()
	require.Positive(t, capSize)
	require.Less(t, capSize, 100000)

	t.Run("a tags facet does not use a 100000 document limit as the hit size", func(t *testing.T) {
		searchReq, errResult := bleveIdx.toBleveSearchRequest(ctx, &resourcepb.ResourceSearchRequest{
			Options: &resourcepb.ListOptions{Key: key},
			Limit:   100000,
			Facet: map[string]*resourcepb.ResourceSearchRequest_Facet{
				"tags": {Field: "tags", Limit: 100000},
			},
		}, nil, false, nil)
		require.Nil(t, errResult)
		require.LessOrEqual(t, searchReq.Size, capSize)
	})

	t.Run("a small page is left alone", func(t *testing.T) {
		searchReq, errResult := bleveIdx.toBleveSearchRequest(ctx, &resourcepb.ResourceSearchRequest{
			Options: &resourcepb.ListOptions{Key: key},
			Limit:   50,
			Facet: map[string]*resourcepb.ResourceSearchRequest_Facet{
				"tags": {Field: "tags", Limit: 50},
			},
		}, nil, false, nil)
		require.Nil(t, errResult)
		require.Equal(t, 50, searchReq.Size)
	})
}
