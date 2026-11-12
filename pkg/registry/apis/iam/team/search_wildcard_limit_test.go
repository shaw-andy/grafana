package team

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/runtime/schema"

	iamv0alpha1 "github.com/grafana/grafana/apps/iam/pkg/apis/iam/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/storage/unified/search"
)

// maxCallerSearchQueryBytes matches the cap already enforced for vector and
// hybrid search. Team search must refuse a longer query, and must not execute
// a caller wildcard, before the query reaches Bleve.
const maxCallerSearchQueryBytes = 1000

const (
	teamCanaryName  = "canary-team"
	teamCanaryTitle = "a-uniquephrase"
)

func TestTeamSearchDoesNotRunCallerWildcards(t *testing.T) {
	client := newTeamIndex(t)
	handler := NewSearchHandler(tracing.NewNoopTracerService(), client, nil)
	viewer := &user.SignedInUser{UserID: 7, OrgID: 1, Namespace: "default"}

	t.Run("literal query still matches", func(t *testing.T) {
		rec := doTeamSearch(t, handler, viewer, "uniquephrase")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), teamCanaryName)
	})

	t.Run("leading wildcard", func(t *testing.T) {
		assertTeamQueryRefused(t, handler, client, viewer, "*a*uniquephrase*")
	})

	t.Run("repeated wildcards", func(t *testing.T) {
		assertTeamQueryRefused(t, handler, client, viewer, "*a*uniquephrase*")
		assertTeamQueryRefused(t, handler, client, viewer, "*a*uniquephrase*")
	})

	t.Run("query longer than the cap", func(t *testing.T) {
		before := client.calls
		rec := doTeamSearch(t, handler, viewer, strings.Repeat("b", maxCallerSearchQueryBytes+1))
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		require.Equal(t, before, client.calls, "over-long query reached the index")
	})
}

func assertTeamQueryRefused(t *testing.T, handler *SearchHandler, client *teamIndex, viewer identity.Requester, query string) {
	t.Helper()
	before := client.calls
	rec := doTeamSearch(t, handler, viewer, query)
	require.NotContains(t, rec.Body.String(), teamCanaryName, "status %d query %q body %s", rec.Code, client.lastQuery, rec.Body.String())
	if client.calls > before {
		require.False(t, teamQueryUnconstrained(client.lastQuery), "index ran caller query %q", client.lastQuery)
	} else {
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	}
	require.Contains(t, []int{http.StatusOK, http.StatusBadRequest}, rec.Code, rec.Body.String())
}

func doTeamSearch(t *testing.T, handler *SearchHandler, viewer identity.Requester, query string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/teams/search?query="+url.QueryEscape(query), nil)
	req = req.WithContext(identity.WithRequester(req.Context(), viewer))
	handler.DoTeamSearch(rec, req)
	return rec
}

func teamQueryUnconstrained(q string) bool {
	if len(q) > maxCallerSearchQueryBytes {
		return true
	}
	body := strings.TrimSuffix(strings.TrimPrefix(q, "*"), "*")
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' {
			i++
			continue
		}
		if body[i] == '*' || body[i] == '?' {
			return true
		}
	}
	return false
}

type teamIndex struct {
	resourcepb.ResourceIndexClient
	index     resource.ResourceIndex
	calls     int
	lastQuery string
}

func (c *teamIndex) Search(ctx context.Context, req *resourcepb.ResourceSearchRequest, _ ...grpc.CallOption) (*resourcepb.ResourceSearchResponse, error) {
	c.calls++
	c.lastQuery = req.GetQuery()
	return c.index.Search(ctx, nil, req, nil, &resource.SearchStats{})
}

func newTeamIndex(t *testing.T) *teamIndex {
	t.Helper()
	gr := iamv0alpha1.TeamResourceInfo.GroupResource()
	key := resource.NamespacedResource{Namespace: "default", Group: gr.Group, Resource: gr.Resource}
	backend, err := search.NewBleveBackend(search.BleveOptions{
		Root:          t.TempDir(),
		FileThreshold: 9999,
		SearchFields: resource.NewSearchFieldsRegistry(nil, nil, map[resource.LowerGroupResource]resource.SearchFieldsProvider{
			resource.NewLowerGroupResource(key.Group, key.Resource): teamSearchFields{},
		}),
	}, nil)
	require.NoError(t, err)
	t.Cleanup(backend.Stop)

	ctx := identity.WithRequester(context.Background(), &user.SignedInUser{Namespace: key.Namespace})
	index, err := backend.BuildIndex(ctx, key, 2, "test", func(resource.ResourceIndex) (int64, error) {
		return 0, nil
	}, nil, false, time.Time{}, 0)
	require.NoError(t, err)
	require.NoError(t, index.BulkIndex(&resource.BulkIndexRequest{Items: []*resource.BulkIndexItem{
		{Action: resource.ActionIndex, Doc: &resource.IndexableDocument{
			RV: 1, Name: teamCanaryName, Title: teamCanaryTitle,
			Key: &resourcepb.ResourceKey{Name: teamCanaryName, Namespace: key.Namespace, Group: key.Group, Resource: key.Resource},
		}},
	}}))
	return &teamIndex{index: index}
}

// teamSearchFields declares the columns team search asks the index to return,
// so the request is not rejected as an unknown field before the query runs.
type teamSearchFields struct{}

func (teamSearchFields) Fields(schema.GroupVersionResource) []resource.SearchFieldDefinition {
	return []resource.SearchFieldDefinition{
		{Name: "email", Type: resource.SearchFieldTypeString, Capabilities: []resource.SearchCapability{resource.SearchCapabilityRetrieve}},
		{Name: "provisioned", Type: resource.SearchFieldTypeBoolean, Capabilities: []resource.SearchCapability{resource.SearchCapabilityRetrieve}},
		{Name: "externalUID", Type: resource.SearchFieldTypeString, Capabilities: []resource.SearchCapability{resource.SearchCapabilityRetrieve}},
	}
}

func (teamSearchFields) PreferredVersion(string, string) string   { return "" }
func (teamSearchFields) IndexAffectingHash(string, string) string { return "" }
