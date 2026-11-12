package search

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	searchv0 "github.com/grafana/grafana/pkg/apis/search/v0alpha1"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/storage/unified/search"
)

// maxCallerSearchQueryBytes matches the cap vector and hybrid search already
// enforce. Live and trash search must refuse a longer text value, and must not
// execute a caller wildcard, before the query reaches Bleve.
const maxCallerSearchQueryBytes = 1000

const (
	searchCanaryName  = "canary-dash"
	searchCanaryTitle = "a-uniquephrase"
)

func TestSearchAPIDoesNotRunCallerWildcards(t *testing.T) {
	client := newExecutingIndex(t)
	handler := NewHandler(client, testProvider(), noop.NewTracerProvider().Tracer(""))

	t.Run("literal text still matches", func(t *testing.T) {
		rec := postSearch(t, handler.SearchFor(testKind), textQuery("uniquephrase"))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), searchCanaryName)
	})

	t.Run("text wildcard", func(t *testing.T) {
		assertSearchRefused(t, client, func() *httptest.ResponseRecorder {
			return postSearch(t, handler.SearchFor(testKind), textQuery("*a*uniquephrase*"))
		})
	})

	t.Run("repeated text wildcards", func(t *testing.T) {
		body := textQuery("*a*uniquephrase*")
		assertSearchRefused(t, client, func() *httptest.ResponseRecorder {
			return postSearch(t, handler.SearchFor(testKind), body)
		})
		assertSearchRefused(t, client, func() *httptest.ResponseRecorder {
			return postSearch(t, handler.SearchFor(testKind), body)
		})
	})

	t.Run("text longer than the cap", func(t *testing.T) {
		before := client.calls
		rec := postSearch(t, handler.SearchFor(testKind), textQuery(strings.Repeat("b", maxCallerSearchQueryBytes+1)))
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		require.Equal(t, before, client.calls, "over-long text reached the index")
	})
}

func TestTrashSearchDoesNotRunCallerWildcards(t *testing.T) {
	client := newExecutingIndex(t)
	handler := NewHandler(client, testProvider(), noop.NewTracerProvider().Tracer(""))

	t.Run("text wildcard", func(t *testing.T) {
		assertSearchRefused(t, client, func() *httptest.ResponseRecorder {
			return postSearch(t, handler.TrashFor(testKind), trashTextQuery("*a*uniquephrase*"))
		})
	})

	t.Run("text longer than the cap", func(t *testing.T) {
		before := client.calls
		rec := postSearch(t, handler.TrashFor(testKind), trashTextQuery(strings.Repeat("b", maxCallerSearchQueryBytes+1)))
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		require.Equal(t, before, client.calls, "over-long trash text reached the index")
	})
}

func assertSearchRefused(t *testing.T, client *executingIndex, do func() *httptest.ResponseRecorder) {
	t.Helper()
	before := client.calls
	rec := do()
	require.NotContains(t, rec.Body.String(), searchCanaryName, "status %d query %q body %s", rec.Code, client.lastQuery, rec.Body.String())
	if client.calls > before {
		require.False(t, unconstrainedQuery(client.lastQuery), "index ran caller query %q", client.lastQuery)
	} else {
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	}
	require.Contains(t, []int{http.StatusOK, http.StatusBadRequest}, rec.Code, rec.Body.String())
}

func postSearch(t *testing.T, h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/search", strings.NewReader(body))
	ctx := identity.WithRequester(req.Context(), &identity.StaticRequester{Namespace: "default"})
	ctx = request.WithNamespace(ctx, "default")
	rec := httptest.NewRecorder()
	h(rec, req.WithContext(ctx))
	return rec
}

func textQuery(value string) string {
	return `{
		"apiVersion": "` + searchv0.APIVERSION + `",
		"kind": "` + searchv0.KindSearchQuery + `",
		"where": {"text": {"value": "` + value + `"}}
	}`
}

func trashTextQuery(value string) string {
	return `{
		"apiVersion": "` + searchv0.APIVERSION + `",
		"kind": "` + searchv0.KindTrashQuery + `",
		"where": {"text": {"value": "` + value + `"}}
	}`
}

func unconstrainedQuery(q string) bool {
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

type executingIndex struct {
	resourcepb.ResourceIndexClient
	index     resource.ResourceIndex
	calls     int
	lastQuery string
}

func (e *executingIndex) Search(ctx context.Context, req *resourcepb.ResourceSearchRequest, _ ...grpc.CallOption) (*resourcepb.ResourceSearchResponse, error) {
	e.calls++
	e.lastQuery = req.GetQuery()
	return e.index.Search(ctx, nil, req, nil, &resource.SearchStats{})
}

func newExecutingIndex(t *testing.T) *executingIndex {
	t.Helper()
	key := resource.NamespacedResource{
		Namespace: "default",
		Group:     testKind.group,
		Resource:  testKind.resource,
	}
	backend, err := search.NewBleveBackend(search.BleveOptions{
		Root:          t.TempDir(),
		FileThreshold: 9999,
		SearchFields:  resource.NewSearchFieldsRegistry(nil, nil, nil),
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
			RV: 1, Name: searchCanaryName, Title: searchCanaryTitle,
			Key: &resourcepb.ResourceKey{Name: searchCanaryName, Namespace: key.Namespace, Group: key.Group, Resource: key.Resource},
		}},
		{Action: resource.ActionIndex, Doc: &resource.IndexableDocument{
			RV: 1, Name: "other", Title: "ordinary dashboard",
			Key: &resourcepb.ResourceKey{Name: "other", Namespace: key.Namespace, Group: key.Group, Resource: key.Resource},
		}},
	}}))
	return &executingIndex{index: index}
}
