package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authnlib "github.com/grafana/authlib/authn"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"

	dashboardv1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	folderv1 "github.com/grafana/grafana/apps/folder/pkg/apis/folder/v1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	grafanaauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/storage/unified/search"
)

// maxCallerSearchQueryBytes is the longest free-text query a caller may hand to
// the index. Vector search and hybrid search already reject a longer query.
// Lexical dashboard search must do the same before the query is executed.
const maxCallerSearchQueryBytes = 1000

const (
	canaryName  = "canary-dash"
	canaryTitle = "a-uniquephrase"
)

// TestDashboardSearchDoesNotRunCallerWildcards is the spec for the dashboard
// search query. It fails while a signed-in caller can hand a wildcard pattern
// to the Bleve index, and passes once an over-long query is rejected before it
// is searched and a pattern containing '*' is either rejected or escaped the
// way user search escapes it.
func TestDashboardSearchDoesNotRunCallerWildcards(t *testing.T) {
	client := newTitleSearchClient(t)
	handler := newSearchHandler(client)
	viewer := signedInViewer()

	t.Run("literal query still matches", func(t *testing.T) {
		before := client.calls
		rec := doDashboardSearch(t, handler, viewer, "/search?type=dashboard&query=uniquephrase")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), canaryName)
		require.Greater(t, client.calls, before)
	})

	t.Run("leading wildcard", func(t *testing.T) {
		assertDashboardQueryRefused(t, handler, client, viewer, "/search?query="+escapeQuery("*uniquephrase*"))
	})

	t.Run("leading wildcard on folder search", func(t *testing.T) {
		assertDashboardQueryRefused(t, handler, client, viewer, "/search?type=folder&query="+escapeQuery("*a*uniquephrase*"))
	})

	t.Run("leading wildcard on dashboard search", func(t *testing.T) {
		assertDashboardQueryRefused(t, handler, client, viewer, "/search?type=dashboard&query="+escapeQuery("*a*uniquephrase*"))
	})

	t.Run("leading wildcard including panel titles", func(t *testing.T) {
		assertDashboardQueryRefused(t, handler, client, viewer, "/search?type=dashboard&panelTitleSearch=true&query="+escapeQuery("*a*uniquephrase*"))
	})

	t.Run("chain of asterisks", func(t *testing.T) {
		assertDashboardQueryRefused(t, handler, client, viewer, "/search?type=dashboard&query="+escapeQuery(strings.Repeat("*", 8)+"uniquephrase"))
	})

	t.Run("repeated wildcards", func(t *testing.T) {
		path := "/search?type=dashboard&query=" + escapeQuery("*a*uniquephrase*")
		assertDashboardQueryRefused(t, handler, client, viewer, path)
		assertDashboardQueryRefused(t, handler, client, viewer, path)
	})

	t.Run("query longer than the cap", func(t *testing.T) {
		before := client.calls
		rec := doDashboardSearch(t, handler, viewer, "/search?type=dashboard&query="+strings.Repeat("b", maxCallerSearchQueryBytes+1))
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		require.Equal(t, before, client.calls, "over-long query reached the index")
		require.NotContains(t, rec.Body.String(), canaryName)
	})
}

func TestDashboardHybridSearchDoesNotRunCallerWildcards(t *testing.T) {
	client := newTitleSearchClient(t)
	handler := newSearchHandler(client)
	viewer := signedInViewer()

	t.Run("leading wildcard", func(t *testing.T) {
		before := client.hybridCalls
		rec := doHybridSearch(t, handler, viewer, "/search/hybrid?query="+escapeQuery("*a*uniquephrase*"))
		require.NotContains(t, rec.Body.String(), canaryName)
		if client.hybridCalls > before {
			require.False(t, queryReachesIndexUnconstrained(client.lastHybridQuery), "hybrid search ran caller query %q", client.lastHybridQuery)
		} else {
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		}
		require.Contains(t, []int{http.StatusOK, http.StatusBadRequest}, rec.Code, rec.Body.String())
	})
}

// TestSignedInViewerMayCallDashboardSearch pins the authorization precondition:
// a non-admin user in their own namespace is allowed to call the search route.
func TestSignedInViewerMayCallDashboardSearch(t *testing.T) {
	path := "/apis/dashboard.grafana.app/v0alpha1/namespaces/default/search"
	attr := requestAttributes(t, http.MethodGet, path)
	require.True(t, attr.IsResourceRequest())
	require.Equal(t, "list", attr.GetVerb())
	require.Equal(t, "search", attr.GetResource())
	require.Equal(t, "dashboard.grafana.app", attr.GetAPIGroup())

	viewer := signedInViewer()
	ctx := identity.WithRequester(context.Background(), viewer)

	nsDecision, _, err := grafanaauthorizer.NewNamespaceAuthorizer().Authorize(ctx, attr)
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionNoOpinion, nsDecision)

	decision, reason, err := grafanaauthorizer.NewServiceAuthorizer().Authorize(ctx, attr)
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision, reason)
}

func newSearchHandler(client *titleSearchClient) *SearchHandler {
	return &SearchHandler{
		log:    log.New("test"),
		client: client,
		tracer: tracing.NewNoopTracerService(),
	}
}

func assertDashboardQueryRefused(t *testing.T, handler *SearchHandler, client *titleSearchClient, viewer identity.Requester, path string) {
	t.Helper()
	before := client.calls
	rec := doDashboardSearch(t, handler, viewer, path)
	require.NotContains(t, rec.Body.String(), canaryName, "caller wildcard matched a title, query cost %v, status %d, body %s", client.lastCost, rec.Code, rec.Body.String())
	if client.calls > before {
		require.False(t, queryReachesIndexUnconstrained(client.lastQuery), "index ran caller query %q", client.lastQuery)
	} else {
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	}
	require.Contains(t, []int{http.StatusOK, http.StatusBadRequest}, rec.Code, rec.Body.String())
}

func doDashboardSearch(t *testing.T, handler *SearchHandler, viewer identity.Requester, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req = req.WithContext(identity.WithRequester(req.Context(), viewer))
	handler.DoSearch(rec, req)
	return rec
}

func doHybridSearch(t *testing.T, handler *SearchHandler, viewer identity.Requester, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req = req.WithContext(identity.WithRequester(req.Context(), viewer))
	handler.DoHybridSearch(rec, req)
	return rec
}

func signedInViewer() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:    7,
		OrgID:     1,
		Namespace: "default",
		// Same delegated permissions AccessClaimsHook installs for a session
		// that has no upstream access token.
		AccessTokenClaims: &authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{
				DelegatedPermissions: identity.ServiceIdentityClaims.Rest.DelegatedPermissions,
			},
		},
	}
}

func requestAttributes(t *testing.T, method, path string) authorizer.Attributes {
	t.Helper()
	factory := &request.RequestInfoFactory{
		APIPrefixes:          sets.NewString("apis"),
		GrouplessAPIPrefixes: sets.NewString(),
	}
	req, err := http.NewRequest(method, path, nil)
	require.NoError(t, err)
	info, err := factory.NewRequestInfo(req)
	require.NoError(t, err)
	return authorizer.AttributesRecord{
		Verb:            info.Verb,
		Namespace:       info.Namespace,
		APIGroup:        info.APIGroup,
		APIVersion:      info.APIVersion,
		Resource:        info.Resource,
		Subresource:     info.Subresource,
		Name:            info.Name,
		ResourceRequest: info.IsResourceRequest,
		Path:            path,
	}
}

func escapeQuery(q string) string {
	return strings.ReplaceAll(q, "*", "%2A")
}

// queryReachesIndexUnconstrained is true when q is longer than the cap or still
// contains a caller-controlled wildcard. A single leading and trailing '*' may
// remain, but only around a body whose own '*', '?' and '\' are escaped.
func queryReachesIndexUnconstrained(q string) bool {
	if len(q) > maxCallerSearchQueryBytes {
		return true
	}
	body := q
	body = strings.TrimPrefix(body, "*")
	body = strings.TrimSuffix(body, "*")
	return hasUnescapedWildcardMeta(body)
}

func hasUnescapedWildcardMeta(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '*' || s[i] == '?' {
			return true
		}
	}
	return false
}

// titleSearchClient runs Search and the hybrid lexical leg on real Bleve indexes.
// Hybrid search copies the caller query onto a ResourceSearchRequest and searches
// the dashboard index; this client does that copy and then calls the index.
type titleSearchClient struct {
	resourcepb.ResourceIndexClient
	byResource      map[string]resource.ResourceIndex
	calls           int
	hybridCalls     int
	lastQuery       string
	lastHybridQuery string
	lastCost        float64
}

func (c *titleSearchClient) Search(ctx context.Context, req *resourcepb.ResourceSearchRequest, _ ...grpc.CallOption) (*resourcepb.ResourceSearchResponse, error) {
	c.calls++
	c.lastQuery = req.GetQuery()
	primary := c.byResource[req.GetOptions().GetKey().GetResource()]
	if primary == nil {
		t := req.GetOptions().GetKey().GetResource()
		return &resourcepb.ResourceSearchResponse{Error: resource.NewBadRequestError("no test index for " + t)}, nil
	}
	federate := make([]resource.ResourceIndex, 0, len(req.Federated))
	for _, key := range req.Federated {
		idx := c.byResource[key.GetResource()]
		if idx == nil {
			return nil, errMissingIndex(key.GetResource())
		}
		federate = append(federate, idx)
	}
	resp, err := primary.Search(ctx, nil, req, federate, &resource.SearchStats{})
	if resp != nil {
		c.lastCost = resp.QueryCost
	}
	return resp, err
}

func (c *titleSearchClient) HybridSearch(ctx context.Context, req *resourcepb.HybridSearchRequest, _ ...grpc.CallOption) (*resourcepb.HybridSearchResponse, error) {
	c.hybridCalls++
	c.lastHybridQuery = req.GetQuery()
	// hybridLexicalRequest copies Query onto the lexical Search request unchanged.
	lex := &resourcepb.ResourceSearchRequest{
		Options: &resourcepb.ListOptions{Key: req.Key},
		Query:   req.Query,
		Limit:   req.Limit,
		Fields:  []string{resource.SEARCH_FIELD_TITLE, resource.SEARCH_FIELD_FOLDER},
	}
	res, err := c.Search(ctx, lex)
	if err != nil {
		return nil, err
	}
	if res.GetError() != nil {
		return nil, resource.GetError(res.GetError())
	}
	out := &resourcepb.HybridSearchResponse{}
	for _, row := range res.GetResults().GetRows() {
		out.Results = append(out.Results, &resourcepb.HybridSearchResult{
			Key:   row.GetKey(),
			Title: canaryTitle,
		})
	}
	return out, nil
}

type missingIndexError string

func (e missingIndexError) Error() string { return "no test index for " + string(e) }

func errMissingIndex(resourceName string) error { return missingIndexError(resourceName) }

func newTitleSearchClient(t *testing.T) *titleSearchClient {
	t.Helper()
	docs := map[string]string{
		canaryName: "a-uniquephrase",
		"other":    "ordinary dashboard",
	}
	dash := buildTitleIndex(t, resource.NamespacedResource{
		Namespace: "default",
		Group:     dashboardv1.GROUP,
		Resource:  dashboardv1.DASHBOARD_RESOURCE,
	}, docs)
	folder := buildTitleIndex(t, resource.NamespacedResource{
		Namespace: "default",
		Group:     folderv1.GROUP,
		Resource:  folderv1.RESOURCE,
	}, docs)
	return &titleSearchClient{
		byResource: map[string]resource.ResourceIndex{
			dashboardv1.DASHBOARD_RESOURCE: dash,
			folderv1.RESOURCE:              folder,
		},
	}
}

func buildTitleIndex(t *testing.T, key resource.NamespacedResource, docs map[string]string) resource.ResourceIndex {
	t.Helper()
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

	items := make([]*resource.BulkIndexItem, 0, len(docs))
	for name, title := range docs {
		items = append(items, &resource.BulkIndexItem{
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
		})
	}
	require.NoError(t, index.BulkIndex(&resource.BulkIndexRequest{Items: items}))
	return index
}
