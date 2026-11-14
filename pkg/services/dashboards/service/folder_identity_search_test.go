package service

import (
	"context"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/selection"
	k8stypes "k8s.io/apimachinery/pkg/types"

	authnlib "github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/authz"
	"github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/slugify"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/apiserver/client"
	"github.com/grafana/grafana/pkg/services/authz/rbac"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/dashboards/dashboardaccess"
	dashboardclient "github.com/grafana/grafana/pkg/services/dashboards/service/client"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/folder/folderimpl"
	"github.com/grafana/grafana/pkg/services/search"
	"github.com/grafana/grafana/pkg/services/search/model"
	starapi "github.com/grafana/grafana/pkg/services/star/api"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/web"
)

const (
	folderIdentityOrgID     int64 = 1
	folderIdentityNamespace       = "default"
	secretFolderUID               = "secret-folder"
	secretFolderTitle             = "Acme Customer Launch"
	secretFolderID          int64 = 4242
	visibleFolderUID              = "visible-folder"
	visibleFolderTitle            = "Visible Projects"
	visibleFolderID         int64 = 7
	sharedDashboardUID            = "shared-dash"
	sharedDashboardTitle          = "Shared board"
	hiddenDashboardUID            = "hidden-dash"
	hiddenDashboardTitle          = "Hidden board"
)

// TestDashboardSearchFolderIdentity covers signed-in dashboard search. A caller who can read
// one dashboard, and a different folder, must not learn the name, legacy id, or slug URL of
// the dashboard's parent. Those fields stay populated when that caller can read the parent.
func TestDashboardSearchFolderIdentity(t *testing.T) {
	index := newFolderIdentityIndex()
	dashboardsSvc, folderSvc := newFolderIdentityServices(index)

	t.Run("folder endpoint denies the parent and allows the dashboard", func(t *testing.T) {
		caller := dashboardOnlyCaller()
		require.Equal(t, http.StatusForbidden, folderIdentityHTTPStatus(t, caller, folder.ActionFoldersRead, folder.ScopeFoldersProvider.GetResourceScopeUID(accesscontrol.Parameter(":uid")), secretFolderUID))
		require.Equal(t, http.StatusOK, folderIdentityHTTPStatus(t, caller, dashboards.ActionDashboardsRead, dashboards.ScopeDashboardsProvider.GetResourceScopeUID(accesscontrol.Parameter(":uid")), sharedDashboardUID))
		require.Equal(t, http.StatusOK, folderIdentityHTTPStatus(t, caller, folder.ActionFoldersRead, folder.ScopeFoldersProvider.GetResourceScopeUID(accesscontrol.Parameter(":uid")), visibleFolderUID))
	})

	t.Run("caller folder search does not return the parent", func(t *testing.T) {
		ctx := identity.WithRequester(context.Background(), dashboardOnlyCaller())
		hits, err := folderSvc.SearchFolders(ctx, folder.SearchFoldersQuery{
			OrgID: folderIdentityOrgID,
			UIDs:  []string{secretFolderUID},
		})
		require.NoError(t, err)
		require.Empty(t, hits)

		// fetchFolderNames reads the parent as the service identity. This identity has to be
		// able to read the folder, or an empty title would not show the leak.
		serviceCtx, _ := identity.WithServiceIdentity(ctx, folderIdentityOrgID)
		elevated, err := folderSvc.SearchFolders(serviceCtx, folder.SearchFoldersQuery{
			OrgID: folderIdentityOrgID,
			UIDs:  []string{secretFolderUID},
		})
		require.NoError(t, err)
		require.Len(t, elevated, 1)
		require.Equal(t, secretFolderTitle, elevated[0].Title)
		require.Equal(t, secretFolderID, elevated[0].ID)
	})

	t.Run("search omits the parent when the caller cannot read it", func(t *testing.T) {
		caller := dashboardOnlyCaller()
		for _, kind := range []string{"", model.TypeDashboard} {
			hits := searchAsCaller(t, dashboardsSvc, caller, kind)
			shared := folderIdentityHit(t, hits, sharedDashboardUID)
			require.Equal(t, sharedDashboardTitle, shared.Title)
			require.Equal(t, secretFolderUID, shared.FolderUID)
			require.Empty(t, shared.FolderTitle)
			require.Zero(t, shared.FolderID)
			require.Empty(t, shared.FolderURL)
			require.Nil(t, folderIdentityHitOptional(hits, hiddenDashboardUID))
			require.Nil(t, folderIdentityHitOptional(hits, secretFolderUID))
		}

		found := findDashboardsAsCaller(t, dashboardsSvc, caller)
		require.Equal(t, sharedDashboardUID, found[0].UID)
		require.Empty(t, found[0].FolderTitle)
		require.Zero(t, found[0].FolderID)
		require.Empty(t, found[0].FolderSlug)

		apiHits := searchHandlerAsCaller(t, dashboardsSvc, caller)
		shared := folderIdentityHit(t, apiHits, sharedDashboardUID)
		require.Empty(t, shared.FolderTitle)
		require.Zero(t, shared.FolderID)
		require.Empty(t, shared.FolderURL)
	})

	t.Run("search keeps the parent when the caller can read it", func(t *testing.T) {
		caller := dashboardOnlyCaller()
		caller.Permissions[folderIdentityOrgID][folder.ActionFoldersRead] = append(
			caller.Permissions[folderIdentityOrgID][folder.ActionFoldersRead],
			folder.ScopeFoldersPrefix+secretFolderUID,
		)
		hits := searchAsCaller(t, dashboardsSvc, caller, model.TypeDashboard)
		shared := folderIdentityHit(t, hits, sharedDashboardUID)
		require.Equal(t, secretFolderTitle, shared.FolderTitle)
		require.Equal(t, secretFolderID, shared.FolderID)
		require.Equal(t, dashboards.GetFolderURL(secretFolderUID, slugify.Slugify(secretFolderTitle)), shared.FolderURL)
		// folders:read on the parent does not grant dashboards:read, so the other board stays hidden.
		require.Nil(t, folderIdentityHitOptional(hits, hiddenDashboardUID))
	})
}

func dashboardOnlyCaller() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:    2,
		UserUID:   "viewer",
		OrgID:     folderIdentityOrgID,
		Namespace: folderIdentityNamespace,
		// Session logins carry the service's delegated permissions so search proceeds
		// to the caller's own grants. See AccessClaimsHook.
		AccessTokenClaims: &authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{
				DelegatedPermissions: identity.ServiceIdentityClaims.Rest.DelegatedPermissions,
			},
		},
		Permissions: map[int64]map[string][]string{
			folderIdentityOrgID: {
				dashboards.ActionDashboardsRead: {dashboards.ScopeDashboardsPrefix + sharedDashboardUID},
				folder.ActionFoldersRead:        {folder.ScopeFoldersPrefix + visibleFolderUID},
			},
		},
	}
}

func searchAsCaller(t *testing.T, svc *DashboardServiceImpl, caller *user.SignedInUser, kind string) model.HitList {
	t.Helper()
	ctx := identity.WithRequester(context.Background(), caller)
	hits, err := svc.SearchDashboards(ctx, &dashboards.FindPersistedDashboardsQuery{
		OrgId:        folderIdentityOrgID,
		SignedInUser: caller,
		Type:         kind,
		Permission:   dashboardaccess.PERMISSION_VIEW,
	})
	require.NoError(t, err)
	return hits
}

func findDashboardsAsCaller(t *testing.T, svc *DashboardServiceImpl, caller *user.SignedInUser) []dashboards.DashboardSearchProjection {
	t.Helper()
	ctx := identity.WithRequester(context.Background(), caller)
	found, err := svc.FindDashboards(ctx, &dashboards.FindPersistedDashboardsQuery{
		OrgId:        folderIdentityOrgID,
		SignedInUser: caller,
		Type:         model.TypeDashboard,
		Permission:   dashboardaccess.PERMISSION_VIEW,
	})
	require.NoError(t, err)
	require.Len(t, found, 1)
	return found
}

func searchHandlerAsCaller(t *testing.T, svc *DashboardServiceImpl, caller *user.SignedInUser) model.HitList {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/search", nil)
	reqCtx := &contextmodel.ReqContext{
		Context:      &web.Context{Req: req},
		SignedInUser: caller,
		IsSignedIn:   true,
	}
	ctx := identity.WithRequester(ctxkey.Set(req.Context(), reqCtx), caller)
	stars := starapi.NewMockK8sClients(t)
	stars.On("GetStars", reqCtx).Return([]string{}, nil)
	handler := &search.SearchService{}
	setUnexported(handler, "dashboardService", dashboards.DashboardService(svc))
	setUnexported(handler, "starClient", starapi.K8sClients(stars))
	setUnexported(handler, "features", featuremgmt.FeatureToggles(featuremgmt.WithFeatures()))
	hits, err := handler.SearchHandler(ctx, &search.Query{
		SignedInUser: caller,
		OrgId:        folderIdentityOrgID,
		Permission:   dashboardaccess.PERMISSION_VIEW,
	})
	require.NoError(t, err)
	return hits
}

func folderIdentityHit(t *testing.T, hits model.HitList, uid string) *model.Hit {
	t.Helper()
	hit := folderIdentityHitOptional(hits, uid)
	require.NotNil(t, hit, "missing search hit %s", uid)
	return hit
}

func folderIdentityHitOptional(hits model.HitList, uid string) *model.Hit {
	for _, hit := range hits {
		if hit.UID == uid {
			return hit
		}
	}
	return nil
}

func folderIdentityHTTPStatus(t *testing.T, caller *user.SignedInUser, action, scope, uid string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/folders/"+uid, nil)
	req = web.SetURLParams(req, map[string]string{":uid": uid})
	reqCtx := &contextmodel.ReqContext{
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(http.MethodGet, rec),
		},
		SignedInUser: caller,
		IsSignedIn:   true,
		Logger:       log.New("folder-identity-test"),
	}
	handler := accesscontrol.Middleware(acimpl.ProvideAccessControlTest())(accesscontrol.EvalPermission(action, scope))
	handler.(func(*contextmodel.ReqContext))(reqCtx)
	if reqCtx.Resp.Status() == 0 {
		return http.StatusOK
	}
	return reqCtx.Resp.Status()
}

func newFolderIdentityServices(index *folderIdentityIndex) (*DashboardServiceImpl, *folderimpl.Service) {
	handler := &folderIdentitySearch{index: index, access: &folderIdentityAccess{registry: rbac.NewMapperRegistry()}}
	folders := &folderimpl.Service{}
	setUnexported(folders, "k8sclient", client.K8sHandler(handler))
	setUnexported(folders, "tracer", otel.Tracer("folder-identity-test"))
	return &DashboardServiceImpl{
		k8sclient:     dashboardclient.K8sHandlerWithFallback(handler),
		folderService: folders,
	}, folders
}

func setUnexported(target any, name string, value any) {
	field := reflect.ValueOf(target).Elem().FieldByName(name)
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(value))
}

type folderDoc struct {
	name     string
	title    string
	folder   string
	group    string
	resource string
	legacyID int64
}

type folderIdentityIndex struct {
	docs []folderDoc
}

func newFolderIdentityIndex() *folderIdentityIndex {
	return &folderIdentityIndex{docs: []folderDoc{
		{name: secretFolderUID, title: secretFolderTitle, group: "folder.grafana.app", resource: "folders", legacyID: secretFolderID},
		{name: visibleFolderUID, title: visibleFolderTitle, group: "folder.grafana.app", resource: "folders", legacyID: visibleFolderID},
		{name: sharedDashboardUID, title: sharedDashboardTitle, folder: secretFolderUID, group: "dashboard.grafana.app", resource: "dashboards"},
		{name: hiddenDashboardUID, title: hiddenDashboardTitle, folder: secretFolderUID, group: "dashboard.grafana.app", resource: "dashboards"},
	}}
}

// folderIdentitySearch is the in-process search index. It keeps the documents above and
// authorizes each one with the same batch check the bleve searcher runs: service tokens
// are decided by authlib, and user grants by the RBAC mapper.
type folderIdentitySearch struct {
	index  *folderIdentityIndex
	access *folderIdentityAccess
}

var _ client.K8sHandler = (*folderIdentitySearch)(nil)

func (s *folderIdentitySearch) GetNamespace(int64) string { return folderIdentityNamespace }

func (s *folderIdentitySearch) Search(ctx context.Context, _ int64, in *resourcepb.ResourceSearchRequest) (*resourcepb.ResourceSearchResponse, error) {
	if in == nil || in.Options == nil || in.Options.Key == nil {
		return nil, errors.New("search request has no key")
	}
	verb := utils.VerbGet
	if in.Permission == int64(dashboardaccess.PERMISSION_EDIT) {
		verb = utils.VerbUpdate
	}
	candidates := s.index.matching(in)
	allowed, err := authorizeDocs(ctx, s.access, in.Options.Key.Namespace, verb, candidates)
	if err != nil {
		return nil, err
	}
	if in.ResultFormat == resourcepb.ResourceSearchRequest_FIELD_VALUES {
		return fieldValueResponse(allowed), nil
	}
	return tableResponse(allowed), nil
}

func (s *folderIdentitySearch) GetWithPreferredAPIVersion(context.Context, string, int64, metav1.GetOptions, string, ...string) (*unstructured.Unstructured, error) {
	return nil, errors.New("not implemented")
}

func (s *folderIdentitySearch) Get(context.Context, string, int64, metav1.GetOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, errors.New("not implemented")
}
func (s *folderIdentitySearch) Create(context.Context, *unstructured.Unstructured, int64, metav1.CreateOptions) (*unstructured.Unstructured, error) {
	return nil, errors.New("not implemented")
}
func (s *folderIdentitySearch) Update(context.Context, *unstructured.Unstructured, int64, metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	return nil, errors.New("not implemented")
}
func (s *folderIdentitySearch) Patch(context.Context, string, k8stypes.PatchType, []byte, int64, metav1.PatchOptions) (*unstructured.Unstructured, error) {
	return nil, errors.New("not implemented")
}
func (s *folderIdentitySearch) Delete(context.Context, string, int64, metav1.DeleteOptions) error {
	return errors.New("not implemented")
}
func (s *folderIdentitySearch) DeleteCollection(context.Context, int64, metav1.ListOptions) error {
	return errors.New("not implemented")
}
func (s *folderIdentitySearch) List(context.Context, int64, metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return nil, errors.New("not implemented")
}
func (s *folderIdentitySearch) GetStats(context.Context, int64) (*resourcepb.ResourceStatsResponse, error) {
	return nil, errors.New("not implemented")
}
func (s *folderIdentitySearch) GetUsersFromMeta(context.Context, []string) (map[string]*user.User, error) {
	return nil, errors.New("not implemented")
}

func (idx *folderIdentityIndex) matching(in *resourcepb.ResourceSearchRequest) []folderDoc {
	resources := map[string]struct{}{in.Options.Key.Resource: {}}
	for _, federated := range in.Federated {
		resources[federated.Resource] = struct{}{}
	}
	var names []string
	if in.Options != nil {
		for _, field := range in.Options.Fields {
			if field.Key == resource.SEARCH_FIELD_NAME && field.Operator == string(selection.In) {
				names = field.Values
			}
		}
	}
	out := make([]folderDoc, 0, len(idx.docs))
	for _, doc := range idx.docs {
		if _, ok := resources[doc.resource]; !ok {
			continue
		}
		if len(names) > 0 && !contains(names, doc.name) {
			continue
		}
		out = append(out, doc)
	}
	return out
}

func authorizeDocs(ctx context.Context, access types.AccessClient, namespace, primaryVerb string, docs []folderDoc) ([]folderDoc, error) {
	seq := func(yield func(folderDoc) bool) {
		for _, doc := range docs {
			if !yield(doc) {
				return
			}
		}
	}
	extract := func(doc folderDoc) authz.BatchCheckItem {
		verb := utils.VerbGet
		if doc.resource != "folders" {
			verb = primaryVerb
		}
		return authz.BatchCheckItem{
			Name:      doc.name,
			Folder:    doc.folder,
			Verb:      verb,
			Group:     doc.group,
			Resource:  doc.resource,
			Namespace: namespace,
		}
	}
	allowed := make([]folderDoc, 0, len(docs))
	for doc, err := range authz.FilterAuthorized(ctx, access, iter.Seq[folderDoc](seq), extract) {
		if err != nil {
			return nil, err
		}
		allowed = append(allowed, doc)
	}
	return allowed, nil
}

func tableResponse(docs []folderDoc) *resourcepb.ResourceSearchResponse {
	rows := make([]*resourcepb.ResourceTableRow, len(docs))
	for i, doc := range docs {
		rows[i] = &resourcepb.ResourceTableRow{
			Key:   &resourcepb.ResourceKey{Name: doc.name, Group: doc.group, Resource: doc.resource},
			Cells: [][]byte{[]byte(doc.title), []byte(doc.folder)},
		}
	}
	return &resourcepb.ResourceSearchResponse{
		TotalHits: int64(len(rows)),
		Results: &resourcepb.ResourceTable{
			Columns: []*resourcepb.ResourceTableColumnDefinition{
				{Name: resource.SEARCH_FIELD_TITLE, Type: resourcepb.ResourceTableColumnDefinition_STRING},
				{Name: resource.SEARCH_FIELD_FOLDER, Type: resourcepb.ResourceTableColumnDefinition_STRING},
			},
			Rows: rows,
		},
	}
}

func fieldValueResponse(docs []folderDoc) *resourcepb.ResourceSearchResponse {
	rows := make([]*resourcepb.ResourceSearchRow, len(docs))
	for i, doc := range docs {
		rows[i] = &resourcepb.ResourceSearchRow{
			Key: &resourcepb.ResourceKey{Name: doc.name, Group: doc.group, Resource: doc.resource},
			Values: []*resourcepb.ResourceSearchValue{
				{FieldIndex: 0, StringValues: []string{doc.title}},
				{FieldIndex: 1, StringValues: []string{doc.folder}},
				{FieldIndex: 2, Int64Values: []int64{doc.legacyID}},
			},
		}
	}
	return &resourcepb.ResourceSearchResponse{
		ResultFormat: resourcepb.ResourceSearchRequest_FIELD_VALUES,
		TotalHits:    int64(len(rows)),
		Fields: []*resourcepb.ResourceSearchField{
			{Name: resource.SEARCH_FIELD_TITLE, Type: resourcepb.ResourceSearchField_STRING},
			{Name: resource.SEARCH_FIELD_FOLDER, Type: resourcepb.ResourceSearchField_STRING},
			{Name: resource.SEARCH_FIELD_LEGACY_ID, Type: resourcepb.ResourceSearchField_INT64},
		},
		Rows: rows,
	}
}

// folderIdentityAccess applies the two decisions the production authz client makes.
// A service identity is allowed from its token. A user is allowed only when the RBAC
// mapper's scope for that object is one of the caller's grants, or the parent folder is.
type folderIdentityAccess struct {
	registry rbac.MapperRegistry
}

func (a *folderIdentityAccess) Check(context.Context, types.AuthInfo, types.CheckRequest, string) (types.CheckResponse, error) {
	return types.CheckResponse{}, errors.New("not implemented")
}

func (a *folderIdentityAccess) Compile(context.Context, types.AuthInfo, types.ListRequest) (types.ItemChecker, types.Zookie, error) {
	return nil, types.NoopZookie{}, errors.New("not implemented")
}

func (a *folderIdentityAccess) BatchCheck(_ context.Context, id types.AuthInfo, req types.BatchCheckRequest) (types.BatchCheckResponse, error) {
	if !types.NamespaceMatches(id.GetNamespace(), req.Namespace) {
		return types.BatchCheckResponse{}, errors.New("namespace mismatch")
	}
	results := make(map[string]types.BatchCheckResult, len(req.Checks))
	for _, check := range req.Checks {
		service := authz.CheckServicePermissions(id, check.Group, check.Resource, check.Verb)
		if service.ServiceCall {
			results[check.CorrelationID] = types.BatchCheckResult{Allowed: service.Allowed}
			continue
		}
		if !service.Allowed {
			results[check.CorrelationID] = types.BatchCheckResult{Allowed: false}
			continue
		}
		results[check.CorrelationID] = types.BatchCheckResult{Allowed: a.userAllowed(id, check)}
	}
	return types.BatchCheckResponse{Results: results}, nil
}

func (a *folderIdentityAccess) userAllowed(id types.AuthInfo, check types.BatchCheckItem) bool {
	if !types.IsIdentityType(id.GetIdentityType(), types.TypeUser, types.TypeServiceAccount, types.TypeAnonymous, types.TypeRenderService) {
		return false
	}
	requester, ok := id.(identity.Requester)
	if !ok {
		return false
	}
	mapping, ok := a.registry.Get(check.Group, check.Resource, check.Subresource)
	if !ok {
		return false
	}
	action, ok := mapping.Action(check.Verb)
	if !ok {
		return false
	}
	scopes := scopesFor(requester, action, mapping.ActionSets(check.Verb))
	if !mapping.SkipWildcard() && scopes["*"] {
		return true
	}
	if check.Name != "" && scopes[mapping.Scope(check.Name)] {
		return true
	}
	if !mapping.HasFolderSupport() || check.Folder == "" {
		return false
	}
	return scopes["folders:uid:"+check.Folder]
}

func scopesFor(requester identity.Requester, action string, actionSets []string) map[string]bool {
	permissions := requester.GetPermissions()
	granted := append([]string{}, permissions[action]...)
	for _, set := range actionSets {
		granted = append(granted, permissions[set]...)
	}
	out := make(map[string]bool, len(granted))
	for _, scope := range granted {
		kind, attribute, identifier := accesscontrol.SplitScope(scope)
		if kind == "*" || attribute == "*" || identifier == "*" {
			return map[string]bool{"*": true}
		}
		out[scope] = true
	}
	return out
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
