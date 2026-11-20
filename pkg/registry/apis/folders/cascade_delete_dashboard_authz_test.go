package folders

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	authnlib "github.com/grafana/authlib/authn"
	authzlib "github.com/grafana/authlib/authz"
	authlib "github.com/grafana/authlib/types"
	dashv1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	foldersv1 "github.com/grafana/grafana/apps/folder/pkg/apis/folder/v1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	grafanaauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

const (
	dashVisibleAllowed = "visible-allowed"
	dashVisibleDenied  = "visible-denied"
	dashHiddenDenied   = "hidden-denied"
	dashChildDenied    = "child-denied"
	dashRacedDenied    = "raced-denied"
	dashKept           = "kept"
)

// signedInCascadeUser is a session user after AccessClaimsHook has filled delegated
// permissions. The user can force-delete the folder (folders:delete is what the
// apiserver authorizer sees via folder.grafana.app:*) and passes the cascade
// preflight (alert.rules:delete and folders:write). Folder-scoped dashboards:delete
// is granted, and so is dashboards:delete on dashVisibleAllowed and dashKept.
// dashboards:delete is denied on every other dashboard name.
func signedInCascadeUser() *identity.StaticRequester {
	return &identity.StaticRequester{
		Type:      authlib.TypeUser,
		Name:      "folder-editor",
		UserUID:   "folder-editor",
		UserID:    7,
		OrgID:     1,
		Namespace: "default",
		AccessTokenClaims: &authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{
				DelegatedPermissions: identity.ServiceIdentityClaims.Rest.DelegatedPermissions,
			},
		},
	}
}

func ctxWithCascadeUser(user identity.Requester) context.Context {
	ctx := apirequest.WithNamespace(context.Background(), "default")
	return identity.WithRequester(ctx, user)
}

// userMayDeleteDashboard is the user RBAC decision for dashboards:delete on one
// dashboard. Folder scope is a separate question and does not authorize these names.
func userMayDeleteDashboard(name string) bool {
	switch name {
	case dashVisibleAllowed, dashKept:
		return true
	default:
		return false
	}
}

// cascadePermissionClient is the access client the cascade asks. Service identities
// are decided only by token permissions, matching authlib ClientImpl.Check: a
// service call never consults user RBAC. A signed-in user is decided by the
// permissions in this test.
type cascadePermissionClient struct {
	checks []contentsAccessCheck
}

func (c *cascadePermissionClient) Check(_ context.Context, info authlib.AuthInfo, req authlib.CheckRequest, folder string) (authlib.CheckResponse, error) {
	c.checks = append(c.checks, contentsAccessCheck{req: req, folder: folder})
	// authlib/authz/client.go ClientImpl.Check: a service call returns the token
	// decision and does not call the authz service.
	res := authzlib.CheckServicePermissions(info, req.Group, req.Resource, req.Verb)
	if res.ServiceCall {
		return authlib.CheckResponse{Allowed: res.Allowed}, nil
	}
	return authlib.CheckResponse{Allowed: userCascadeAllows(req)}, nil
}

func userCascadeAllows(req authlib.CheckRequest) bool {
	switch {
	case req.Group == cascadeAlertRuleGroup && req.Resource == cascadeAlertRuleResource && req.Verb == utils.VerbDelete:
		return true
	case req.Group == foldersv1.FolderResourceInfo.GroupVersionResource().Group &&
		req.Resource == foldersv1.FolderResourceInfo.GroupVersionResource().Resource &&
		req.Verb == utils.VerbUpdate:
		return true
	case req.Group == dashv1.DashboardResourceInfo.GroupVersionResource().Group &&
		req.Resource == dashv1.DashboardResourceInfo.GroupVersionResource().Resource &&
		req.Verb == utils.VerbDelete:
		// An empty name is folder scope. It does not authorize a named dashboard.
		if req.Name == "" {
			return true
		}
		return userMayDeleteDashboard(req.Name)
	default:
		return false
	}
}

func (c *cascadePermissionClient) BatchCheck(context.Context, authlib.AuthInfo, authlib.BatchCheckRequest) (authlib.BatchCheckResponse, error) {
	return authlib.BatchCheckResponse{}, nil
}

func (c *cascadePermissionClient) Compile(context.Context, authlib.AuthInfo, authlib.ListRequest) (authlib.ItemChecker, authlib.Zookie, error) {
	return func(string, string) bool { return false }, authlib.NoopZookie{}, nil
}

// successiveDashboardSearcher returns a different dashboard listing on each
// service-identity search of the same folder. A later search can include a
// dashboard the earlier search did not. A signed-in user search never includes
// dashboards that user cannot see.
type successiveDashboardSearcher struct {
	*fakeCascadeSearcher
	serviceListings map[string][][]string
	userVisible     map[string][]string
	serviceCalls    map[string]int
}

func (s *successiveDashboardSearcher) Search(ctx context.Context, req *resourcepb.ResourceSearchRequest, opts ...grpc.CallOption) (*resourcepb.ResourceSearchResponse, error) {
	if req.Options != nil && req.Options.Key != nil &&
		req.Options.Key.Resource == dashv1.DashboardResourceInfo.GroupVersionResource().Resource {
		return s.searchDashboards(ctx, req), nil
	}
	return s.fakeCascadeSearcher.Search(ctx, req, opts...)
}

func (s *successiveDashboardSearcher) searchDashboards(ctx context.Context, req *resourcepb.ResourceSearchRequest) *resourcepb.ResourceSearchResponse {
	s.fakeCascadeSearcher.searchCtx = ctx
	s.fakeCascadeSearcher.requests = append(s.fakeCascadeSearcher.requests, req)

	if req.Offset > 0 {
		return &resourcepb.ResourceSearchResponse{Results: &resourcepb.ResourceTable{}, TotalHits: 0}
	}

	var names []string
	for _, folderUID := range folderFilterValues(req) {
		if identity.IsServiceIdentity(ctx) {
			listings := s.serviceListings[folderUID]
			if len(listings) == 0 {
				continue
			}
			n := s.serviceCalls[folderUID]
			s.serviceCalls[folderUID] = n + 1
			if n >= len(listings) {
				n = len(listings) - 1
			}
			names = append(names, listings[n]...)
		} else {
			names = append(names, s.userVisible[folderUID]...)
		}
	}
	rows := make([]*resourcepb.ResourceTableRow, 0, len(names))
	for _, n := range names {
		rows = append(rows, &resourcepb.ResourceTableRow{Key: &resourcepb.ResourceKey{Name: n}})
	}
	return &resourcepb.ResourceSearchResponse{
		Results:   &resourcepb.ResourceTable{Rows: rows},
		TotalHits: int64(len(rows)),
	}
}

// dashboardDeleteChain is the authorizer chain in front of dashboard storage:
// impersonation, privileged groups, namespace, then the dashboard authorizer
// (ServiceAuthorizer). Storage then applies authlib ClientImpl.Check.
func dashboardDeleteChain() authorizer.Authorizer {
	chain := grafanaauthorizer.NewGrafanaBuiltInSTAuthorizer()
	gv := dashv1.DashboardResourceInfo.GroupVersion()
	chain.Register(gv, grafanaauthorizer.NewServiceAuthorizer())
	return chain
}

func folderDeleteChain() authorizer.Authorizer {
	chain := grafanaauthorizer.NewGrafanaBuiltInSTAuthorizer()
	gv := foldersv1.FolderResourceInfo.GroupVersion()
	chain.Register(gv, grafanaauthorizer.NewServiceAuthorizer())
	return chain
}

// authorizeDashboardDelete applies the dashboard apiserver decision for this
// caller. Service identity is allowed by its token (dashboard.grafana.app:*)
// at both layers. A signed-in user still needs dashboards:delete on this name.
func authorizeDashboardDelete(ctx context.Context, name, namespace string) error {
	gvr := dashv1.DashboardResourceInfo.GroupVersionResource()
	gv := dashv1.DashboardResourceInfo.GroupVersion()
	decision, reason, err := dashboardDeleteChain().Authorize(ctx, authorizer.AttributesRecord{
		Verb:            utils.VerbDelete,
		Namespace:       namespace,
		APIGroup:        gvr.Group,
		APIVersion:      gv.Version,
		Resource:        gvr.Resource,
		Name:            name,
		ResourceRequest: true,
	})
	if err != nil {
		return err
	}
	if decision != authorizer.DecisionAllow {
		return apierrors.NewForbidden(gvr.GroupResource(), name, errString(reason))
	}

	info, err := identity.GetRequester(ctx)
	if err != nil {
		return apierrors.NewForbidden(gvr.GroupResource(), name, err)
	}
	res := authzlib.CheckServicePermissions(info, gvr.Group, gvr.Resource, utils.VerbDelete)
	allowed := false
	switch {
	case res.ServiceCall:
		allowed = res.Allowed
	default:
		allowed = userMayDeleteDashboard(name)
	}
	if !allowed {
		return apierrors.NewForbidden(gvr.GroupResource(), name, errString("dashboards:delete denied"))
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

// authzDashboardNamespace deletes a dashboard only after authorizeDashboardDelete
// allows this caller. The underlying fake client performs the delete itself.
type authzDashboardNamespace struct {
	dynamic.NamespaceableResourceInterface
}

func (n authzDashboardNamespace) Namespace(ns string) dynamic.ResourceInterface {
	return authzDashboardResource{ResourceInterface: n.NamespaceableResourceInterface.Namespace(ns), namespace: ns}
}

type authzDashboardResource struct {
	dynamic.ResourceInterface
	namespace string
}

func (r authzDashboardResource) Delete(ctx context.Context, name string, options metav1.DeleteOptions, subresources ...string) error {
	if err := authorizeDashboardDelete(ctx, name, r.namespace); err != nil {
		return err
	}
	return r.ResourceInterface.Delete(ctx, name, options, subresources...)
}

func newAuthorizingDashboardCascade(store *fakeFolderStorage, searcher *successiveDashboardSearcher, objs ...runtime.Object) (*cascadeDeleteStorage, *dynamicfake.FakeDynamicClient, *cascadePermissionClient) {
	gvr := dashv1.DashboardResourceInfo.GroupVersionResource()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvr: "DashboardList"}, objs...)
	wrapped := authzDashboardNamespace{NamespaceableResourceInterface: dyn.Resource(gvr)}
	var iface dynamic.NamespaceableResourceInterface = wrapped
	ac := &cascadePermissionClient{}
	s := &cascadeDeleteStorage{
		Storage:  store,
		searcher: searcher,
		dashboardClient: func(context.Context) (*dynamic.NamespaceableResourceInterface, error) {
			return &iface, nil
		},
		variableClient: nilVariableClient,
		accessClient:   ac,
	}
	return s, dyn, ac
}

func dashboardStillPresent(t *testing.T, dyn *dynamicfake.FakeDynamicClient, namespace, name string) {
	t.Helper()
	gvr := dashv1.DashboardResourceInfo.GroupVersionResource()
	_, err := dyn.Resource(gvr).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})
	require.NoError(t, err, "dashboard %s must still exist", name)
}

func TestFolderForceDeleteReachesStorageForSignedInUser(t *testing.T) {
	user := signedInCascadeUser()
	ctx := identity.WithRequester(context.Background(), user)
	gvr := foldersv1.FolderResourceInfo.GroupVersionResource()
	gv := foldersv1.FolderResourceInfo.GroupVersion()

	decision, reason, err := folderDeleteChain().Authorize(ctx, authorizer.AttributesRecord{
		Verb:            utils.VerbDelete,
		Namespace:       "default",
		APIGroup:        gvr.Group,
		APIVersion:      gv.Version,
		Resource:        gvr.Resource,
		Name:            "root",
		ResourceRequest: true,
	})
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision, "reason: %s", reason)
}

func TestServiceIdentityDashboardDeleteIsAllowed(t *testing.T) {
	ctx := identity.WithServiceIdentityContext(context.Background(), 1)
	require.NoError(t, authorizeDashboardDelete(ctx, dashVisibleDenied, "default"))
	require.NoError(t, authorizeDashboardDelete(ctx, dashHiddenDenied, "default"))
}

func TestSignedInUserDashboardDeleteIsDeniedForUnpermittedDashboard(t *testing.T) {
	ctx := identity.WithRequester(context.Background(), signedInCascadeUser())
	err := authorizeDashboardDelete(ctx, dashVisibleDenied, "default")
	require.True(t, apierrors.IsForbidden(err))
	require.NoError(t, authorizeDashboardDelete(ctx, dashVisibleAllowed, "default"))
}

func TestCascadeDelete_ForceDeleteLeavesDashboardsTheUserCannotDelete(t *testing.T) {
	setOpenFeatureToggles(t, map[string]bool{
		featuremgmt.FlagKubernetesFolderCascadeDelete:   true,
		featuremgmt.FlagGrafanaDashboardGlobalVariables: false,
	})

	user := signedInCascadeUser()
	root := newFolder("root")
	root.Namespace = "default"
	child := newFolder("child")
	child.Namespace = "default"
	store := &fakeFolderStorage{existing: map[string]*foldersv1.Folder{"root": root, "child": child}}

	searcher := &successiveDashboardSearcher{
		fakeCascadeSearcher: &fakeCascadeSearcher{
			childrenByParent: map[string][]string{"root": {"child"}},
		},
		serviceCalls: map[string]int{},
		// First service listing is what the cascade sees today. A second listing
		// adds a dashboard that was not in the set that could have been authorized.
		serviceListings: map[string][][]string{
			"root": {
				{dashVisibleAllowed, dashVisibleDenied, dashHiddenDenied},
				{dashVisibleAllowed, dashVisibleDenied, dashHiddenDenied, dashRacedDenied},
			},
			"child": {
				{dashChildDenied},
				{dashChildDenied, dashRacedDenied},
			},
		},
		userVisible: map[string][]string{
			"root":  {dashVisibleAllowed, dashVisibleDenied},
			"child": {dashChildDenied},
		},
	}

	names := []string{dashVisibleAllowed, dashVisibleDenied, dashHiddenDenied, dashChildDenied, dashRacedDenied}
	objs := make([]runtime.Object, 0, len(names))
	for _, name := range names {
		objs = append(objs, unstructuredDashboard("default", name))
	}
	s, dyn, _ := newAuthorizingDashboardCascade(store, searcher, objs...)

	validate := func(ctx context.Context, obj runtime.Object) error {
		f, ok := obj.(*foldersv1.Folder)
		require.True(t, ok)
		return validateOnDelete(ctx, f, searcher, forceDelete(), true)
	}

	_, _, err := s.Delete(ctxWithCascadeUser(user), "root", validate, forceDelete())
	gvr := dashv1.DashboardResourceInfo.GroupVersionResource()
	removed := make([]string, 0)
	for _, name := range names {
		_, getErr := dyn.Resource(gvr).Namespace("default").Get(context.Background(), name, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			removed = append(removed, name)
		}
	}
	require.Truef(t, apierrors.IsForbidden(err), "delete returned %v; deleted folders %v; removed dashboards %v", err, store.deleted, removed)

	for _, name := range names {
		dashboardStillPresent(t, dyn, "default", name)
	}
	require.Empty(t, store.deleted, "cascade must stop before deleting folders")
	require.Contains(t, store.existing, "root")
	require.Contains(t, store.existing, "child")
}

func TestCascadeDelete_LaterDashboardListingIsNotDeletedWithoutAuthorization(t *testing.T) {
	setKubernetesFolderCascadeDeleteToggle(t, true)

	user := signedInCascadeUser()
	root := newFolder("root")
	root.Namespace = "default"
	store := &fakeFolderStorage{existing: map[string]*foldersv1.Folder{"root": root}}
	searcher := &successiveDashboardSearcher{
		fakeCascadeSearcher: &fakeCascadeSearcher{},
		serviceCalls:        map[string]int{},
		serviceListings: map[string][][]string{
			"root": {
				{dashKept},
				{dashKept, dashRacedDenied},
			},
		},
		userVisible: map[string][]string{
			"root": {dashKept},
		},
	}
	s, dyn, _ := newAuthorizingDashboardCascade(store, searcher,
		unstructuredDashboard("default", dashKept),
		unstructuredDashboard("default", dashRacedDenied),
	)

	_, _, err := s.Delete(ctxWithCascadeUser(user), "root", nil, forceDelete())
	require.NoError(t, err)

	dashboardStillPresent(t, dyn, "default", dashRacedDenied)
	gvr := dashv1.DashboardResourceInfo.GroupVersionResource()
	_, err = dyn.Resource(gvr).Namespace("default").Get(context.Background(), dashKept, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err), "the dashboard the user may delete is deleted with the folder")
	require.Equal(t, []string{"root"}, store.deleted)
}
