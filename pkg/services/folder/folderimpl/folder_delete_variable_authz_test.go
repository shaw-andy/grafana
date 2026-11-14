package folderimpl

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/grpchan/inprocgrpc"
	authnlib "github.com/grafana/authlib/authn"
	authzlib "github.com/grafana/authlib/authz"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	authlib "github.com/grafana/authlib/types"
	"github.com/open-feature/go-sdk/openfeature"
	"github.com/open-feature/go-sdk/openfeature/memprovider"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	dashboardv1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	dashv2beta1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2beta1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/log/logtest"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/apiserver/client"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/publicdashboards"
	"github.com/grafana/grafana/pkg/services/store/entity"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/storage/unified/search"
)

const (
	folderDeleteOrgID        int64 = 1
	folderDeleteNamespace          = "default"
	folderDeleteFolderUID          = "fld"
	folderDeleteVisibleDash        = "visible-dash"
	folderDeleteHiddenDash         = "hidden-dash"
	folderDeleteVariableName       = "shared-query"
)

// TestFolderDeleteLeavesVariablesWhenTheFolderDeleteIsRefused is the spec for
// DELETE /api/folders/{uid} (folder.Service.Delete).
//
// The caller holds folders:delete and cannot read every dashboard in the
// folder. Search omits those dashboards, the folder API then counts every
// dashboard and refuses the delete. Variables must still be stored when that
// refusal comes back. A caller without variables:delete must not lose them on
// this path, whether or not the global variables feature is enabled.
//
// Kubernetes folder cascade delete is not covered. Service.Delete calls the
// folder API with empty DeleteOptions, and cascade replaces that delete only
// when gracePeriodSeconds is 0.
func TestFolderDeleteLeavesVariablesWhenTheFolderDeleteIsRefused(t *testing.T) {
	cases := []struct {
		name               string
		globalVariables    bool
		mayDeleteVariables bool
		hiddenDashboard    bool
		visibleDashboard   bool
		forceDeleteRules   bool
	}{
		{name: "hidden dashboard and no variable grant, feature off", hiddenDashboard: true, visibleDashboard: true},
		{name: "hidden dashboard and no variable grant, feature on", globalVariables: true, hiddenDashboard: true, visibleDashboard: true},
		{name: "only a variable and no variable grant, feature off"},
		{name: "only a variable and no variable grant, feature on", globalVariables: true},
		{name: "hidden dashboard even when the caller may delete variables", globalVariables: true, mayDeleteVariables: true, hiddenDashboard: true, visibleDashboard: true},
		{name: "every dashboard hidden", hiddenDashboard: true},
		{name: "forceDeleteRules still removes variables before the folder delete is refused", hiddenDashboard: true, forceDeleteRules: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setFolderDeleteGlobalVariables(t, tc.globalVariables)
			result := deleteFolderWithSplitDashboardAccess(t, tc.mayDeleteVariables, tc.hiddenDashboard, tc.visibleDashboard, tc.forceDeleteRules)

			if !tc.mayDeleteVariables {
				require.Contains(t, result.variables, folderDeleteVariableName, "caller without variables:delete removed the variable; delete error: %v", result.err)
			}
			if result.err != nil {
				require.Contains(t, result.variables, folderDeleteVariableName, "variable was removed before folder delete was refused: %v", result.err)
				require.False(t, result.folderDeleted, "folder delete was recorded after the call returned an error")
			}
			if tc.hiddenDashboard {
				require.Contains(t, result.dashboards, folderDeleteHiddenDash, "dashboard the caller cannot read was deleted")
			}
		})
	}
}

type folderDeleteResult struct {
	err           error
	variables     map[string]string
	dashboards    map[string]struct{}
	folderDeleted bool
}

func deleteFolderWithSplitDashboardAccess(t *testing.T, mayDeleteVariables, hiddenDashboard, visibleDashboard, forceDeleteRules bool) folderDeleteResult {
	t.Helper()

	perms := map[string][]string{
		folder.ActionFoldersDelete: {folder.ScopeFoldersProvider.GetResourceScopeUID(folderDeleteFolderUID)},
	}
	if visibleDashboard {
		perms[dashboards.ActionDashboardsRead] = []string{dashboards.ScopeDashboardsPrefix + folderDeleteVisibleDash}
		perms[dashboards.ActionDashboardsDelete] = []string{dashboards.ScopeDashboardsPrefix + folderDeleteVisibleDash}
	}
	if mayDeleteVariables {
		perms[accesscontrol.ActionVariablesDelete] = []string{folder.ScopeFoldersProvider.GetResourceScopeUID(folderDeleteFolderUID)}
	}

	editor := &identity.StaticRequester{
		Type:      authlib.TypeUser,
		UserID:    7,
		UserUID:   "editor",
		OrgID:     folderDeleteOrgID,
		Namespace: folderDeleteNamespace,
		Permissions: map[int64]map[string][]string{
			folderDeleteOrgID: perms,
		},
		// Signed-in sessions have no upstream access token. AccessClaimsHook
		// copies the service delegated permissions so the authz client will ask
		// about this user's grants instead of refusing the delegation.
		AccessTokenClaims: &authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{
				DelegatedPermissions: append([]string(nil), identity.ServiceIdentityClaims.Rest.DelegatedPermissions...),
			},
		},
	}

	access := newDashboardRBACAccessClient(t, editor.GetUID(), perms)
	dashGVR := dashboardv1.DashboardResourceInfo.GroupVersionResource()
	varGVR := dashv2beta1.VariableResourceInfo.GroupVersionResource()
	dashIndex := newFolderDeleteIndex(t, dashGVR.Resource)
	varIndex := newFolderDeleteIndex(t, varGVR.Resource)

	dashboardsLeft := map[string]struct{}{}
	if visibleDashboard {
		indexFolderChild(t, dashIndex, dashGVR, folderDeleteVisibleDash)
		dashboardsLeft[folderDeleteVisibleDash] = struct{}{}
	}
	if hiddenDashboard {
		indexFolderChild(t, dashIndex, dashGVR, folderDeleteHiddenDash)
		dashboardsLeft[folderDeleteHiddenDash] = struct{}{}
	}
	variablesLeft := map[string]string{folderDeleteVariableName: folderDeleteFolderUID}
	indexFolderChild(t, varIndex, varGVR, folderDeleteVariableName)

	ac := acimpl.ProvideAccessControl(featuremgmt.WithFeatures())

	dashHandler := &folderDeleteK8sHandler{
		gvr:    dashGVR,
		index:  dashIndex,
		access: access,
		delete: func(ctx context.Context, name string) error {
			requester, err := identity.GetRequester(ctx)
			if err != nil {
				return apierrors.NewUnauthorized("valid user is required")
			}
			if !dashboardGrantAllows(requester.GetPermissions(), utils.VerbDelete, name, folderDeleteFolderUID) {
				return apierrors.NewForbidden(dashboardv1.DashboardResourceInfo.GroupResource(), name, folder.ErrAccessDenied)
			}
			if err := deleteIndexed(dashIndex, dashGVR, name); err != nil {
				return err
			}
			delete(dashboardsLeft, name)
			return nil
		},
	}
	varHandler := &folderDeleteK8sHandler{
		gvr:    varGVR,
		index:  varIndex,
		access: access,
		delete: func(ctx context.Context, name string) error {
			if err := authorizeVariableDelete(ctx, ac, folderDeleteFolderUID); err != nil {
				return err
			}
			if err := deleteIndexed(varIndex, varGVR, name); err != nil {
				return err
			}
			delete(variablesLeft, name)
			return nil
		},
	}

	folderDeleted := false
	store := &folderDeleteStore{
		Store: folder.NewFakeStore(),
		deleteFn: func(ctx context.Context, uids []string, _ int64) error {
			for _, uid := range uids {
				dashCount, err := dashIndex.DocCount(ctx, uid, resource.NewSearchStats("doc-count"))
				if err != nil {
					return err
				}
				if dashCount > 0 {
					return folder.ErrFolderNotEmpty.Errorf("folder is not empty, contains %d dashboards", dashCount)
				}
				varCount, err := varIndex.DocCount(ctx, uid, resource.NewSearchStats("doc-count"))
				if err != nil {
					return err
				}
				if varCount > 0 {
					return folder.ErrFolderNotEmpty.Errorf("folder is not empty, contains %d variables", varCount)
				}
			}
			folderDeleted = true
			return nil
		},
	}

	svc := &Service{
		unifiedStore:           store,
		dashboardK8sClient:     dashHandler,
		variableK8sClient:      varHandler,
		publicDashboardService: nopPublicDashboards{},
		registry: map[string]folder.RegistryService{
			entity.StandardKindAlertRule:    emptyFolderRegistry{kind: entity.StandardKindAlertRule},
			entity.StandardKindLibraryPanel: emptyFolderRegistry{kind: entity.StandardKindLibraryPanel},
		},
		tracer: noop.NewTracerProvider().Tracer("folder-delete-variable-authz"),
		log:    slog.New(logtest.NewNopHandler(t)),
	}

	ctx := identity.WithRequester(context.Background(), editor)
	err := svc.Delete(ctx, &folder.DeleteFolderCommand{
		UID:              folderDeleteFolderUID,
		OrgID:            folderDeleteOrgID,
		SignedInUser:     editor,
		ForceDeleteRules: forceDeleteRules,
	})
	return folderDeleteResult{
		err:           err,
		variables:     variablesLeft,
		dashboards:    dashboardsLeft,
		folderDeleted: folderDeleted,
	}
}

// authorizeVariableDelete is the variable delete gate the apiserver runs:
// newVariableAuthorizer, then validateVariableDelete's folder-scoped admission.
// The dashboard package cannot be imported from this test (it already imports
// folderimpl), so the branches below are the ones those two functions run for
// a resource delete when classic access control is wired.
func authorizeVariableDelete(ctx context.Context, ac accesscontrol.AccessControl, folderUID string) error {
	enabled := openfeature.NewDefaultClient().Boolean(ctx, featuremgmt.FlagGrafanaDashboardGlobalVariables, false, openfeature.TransactionContext(ctx))
	if !enabled {
		if identity.IsServiceIdentity(ctx) {
			// get, list, watch, delete, and deletecollection are allowed for the
			// service identity while the feature is off. This call is a delete.
		} else {
			return apierrors.NewForbidden(dashv2beta1.VariableResourceInfo.GroupResource(), "", folder.ErrAccessDenied)
		}
	} else {
		requester, err := identity.GetRequester(ctx)
		if err != nil {
			return apierrors.NewForbidden(dashv2beta1.VariableResourceInfo.GroupResource(), "", folder.ErrAccessDenied)
		}
		// Delete is a coarse variables:delete check. Admission below narrows it
		// to the folder.
		ok, err := ac.Evaluate(ctx, requester, accesscontrol.EvalPermission(accesscontrol.ActionVariablesDelete))
		if err != nil || !ok {
			return apierrors.NewForbidden(dashv2beta1.VariableResourceInfo.GroupResource(), "", folder.ErrAccessDenied)
		}
	}

	requester, err := identity.GetRequester(ctx)
	if err != nil {
		return apierrors.NewForbidden(dashv2beta1.VariableResourceInfo.GroupResource(), "", folder.ErrAccessDenied)
	}
	scope := folder.ScopeFoldersProvider.GetResourceScopeUID(folderUID)
	if folderUID == "" {
		scope = folder.ScopeFoldersProvider.GetResourceScopeUID(accesscontrol.GeneralFolderUID)
	}
	ok, err := ac.Evaluate(ctx, requester, accesscontrol.EvalPermission(accesscontrol.ActionVariablesDelete, scope))
	if err != nil || !ok {
		return apierrors.NewForbidden(dashv2beta1.VariableResourceInfo.GroupResource(), "", folder.ErrAccessDenied)
	}
	return nil
}

func newFolderDeleteIndex(t *testing.T, resourceName string) resource.ResourceIndex {
	t.Helper()
	backend, err := search.NewBleveBackend(search.BleveOptions{
		Root:          t.TempDir(),
		FileThreshold: 1 << 20,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(backend.Stop)

	ctx := identity.WithRequester(context.Background(), &identity.StaticRequester{Namespace: folderDeleteNamespace})
	index, err := backend.BuildIndex(ctx, resource.NamespacedResource{
		Namespace: folderDeleteNamespace,
		Group:     dashboardv1.DashboardResourceInfo.GroupVersionResource().Group,
		Resource:  resourceName,
	}, 10, "test", func(resource.ResourceIndex) (int64, error) { return 0, nil }, nil, false, time.Time{}, 0)
	require.NoError(t, err)
	return index
}

func indexFolderChild(t *testing.T, index resource.ResourceIndex, gvr schema.GroupVersionResource, name string) {
	t.Helper()
	require.NoError(t, index.BulkIndex(&resource.BulkIndexRequest{Items: []*resource.BulkIndexItem{{
		Action: resource.ActionIndex,
		Doc: &resource.IndexableDocument{
			Name:   name,
			Title:  name,
			Folder: folderDeleteFolderUID,
			Key: &resourcepb.ResourceKey{
				Namespace: folderDeleteNamespace,
				Group:     gvr.Group,
				Resource:  gvr.Resource,
				Name:      name,
			},
		},
	}}}))
}

func deleteIndexed(index resource.ResourceIndex, gvr schema.GroupVersionResource, name string) error {
	return index.BulkIndex(&resource.BulkIndexRequest{Items: []*resource.BulkIndexItem{{
		Action: resource.ActionDelete,
		Key: &resourcepb.ResourceKey{
			Namespace: folderDeleteNamespace,
			Group:     gvr.Group,
			Resource:  gvr.Resource,
			Name:      name,
		},
	}}})
}

// folderDeleteK8sHandler serves one resource the way the in-process client does:
// Search goes to the bleve index with the caller's context, and Delete runs the
// callback (dashboard grant or variable authorizer plus admission).
type folderDeleteK8sHandler struct {
	gvr    schema.GroupVersionResource
	index  resource.ResourceIndex
	access authlib.AccessClient
	delete func(ctx context.Context, name string) error
}

func (h *folderDeleteK8sHandler) GetNamespace(int64) string { return folderDeleteNamespace }

func (h *folderDeleteK8sHandler) Search(ctx context.Context, orgID int64, in *resourcepb.ResourceSearchRequest) (*resourcepb.ResourceSearchResponse, error) {
	if in.Options == nil {
		in.Options = &resourcepb.ListOptions{}
	}
	if in.Options.Key == nil {
		in.Options.Key = &resourcepb.ResourceKey{
			Namespace: h.GetNamespace(orgID),
			Group:     h.gvr.Group,
			Resource:  h.gvr.Resource,
		}
	}
	return h.index.Search(ctx, h.access, in, nil, resource.NewSearchStats("search"))
}

func (h *folderDeleteK8sHandler) Delete(ctx context.Context, name string, _ int64, _ metav1.DeleteOptions) error {
	return h.delete(ctx, name)
}

func (h *folderDeleteK8sHandler) Get(context.Context, string, int64, metav1.GetOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, status.Error(codes.Unimplemented, "unused")
}
func (h *folderDeleteK8sHandler) Create(context.Context, *unstructured.Unstructured, int64, metav1.CreateOptions) (*unstructured.Unstructured, error) {
	return nil, status.Error(codes.Unimplemented, "unused")
}
func (h *folderDeleteK8sHandler) Update(context.Context, *unstructured.Unstructured, int64, metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	return nil, status.Error(codes.Unimplemented, "unused")
}
func (h *folderDeleteK8sHandler) Patch(context.Context, string, types.PatchType, []byte, int64, metav1.PatchOptions) (*unstructured.Unstructured, error) {
	return nil, status.Error(codes.Unimplemented, "unused")
}
func (h *folderDeleteK8sHandler) DeleteCollection(context.Context, int64, metav1.ListOptions) error {
	return status.Error(codes.Unimplemented, "unused")
}
func (h *folderDeleteK8sHandler) List(context.Context, int64, metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return nil, status.Error(codes.Unimplemented, "unused")
}
func (h *folderDeleteK8sHandler) GetStats(context.Context, int64) (*resourcepb.ResourceStatsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unused")
}
func (h *folderDeleteK8sHandler) GetUsersFromMeta(context.Context, []string) (map[string]*user.User, error) {
	return nil, status.Error(codes.Unimplemented, "unused")
}

var _ client.K8sHandler = (*folderDeleteK8sHandler)(nil)

type folderDeleteStore struct {
	folder.Store
	deleteFn func(ctx context.Context, uids []string, orgID int64) error
}

func (s *folderDeleteStore) Delete(ctx context.Context, uids []string, orgID int64) error {
	return s.deleteFn(ctx, uids, orgID)
}

type emptyFolderRegistry struct{ kind string }

func (e emptyFolderRegistry) Kind() string { return e.kind }
func (emptyFolderRegistry) DeleteInFolders(context.Context, int64, []string, identity.Requester) error {
	return nil
}
func (emptyFolderRegistry) CountInFolders(context.Context, int64, []string, identity.Requester) (int64, error) {
	return 0, nil
}

type nopPublicDashboards struct{}

func (nopPublicDashboards) FindByDashboardUid(context.Context, int64, string) (*publicdashboards.PublicDashboard, error) {
	return nil, nil
}
func (nopPublicDashboards) Delete(context.Context, int64, string) error { return nil }
func (nopPublicDashboards) DeleteByDashboardUIDs(context.Context, int64, []string) error {
	return nil
}

func setFolderDeleteGlobalVariables(t *testing.T, enabled bool) {
	t.Helper()
	variant := "disabled"
	if enabled {
		variant = "enabled"
	}
	require.NoError(t, openfeature.SetProviderAndWait(memprovider.NewInMemoryProvider(map[string]memprovider.InMemoryFlag{
		featuremgmt.FlagGrafanaDashboardGlobalVariables: {
			Key:            featuremgmt.FlagGrafanaDashboardGlobalVariables,
			DefaultVariant: variant,
			Variants: map[string]any{
				"enabled":  true,
				"disabled": false,
			},
		},
	})))
	t.Cleanup(func() {
		_ = openfeature.SetProviderAndWait(openfeature.NoopProvider{})
	})
}

// newDashboardRBACAccessClient is the authlib client Grafana wires in front of
// the RBAC service. Service identities are allowed from their token inside that
// client. User checks are answered with the same scope rules as
// checkPermissionWithMapping for a root folder: an object scope, a folder
// scope, or a wildcard.
func newDashboardRBACAccessClient(t *testing.T, subject string, perms map[string][]string) authlib.AccessClient {
	t.Helper()
	channel := &inprocgrpc.Channel{}
	authzv1.RegisterAuthzServiceServer(channel, &dashboardRBACServer{subject: subject, perms: perms})
	return authzlib.NewClient(channel)
}

type dashboardRBACServer struct {
	authzv1.UnimplementedAuthzServiceServer
	subject string
	perms   map[string][]string
}

func (s *dashboardRBACServer) BatchCheck(_ context.Context, req *authzv1.BatchCheckRequest) (*authzv1.BatchCheckResponse, error) {
	results := make(map[string]*authzv1.BatchCheckResult, len(req.GetChecks()))
	for _, check := range req.GetChecks() {
		allowed := false
		if req.GetSubject() == s.subject {
			allowed = grantAllows(s.perms, check.GetResource(), check.GetVerb(), check.GetName(), check.GetFolder())
		}
		results[check.GetCorrelationId()] = &authzv1.BatchCheckResult{Allowed: allowed}
	}
	return &authzv1.BatchCheckResponse{Results: results}, nil
}

func dashboardGrantAllows(perms map[string][]string, verb, name, folderUID string) bool {
	return grantAllows(perms, "dashboards", verb, name, folderUID)
}

// grantAllows applies checkPermissionWithMapping's scope match for dashboards.
// Action sets are the ones newDashboardTranslation attaches to each verb.
func grantAllows(perms map[string][]string, resourceName, verb, name, folderUID string) bool {
	var actions []string
	switch resourceName {
	case "dashboards":
		switch verb {
		case utils.VerbGet, utils.VerbList, utils.VerbWatch:
			actions = []string{
				dashboards.ActionDashboardsRead,
				"dashboards:view", "folders:view",
				"dashboards:edit", "folders:edit",
				"dashboards:admin", "folders:admin",
			}
		case utils.VerbDelete, utils.VerbDeleteCollection:
			actions = []string{
				dashboards.ActionDashboardsDelete,
				"dashboards:edit", "folders:edit",
				"dashboards:admin", "folders:admin",
			}
		default:
			return false
		}
	case "variables":
		switch verb {
		case utils.VerbGet, utils.VerbList, utils.VerbWatch:
			actions = []string{accesscontrol.ActionVariablesRead}
		case utils.VerbDelete, utils.VerbDeleteCollection:
			actions = []string{accesscontrol.ActionVariablesDelete}
		default:
			return false
		}
	default:
		return false
	}

	scopes := map[string]bool{}
	for _, action := range actions {
		for _, scope := range perms[action] {
			if scope == "*" || strings.HasSuffix(scope, ":*") {
				return true
			}
			scopes[scope] = true
		}
	}
	if scopes["*"] {
		return true
	}
	if name != "" && scopes[resourceName+":uid:"+name] {
		return true
	}
	if folderUID != "" && scopes["folders:uid:"+folderUID] {
		return true
	}
	return false
}
