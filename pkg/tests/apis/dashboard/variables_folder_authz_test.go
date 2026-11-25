package dashboards

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/watch"

	dashv2beta1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2beta1"
	foldersV1 "github.com/grafana/grafana/apps/folder/pkg/apis/folder/v1beta1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// Values stored on the restricted-folder variables. They are fixtures, not credentials.
const (
	restrictedCustomQuery   = "folder-private-query-definition"
	restrictedCustomOption  = "folder-private-option"
	restrictedCustomCurrent = "folder-private-current"
	restrictedConstantValue = "folder-private-constant-value"
	rootVariableQuery       = "stack-wide-query-definition"
	sharedFolderQuery       = "folder-view-granted-query"
)

// TestIntegrationVariablesFolderReadAuthz checks that a basic Viewer (and an Editor,
// who inherits the Viewer grant) cannot read variables stored in a folder they have
// no permission to open, while stack-wide variables and variables in a folder they
// can view stay readable.
//
// get, list (store scan, metadata.name fast path, and field/label selectors), and
// watch all resolve variables:read. Each one is exercised against the restricted
// folder. History and trash lists are not covered.
func TestIntegrationVariablesFolderReadAuthz(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	helper := apis.NewK8sTestHelper(t, testinfra.GrafanaOpts{
		DisableAnonymous:     true,
		EnableFeatureToggles: []string{"grafana.dashboardGlobalVariables"},
	})
	t.Cleanup(helper.Shutdown)

	ctx := context.Background()
	admin := helper.Org1.Admin
	editor := helper.Org1.Editor
	viewer := helper.Org1.Viewer

	adminID, err := identity.UserIdentifier(admin.Identity.GetID())
	require.NoError(t, err)
	viewerID, err := identity.UserIdentifier(viewer.Identity.GetID())
	require.NoError(t, err)

	adminVariables := helper.GetResourceClient(apis.ResourceClientArgs{
		User: admin,
		GVR:  dashv2beta1.VariableResourceInfo.GroupVersionResource(),
	})
	editorVariables := helper.GetResourceClient(apis.ResourceClientArgs{
		User: editor,
		GVR:  dashv2beta1.VariableResourceInfo.GroupVersionResource(),
	})
	viewerVariables := helper.GetResourceClient(apis.ResourceClientArgs{
		User: viewer,
		GVR:  dashv2beta1.VariableResourceInfo.GroupVersionResource(),
	})
	adminFolders := helper.GetResourceClient(apis.ResourceClientArgs{
		User: admin,
		GVR:  foldersV1.FolderResourceInfo.GroupVersionResource(),
	})
	viewerFolders := helper.GetResourceClient(apis.ResourceClientArgs{
		User: viewer,
		GVR:  foldersV1.FolderResourceInfo.GroupVersionResource(),
	})

	namespace := helper.Namespacer(admin.Identity.GetOrgID())

	restrictedFolder, err := adminFolders.Resource.Create(ctx, buildFolderObject(namespace, "Finance"), metav1.CreateOptions{})
	require.NoError(t, err)
	// Replace the default folder ACL. Viewer and Editor builtin roles are not
	// in this list, so neither holds view or edit on the folder.
	setFolderPermissions(t, helper, admin, restrictedFolder.GetName(), []ResourcePermissionSetting{
		{UserID: &adminID, Level: ResourcePermissionLevelAdmin},
	})

	sharedFolder, err := adminFolders.Resource.Create(ctx, buildFolderObject(namespace, "Shared"), metav1.CreateOptions{})
	require.NoError(t, err)
	setFolderPermissions(t, helper, admin, sharedFolder.GetName(), []ResourcePermissionSetting{
		{UserID: &adminID, Level: ResourcePermissionLevelAdmin},
		{UserID: &viewerID, Level: ResourcePermissionLevelView},
	})

	rootVariable := withVariableValues(buildVariableObject("", "publicRegion", ""), rootVariableQuery, "public-option", "public-current")
	createdRoot, err := adminVariables.Resource.Create(ctx, rootVariable, metav1.CreateOptions{})
	require.NoError(t, err)

	customVariable := withVariableValues(
		buildVariableObject("", "financeBudget", restrictedFolder.GetName()),
		restrictedCustomQuery,
		restrictedCustomOption,
		restrictedCustomCurrent,
	)
	createdCustom, err := adminVariables.Resource.Create(ctx, customVariable, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, "financeBudget--"+restrictedFolder.GetName(), createdCustom.GetName())

	constantVariable := buildConstantVariableObject("financeToken", restrictedFolder.GetName(), restrictedConstantValue)
	createdConstant, err := adminVariables.Resource.Create(ctx, constantVariable, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, "financeToken--"+restrictedFolder.GetName(), createdConstant.GetName())

	sharedVariable := withVariableValues(
		buildVariableObject("", "sharedRegion", sharedFolder.GetName()),
		sharedFolderQuery,
		"shared-option",
		"shared-current",
	)
	createdShared, err := adminVariables.Resource.Create(ctx, sharedVariable, metav1.CreateOptions{})
	require.NoError(t, err)

	// The objects exist and carry the private spec. Admin is granted all-folders
	// variable write, so this read is expected to succeed.
	adminGot, err := adminVariables.Resource.Get(ctx, createdCustom.GetName(), metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, restrictedCustomQuery, variableSpecQuery(adminGot))
	require.Contains(t, variableSpecJSON(t, adminGot), restrictedCustomOption)
	require.Contains(t, variableSpecJSON(t, adminGot), restrictedCustomCurrent)
	adminConstant, err := adminVariables.Resource.Get(ctx, createdConstant.GetName(), metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, restrictedConstantValue, variableSpecQuery(adminConstant))

	// The folder ACL itself must hold. If the Viewer can open the folder, the
	// variable assertions below would not be testing a missing folder grant.
	_, err = viewerFolders.Resource.Get(ctx, restrictedFolder.GetName(), metav1.GetOptions{})
	require.Error(t, err)
	require.True(t, k8serrors.IsForbidden(err), "viewer should not read the restricted folder, got: %v", err)

	t.Run("viewer can read stack-wide variables", func(t *testing.T) {
		got, err := viewerVariables.Resource.Get(ctx, createdRoot.GetName(), metav1.GetOptions{})
		require.NoError(t, err)
		require.Equal(t, rootVariableQuery, variableSpecQuery(got))
	})

	t.Run("viewer can read a variable in a folder they can view", func(t *testing.T) {
		got, err := viewerVariables.Resource.Get(ctx, createdShared.GetName(), metav1.GetOptions{})
		require.NoError(t, err)
		require.Equal(t, sharedFolderQuery, variableSpecQuery(got))

		list, err := viewerVariables.Resource.List(ctx, metav1.ListOptions{
			LabelSelector: folderLabelSelectorKey + "=" + sharedFolder.GetName(),
		})
		require.NoError(t, err)
		require.True(t, containsVariableName(list.Items, createdShared.GetName()))
	})

	t.Run("viewer cannot get variables stored in a folder they cannot view", func(t *testing.T) {
		assertVariableReadDenied(t, viewerVariables, createdCustom.GetName(), restrictedCustomQuery, restrictedCustomOption, restrictedCustomCurrent)
		assertVariableReadDenied(t, viewerVariables, createdConstant.GetName(), restrictedConstantValue)
	})

	t.Run("viewer list omits variables stored in a folder they cannot view", func(t *testing.T) {
		list, err := viewerVariables.Resource.List(ctx, metav1.ListOptions{})
		require.NoError(t, err)
		require.True(t, containsVariableName(list.Items, createdRoot.GetName()))
		require.True(t, containsVariableName(list.Items, createdShared.GetName()))
		assertListOmitsRestricted(t, list, createdCustom.GetName(), createdConstant.GetName())
	})

	t.Run("viewer metadata.name list omits the restricted variable", func(t *testing.T) {
		list, err := viewerVariables.Resource.List(ctx, metav1.ListOptions{
			FieldSelector: "metadata.name=" + createdCustom.GetName(),
		})
		require.NoError(t, err)
		assertListOmitsRestricted(t, list, createdCustom.GetName(), createdConstant.GetName())
	})

	t.Run("viewer field selector omits the restricted variable", func(t *testing.T) {
		byName, err := viewerVariables.Resource.List(ctx, metav1.ListOptions{
			FieldSelector: "spec.spec.name=financeBudget",
		})
		require.NoError(t, err)
		assertListOmitsRestricted(t, byName, createdCustom.GetName(), createdConstant.GetName())
	})

	t.Run("viewer label selector omits the restricted variable", func(t *testing.T) {
		byFolder, err := viewerVariables.Resource.List(ctx, metav1.ListOptions{
			LabelSelector: folderLabelSelectorKey + "=" + restrictedFolder.GetName(),
		})
		require.NoError(t, err)
		assertListOmitsRestricted(t, byFolder, createdCustom.GetName(), createdConstant.GetName())
	})

	t.Run("viewer watch does not deliver variables stored in a folder they cannot view", func(t *testing.T) {
		rootSeen := watchVariableQueries(t, viewerVariables, createdRoot.GetName())
		require.Contains(t, rootSeen, rootVariableQuery, "watch of a stack-wide variable must deliver it, so a missing restricted event is not an empty watch")

		restrictedSeen := watchVariableQueries(t, viewerVariables, createdCustom.GetName())
		require.NotContains(t, restrictedSeen, restrictedCustomQuery)
		require.Empty(t, restrictedSeen)

		constantSeen := watchVariableQueries(t, viewerVariables, createdConstant.GetName())
		require.NotContains(t, constantSeen, restrictedConstantValue)
		require.Empty(t, constantSeen)
	})

	t.Run("editor inherits the viewer grant and cannot read the restricted folder", func(t *testing.T) {
		got, err := editorVariables.Resource.Get(ctx, createdRoot.GetName(), metav1.GetOptions{})
		require.NoError(t, err)
		require.Equal(t, rootVariableQuery, variableSpecQuery(got))

		_, err = editorVariables.Resource.Get(ctx, createdShared.GetName(), metav1.GetOptions{})
		require.Error(t, err)
		require.True(t, k8serrors.IsForbidden(err), "editor has no grant on the shared folder, got: %v", err)

		assertVariableReadDenied(t, editorVariables, createdCustom.GetName(), restrictedCustomQuery, restrictedCustomOption, restrictedCustomCurrent)
		assertVariableReadDenied(t, editorVariables, createdConstant.GetName(), restrictedConstantValue)

		list, err := editorVariables.Resource.List(ctx, metav1.ListOptions{})
		require.NoError(t, err)
		require.True(t, containsVariableName(list.Items, createdRoot.GetName()))
		assertListOmitsRestricted(t, list, createdCustom.GetName(), createdConstant.GetName())
		require.False(t, containsVariableName(list.Items, createdShared.GetName()))
	})
}

func assertVariableReadDenied(t *testing.T, client *apis.K8sResourceClient, name string, leaked ...string) {
	t.Helper()
	got, err := client.Resource.Get(context.Background(), name, metav1.GetOptions{})
	if err == nil {
		t.Fatalf("read of %s succeeded and returned spec %s", name, variableSpecJSON(t, got))
	}
	require.True(t, k8serrors.IsForbidden(err), "expected forbidden for %s, got: %v", name, err)
	for _, secret := range leaked {
		require.NotContains(t, err.Error(), secret)
	}
}

func assertListOmitsRestricted(t *testing.T, list *unstructured.UnstructuredList, names ...string) {
	t.Helper()
	raw, err := json.Marshal(list.Items)
	require.NoError(t, err)
	body := string(raw)
	for _, name := range names {
		require.False(t, containsVariableName(list.Items, name), "list included %s: %s", name, body)
	}
	require.NotContains(t, body, restrictedCustomQuery)
	require.NotContains(t, body, restrictedCustomOption)
	require.NotContains(t, body, restrictedCustomCurrent)
	require.NotContains(t, body, restrictedConstantValue)
}

func withVariableValues(obj *unstructured.Unstructured, query, option, current string) *unstructured.Unstructured {
	spec := obj.Object["spec"].(map[string]any)["spec"].(map[string]any)
	spec["query"] = query
	spec["current"] = map[string]any{"text": current, "value": current}
	spec["options"] = []any{
		map[string]any{"text": option, "value": option, "selected": true},
	}
	return obj
}

func buildConstantVariableObject(variableName, folderUID, value string) *unstructured.Unstructured {
	obj := buildVariableObject("", variableName, folderUID)
	obj.Object["spec"] = map[string]any{
		"kind": "ConstantVariable",
		"spec": map[string]any{
			"name":        variableName,
			"query":       value,
			"current":     map[string]any{"text": value, "value": value},
			"hide":        "dontHide",
			"skipUrlSync": false,
		},
	}
	return obj
}

func variableSpecQuery(obj *unstructured.Unstructured) string {
	spec, ok := obj.Object["spec"].(map[string]any)
	if !ok {
		return ""
	}
	inner, ok := spec["spec"].(map[string]any)
	if !ok {
		return ""
	}
	query, _ := inner["query"].(string)
	return query
}

func variableSpecJSON(t *testing.T, obj *unstructured.Unstructured) string {
	t.Helper()
	raw, err := json.Marshal(obj.Object["spec"])
	require.NoError(t, err)
	return string(raw)
}

// watchVariableQueries reads the initial watch events for one variable name.
// The caller uses a variable the subject is allowed to see to prove the watch
// delivered state, then applies the same call to a restricted name.
func watchVariableQueries(t *testing.T, client *apis.K8sResourceClient, name string) []string {
	t.Helper()
	sendInitial := true
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	watcher, err := client.Resource.Watch(ctx, metav1.ListOptions{
		FieldSelector:        "metadata.name=" + name,
		ResourceVersion:      "0",
		ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		SendInitialEvents:    &sendInitial,
		AllowWatchBookmarks:  true,
	})
	require.NoError(t, err)
	defer watcher.Stop()

	var queries []string
	for {
		select {
		case <-ctx.Done():
			return queries
		case evt, ok := <-watcher.ResultChan():
			if !ok {
				return queries
			}
			switch evt.Type {
			case watch.Bookmark:
				return queries
			case watch.Error:
				status, ok := evt.Object.(*metav1.Status)
				if ok && status.Code == 403 {
					return queries
				}
				require.Failf(t, "watch failed", "event %#v", evt)
			case watch.Added:
				obj, ok := evt.Object.(*unstructured.Unstructured)
				require.True(t, ok, "watch event object is %T", evt.Object)
				queries = append(queries, variableSpecQuery(obj))
			}
		}
	}
}
