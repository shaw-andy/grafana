package dashboards

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	dashboardV2beta1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2beta1"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// TestIntegrationNotebookWritesFollowNotebookPermissions is the authorization
// contract for dashboard.grafana.app/v2beta1 notebooks once dashboard.notebooks
// is enabled. A Viewer, who holds notebooks:read and not notebooks:write or
// notebooks:delete, can read a notebook and cannot create, replace, patch, or
// delete one. A member with no notebook grants cannot read it either. An Editor,
// who holds the writer role, still can. A refused write must leave the notebook
// that was named in the request unchanged.
func TestIntegrationNotebookWritesFollowNotebookPermissions(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	helper := apis.NewK8sTestHelper(t, testinfra.GrafanaOpts{
		AppModeProduction:    true,
		DisableAnonymous:     true,
		APIServerStorageType: "unified",
		EnableFeatureToggles: []string{featuremgmt.FlagDashboardNotebooks},
	})
	t.Cleanup(helper.Shutdown)

	gvr := schema.GroupVersionResource{
		Group:    dashboardV2beta1.GROUP,
		Version:  dashboardV2beta1.VERSION,
		Resource: "notebooks",
	}
	ctx := context.Background()
	admin := helper.GetResourceClient(apis.ResourceClientArgs{User: helper.Org1.Admin, GVR: gvr})
	editor := helper.GetResourceClient(apis.ResourceClientArgs{User: helper.Org1.Editor, GVR: gvr})
	viewer := helper.GetResourceClient(apis.ResourceClientArgs{User: helper.Org1.Viewer, GVR: gvr})
	none := helper.GetResourceClient(apis.ResourceClientArgs{User: helper.Org1.None, GVR: gvr})

	const victimTitle = "original investigation"
	// Each write targets its own notebook. A write that wrongly succeeds must not
	// turn a later check into NotFound.
	readTarget := createNotebook(t, ctx, admin, gvr, "nb-rbac-read", victimTitle)
	updateTarget := createNotebook(t, ctx, admin, gvr, "nb-rbac-update", victimTitle)
	patchTarget := createNotebook(t, ctx, admin, gvr, "nb-rbac-patch", victimTitle)
	deleteTarget := createNotebook(t, ctx, admin, gvr, "nb-rbac-delete", victimTitle)
	noneTarget := createNotebook(t, ctx, admin, gvr, "nb-rbac-none", victimTitle)
	editorTarget := createNotebook(t, ctx, admin, gvr, "nb-rbac-editor", victimTitle)

	t.Run("viewer can read the notebook", func(t *testing.T) {
		got, err := viewer.Resource.Get(ctx, readTarget.GetName(), metav1.GetOptions{})
		require.NoError(t, err)
		require.Equal(t, victimTitle, notebookTitle(t, got))
	})

	t.Run("viewer list includes the notebook", func(t *testing.T) {
		list, err := viewer.Resource.List(ctx, metav1.ListOptions{})
		require.NoError(t, err)
		require.True(t, notebookListHas(list, readTarget.GetName()))
	})

	t.Run("viewer create is forbidden and stores nothing", func(t *testing.T) {
		const name = "nb-rbac-viewer-create"
		_, err := viewer.Resource.Create(ctx, notebookObject(gvr, name, "viewer created this"), metav1.CreateOptions{})
		requireForbidden(t, err)
		_, err = admin.Resource.Get(ctx, name, metav1.GetOptions{})
		require.True(t, apierrors.IsNotFound(err), "forbidden create still stored %s: %v", name, err)
	})

	t.Run("viewer update is forbidden and leaves the stored notebook", func(t *testing.T) {
		replaced := updateTarget.DeepCopy()
		require.NoError(t, unstructured.SetNestedField(replaced.Object, "viewer overwrote this", "spec", "title"))
		_, err := viewer.Resource.Update(ctx, replaced, metav1.UpdateOptions{})
		requireForbidden(t, err)
		require.Equal(t, victimTitle, notebookTitle(t, mustGetNotebook(t, ctx, admin, updateTarget.GetName())))
	})

	t.Run("viewer patch is forbidden and leaves the stored notebook", func(t *testing.T) {
		_, err := viewer.Resource.Patch(ctx, patchTarget.GetName(), types.MergePatchType,
			[]byte(`{"spec":{"title":"viewer patched this"}}`), metav1.PatchOptions{})
		requireForbidden(t, err)
		require.Equal(t, victimTitle, notebookTitle(t, mustGetNotebook(t, ctx, admin, patchTarget.GetName())))
	})

	t.Run("viewer delete is forbidden and leaves the stored notebook", func(t *testing.T) {
		err := viewer.Resource.Delete(ctx, deleteTarget.GetName(), metav1.DeleteOptions{})
		requireForbidden(t, err)
		require.Equal(t, victimTitle, notebookTitle(t, mustGetNotebook(t, ctx, admin, deleteTarget.GetName())))
	})

	t.Run("a member with no notebook grants cannot read it", func(t *testing.T) {
		_, err := none.Resource.Get(ctx, noneTarget.GetName(), metav1.GetOptions{})
		requireForbidden(t, err)
	})

	t.Run("a member with no notebook grants cannot list it", func(t *testing.T) {
		list, err := none.Resource.List(ctx, metav1.ListOptions{})
		if err != nil {
			requireForbidden(t, err)
			return
		}
		require.False(t, notebookListHas(list, noneTarget.GetName()))
	})

	t.Run("a member with no notebook grants cannot create one", func(t *testing.T) {
		const createdName = "nb-rbac-none-create"
		_, err := none.Resource.Create(ctx, notebookObject(gvr, createdName, "none created this"), metav1.CreateOptions{})
		requireForbidden(t, err)
		_, err = admin.Resource.Get(ctx, createdName, metav1.GetOptions{})
		require.True(t, apierrors.IsNotFound(err), "forbidden create still stored the notebook: %v", err)
	})

	noneUpdate := createNotebook(t, ctx, admin, gvr, "nb-rbac-none-update", victimTitle)
	nonePatch := createNotebook(t, ctx, admin, gvr, "nb-rbac-none-patch", victimTitle)
	noneDelete := createNotebook(t, ctx, admin, gvr, "nb-rbac-none-delete", victimTitle)

	t.Run("a member with no notebook grants cannot update it", func(t *testing.T) {
		replaced := noneUpdate.DeepCopy()
		require.NoError(t, unstructured.SetNestedField(replaced.Object, "none overwrote this", "spec", "title"))
		_, err := none.Resource.Update(ctx, replaced, metav1.UpdateOptions{})
		requireForbidden(t, err)
		require.Equal(t, victimTitle, notebookTitle(t, mustGetNotebook(t, ctx, admin, noneUpdate.GetName())))
	})

	t.Run("a member with no notebook grants cannot patch it", func(t *testing.T) {
		_, err := none.Resource.Patch(ctx, nonePatch.GetName(), types.MergePatchType,
			[]byte(`{"spec":{"title":"none patched this"}}`), metav1.PatchOptions{})
		requireForbidden(t, err)
		require.Equal(t, victimTitle, notebookTitle(t, mustGetNotebook(t, ctx, admin, nonePatch.GetName())))
	})

	t.Run("a member with no notebook grants cannot delete it", func(t *testing.T) {
		err := none.Resource.Delete(ctx, noneDelete.GetName(), metav1.DeleteOptions{})
		requireForbidden(t, err)
		require.Equal(t, victimTitle, notebookTitle(t, mustGetNotebook(t, ctx, admin, noneDelete.GetName())))
	})

	t.Run("editor can still update the notebook", func(t *testing.T) {
		const editorTitle = "editor revision"
		current := mustGetNotebook(t, ctx, editor, editorTarget.GetName())
		require.NoError(t, unstructured.SetNestedField(current.Object, editorTitle, "spec", "title"))
		updated, err := editor.Resource.Update(ctx, current, metav1.UpdateOptions{})
		require.NoError(t, err)
		require.Equal(t, editorTitle, notebookTitle(t, updated))
		require.Equal(t, editorTitle, notebookTitle(t, mustGetNotebook(t, ctx, admin, editorTarget.GetName())))
	})
}

func notebookObject(gvr schema.GroupVersionResource, name, title string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{
			"title":    title,
			"elements": map[string]any{},
			"layout": map[string]any{
				"kind": "NotebookLayout",
				"spec": map[string]any{"cells": []any{}},
			},
		},
	}}
	obj.SetName(name)
	obj.SetAPIVersion(gvr.GroupVersion().String())
	obj.SetKind("Notebook")
	return obj
}

func notebookTitle(t *testing.T, obj *unstructured.Unstructured) string {
	t.Helper()
	title, found, err := unstructured.NestedString(obj.Object, "spec", "title")
	require.NoError(t, err)
	require.True(t, found)
	return title
}

func mustGetNotebook(t *testing.T, ctx context.Context, client *apis.K8sResourceClient, name string) *unstructured.Unstructured {
	t.Helper()
	got, err := client.Resource.Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)
	return got
}

func notebookListHas(list *unstructured.UnstructuredList, name string) bool {
	for _, item := range list.Items {
		if item.GetName() == name {
			return true
		}
	}
	return false
}

func requireForbidden(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	require.Truef(t, apierrors.IsForbidden(err), "expected Forbidden, got %v", err)
}
