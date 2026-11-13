package dashboards

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	dashboardV0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	dashboardV1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	dashboardV1beta1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1beta1"
	dashboardV2 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2"
	dashboardV2alpha1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2alpha1"
	dashboardV2beta1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2beta1"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// TestIntegrationProvisionedDashboardDeleteRejectsClientGracePeriod is the spec for the
// provisioned-dashboard delete bypass. It fails while a client-supplied grace period of
// zero (or a collection delete) can remove a file-provisioned dashboard.
func TestIntegrationProvisionedDashboardDeleteRejectsClientGracePeriod(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	helper := apis.NewK8sTestHelper(t, testinfra.GrafanaOpts{
		DisableAnonymous: true,
	})
	t.Cleanup(helper.Shutdown)

	// An Editor does not receive dashboards:delete from the basic role. Grant the
	// permission the finding assumes, on every dashboard, so the delete reaches the
	// provisioned-dashboard check instead of stopping at authorization.
	helper.SetPermissions(helper.Org1.Editor, []resourcepermissions.SetResourcePermissionCommand{
		{
			Actions: []string{
				dashboards.ActionDashboardsRead,
				dashboards.ActionDashboardsWrite,
				dashboards.ActionDashboardsDelete,
			},
			Resource:          "dashboards",
			ResourceAttribute: "uid",
			ResourceID:        "*",
		},
	})

	versions := []schema.GroupVersionResource{
		dashboardV0.DashboardResourceInfo.GroupVersionResource(),
		dashboardV1beta1.DashboardResourceInfo.GroupVersionResource(),
		dashboardV1.DashboardResourceInfo.GroupVersionResource(),
		dashboardV2alpha1.DashboardResourceInfo.GroupVersionResource(),
		dashboardV2beta1.DashboardResourceInfo.GroupVersionResource(),
		dashboardV2.DashboardResourceInfo.GroupVersionResource(),
	}
	for _, gvr := range versions {
		t.Run(gvr.Version, func(t *testing.T) {
			runProvisionedDeleteGraceTest(t, helper, gvr)
		})
	}
}

func runProvisionedDeleteGraceTest(t *testing.T, helper *apis.K8sTestHelper, gvr schema.GroupVersionResource) {
	t.Helper()
	ctx := context.Background()

	admin := helper.GetResourceClient(apis.ResourceClientArgs{
		User: helper.Org1.Admin,
		GVR:  gvr,
	})
	editor := helper.GetResourceClient(apis.ResourceClientArgs{
		User: helper.Org1.Editor,
		GVR:  gvr,
	})
	viewer := helper.GetResourceClient(apis.ResourceClientArgs{
		User: helper.Org1.Viewer,
		GVR:  gvr,
	})

	prefix := gvr.Version

	t.Run("editor can delete a dashboard that is not provisioned", func(t *testing.T) {
		plain := createDashboard(t, ctx, admin, gvr, prefix+"-plain", "Editor may delete this")
		err := editor.Resource.Delete(ctx, plain.GetName(), metav1.DeleteOptions{})
		require.NoError(t, err)
		_, err = editor.Resource.Get(ctx, plain.GetName(), metav1.GetOptions{})
		require.True(t, apierrors.IsNotFound(err), "non-provisioned dashboard should be gone, got %v", err)
	})

	t.Run("editor delete without a grace period is rejected", func(t *testing.T) {
		target, bystander := provisionedPair(t, ctx, admin, gvr, prefix+"-normal")
		before := mustGetDashboard(t, ctx, editor, target.GetName())
		err := editor.Resource.Delete(ctx, target.GetName(), metav1.DeleteOptions{})
		require.Error(t, err)
		require.False(t, apierrors.IsNotFound(err))
		assertSameProvisionedDashboard(t, ctx, editor, before)
		assertUntouched(t, ctx, editor, bystander)
	})

	t.Run("viewer cannot delete a provisioned dashboard with a zero grace period", func(t *testing.T) {
		target, bystander := provisionedPair(t, ctx, admin, gvr, prefix+"-viewer")
		before := mustGetDashboard(t, ctx, admin, target.GetName())
		zero := int64(0)
		err := viewer.Resource.Delete(ctx, target.GetName(), metav1.DeleteOptions{GracePeriodSeconds: &zero})
		require.Error(t, err)
		assertSameProvisionedDashboard(t, ctx, admin, before)
		assertUntouched(t, ctx, admin, bystander)
	})

	t.Run("editor delete with grace period zero is rejected", func(t *testing.T) {
		target, bystander := provisionedPair(t, ctx, admin, gvr, prefix+"-body")
		before := mustGetDashboard(t, ctx, editor, target.GetName())
		zero := int64(0)
		uid := before.GetUID()
		rv := before.GetResourceVersion()
		err := editor.Resource.Delete(ctx, target.GetName(), metav1.DeleteOptions{
			GracePeriodSeconds: &zero,
			Preconditions: &metav1.Preconditions{
				UID:             &uid,
				ResourceVersion: &rv,
			},
		})
		require.Error(t, err)
		require.False(t, apierrors.IsNotFound(err))
		// The refused delete must not have removed the dashboard that was authorized,
		// and it must not have removed a different dashboard in its place.
		assertSameProvisionedDashboard(t, ctx, editor, before)
		assertUntouched(t, ctx, editor, bystander)
	})

	t.Run("editor query grace period zero is rejected", func(t *testing.T) {
		target, bystander := provisionedPair(t, ctx, admin, gvr, prefix+"-query")
		before := mustGetDashboard(t, ctx, editor, target.GetName())
		gv := gvr.GroupVersion()
		client := helper.Org1.Editor.RESTClient(t, &gv)
		var statusCode int
		err := client.Delete().
			Namespace(editor.Args.Namespace).
			Resource(gvr.Resource).
			Name(target.GetName()).
			Param("gracePeriodSeconds", "0").
			Do(ctx).
			StatusCode(&statusCode).
			Error()
		require.Error(t, err)
		require.NotEqual(t, http.StatusOK, statusCode)
		require.NotEqual(t, http.StatusAccepted, statusCode)
		assertSameProvisionedDashboard(t, ctx, editor, before)
		assertUntouched(t, ctx, editor, bystander)
	})

	t.Run("collection delete does not remove provisioned dashboards", func(t *testing.T) {
		// Dedicated objects, so a collection delete cannot be confused with an
		// earlier named delete. Both grace-period values are tried because a
		// collection request is admitted with an empty name either way.
		first, second := provisionedPair(t, ctx, admin, gvr, prefix+"-collection")
		firstBefore := mustGetDashboard(t, ctx, editor, first.GetName())
		secondBefore := mustGetDashboard(t, ctx, editor, second.GetName())

		zero := int64(0)
		err := editor.Resource.DeleteCollection(ctx, metav1.DeleteOptions{GracePeriodSeconds: &zero}, metav1.ListOptions{})
		if err != nil {
			require.Truef(t, apierrors.IsMethodNotSupported(err) || apierrors.IsNotFound(err),
				"collection delete returned %v", err)
		}
		assertSameProvisionedDashboard(t, ctx, editor, firstBefore)
		assertSameProvisionedDashboard(t, ctx, editor, secondBefore)

		err = editor.Resource.DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
		if err != nil {
			require.Truef(t, apierrors.IsMethodNotSupported(err) || apierrors.IsNotFound(err),
				"collection delete returned %v", err)
		}
		assertSameProvisionedDashboard(t, ctx, editor, firstBefore)
		assertSameProvisionedDashboard(t, ctx, editor, secondBefore)
	})
}

func provisionedPair(t *testing.T, ctx context.Context, admin *apis.K8sResourceClient, gvr schema.GroupVersionResource, prefix string) (*unstructured.Unstructured, *unstructured.Unstructured) {
	t.Helper()
	target := markClassicFileProvisioned(t, ctx, admin, createDashboard(t, ctx, admin, gvr, prefix+"-target", prefix+" target"))
	bystander := markClassicFileProvisioned(t, ctx, admin, createDashboard(t, ctx, admin, gvr, prefix+"-other", prefix+" other"))
	return target, bystander
}

func createDashboard(t *testing.T, ctx context.Context, client *apis.K8sResourceClient, gvr schema.GroupVersionResource, name, title string) *unstructured.Unstructured {
	t.Helper()
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{
			"title":         title,
			"schemaVersion": int64(42),
		},
	}}
	obj.SetName(name)
	obj.SetAPIVersion(gvr.GroupVersion().String())
	obj.SetKind("Dashboard")
	created, err := client.Resource.Create(ctx, obj, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, name, created.GetName())
	return created
}

func markClassicFileProvisioned(t *testing.T, ctx context.Context, client *apis.K8sResourceClient, obj *unstructured.Unstructured) *unstructured.Unstructured {
	t.Helper()
	meta, err := utils.MetaAccessor(obj)
	require.NoError(t, err)
	meta.SetManagerProperties(utils.ManagerProperties{
		Kind:     utils.ManagerKindClassicFP, //nolint:staticcheck
		Identity: "file-provisioner",
	})
	updated, err := client.Resource.Update(ctx, obj, metav1.UpdateOptions{})
	require.NoError(t, err)
	got, managed := mustManager(t, updated)
	require.True(t, managed)
	require.Equal(t, utils.ManagerKindClassicFP, got.Kind) //nolint:staticcheck
	require.Equal(t, "file-provisioner", got.Identity)
	return updated
}

func mustGetDashboard(t *testing.T, ctx context.Context, client *apis.K8sResourceClient, name string) *unstructured.Unstructured {
	t.Helper()
	obj, err := client.Resource.Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, name, obj.GetName())
	return obj
}

func assertUntouched(t *testing.T, ctx context.Context, client *apis.K8sResourceClient, before *unstructured.Unstructured) {
	t.Helper()
	got := mustGetDashboard(t, ctx, client, before.GetName())
	require.Equal(t, before.GetUID(), got.GetUID(), "dashboard %s was replaced", before.GetName())
	require.Equal(t, before.GetResourceVersion(), got.GetResourceVersion(), "dashboard %s changed", before.GetName())
}

func assertSameProvisionedDashboard(t *testing.T, ctx context.Context, client *apis.K8sResourceClient, before *unstructured.Unstructured) {
	t.Helper()
	got := mustGetDashboard(t, ctx, client, before.GetName())
	require.Equal(t, before.GetUID(), got.GetUID(), "dashboard %s was replaced", before.GetName())
	require.Equal(t, before.GetResourceVersion(), got.GetResourceVersion(), "dashboard %s was written by a delete that should have been refused", before.GetName())
	mgr, managed := mustManager(t, got)
	require.True(t, managed, "dashboard %s lost its file-provisioning manager", before.GetName())
	require.Equal(t, utils.ManagerKindClassicFP, mgr.Kind) //nolint:staticcheck
	require.Equal(t, "file-provisioner", mgr.Identity)
}

func mustManager(t *testing.T, obj *unstructured.Unstructured) (utils.ManagerProperties, bool) {
	t.Helper()
	meta, err := utils.MetaAccessor(obj)
	require.NoError(t, err)
	return meta.GetManagerProperties()
}
