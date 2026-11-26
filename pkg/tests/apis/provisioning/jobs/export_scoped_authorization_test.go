package jobs

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"

	dashboardv1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	folderv1 "github.com/grafana/grafana/apps/folder/pkg/apis/folder/v1"
	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/apis/provisioning/common"
)

// TestIntegrationProvisioning_ExportAndMigrateDoNotCopyDeniedDashboards checks
// that a push or migrate job copies a dashboard into the connected repository
// only when the caller can read that dashboard.
//
// A new root folder is readable by every Editor until its ACL is replaced.
// This test leaves that default grant on one folder and removes it from
// another, so the caller can read exactly one folder. A full push, a push
// that names the denied dashboard, and a migrate must not write that
// dashboard into the repository. A selective push of the dashboard the
// caller can read must still succeed, and an Editor who holds a wildcard
// read on every folder must still be able to export and migrate the denied
// dashboard.
func TestIntegrationProvisioning_ExportAndMigrateDoNotCopyDeniedDashboards(t *testing.T) {
	helper := sharedHelper(t)

	const (
		allowedFolderUID = "allowed-export-folder"
		deniedFolderUID  = "denied-export-folder"
		allowedMarker    = "allowed-dashboard-marker-6f8b3b8d"
		deniedMarker     = "denied-dashboard-marker-6f8b3b8d"
		migrateMarker    = "denied-migrate-marker-6f8b3b8d"
		repo             = "scoped-export-auth-repo"
		dashboardGroup   = "dashboard.grafana.app"
		dashboardKind    = "Dashboard"
		folderResource   = "folders"
	)

	helper.CreateUnmanagedFolderWithName(t, allowedFolderUID, allowedFolderUID, "")
	helper.CreateUnmanagedFolderWithName(t, deniedFolderUID, deniedFolderUID, "")
	common.RequireDefaultRootFolderPermissions(t, helper, allowedFolderUID)
	common.RequireDefaultRootFolderPermissions(t, helper, deniedFolderUID)
	// Drop the default Editor and Viewer grants so this Editor cannot read the folder.
	common.SetFolderPermissions(t, helper, deniedFolderUID, common.RolePermission{
		Role:       "Admin",
		Permission: common.FolderPermissionAdmin,
	})
	deniedPerms := common.FolderPermissions(t, helper, deniedFolderUID)
	common.RequirePermissionLacksRole(t, deniedPerms, "Viewer", common.FolderPermissionView)
	common.RequirePermissionLacksRole(t, deniedPerms, "Editor", common.FolderPermissionEdit)

	allowedDash := helper.CreateUnmanagedDashboard(t, allowedMarker, allowedFolderUID)
	deniedDash := helper.CreateUnmanagedDashboard(t, deniedMarker, deniedFolderUID)

	scopedUser := helper.CreateUser("scoped-export-editor", apis.Org1, org.RoleEditor, nil)
	wildcardUser := helper.CreateUser("wildcard-export-editor", apis.Org1, org.RoleEditor, []resourcepermissions.SetResourcePermissionCommand{{
		Actions:           []string{"dashboards:read", "folders:read"},
		Resource:          folderResource,
		ResourceAttribute: "uid",
		ResourceID:        "*",
	}})

	gv := &schema.GroupVersion{Group: "provisioning.grafana.app", Version: "v0alpha1"}
	scopedClient := scopedUser.RESTClient(t, gv)
	wildcardClient := wildcardUser.RESTClient(t, gv)
	scopedDashboards := helper.GetResourceClient(apis.ResourceClientArgs{
		User: scopedUser,
		GVR:  dashboardv1.DashboardResourceInfo.GroupVersionResource(),
	})
	scopedFolders := helper.GetResourceClient(apis.ResourceClientArgs{
		User: scopedUser,
		GVR:  folderv1.FolderResourceInfo.GroupVersionResource(),
	})

	t.Run("scoped editor can read only the allowed folder", func(t *testing.T) {
		t.Helper()
		_, err := helper.DashboardsV1.Resource.Get(t.Context(), deniedDash, metav1.GetOptions{})
		require.NoError(t, err, "admin should be able to read the denied dashboard")

		_, err = scopedDashboards.Resource.Get(t.Context(), allowedDash, metav1.GetOptions{})
		require.NoError(t, err, "scoped editor should be able to read the allowed dashboard")
		_, err = scopedFolders.Resource.Get(t.Context(), allowedFolderUID, metav1.GetOptions{})
		require.NoError(t, err, "scoped editor should be able to read the allowed folder")

		_, err = scopedDashboards.Resource.Get(t.Context(), deniedDash, metav1.GetOptions{})
		require.Error(t, err, "scoped editor should not be able to read the denied dashboard")
		require.True(t, apierrors.IsForbidden(err) || apierrors.IsNotFound(err), "got %v", err)

		_, err = scopedFolders.Resource.Get(t.Context(), deniedFolderUID, metav1.GetOptions{})
		require.Error(t, err, "scoped editor should not be able to read the denied folder")
		require.True(t, apierrors.IsForbidden(err) || apierrors.IsNotFound(err), "got %v", err)
	})

	helper.CreateLocalRepo(t, common.TestRepo{
		Name:       repo,
		SyncTarget: string(provisioning.SyncTargetTypeInstance),
		Workflows:  []string{string(provisioning.WriteWorkflow)},
		SkipSync:   true,
		Copies:     map[string]string{},
	})

	t.Run("full push does not copy dashboards the caller cannot read", func(t *testing.T) {
		helper.CleanProvisioningDir(t)
		submitProvisioningJob(t, helper, scopedClient, repo, provisioning.JobSpec{
			Action: provisioning.JobActionPush,
			Push:   &provisioning.ExportJobOptions{},
		})
		require.Falsef(t, repoContains(t, helper, deniedMarker),
			"full export wrote %q, which the caller cannot read", deniedMarker)
		requireDashboardStillExists(t, helper, deniedDash)
	})

	t.Run("selective push of a denied dashboard does not copy it", func(t *testing.T) {
		helper.CleanProvisioningDir(t)
		submitProvisioningJob(t, helper, scopedClient, repo, provisioning.JobSpec{
			Action: provisioning.JobActionPush,
			Push: &provisioning.ExportJobOptions{
				Resources: []provisioning.ResourceRef{{
					Name:  deniedDash,
					Kind:  dashboardKind,
					Group: dashboardGroup,
				}},
			},
		})
		require.Falsef(t, repoContains(t, helper, deniedMarker),
			"selective export wrote %q, which the caller cannot read", deniedMarker)
		requireDashboardStillExists(t, helper, deniedDash)
	})

	t.Run("selective push still copies a dashboard the caller can read", func(t *testing.T) {
		helper.CleanProvisioningDir(t)
		submitProvisioningJob(t, helper, scopedClient, repo, provisioning.JobSpec{
			Action: provisioning.JobActionPush,
			Push: &provisioning.ExportJobOptions{
				Resources: []provisioning.ResourceRef{{
					Name:  allowedDash,
					Kind:  dashboardKind,
					Group: dashboardGroup,
				}},
			},
		})
		require.Truef(t, repoContains(t, helper, allowedMarker),
			"selective export omitted %q, which the caller can read", allowedMarker)
		require.Falsef(t, repoContains(t, helper, deniedMarker),
			"selective export of an allowed dashboard also wrote %q", deniedMarker)
	})

	t.Run("wildcard reader can export a dashboard in a restricted folder", func(t *testing.T) {
		helper.CleanProvisioningDir(t)
		submitProvisioningJob(t, helper, wildcardClient, repo, provisioning.JobSpec{
			Action: provisioning.JobActionPush,
			Push:   &provisioning.ExportJobOptions{},
		})
		require.Truef(t, repoContains(t, helper, deniedMarker),
			"org-wide reader export omitted %q", deniedMarker)
	})

	t.Run("migrate does not copy dashboards the caller cannot read", func(t *testing.T) {
		helper.CleanProvisioningDir(t)
		submitProvisioningJob(t, helper, scopedClient, repo, provisioning.JobSpec{
			Action: provisioning.JobActionMigrate,
			Migrate: &provisioning.MigrateJobOptions{
				SkipResourceDeletion: true,
			},
		})
		require.Falsef(t, repoContains(t, helper, deniedMarker),
			"migrate wrote %q, which the caller cannot read", deniedMarker)
		requireDashboardStillExists(t, helper, deniedDash)
	})

	// A successful migrate takes ownership of the resources it exports, and a
	// later export skips managed resources. Create a new unmanaged dashboard
	// after the scoped migrate so this control is independent of that job.
	t.Run("wildcard reader can migrate a dashboard in a restricted folder", func(t *testing.T) {
		helper.CreateUnmanagedDashboard(t, migrateMarker, deniedFolderUID)
		helper.CleanProvisioningDir(t)
		submitProvisioningJob(t, helper, wildcardClient, repo, provisioning.JobSpec{
			Action: provisioning.JobActionMigrate,
			Migrate: &provisioning.MigrateJobOptions{
				SkipResourceDeletion: true,
			},
		})
		require.Truef(t, repoContains(t, helper, migrateMarker),
			"org-wide reader migrate omitted %q", migrateMarker)
	})
}

func submitProvisioningJob(t *testing.T, helper *common.ProvisioningTestHelper, client *rest.RESTClient, repo string, spec provisioning.JobSpec) {
	t.Helper()
	var statusCode int
	result := client.Post().
		Namespace("default").
		Resource("repositories").
		Name(repo).
		SubResource("jobs").
		Body(common.AsJSON(spec)).
		SetHeader("Content-Type", "application/json").
		Do(t.Context()).
		StatusCode(&statusCode)
	if err := result.Error(); err != nil {
		if apierrors.IsForbidden(err) || statusCode == http.StatusForbidden {
			return
		}
		require.NoError(t, err)
	}
	require.Equal(t, http.StatusAccepted, statusCode)
	obj, err := result.Get()
	require.NoError(t, err)
	job, ok := obj.(*unstructured.Unstructured)
	require.True(t, ok, "expecting unstructured job, got %T", obj)
	helper.AwaitJob(t, job)
}

func repoContains(t *testing.T, helper *common.ProvisioningTestHelper, needle string) bool {
	t.Helper()
	found := false
	root := helper.ProvisioningPath
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(path, needle) || strings.Contains(string(body), needle) {
			found = true
		}
		return nil
	})
	require.NoError(t, err)
	return found
}

func requireDashboardStillExists(t *testing.T, helper *common.ProvisioningTestHelper, name string) {
	t.Helper()
	_, err := helper.DashboardsV1.Resource.Get(t.Context(), name, metav1.GetOptions{})
	require.NoError(t, err)
}
