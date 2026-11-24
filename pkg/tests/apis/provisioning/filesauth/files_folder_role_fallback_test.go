package filesauth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	dashboardV1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/apis/provisioning/common"
)

// TestIntegrationProvisioning_RestrictedFolderFilesIgnoreOrgRoleFallback is the
// spec for folder-scoped authorization on the Git Sync files API.
//
// An administrator syncs a repository and then removes the Editor and Viewer
// role grants from one folder, leaving that folder to a narrower ACL (here,
// Admin only). A separate folder keeps the default Editor grant so the same
// caller still has a real edit permission somewhere else.
//
// The files subresource must refuse that caller for every read and write of
// the restricted folder: the org role must not override the folder denial, and
// a check against the folder the caller can edit must not authorize a change
// to the folder they cannot. The repository file and the Grafana object must
// stay as they were when the response is a denial.
//
// Directory delete and directory move on the configured branch are rejected
// before the per-resource authorizer (405). They are not asserted here.
// Branch-workflow copies of those two operations are also not covered.
func TestIntegrationProvisioning_RestrictedFolderFilesIgnoreOrgRoleFallback(t *testing.T) {
	helper := sharedHelper(t)

	const (
		repoName      = "restricted-folder-files-repo"
		restrictedUID = "finance-uid"
		allowedUID    = "open-uid"
		revenueName   = "revenue-dash"
		publicName    = "public-dash"
		revenueTitle  = "Restricted Revenue"
		publicTitle   = "Public Overview"
		stolenTitle   = "Stolen Revenue"
		rawSecret     = "restricted-raw-marker"
		revenuePath   = "finance/revenue.json"
		movablePath   = "finance/movable.json"
		readmePath    = "finance/README.md"
		publicPath    = "open/public.json"
		createdPath   = "finance/new-revenue.json"
		movedIntoPath = "finance/from-open.json"
		movedOutPath  = "open/from-finance.json"
		childFolder   = "finance/secret/"
	)

	revenueBody := dashboardFile(revenueName, revenueTitle)
	publicBody := dashboardFile(publicName, publicTitle)
	// The submitted document names the folder the caller is allowed to edit.
	// Authorization has to follow the request path (finance), which the caller
	// cannot edit. Accepting this write would change a different folder from
	// the one the document claims.
	stolenBody := dashboardFileWithFolder(revenueName, stolenTitle, allowedUID)
	createdBody := dashboardFileWithFolder("new-revenue-dash", "Created In Finance", allowedUID)

	writeToProvisioningPath(t, helper, "finance/_folder.json", folderMetadataJSON(restrictedUID, "Finance"))
	writeToProvisioningPath(t, helper, revenuePath, revenueBody)
	movableBody := dashboardFileWithFolder("movable-dash", revenueTitle, allowedUID)
	writeToProvisioningPath(t, helper, movablePath, movableBody)
	writeToProvisioningPath(t, helper, readmePath, []byte(rawSecret))
	writeToProvisioningPath(t, helper, "open/_folder.json", folderMetadataJSON(allowedUID, "Open"))
	writeToProvisioningPath(t, helper, publicPath, publicBody)

	helper.CreateLocalRepo(t, common.TestRepo{
		Name:       repoName,
		SyncTarget: "instance",
		Workflows:  []string{"write"},
	})

	_, err := helper.Folders.Resource.Get(t.Context(), restrictedUID, metav1.GetOptions{})
	require.NoError(t, err, "restricted folder should exist after sync")
	_, err = helper.Folders.Resource.Get(t.Context(), allowedUID, metav1.GetOptions{})
	require.NoError(t, err, "allowed folder should exist after sync")
	_, err = helper.DashboardsV1.Resource.Get(t.Context(), revenueName, metav1.GetOptions{})
	require.NoError(t, err, "restricted dashboard should exist after sync")

	// Replace the restricted folder ACL so the Editor and Viewer roles no
	// longer have a grant there. The open folder keeps its default Editor grant.
	common.SetFolderPermissions(t, helper, restrictedUID, common.RolePermission{
		Role:       "Admin",
		Permission: common.FolderPermissionAdmin,
	})
	financePerms := common.FolderPermissions(t, helper, restrictedUID)
	common.RequirePermissionLacksRole(t, financePerms, "Editor", common.FolderPermissionEdit)
	common.RequirePermissionLacksRole(t, financePerms, "Viewer", common.FolderPermissionView)

	editorDashboards := helper.GetResourceClient(apis.ResourceClientArgs{
		User:      helper.Org1.Editor,
		Namespace: "default",
		GVR:       dashboardV1.DashboardResourceInfo.GroupVersionResource(),
	})
	viewerDashboards := helper.GetResourceClient(apis.ResourceClientArgs{
		User:      helper.Org1.Viewer,
		Namespace: "default",
		GVR:       dashboardV1.DashboardResourceInfo.GroupVersionResource(),
	})

	_, err = editorDashboards.Resource.Get(t.Context(), revenueName, metav1.GetOptions{})
	require.Truef(t, apierrors.IsForbidden(err), "dashboard API should deny the editor on %s, got %v", revenueName, err)
	_, err = viewerDashboards.Resource.Get(t.Context(), revenueName, metav1.GetOptions{})
	require.Truef(t, apierrors.IsForbidden(err), "dashboard API should deny the viewer on %s, got %v", revenueName, err)
	_, err = editorDashboards.Resource.Get(t.Context(), publicName, metav1.GetOptions{})
	require.NoError(t, err, "editor should still read the dashboard in the folder they can edit")

	editorFiles := helper.NewFilesClient(repoName).WithUser("editor:editor")
	viewerFiles := helper.NewFilesClient(repoName).WithUser("viewer:viewer")
	revenueOnDisk := filepath.Join(helper.ProvisioningPath, revenuePath)
	movableOnDisk := filepath.Join(helper.ProvisioningPath, movablePath)
	publicOnDisk := filepath.Join(helper.ProvisioningPath, publicPath)
	originalRevenue, err := os.ReadFile(revenueOnDisk)
	require.NoError(t, err)
	originalMovable, err := os.ReadFile(movableOnDisk)
	require.NoError(t, err)
	originalPublic, err := os.ReadFile(publicOnDisk)
	require.NoError(t, err)

	assertDenied := func(t *testing.T, resp *common.FilesResponse) {
		t.Helper()
		require.Equal(t, http.StatusForbidden, resp.StatusCode, "body: %s", resp.BodyString())
		require.NotContains(t, resp.BodyString(), revenueTitle)
		require.NotContains(t, resp.BodyString(), stolenTitle)
		require.NotContains(t, resp.BodyString(), rawSecret)
	}

	t.Run("editor can still update a dashboard in the folder they can edit", func(t *testing.T) {
		updated := dashboardFile(publicName, "Public Overview Updated")
		resp := editorFiles.Do(t, http.MethodPut, publicPath+"?skipDryRun=true", updated)
		require.Equalf(t, http.StatusOK, resp.StatusCode, "editor with the default grant must still write %s: %s", publicPath, resp.BodyString())
		got, err := os.ReadFile(publicOnDisk)
		require.NoError(t, err)
		require.Contains(t, string(got), "Public Overview Updated")
		// Restore the file so a later denied move can compare it.
		require.NoError(t, os.WriteFile(publicOnDisk, originalPublic, 0o600))
	})

	t.Run("viewer cannot read the restricted dashboard file", func(t *testing.T) {
		assertDenied(t, viewerFiles.Do(t, http.MethodGet, revenuePath, nil))
	})

	t.Run("editor cannot read the restricted dashboard file", func(t *testing.T) {
		assertDenied(t, editorFiles.Do(t, http.MethodGet, revenuePath, nil))
	})

	t.Run("viewer cannot read a raw file in the restricted folder", func(t *testing.T) {
		assertDenied(t, viewerFiles.Do(t, http.MethodGet, readmePath, nil))
	})

	t.Run("editor cannot read a raw file in the restricted folder", func(t *testing.T) {
		assertDenied(t, editorFiles.Do(t, http.MethodGet, readmePath, nil))
	})

	t.Run("viewer cannot overwrite the restricted dashboard", func(t *testing.T) {
		resp := viewerFiles.Do(t, http.MethodPut, revenuePath+"?skipDryRun=true", stolenBody)
		assertDenied(t, resp)
		got, err := os.ReadFile(revenueOnDisk)
		require.NoError(t, err)
		require.Equal(t, string(originalRevenue), string(got))
	})

	t.Run("editor cannot overwrite the restricted dashboard", func(t *testing.T) {
		resp := editorFiles.Do(t, http.MethodPut, revenuePath+"?skipDryRun=true", stolenBody)
		assertDenied(t, resp)
		got, err := os.ReadFile(revenueOnDisk)
		require.NoError(t, err)
		require.Equal(t, string(originalRevenue), string(got))
		dash, err := helper.DashboardsV1.Resource.Get(t.Context(), revenueName, metav1.GetOptions{})
		require.NoError(t, err)
		title, _, _ := unstructured.NestedString(dash.Object, "spec", "title")
		require.Equal(t, revenueTitle, title)
	})

	t.Run("editor cannot create a dashboard in the restricted folder", func(t *testing.T) {
		resp := editorFiles.Do(t, http.MethodPost, createdPath+"?skipDryRun=true", createdBody)
		assertDenied(t, resp)
		_, statErr := os.Stat(filepath.Join(helper.ProvisioningPath, createdPath))
		require.ErrorIs(t, statErr, os.ErrNotExist)
	})

	t.Run("editor cannot delete the restricted dashboard", func(t *testing.T) {
		resp := editorFiles.Do(t, http.MethodDelete, revenuePath+"?skipDryRun=true", nil)
		assertDenied(t, resp)
		got, err := os.ReadFile(revenueOnDisk)
		require.NoError(t, err)
		require.Equal(t, string(originalRevenue), string(got))
		_, err = helper.DashboardsV1.Resource.Get(t.Context(), revenueName, metav1.GetOptions{})
		require.NoError(t, err, "dashboard must still exist after a denied delete")
	})

	t.Run("editor cannot move a dashboard out of the restricted folder", func(t *testing.T) {
		// Destination is the folder the editor can edit. Source is the one they cannot.
		path := movedOutPath + "?" + url.Values{
			"originalPath": {movablePath},
			"skipDryRun":   {"true"},
		}.Encode()
		resp := editorFiles.Do(t, http.MethodPost, path, movableBody)
		assertDenied(t, resp)
		_, statErr := os.Stat(filepath.Join(helper.ProvisioningPath, movedOutPath))
		require.ErrorIs(t, statErr, os.ErrNotExist)
		got, err := os.ReadFile(movableOnDisk)
		require.NoError(t, err)
		require.Equal(t, string(originalMovable), string(got))
	})

	t.Run("editor cannot move a dashboard into the restricted folder", func(t *testing.T) {
		// Source is the folder the editor can edit. Destination is the one they cannot.
		path := movedIntoPath + "?" + url.Values{
			"originalPath": {publicPath},
			"skipDryRun":   {"true"},
		}.Encode()
		resp := editorFiles.Do(t, http.MethodPost, path, publicBody)
		assertDenied(t, resp)
		_, statErr := os.Stat(filepath.Join(helper.ProvisioningPath, movedIntoPath))
		require.ErrorIs(t, statErr, os.ErrNotExist)
		got, err := os.ReadFile(publicOnDisk)
		require.NoError(t, err)
		require.Equal(t, string(originalPublic), string(got))
	})

	t.Run("editor cannot create a folder inside the restricted folder", func(t *testing.T) {
		resp := editorFiles.Do(t, http.MethodPost, childFolder+"?skipDryRun=true", nil)
		assertDenied(t, resp)
		_, statErr := os.Stat(filepath.Join(helper.ProvisioningPath, "finance", "secret"))
		require.ErrorIs(t, statErr, os.ErrNotExist)
	})

	t.Run("editor cannot retitle the restricted folder", func(t *testing.T) {
		body := common.FolderBody(t, restrictedUID, "Stolen Finance")
		resp := editorFiles.Do(t, http.MethodPut, "finance/?skipDryRun=true", body)
		assertDenied(t, resp)
		meta, err := os.ReadFile(filepath.Join(helper.ProvisioningPath, "finance", "_folder.json"))
		require.NoError(t, err)
		require.NotContains(t, string(meta), "Stolen Finance")
		folder, err := helper.Folders.Resource.Get(t.Context(), restrictedUID, metav1.GetOptions{})
		require.NoError(t, err)
		title, _, _ := unstructured.NestedString(folder.Object, "spec", "title")
		require.Equal(t, "Finance", title)
	})

}

func writeToProvisioningPath(t *testing.T, helper *common.ProvisioningTestHelper, relativePath string, data []byte) {
	t.Helper()
	fullPath := filepath.Join(helper.ProvisioningPath, relativePath)
	require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o750))
	require.NoError(t, os.WriteFile(fullPath, data, 0o600))
}

func folderMetadataJSON(uid, title string) []byte {
	folder := map[string]any{
		"apiVersion": "folder.grafana.app/v1",
		"kind":       "Folder",
		"metadata": map[string]any{
			"name": uid,
		},
		"spec": map[string]any{
			"title": title,
		},
	}
	data, _ := json.MarshalIndent(folder, "", "\t")
	return data
}

func dashboardFile(name, title string) []byte {
	return dashboardFileWithFolder(name, title, "")
}

func dashboardFileWithFolder(name, title, folderUID string) []byte {
	meta := `"metadata": {"name": "` + name + `"}`
	if folderUID != "" {
		meta = `"metadata": {"name": "` + name + `", "annotations": {"grafana.app/folder": "` + folderUID + `"}}`
	}
	return []byte(`{
		"apiVersion": "dashboard.grafana.app/v0alpha1",
		"kind": "Dashboard",
		` + meta + `,
		"spec": {"title": "` + title + `"}
	}`)
}
