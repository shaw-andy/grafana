package filelistauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	dashboardV1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/apis/provisioning/common"
)

// TestIntegrationProvisioning_ViewerFileListHidesUnreadableFolders checks the
// files directory listing for a signed-in Viewer.
//
// The Viewer can read one provisioned folder and cannot read another, measured
// by the dashboard API. A single file GET must follow that split, and the
// repository file listing must too: path, size, and content hash of a file
// under the unreadable folder must not be returned, and the file body must not
// be returned either. The listing is allowed for this Viewer
// (repositories:read is granted to the Viewer role); re-checking that
// permission and then returning the whole tree still fails this test. Filtering
// the tree with the files access checker also fails it, because that checker
// allows a Viewer through the role fallback even when the dashboard API forbids
// the folder.
//
// These assertions fail while the directory listing returns every blob from
// ReadTree and while a single-file GET returns the resource. v1beta1 registers
// the same files connector as v0alpha1.
func TestIntegrationProvisioning_ViewerFileListHidesUnreadableFolders(t *testing.T) {
	helper := sharedHelper(t)

	const (
		repo         = "viewer-file-list-auth"
		allowedPath  = "allowed-team/visible.json"
		secretPath   = "secret-team/hidden.json"
		secretReadme = "secret-team/README.md"
		allowedUID   = "visible-dash"
		secretUID    = "hidden-dash"
	)

	repoDir := filepath.Join(helper.ProvisioningPath, repo)
	writeRepoFile(t, repoDir, allowedPath, common.DashboardJSON(allowedUID, "Visible Dashboard", 1))
	writeRepoFile(t, repoDir, secretPath, common.DashboardJSON(secretUID, "Hidden Dashboard", 1))
	writeRepoFile(t, repoDir, secretReadme, []byte("# hidden notes\n"))

	helper.CreateLocalRepo(t, common.TestRepo{
		Name:       repo,
		LocalPath:  repoDir,
		SyncTarget: "instance",
	})

	helper.RequireRepoDashboardCount(t, repo, 2)
	allowedFolder := common.RequireRepoFolderTitle(t, helper.Folders, repo, "allowed-team")
	secretFolder := common.RequireRepoFolderTitle(t, helper.Folders, repo, "secret-team")
	common.RequireRepoDashboardParent(t, helper.DashboardsV1, repo, allowedPath, allowedFolder)
	common.RequireRepoDashboardParent(t, helper.DashboardsV1, repo, secretPath, secretFolder)

	// Root folders are created with Viewer view. Replace the secret folder ACL
	// so the Viewer role has no permission on it. The allowed folder keeps the
	// default Viewer grant.
	common.RequireDefaultRootFolderPermissions(t, helper, secretFolder)
	common.RequireDefaultRootFolderPermissions(t, helper, allowedFolder)
	common.SetFolderPermissions(t, helper, secretFolder, common.RolePermission{
		Role:       "Admin",
		Permission: common.FolderPermissionAdmin,
	})

	viewerDashboards := helper.GetResourceClient(apis.ResourceClientArgs{
		User:      helper.Org1.Viewer,
		Namespace: "default",
		GVR:       dashboardV1.DashboardResourceInfo.GroupVersionResource(),
	})
	_, err := viewerDashboards.Resource.Get(t.Context(), allowedUID, metav1.GetOptions{})
	require.NoError(t, err, "viewer should still read the dashboard in the allowed folder")
	_, err = viewerDashboards.Resource.Get(t.Context(), secretUID, metav1.GetOptions{})
	require.Error(t, err)
	require.True(t, apierrors.IsForbidden(err), "viewer should not read the dashboard in the secret folder, got %v", err)

	viewerFiles := helper.NewFilesClient(repo).WithUser("viewer:viewer")
	t.Run("single file read", func(t *testing.T) {
		allowedGet := viewerFiles.Do(t, http.MethodGet, allowedPath, nil)
		require.Equal(t, http.StatusOK, allowedGet.StatusCode, "viewer should read the file in the allowed folder: %s", allowedGet.BodyString())
		secretGet := viewerFiles.Do(t, http.MethodGet, secretPath, nil)
		require.Equal(t, http.StatusForbidden, secretGet.StatusCode, "viewer should not read the file in the secret folder: %s", secretGet.BodyString())
		require.NotContains(t, secretGet.BodyString(), "Hidden Dashboard")
		readmeGet := viewerFiles.Do(t, http.MethodGet, secretReadme, nil)
		require.Equal(t, http.StatusForbidden, readmeGet.StatusCode, "viewer should not read a raw file in the secret folder: %s", readmeGet.BodyString())
		require.NotContains(t, readmeGet.BodyString(), "hidden notes")
	})

	for _, version := range []string{"v0alpha1", "v1beta1"} {
		t.Run(version, func(t *testing.T) {
			status, items, body := listRepositoryFiles(t, helper, repo, version, "", "viewer:viewer")
			require.Equal(t, http.StatusOK, status, "viewer listing should succeed: %s", body)

			byPath := fileItemsByPath(items)
			allowed, ok := byPath[allowedPath]
			require.True(t, ok, "listing should still include the readable file, got %#v", items)
			require.NotEmpty(t, allowed.Hash, "listing should include the content hash of a readable file")
			require.Positive(t, allowed.Size, "listing should include the size of a readable file")

			for path, item := range byPath {
				require.Falsef(t, strings.HasPrefix(path, "secret-team/"),
					"listing leaked %s (size %d hash %s) from folder %s: %s", path, item.Size, item.Hash, secretFolder, body)
			}
			require.NotContains(t, string(body), "hidden notes")
			require.NotContains(t, string(body), secretPath)
			require.NotContains(t, string(body), secretReadme)
		})
	}
}

func writeRepoFile(t *testing.T, root, rel string, body []byte) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
	require.NoError(t, os.WriteFile(full, body, 0o600))
}

func fileItemsByPath(items []provisioning.FileItem) map[string]provisioning.FileItem {
	out := make(map[string]provisioning.FileItem, len(items))
	for _, item := range items {
		out[item.Path] = item
	}
	return out
}

func listRepositoryFiles(t *testing.T, helper *common.ProvisioningTestHelper, repo, version, ref, user string) (int, []provisioning.FileItem, []byte) {
	t.Helper()
	addr := helper.GetEnv().Server.HTTPServer.Listener.Addr().String()
	endpoint := fmt.Sprintf("http://%s@%s/apis/provisioning.grafana.app/%s/namespaces/default/repositories/%s/files/",
		user, addr, version, repo)
	if ref != "" {
		endpoint += "?ref=" + url.QueryEscape(ref)
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, body
	}
	var list provisioning.FileList
	require.NoError(t, json.Unmarshal(body, &list), "file list response: %s", body)
	return resp.StatusCode, list.Items, body
}
