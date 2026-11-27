package jobs

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/pkg/tests/apis/provisioning/common"
)

// TestIntegrationProvisioning_JobsCollectionBypassesConnectorAuthorization
// posts the same job an Editor is not allowed to run through the repository
// jobs connector (POST repositories/{name}/jobs) directly at the jobs
// collection (POST namespaces/{ns}/jobs). The collection must apply the same
// per-action rules and must not let the driver delete, move, or rewrite the
// repository. These assertions fail while that gap is present.
func TestIntegrationProvisioning_JobsCollectionBypassesConnectorAuthorization(t *testing.T) {
	helper := sharedHelper(t)

	const (
		repo              = "jobs-collection-authz"
		restrictedDash    = "restricted-secret"
		allowedDash       = "allowed-visible"
		extraDash         = "allowed-extra"
		restrictedFileRel = "restricted-team/secret.json"
		otherFileRel      = "restricted-team/other.json"
		allowedFileRel    = "allowed/visible.json"
		extraFileRel      = "allowed/extra.json"
		canaryRel         = "canary.json"
	)

	helper.CreateLocalRepo(t, common.TestRepo{
		Name:       repo,
		SyncTarget: "folder",
		Workflows:  []string{"write"},
		SkipSync:   true,
	})
	root := helper.ProvisioningPath
	helper.WriteToProvisioningPath(t, restrictedFileRel, dashboardJSON(restrictedDash, "Restricted secret"))
	helper.WriteToProvisioningPath(t, otherFileRel, dashboardJSON("restricted-other", "Restricted other"))
	helper.WriteToProvisioningPath(t, allowedFileRel, dashboardJSON(allowedDash, "Allowed visible"))
	helper.WriteToProvisioningPath(t, extraFileRel, dashboardJSON(extraDash, "Allowed extra"))
	helper.WriteToProvisioningPath(t, canaryRel, dashboardJSON("canary-dash", "Canary"))
	helper.SyncAndWait(t, repo, nil)

	helper.RequireRepoDashboardCount(t, repo, 5)
	require.FileExists(t, filepath.Join(root, restrictedFileRel))

	// Editors can delete a dashboard file in a folder they can edit. They cannot
	// delete the folder directory itself: the connector's path check denies
	// folders:delete on restricted-team/. A job that lists an allowed file and
	// that directory must not delete either one.
	dirSpec := provisioning.JobSpec{
		Action:     provisioning.JobActionDelete,
		Repository: repo,
		Delete: &provisioning.DeleteJobOptions{
			Paths: []string{"restricted-team/"},
		},
	}

	t.Run("jobs collection delete of a restricted directory is rejected before the directory or its dashboards are removed", func(t *testing.T) {
		before := treeFingerprint(t, root)
		requireConnectorRefused(t, helper.EditorREST, repo, dirSpec)
		require.FileExists(t, filepath.Join(root, restrictedFileRel))

		rejectEditorJob(t, helper, repo, "editor-delete-restricted-dir", dirSpec, before)
		require.FileExists(t, filepath.Join(root, restrictedFileRel))
		require.FileExists(t, filepath.Join(root, otherFileRel))
		requireDashboardExists(t, helper, restrictedDash)
		requireDashboardExists(t, helper, "restricted-other")
	})

	t.Run("jobs collection delete is rejected for every path in the spec", func(t *testing.T) {
		// The editor may delete allowed/visible.json and may not delete the
		// restricted-team directory. Authorizing only the file and then deleting
		// every path, or deleting the directory before refusing, fails this test.
		before := treeFingerprint(t, root)
		spec := provisioning.JobSpec{
			Action:     provisioning.JobActionDelete,
			Repository: repo,
			Delete: &provisioning.DeleteJobOptions{
				Paths: []string{allowedFileRel, "restricted-team/"},
			},
		}
		requireConnectorRefused(t, helper.EditorREST, repo, spec)
		rejectEditorJob(t, helper, repo, "editor-delete-mixed", spec, before)
		require.FileExists(t, filepath.Join(root, allowedFileRel))
		require.FileExists(t, filepath.Join(root, restrictedFileRel))
		requireDashboardExists(t, helper, allowedDash)
		requireDashboardExists(t, helper, restrictedDash)
	})

	t.Run("jobs collection move of the restricted directory is rejected", func(t *testing.T) {
		before := treeFingerprint(t, root)
		spec := provisioning.JobSpec{
			Action:     provisioning.JobActionMove,
			Repository: repo,
			Move: &provisioning.MoveJobOptions{
				Paths:      []string{"restricted-team/"},
				TargetPath: "moved/",
			},
		}
		requireConnectorRefused(t, helper.EditorREST, repo, spec)

		rejectEditorJob(t, helper, repo, "editor-move-restricted", spec, before)
		require.FileExists(t, filepath.Join(root, restrictedFileRel))
		require.NoFileExists(t, filepath.Join(root, "moved", "secret.json"))
	})

	t.Run("jobs collection pull is rejected for an editor", func(t *testing.T) {
		before := treeFingerprint(t, root)
		spec := provisioning.JobSpec{
			Action:     provisioning.JobActionPull,
			Repository: repo,
			Pull:       &provisioning.SyncJobOptions{},
		}
		requireConnectorRefused(t, helper.EditorREST, repo, spec)
		rejectEditorJob(t, helper, repo, "editor-pull", spec, before)
	})

	t.Run("jobs collection pull request is rejected", func(t *testing.T) {
		before := treeFingerprint(t, root)
		spec := provisioning.JobSpec{
			Action:     provisioning.JobActionPullRequest,
			Repository: repo,
			PullRequest: &provisioning.PullRequestJobOptions{
				PR:  7,
				Ref: "feature",
			},
		}
		status, err := postConnectorJob(t, helper.AdminREST, repo, spec)
		require.Error(t, err)
		require.Equal(t, http.StatusBadRequest, status)
		rejectEditorJob(t, helper, repo, "editor-pr", spec, before)
	})

	t.Run("jobs collection releaseResources is rejected for an editor when the repository is gone", func(t *testing.T) {
		// A healthy repository is refused with 409 before the admin check, for
		// every caller. The admin-only rule applies once the repository is
		// missing, which is when the worker will release whatever it still manages.
		const missing = "jobs-collection-missing-repo"
		spec := provisioning.JobSpec{
			Action:     provisioning.JobActionReleaseResources,
			Repository: missing,
		}
		requireConnectorRefused(t, helper.EditorREST, missing, spec)

		adminStatus, adminErr := postConnectorJob(t, helper.AdminREST, missing, spec)
		require.NoError(t, adminErr, "admin should still be able to enqueue releaseResources (status %d)", adminStatus)
		require.Equal(t, http.StatusAccepted, adminStatus)

		rejectEditorJob(t, helper, missing, "editor-release", spec, treeFingerprint(t, root))
		requireDashboardExists(t, helper, restrictedDash)
	})

	t.Run("jobs collection deleteResources is rejected for an editor when the repository is gone", func(t *testing.T) {
		const missing = "jobs-collection-missing-repo-delete"
		spec := provisioning.JobSpec{
			Action:     provisioning.JobActionDeleteResources,
			Repository: missing,
		}
		requireConnectorRefused(t, helper.EditorREST, missing, spec)
		rejectEditorJob(t, helper, missing, "editor-delete-resources", spec, treeFingerprint(t, root))
		requireDashboardExists(t, helper, restrictedDash)
	})

	t.Run("jobs collection fixFolderMetadata is rejected when the connector rejects it", func(t *testing.T) {
		before := treeFingerprint(t, root)
		spec := provisioning.JobSpec{
			Action:     provisioning.JobActionFixFolderMetadata,
			Repository: repo,
		}
		status, err := postConnectorJob(t, helper.EditorREST, repo, spec)
		require.Error(t, err)
		require.Equal(t, http.StatusBadRequest, status)
		rejectEditorJob(t, helper, repo, "editor-fix-metadata", spec, before)
		require.NoFileExists(t, filepath.Join(root, "restricted-team", "_folder.json"))
	})

	// From here the repository is read-only. Write actions must be refused on
	// both entry points, and the stored files must stay byte-for-byte.
	setWorkflows(t, helper, repo)

	t.Run("jobs collection delete is rejected when the repository workflow disallows writes", func(t *testing.T) {
		before := treeFingerprint(t, root)
		spec := provisioning.JobSpec{
			Action:     provisioning.JobActionDelete,
			Repository: repo,
			Delete: &provisioning.DeleteJobOptions{
				Paths: []string{canaryRel},
			},
		}
		requireConnectorRefused(t, helper.EditorREST, repo, spec)
		rejectEditorJob(t, helper, repo, "editor-delete-readonly", spec, before)
		require.FileExists(t, filepath.Join(root, canaryRel))
		requireDashboardExists(t, helper, "canary-dash")
	})

	t.Run("jobs collection push is rejected when the repository workflow disallows writes", func(t *testing.T) {
		before := treeFingerprint(t, root)
		spec := provisioning.JobSpec{
			Action:     provisioning.JobActionPush,
			Repository: repo,
			Push:       &provisioning.ExportJobOptions{},
		}
		status, err := postConnectorJob(t, helper.EditorREST, repo, spec)
		require.Error(t, err)
		require.GreaterOrEqual(t, status, 400)
		require.Less(t, status, 500)
		rejectEditorJob(t, helper, repo, "editor-push-readonly", spec, before)
	})

	t.Run("jobs collection migrate is rejected when the repository workflow disallows writes", func(t *testing.T) {
		before := treeFingerprint(t, root)
		spec := provisioning.JobSpec{
			Action:     provisioning.JobActionMigrate,
			Repository: repo,
			Migrate:    &provisioning.MigrateJobOptions{},
		}
		status, err := postConnectorJob(t, helper.EditorREST, repo, spec)
		require.Error(t, err)
		require.GreaterOrEqual(t, status, 400)
		require.Less(t, status, 500)
		rejectEditorJob(t, helper, repo, "editor-migrate-readonly", spec, before)
		require.FileExists(t, filepath.Join(root, canaryRel))
	})

	t.Run("an admin can still create a pull job through the connector", func(t *testing.T) {
		spec := provisioning.JobSpec{
			Action:     provisioning.JobActionPull,
			Repository: repo,
			Pull:       &provisioning.SyncJobOptions{},
		}
		status, err := postConnectorJob(t, helper.AdminREST, repo, spec)
		require.NoError(t, err, "admin pull through the connector should stay allowed (status %d)", status)
		require.Equal(t, http.StatusAccepted, status)
		helper.AwaitJobs(t, repo)
		require.FileExists(t, filepath.Join(root, restrictedFileRel))
		requireDashboardExists(t, helper, restrictedDash)
	})
}

// rejectEditorJob creates a Job through the jobs collection as the Editor.
// The request must be refused, the Job must not remain queued, and the
// repository tree must be unchanged. When the request is accepted, the helper
// waits until the driver finishes the job so a delete or sync that follows
// the create is visible in the tree comparison.
func rejectEditorJob(t *testing.T, helper *common.ProvisioningTestHelper, repo, name string, spec provisioning.JobSpec, before map[string]string) {
	t.Helper()
	spec.Repository = repo
	job := &provisioning.Job{
		TypeMeta: metav1.TypeMeta{
			APIVersion: provisioning.JobResourceInfo.GroupVersion().String(),
			Kind:       "Job",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: spec,
	}

	var status int
	result := helper.EditorREST.Post().
		Namespace("default").
		Resource("jobs").
		Body(common.AsJSON(job)).
		SetHeader("Content-Type", "application/json").
		Do(t.Context()).
		StatusCode(&status)

	if result.Error() == nil || jobStillQueued(t, helper, name) {
		waitForActiveJobGone(t, helper, name)
	}

	restrictedStat := "present"
	if _, statErr := os.Stat(filepath.Join(helper.ProvisioningPath, "restricted-team", "secret.json")); statErr != nil {
		restrictedStat = statErr.Error()
	}
	canaryStat := "present"
	if _, statErr := os.Stat(filepath.Join(helper.ProvisioningPath, "canary.json")); statErr != nil {
		canaryStat = statErr.Error()
	}
	dashStat := "present"
	if _, dashErr := helper.DashboardsV1.Resource.Get(t.Context(), "restricted-secret", metav1.GetOptions{}); dashErr != nil {
		dashStat = dashErr.Error()
	}
	require.Error(t, result.Error(), "editor must not create job %q (%s) through the jobs collection; status %d; restricted file: %s; restricted dashboard: %s; canary: %s", name, spec.Action, status, restrictedStat, dashStat, canaryStat)
	require.GreaterOrEqual(t, status, 400, "job %q was created with status %d", name, status)
	require.Less(t, status, 500, "job %q failed inside the server (status %d) instead of being refused", name, status)
	require.False(t, jobStillQueued(t, helper, name), "job %q is still queued after a refusal", name)
	require.Equal(t, before, treeFingerprint(t, helper.ProvisioningPath), "repository files changed while creating job %q", name)
}

// requireConnectorRefused asserts the repository jobs connector did not accept
// the job. Permission failures are sometimes wrapped, so the status may be 500
// while the message still reports the denial; acceptance is 2xx.
func requireConnectorRefused(t *testing.T, client *rest.RESTClient, repo string, spec provisioning.JobSpec) {
	t.Helper()
	status, err := postConnectorJob(t, client, repo, spec)
	require.Error(t, err, "connector accepted the job with status %d", status)
	require.NotContains(t, []int{http.StatusOK, http.StatusCreated, http.StatusAccepted}, status)
}

func postConnectorJob(t *testing.T, client *rest.RESTClient, repo string, spec provisioning.JobSpec) (int, error) {
	t.Helper()
	var status int
	result := client.Post().
		Namespace("default").
		Resource("repositories").
		Name(repo).
		SubResource("jobs").
		Body(common.AsJSON(spec)).
		SetHeader("Content-Type", "application/json").
		Do(t.Context()).
		StatusCode(&status)
	return status, result.Error()
}

func jobStillQueued(t *testing.T, helper *common.ProvisioningTestHelper, name string) bool {
	t.Helper()
	_, err := helper.Jobs.Resource.Get(t.Context(), name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false
	}
	require.NoError(t, err)
	return true
}

func waitForActiveJobGone(t *testing.T, helper *common.ProvisioningTestHelper, name string) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, err := helper.Jobs.Resource.Get(t.Context(), name, metav1.GetOptions{})
		return apierrors.IsNotFound(err)
	}, common.WaitTimeoutDefault, common.WaitIntervalDefault, "job %s should leave the active queue", name)
}

func requireDashboardExists(t *testing.T, helper *common.ProvisioningTestHelper, name string) {
	t.Helper()
	_, err := helper.DashboardsV1.Resource.Get(t.Context(), name, metav1.GetOptions{})
	require.NoError(t, err, "dashboard %q should still exist", name)
}

func setWorkflows(t *testing.T, helper *common.ProvisioningTestHelper, repo string) {
	t.Helper()
	obj, err := helper.Repositories.Resource.Get(t.Context(), repo, metav1.GetOptions{})
	require.NoError(t, err)
	require.NoError(t, unstructured.SetNestedStringSlice(obj.Object, []string{}, "spec", "workflows"))
	_, err = helper.Repositories.Resource.Update(t.Context(), obj, metav1.UpdateOptions{})
	require.NoError(t, err, "should switch repository to a read-only workflow")
}

func dashboardJSON(name, title string) []byte {
	return []byte(`{
  "apiVersion": "dashboard.grafana.app/v0alpha1",
  "kind": "Dashboard",
  "metadata": {"name": "` + name + `"},
  "spec": {"title": "` + title + `"}
}`)
}

func treeFingerprint(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(p) //nolint:gosec
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		out[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	require.NoError(t, err)
	return out
}
