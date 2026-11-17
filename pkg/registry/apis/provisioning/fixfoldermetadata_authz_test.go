package provisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/dynamic"

	authlib "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/apps/provisioning/pkg/apis/auth"
	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs/fixfoldermetadata"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/resources"
)

const (
	fixMetaRepoName      = "git-sync-repo"
	fixMetaNamespace     = "default"
	fixMetaRestrictedUID = "restricted-uid"
	fixMetaBranch        = "folder-metadata-fix"
)

// TestFixFolderMetadataEditorCannotRewriteUnpermittedFolders is the spec for the
// fixFolderMetadata job. An Editor who is allowed to create jobs must not be able
// to publish folder metadata or remove keep files for directories they cannot
// write or delete, on the configured branch or on a branch the repository allows.
//
// The assertions are on the tree published by the real worker. They fail while
// the job is admitted and the worker writes every directory as the provisioning
// identity. Refusing the job, or publishing only directories that were authorized
// for this caller before any write, makes them pass. A directory that shows up
// after the job is admitted is not one of those directories.
func TestFixFolderMetadataEditorCannotRewriteUnpermittedFolders(t *testing.T) {
	t.Run("write workflow with options omitted", func(t *testing.T) {
		runEditorFixFolderMetadata(t, editorFixFolderCase{
			repo: writeRepo(),
			spec: provisioning.JobSpec{Action: provisioning.JobActionFixFolderMetadata},
		})
	})

	t.Run("write workflow with an empty ref", func(t *testing.T) {
		runEditorFixFolderMetadata(t, editorFixFolderCase{
			repo: writeRepo(),
			spec: provisioning.JobSpec{
				Action:            provisioning.JobActionFixFolderMetadata,
				FixFolderMetadata: &provisioning.FixFolderMetadataJobOptions{Ref: ""},
			},
		})
	})

	t.Run("branch workflow publishes a branch", func(t *testing.T) {
		runEditorFixFolderMetadata(t, editorFixFolderCase{
			repo: branchRepo(),
			spec: provisioning.JobSpec{
				Action:            provisioning.JobActionFixFolderMetadata,
				FixFolderMetadata: &provisioning.FixFolderMetadataJobOptions{Ref: fixMetaBranch},
			},
		})
	})

	t.Run("directory added after the job is admitted is not published", func(t *testing.T) {
		runEditorFixFolderMetadata(t, editorFixFolderCase{
			repo:             writeRepo(),
			spec:             provisioning.JobSpec{Action: provisioning.JobActionFixFolderMetadata},
			allowAllFolders:  true,
			injectLateFolder: true,
		})
	})
}

// TestFixFolderMetadataAdminStillPublishesFolderMetadata is the control for the
// harness. An administrator, who holds repositories:write, still drives the real
// worker through to a published tree. If this fails, the editor tests are not
// exercising the job.
func TestFixFolderMetadataAdminStillPublishesFolderMetadata(t *testing.T) {
	h := newFixFolderHarness(t, writeRepo(), false)
	ctx := fixFolderUserContext(identity.RoleAdmin)

	admitted := h.admit(t, ctx, provisioning.JobSpec{Action: provisioning.JobActionFixFolderMetadata})
	require.True(t, admitted, "admin holds repositories:write and folder write; the job must be admitted")
	require.NoError(t, h.runAdmittedJob(t))

	require.False(t, h.repo.exists("", "restricted/.keep"), "admin job removes a keep file once folder metadata exists")
	require.False(t, h.repo.exists("", "restricted/child/.keep"), "admin job removes a keep file from a directory that received metadata")
	require.True(t, h.repo.exists("", "restricted/child/_folder.json"), "admin job writes folder metadata for a directory that lacks it")
	require.True(t, h.repo.exists("", "allowed/_folder.json"), "admin job writes folder metadata for every directory that lacks it")
	require.Equal(t, fixMetaRestrictedUID, h.repo.folderUID("", "restricted/_folder.json"), "existing folder metadata is left in place")
	require.True(t, h.repo.exists("", "restricted/dash.json"), "unrelated files stay in the tree")
}

type editorFixFolderCase struct {
	repo             *provisioning.Repository
	spec             provisioning.JobSpec
	allowAllFolders  bool
	injectLateFolder bool
}

func runEditorFixFolderMetadata(t *testing.T, tc editorFixFolderCase) {
	t.Helper()
	h := newFixFolderHarness(t, tc.repo, tc.allowAllFolders)
	ctx := fixFolderUserContext(identity.RoleEditor)

	admitted := h.admit(t, ctx, tc.spec)
	if admitted && tc.injectLateFolder {
		// The queue has accepted the job. The tree the worker will read is not
		// the tree that was authorized: a directory appears before the worker runs.
		h.repo.seedDir("late/")
		h.repo.seedFile("late/.keep", nil)
		h.repo.seedDir("late/child/")
		h.repo.seedFile("late/child/.keep", nil)
	}
	if admitted {
		require.NoError(t, h.runAdmittedJob(t))
	}

	for ref, tree := range h.repo.snapshot() {
		if !tc.allowAllFolders {
			require.Truef(t, blobExists(tree, "restricted/.keep"), "ref %q deleted restricted/.keep", ref)
			require.Truef(t, blobExists(tree, "restricted/child/.keep"), "ref %q deleted restricted/child/.keep", ref)
			require.Falsef(t, blobExists(tree, "restricted/child/_folder.json"), "ref %q wrote restricted/child/_folder.json", ref)
			require.Equalf(t, fixMetaRestrictedUID, folderUID(tree, "restricted/_folder.json"), "ref %q rewrote restricted/_folder.json", ref)
			require.Truef(t, blobExists(tree, "restricted/dash.json"), "ref %q removed an unrelated file", ref)
		}
		require.Falsef(t, blobExists(tree, "late/_folder.json"), "ref %q wrote late/_folder.json for a directory that was not in the tree when the job was admitted", ref)
		require.Falsef(t, blobExists(tree, "late/child/_folder.json"), "ref %q wrote late/child/_folder.json for a directory that was not in the tree when the job was admitted", ref)
		if blobExists(tree, "late/.keep") {
			require.Truef(t, blobExists(tree, "late/child/.keep"), "ref %q deleted late/child/.keep", ref)
		}
	}
}

func writeRepo() *provisioning.Repository {
	return &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: fixMetaRepoName, Namespace: fixMetaNamespace},
		Spec: provisioning.RepositorySpec{
			Type:      provisioning.LocalRepositoryType,
			Title:     "Git Sync",
			Workflows: []provisioning.Workflow{provisioning.WriteWorkflow},
			Sync:      provisioning.SyncOptions{Target: provisioning.SyncTargetTypeFolder},
		},
	}
}

func branchRepo() *provisioning.Repository {
	return &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: fixMetaRepoName, Namespace: fixMetaNamespace},
		Spec: provisioning.RepositorySpec{
			Type:      provisioning.GitHubRepositoryType,
			Title:     "Git Sync",
			Workflows: []provisioning.Workflow{provisioning.BranchWorkflow},
			Sync:      provisioning.SyncOptions{Target: provisioning.SyncTargetTypeFolder},
			GitHub:    &provisioning.GitHubRepositoryConfig{Branch: "main"},
		},
	}
}

func fixFolderUserContext(role identity.RoleType) context.Context {
	user := &identity.StaticRequester{
		Type:      authlib.TypeUser,
		UserID:    2,
		UserUID:   string(role),
		OrgID:     1,
		OrgRole:   role,
		Login:     string(role),
		Name:      string(role),
		Namespace: fixMetaNamespace,
	}
	ctx := request.WithNamespace(context.Background(), fixMetaNamespace)
	return identity.WithRequester(ctx, user)
}

type fixFolderHarness struct {
	repo    *memGitRepo
	queue   *recordingJobQueue
	builder *APIBuilder
	conn    *jobsConnector
	worker  *fixfoldermetadata.Worker
}

func newFixFolderHarness(t *testing.T, cfg *provisioning.Repository, allowAllFolders bool) *fixFolderHarness {
	t.Helper()
	repo := newMemGitRepo(cfg)
	repo.seedDir("allowed/")
	repo.seedDir("restricted/")
	repo.seedFile("restricted/_folder.json", []byte(`{"apiVersion":"folder.grafana.app/v1beta1","kind":"Folder","metadata":{"name":"`+fixMetaRestrictedUID+`"},"spec":{"title":"restricted"}}`))
	repo.seedFile("restricted/.keep", nil)
	repo.seedFile("restricted/dash.json", []byte(`{"uid":"dash","title":"Dash"}`))
	repo.seedDir("restricted/child/")
	repo.seedFile("restricted/child/.keep", nil)

	checker := auth.NewSessionAccessChecker(&folderJobAccess{
		allowAllFolders: allowAllFolders,
		// The editor can write and delete only the allowed directory. The
		// restricted directory, its child, and the repository root are absent.
		grants: map[string]folderGrant{
			resources.ParseFolder("allowed/", cfg.Name).ID: {create: true, write: true, delete: true},
		},
	})
	clients := newFixFolderClients(t)
	queue := &recordingJobQueue{}
	conn := NewJobsConnector(
		&fakeRepoGetter{repo: repo},
		nil,
		&fakeJobQueueGetter{queue: queue},
		nil,
		checker,
		clients,
		true,
		nil,
	)
	return &fixFolderHarness{
		repo:  repo,
		queue: queue,
		builder: &APIBuilder{
			accessWithEditor: checker.WithFallbackRole(identity.RoleEditor),
			accessWithAdmin:  checker.WithFallbackRole(identity.RoleAdmin),
		},
		conn:   conn,
		worker: fixfoldermetadata.NewWorker(clients),
	}
}

// admit runs the repository subresource authorizer and, when it allows the
// caller through, the jobs connector. That is the path from the POST to the queue.
func (h *fixFolderHarness) admit(t *testing.T, ctx context.Context, spec provisioning.JobSpec) bool {
	t.Helper()
	decision, reason, err := h.builder.GetAuthorizer().Authorize(ctx, authorizer.AttributesRecord{
		Verb:            utils.VerbCreate,
		APIGroup:        provisioning.GROUP,
		Resource:        provisioning.RepositoryResourceInfo.GetName(),
		Subresource:     "jobs",
		Name:            fixMetaRepoName,
		Namespace:       fixMetaNamespace,
		ResourceRequest: true,
	})
	require.NoError(t, err)
	if decision != authorizer.DecisionAllow {
		require.Empty(t, h.repo.published(), "authorizer refused the job (%s) after publishing %v", reason, h.repo.published())
		return false
	}

	body, err := json.Marshal(spec)
	require.NoError(t, err)
	responder := &fakeResponder{}
	handler, err := h.conn.Connect(ctx, fixMetaRepoName, nil, responder)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if responder.err != nil {
		require.Empty(t, h.repo.published(), "job was refused after publishing %v: %v", h.repo.published(), responder.err)
		return false
	}
	require.NotEmpty(t, h.queue.jobs, "authorizer and connector both allowed the job, but nothing was queued")
	require.Equal(t, http.StatusAccepted, responder.statusCode)
	return true
}

// runAdmittedJob is the driver hand-off: the provisioning identity replaces the
// caller, then the real worker reads the tree, writes, and pushes.
func (h *fixFolderHarness) runAdmittedJob(t *testing.T) error {
	t.Helper()
	job := h.queue.jobs[len(h.queue.jobs)-1]
	ctx := request.WithNamespace(context.Background(), job.Namespace)
	ctx, _, err := identity.WithProvisioningIdentity(ctx, job.Namespace)
	if err != nil {
		return err
	}
	return h.worker.Process(ctx, h.repo, *job, nopJobProgress{})
}

func newFixFolderClients(t *testing.T) resources.ClientFactory {
	t.Helper()
	rc := resources.NewMockResourceClients(t)
	rc.EXPECT().SupportedResources().Return(resources.SupportedProvisioningResources).Maybe()
	rc.EXPECT().Folder(mock.Anything).Return(nil, resources.FolderKind, nil).Maybe()
	rc.EXPECT().ForKind(mock.Anything, mock.Anything).RunAndReturn(
		func(_ context.Context, gvk schema.GroupVersionKind) (dynamic.ResourceInterface, schema.GroupVersionResource, error) {
			switch gvk.GroupKind() {
			case resources.DashboardKind.GroupKind():
				return nil, resources.DashboardResource, nil
			case resources.FolderKind.GroupKind():
				return nil, resources.FolderResource, nil
			default:
				return nil, schema.GroupVersionResource{}, fmt.Errorf("unexpected kind %v", gvk)
			}
		},
	).Maybe()
	cf := resources.NewMockClientFactory(t)
	cf.EXPECT().Clients(mock.Anything, mock.Anything).Return(rc, nil).Maybe()
	return cf
}

// folderGrant is the folder create/write/delete set the access checker allows
// for one folder id. It is the same split the folder authorizer uses.
type folderGrant struct {
	create bool
	write  bool
	delete bool
}

// folderJobAccess is the inner access checker behind the real session checker.
// The provisioning service identity is allowed, matching the wildcard folder
// permissions on that identity. Everyone else is allowed jobs:create when they
// hold the Editor role, repositories:write when they hold Admin, and folder
// verbs only for ids in grants (or every folder when allowAllFolders is set).
type folderJobAccess struct {
	allowAllFolders bool
	grants          map[string]folderGrant
}

func (c *folderJobAccess) Check(_ context.Context, id authlib.AuthInfo, req authlib.CheckRequest, folder string) (authlib.CheckResponse, error) {
	if identity.IsProvisioningServiceIdentity(id) {
		return authlib.CheckResponse{Allowed: true}, nil
	}
	role := identity.RoleNone
	if requester, ok := id.(identity.Requester); ok {
		role = requester.GetOrgRole()
	}
	if req.Group == provisioning.GROUP && req.Resource == provisioning.JobResourceInfo.GetName() {
		if role.Includes(identity.RoleEditor) {
			return authlib.CheckResponse{Allowed: true}, nil
		}
		return authlib.CheckResponse{Allowed: false}, nil
	}
	if req.Group == provisioning.GROUP && req.Resource == provisioning.RepositoryResourceInfo.GetName() {
		if role.Includes(identity.RoleAdmin) {
			return authlib.CheckResponse{Allowed: true}, nil
		}
		return authlib.CheckResponse{Allowed: false}, nil
	}
	if req.Group == resources.FolderResource.Group && req.Resource == resources.FolderResource.Resource {
		if role.Includes(identity.RoleAdmin) || c.allowAllFolders {
			return authlib.CheckResponse{Allowed: true}, nil
		}
		key := req.Name
		if key == "" {
			key = folder
		}
		grant := c.grants[key]
		allowed := false
		switch req.Verb {
		case utils.VerbCreate:
			allowed = grant.create
		case utils.VerbUpdate, utils.VerbPatch:
			allowed = grant.write
		case utils.VerbDelete, utils.VerbDeleteCollection:
			allowed = grant.delete
		}
		return authlib.CheckResponse{Allowed: allowed}, nil
	}
	return authlib.CheckResponse{Allowed: false}, nil
}

func (c *folderJobAccess) Compile(context.Context, authlib.AuthInfo, authlib.ListRequest) (authlib.ItemChecker, authlib.Zookie, error) {
	return nil, nil, nil
}

type recordingJobQueue struct {
	jobs []*provisioning.Job
}

func (q *recordingJobQueue) Insert(_ context.Context, namespace string, spec provisioning.JobSpec) (*provisioning.Job, error) {
	job := &provisioning.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "fix-folder-metadata", Namespace: namespace},
		Spec:       spec,
	}
	q.jobs = append(q.jobs, job)
	return job, nil
}

func (q *recordingJobQueue) CleanupQueue(context.Context, string, string) (int, error) {
	return 0, nil
}

type nopJobProgress struct{}

func (nopJobProgress) Started() time.Time                                       { return time.Time{} }
func (nopJobProgress) Record(context.Context, jobs.JobResourceResult)           {}
func (nopJobProgress) RecordDryRun(context.Context, jobs.JobResourceResult)     {}
func (nopJobProgress) ResetResults(bool)                                        {}
func (nopJobProgress) SetFinalMessage(context.Context, string)                  {}
func (nopJobProgress) SetMessage(context.Context, string)                       {}
func (nopJobProgress) SetTotal(context.Context, int)                            {}
func (nopJobProgress) SetVariance(string)                                       {}
func (nopJobProgress) Variance() string                                         { return "" }
func (nopJobProgress) TooManyErrors() error                                     { return nil }
func (nopJobProgress) StrictMaxErrors(int)                                      {}
func (nopJobProgress) SetRefURLs(context.Context, *provisioning.RepositoryURLs) {}
func (nopJobProgress) Complete(context.Context, error) provisioning.JobStatus {
	return provisioning.JobStatus{}
}
func (nopJobProgress) ResultReasons() []string                { return nil }
func (nopJobProgress) HasDirPathFailedCreation(string) bool   { return false }
func (nopJobProgress) HasDirPathFailedDeletion(string) bool   { return false }
func (nopJobProgress) HasChildPathFailedCreation(string) bool { return false }
func (nopJobProgress) HasChildPathFailedUpdate(string) bool   { return false }

func blobExists(tree map[string]memFile, path string) bool {
	file, ok := tree[path]
	return ok && file.blob
}

func folderUID(tree map[string]memFile, path string) string {
	file, ok := tree[path]
	if !ok {
		return ""
	}
	var obj struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(file.data, &obj)
	return obj.Metadata.Name
}

type memFile struct {
	data []byte
	blob bool
}

type publishedChange struct {
	ref  string
	path string
	op   string
}

// memGitRepo is the staged git repository the worker drives, reduced to the
// steps in apps/provisioning/pkg/repository/git/staged.go: Read and ReadTree
// on a staged repository read the configured branch, Create and Delete in
// commit-once mode only stage, and Push is what publishes the commit.
type memGitRepo struct {
	mu       sync.Mutex
	cfg      *provisioning.Repository
	base     map[string]*memFile
	branches map[string]map[string]*memFile
	changes  []publishedChange
}

func newMemGitRepo(cfg *provisioning.Repository) *memGitRepo {
	return &memGitRepo{
		cfg:      cfg,
		base:     map[string]*memFile{},
		branches: map[string]map[string]*memFile{},
	}
}

func (r *memGitRepo) Config() *provisioning.Repository { return r.cfg }

func (r *memGitRepo) Test(context.Context) (*provisioning.TestResults, error) {
	return &provisioning.TestResults{Success: true}, nil
}

func (r *memGitRepo) seedDir(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if path != "" && path[len(path)-1] != '/' {
		path += "/"
	}
	r.base[path] = &memFile{}
}

func (r *memGitRepo) seedFile(path string, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	copied := append([]byte(nil), data...)
	r.base[path] = &memFile{data: copied, blob: true}
}

func (r *memGitRepo) Read(_ context.Context, path, ref string) (*repository.FileInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	file, ok := r.treeLocked(ref)[path]
	if !ok || !file.blob {
		return nil, repository.ErrFileNotFound
	}
	return &repository.FileInfo{Path: path, Data: append([]byte(nil), file.data...), Ref: ref}, nil
}

func (r *memGitRepo) ReadTree(_ context.Context, ref string) ([]repository.FileTreeEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tree := r.treeLocked(ref)
	out := make([]repository.FileTreeEntry, 0, len(tree))
	for path, file := range tree {
		out = append(out, repository.FileTreeEntry{Path: path, Blob: file.blob})
	}
	return out, nil
}

func (r *memGitRepo) Create(ctx context.Context, path, ref string, data []byte, message string) error {
	return r.writeBase(path, ref, data)
}

func (r *memGitRepo) Update(ctx context.Context, path, ref string, data []byte, message string) error {
	return r.writeBase(path, ref, data)
}

func (r *memGitRepo) Write(ctx context.Context, path, ref string, data []byte, message string) error {
	return r.writeBase(path, ref, data)
}

func (r *memGitRepo) Delete(_ context.Context, path, ref, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tree := r.treeLocked(ref)
	if _, ok := tree[path]; !ok {
		return repository.ErrFileNotFound
	}
	delete(tree, path)
	r.changes = append(r.changes, publishedChange{ref: r.canonical(ref), path: path, op: "delete"})
	return nil
}

func (r *memGitRepo) Move(context.Context, string, string, string, string) error {
	return repository.ErrFileNotFound
}

func (r *memGitRepo) writeBase(path, ref string, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tree := r.treeLocked(ref)
	tree[path] = &memFile{data: append([]byte(nil), data...), blob: true}
	r.changes = append(r.changes, publishedChange{ref: r.canonical(ref), path: path, op: "create"})
	return nil
}

func (r *memGitRepo) Stage(_ context.Context, opts repository.StageOptions) (repository.StagedRepository, error) {
	return &memStagedRepo{base: r, opts: opts, overlay: map[string]stagedOp{}}, nil
}

func (r *memGitRepo) treeLocked(ref string) map[string]*memFile {
	ref = r.canonical(ref)
	if ref == "" {
		return r.base
	}
	if tree, ok := r.branches[ref]; ok {
		return tree
	}
	return r.base
}

func (r *memGitRepo) canonical(ref string) string {
	if ref == "" || ref == r.cfg.Branch() {
		return ""
	}
	return ref
}

func (r *memGitRepo) exists(ref, path string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	file, ok := r.treeLocked(ref)[path]
	return ok && file.blob
}

func (r *memGitRepo) folderUID(ref, path string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	file, ok := r.treeLocked(ref)[path]
	if !ok {
		return ""
	}
	var obj struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(file.data, &obj)
	return obj.Metadata.Name
}

func (r *memGitRepo) published() []publishedChange {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]publishedChange(nil), r.changes...)
	return out
}

func (r *memGitRepo) snapshot() map[string]map[string]memFile {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]map[string]memFile{"": cloneTree(r.base)}
	for ref, tree := range r.branches {
		out[ref] = cloneTree(tree)
	}
	return out
}

func cloneTree(in map[string]*memFile) map[string]memFile {
	out := make(map[string]memFile, len(in))
	for path, file := range in {
		out[path] = memFile{data: append([]byte(nil), file.data...), blob: file.blob}
	}
	return out
}

type stagedOp struct {
	delete bool
	data   []byte
}

// memStagedRepo follows stagedGitRepository: reads come from the configured
// branch, and commit-once writes stay in the overlay until Push.
type memStagedRepo struct {
	base    *memGitRepo
	opts    repository.StageOptions
	mu      sync.Mutex
	overlay map[string]stagedOp
	pushed  bool
}

func (s *memStagedRepo) Config() *provisioning.Repository { return s.base.Config() }

func (s *memStagedRepo) Test(ctx context.Context) (*provisioning.TestResults, error) {
	return s.base.Test(ctx)
}

func (s *memStagedRepo) Read(ctx context.Context, path, ref string) (*repository.FileInfo, error) {
	if !s.refSupported(ref) {
		return nil, repository.ErrInvalidRef
	}
	// stagedGitRepository.Read reads the underlying repository, not the staged writer.
	return s.base.Read(ctx, path, "")
}

func (s *memStagedRepo) ReadTree(ctx context.Context, ref string) ([]repository.FileTreeEntry, error) {
	if !s.refSupported(ref) {
		return nil, repository.ErrInvalidRef
	}
	// stagedGitRepository.ReadTree forces the configured branch.
	return s.base.ReadTree(ctx, "")
}

func (s *memStagedRepo) Create(_ context.Context, path, ref string, data []byte, _ string) error {
	if !s.refSupported(ref) {
		return repository.ErrInvalidRef
	}
	s.stage(path, stagedOp{data: append([]byte(nil), data...)})
	return nil
}

func (s *memStagedRepo) Update(_ context.Context, path, ref string, data []byte, _ string) error {
	if !s.refSupported(ref) {
		return repository.ErrInvalidRef
	}
	s.stage(path, stagedOp{data: append([]byte(nil), data...)})
	return nil
}

func (s *memStagedRepo) Write(_ context.Context, path, ref string, data []byte, _ string) error {
	if !s.refSupported(ref) {
		return repository.ErrInvalidRef
	}
	s.stage(path, stagedOp{data: append([]byte(nil), data...)})
	return nil
}

func (s *memStagedRepo) Delete(_ context.Context, path, ref, _ string) error {
	if !s.refSupported(ref) {
		return repository.ErrInvalidRef
	}
	s.stage(path, stagedOp{delete: true})
	return nil
}

func (s *memStagedRepo) Move(context.Context, string, string, string, string) error {
	return repository.ErrFileNotFound
}

func (s *memStagedRepo) stage(path string, op stagedOp) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Commit-once mode, which this job uses, records the blob and lets Push publish it.
	s.overlay[path] = op
}

func (s *memStagedRepo) Push(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.overlay) == 0 {
		return repository.ErrNothingToPush
	}
	s.base.mu.Lock()
	defer s.base.mu.Unlock()
	target := s.opts.Ref
	if target == "" || target == s.base.cfg.Branch() {
		target = ""
	}
	var tree map[string]*memFile
	if target == "" {
		tree = s.base.base
	} else {
		tree = map[string]*memFile{}
		for path, file := range s.base.base {
			tree[path] = &memFile{data: append([]byte(nil), file.data...), blob: file.blob}
		}
		s.base.branches[target] = tree
	}
	for path, op := range s.overlay {
		if op.delete {
			delete(tree, path)
			s.base.changes = append(s.base.changes, publishedChange{ref: target, path: path, op: "delete"})
			continue
		}
		tree[path] = &memFile{data: append([]byte(nil), op.data...), blob: true}
		s.base.changes = append(s.base.changes, publishedChange{ref: target, path: path, op: "create"})
	}
	s.pushed = true
	s.overlay = map[string]stagedOp{}
	return nil
}

func (s *memStagedRepo) Remove(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.pushed {
		s.overlay = map[string]stagedOp{}
	}
	return nil
}

func (s *memStagedRepo) refSupported(ref string) bool {
	if ref == "" || ref == s.base.cfg.Branch() {
		return true
	}
	staging := s.opts.Ref
	if staging == "" {
		staging = s.base.cfg.Branch()
	}
	return ref == staging
}
