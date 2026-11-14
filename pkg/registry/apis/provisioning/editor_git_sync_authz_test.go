package provisioning

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/dynamic"

	"github.com/grafana/authlib/authz"
	authlib "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/apps/provisioning/pkg/apis/auth"
	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/safepath"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs"
	deletejob "github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs/delete"
	movejob "github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs/move"
	syncjob "github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs/sync"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/resources"
)

const (
	gitSyncRepoName   = "git-sync"
	gitSyncNamespace  = "default"
	gitSyncAllowed    = "allowed/mine.json"
	gitSyncIncoming   = "restricted/incoming.json"
	gitSyncSecret     = "restricted/secret.json"
	gitSyncMineName   = "mine-dash"
	gitSyncRestricted = "restricted-dash"
)

// classicDashboard is the same classic dashboard document the job authorizer
// tests already parse as dashboard.grafana.app/Dashboard.
var classicDashboard = []byte(`{"uid":"test","schemaVersion":7,"panels":[],"tags":[]}`)

// folderScopedAccess is the user-permission half of an access check.
// An organization admin is allowed. An editor is allowed only for dashboard
// writes in one folder. Every other check is denied, so the jobs route (which
// falls back to the Editor role) and authorizeAdminJob (which falls back to
// the Admin role) decide from the caller's org role.
type folderScopedAccess struct {
	allowedFolder string
}

func (f folderScopedAccess) Check(_ context.Context, id authlib.AuthInfo, req authlib.CheckRequest, folder string) (authlib.CheckResponse, error) {
	requester, ok := id.(identity.Requester)
	if ok && requester.GetOrgRole().Includes(identity.RoleAdmin) {
		return authlib.CheckResponse{Allowed: true}, nil
	}
	if req.Group == resources.DashboardResource.Group &&
		req.Resource == resources.DashboardResource.Resource &&
		folder == f.allowedFolder {
		return authlib.CheckResponse{Allowed: true}, nil
	}
	return authlib.CheckResponse{}, nil
}

// gitSyncWorld is the repository, the Grafana resources it manages, and the
// dynamic client the full sync writes through.
type gitSyncWorld struct {
	mu            sync.Mutex
	cfg           *provisioning.Repository
	allowedFolder string
	files         map[string]gitSyncFile
	grafana       map[string]provisioning.ResourceListItem
	gitDeleted    []string
	gitMoved      []string
	deleted       []gitSyncMutation
	created       []gitSyncMutation
}

type gitSyncFile struct {
	data []byte
	hash string
}

type gitSyncMutation struct {
	target string
	actor  string
}

func newGitSyncWorld(t *testing.T) *gitSyncWorld {
	t.Helper()
	cfg := &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: gitSyncRepoName, Namespace: gitSyncNamespace},
		Spec: provisioning.RepositorySpec{
			Title: "Git Sync",
			Type:  provisioning.GitRepositoryType,
			Git:   &provisioning.GitRepositoryConfig{Branch: "main"},
			Workflows: []provisioning.Workflow{
				provisioning.WriteWorkflow,
			},
			Sync: provisioning.SyncOptions{Target: provisioning.SyncTargetTypeInstance},
		},
		Status: provisioning.RepositoryStatus{
			Health: provisioning.HealthStatus{Healthy: true, Checked: 1},
		},
	}
	allowed := resources.ParseFolder("allowed/", cfg.Name).ID
	restricted := resources.ParseFolder("restricted/", cfg.Name).ID
	return &gitSyncWorld{
		cfg:           cfg,
		allowedFolder: allowed,
		files: map[string]gitSyncFile{
			gitSyncAllowed:  {data: classicDashboard, hash: "mine-hash"},
			gitSyncIncoming: {data: classicDashboard, hash: "incoming-hash"},
			gitSyncSecret:   {data: classicDashboard, hash: "secret-hash"},
		},
		grafana: map[string]provisioning.ResourceListItem{
			gitSyncMineName: {
				Path: gitSyncAllowed, Name: gitSyncMineName, Hash: "mine-hash",
				Group: resources.DashboardResource.Group, Resource: resources.DashboardResource.Resource,
				Folder: allowed,
			},
			gitSyncRestricted: {
				Path: "restricted/other.json", Name: gitSyncRestricted, Hash: "other-hash",
				Group: resources.DashboardResource.Group, Resource: resources.DashboardResource.Resource,
				Folder: restricted,
			},
		},
	}
}

func (w *gitSyncWorld) Config() *provisioning.Repository { return w.cfg }

func (w *gitSyncWorld) Test(context.Context) (*provisioning.TestResults, error) {
	return &provisioning.TestResults{Success: true}, nil
}

func (w *gitSyncWorld) Read(_ context.Context, path, _ string) (*repository.FileInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	file, ok := w.files[path]
	if !ok {
		return nil, repository.ErrFileNotFound
	}
	return &repository.FileInfo{Path: path, Data: file.data, Hash: file.hash}, nil
}

func (w *gitSyncWorld) ReadTree(context.Context, string) ([]repository.FileTreeEntry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	entries := make([]repository.FileTreeEntry, 0, len(w.files))
	for path, file := range w.files {
		entries = append(entries, repository.FileTreeEntry{Path: path, Hash: file.hash, Blob: true, Size: int64(len(file.data))})
	}
	return entries, nil
}

func (w *gitSyncWorld) Create(context.Context, string, string, []byte, string) error {
	return fmt.Errorf("git create was not part of this job")
}

func (w *gitSyncWorld) Update(context.Context, string, string, []byte, string) error {
	return fmt.Errorf("git update was not part of this job")
}

func (w *gitSyncWorld) Write(context.Context, string, string, []byte, string) error {
	return fmt.Errorf("git write was not part of this job")
}

func (w *gitSyncWorld) Delete(_ context.Context, path, _, _ string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.files[path]; !ok {
		return repository.ErrFileNotFound
	}
	delete(w.files, path)
	w.gitDeleted = append(w.gitDeleted, path)
	return nil
}

func (w *gitSyncWorld) Move(_ context.Context, oldPath, newPath, _, _ string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	file, ok := w.files[oldPath]
	if !ok {
		return repository.ErrFileNotFound
	}
	delete(w.files, oldPath)
	w.files[newPath] = file
	w.gitMoved = append(w.gitMoved, oldPath)
	return nil
}

func (w *gitSyncWorld) List(context.Context) (*provisioning.ResourceList, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	list := &provisioning.ResourceList{}
	for _, item := range w.grafana {
		list.Items = append(list.Items, item)
	}
	return list, nil
}

func (w *gitSyncWorld) Stats(context.Context) (*provisioning.ResourceStats, error) {
	return nil, nil
}

func (w *gitSyncWorld) SetTree(resources.FolderTree) {}

func (w *gitSyncWorld) EnsureFolderExists(context.Context, resources.Folder, string) error {
	return nil
}

func (w *gitSyncWorld) EnsureFolderPathExist(context.Context, string, string, ...resources.EnsurePathOption) (string, error) {
	return "", fmt.Errorf("folder ensure is not used by this sync")
}

func (w *gitSyncWorld) EnsureFolderTreeExists(context.Context, resources.FolderTree, resources.EnsureFolderTreeExistsOptions) error {
	return fmt.Errorf("folder tree ensure is not used by this sync")
}

func (w *gitSyncWorld) RemoveFolderFromTree(string) {}

func (w *gitSyncWorld) RemoveFolder(context.Context, string) error {
	return fmt.Errorf("folder remove is not used by this sync")
}

func (w *gitSyncWorld) RenameFolderPath(context.Context, string, string, string, string, ...resources.EnsurePathOption) (string, error) {
	return "", fmt.Errorf("folder rename is not used by this sync")
}

func (w *gitSyncWorld) WriteResourceFileFromObject(context.Context, *unstructured.Unstructured, resources.WriteOptions) (string, int, error) {
	return "", 0, fmt.Errorf("writing a file from an object is not used by this sync")
}

func (w *gitSyncWorld) WriteResourceFromFile(ctx context.Context, path, _ string, _ ...resources.WriteResourceOption) (string, schema.GroupVersionKind, int, error) {
	folder := resources.ParseFolder(safepath.Dir(path), w.cfg.Name).ID
	if err := w.authorizeStorage(ctx, utils.VerbCreate, folder); err != nil {
		return "", schema.GroupVersionKind{}, 0, err
	}
	w.recordCreate(ctx, path)
	return "created-from-" + path, resources.DashboardKind, len(classicDashboard), nil
}

func (w *gitSyncWorld) ReplaceResourceFromFile(ctx context.Context, path, ref, _ string, _ schema.GroupVersionResource, opts ...resources.WriteResourceOption) (string, schema.GroupVersionKind, int, error) {
	return w.WriteResourceFromFile(ctx, path, ref, opts...)
}

func (w *gitSyncWorld) ReplaceResourceFromFileByRef(ctx context.Context, path, ref, _ string, opts ...resources.WriteResourceOption) (string, schema.GroupVersionKind, int, error) {
	return w.WriteResourceFromFile(ctx, path, ref, opts...)
}

func (w *gitSyncWorld) RemoveResourceFromFile(context.Context, string, string) (string, string, schema.GroupVersionKind, int, error) {
	return "", "", schema.GroupVersionKind{}, 0, fmt.Errorf("remove from file is not used by this sync")
}

func (w *gitSyncWorld) FindResourcePath(context.Context, string, schema.GroupVersionKind) (string, error) {
	return "", fmt.Errorf("find resource path is not used by this sync")
}

func (w *gitSyncWorld) RenameResourceFile(context.Context, string, string, string, string, ...resources.EnsurePathOption) (string, string, schema.GroupVersionKind, int, error) {
	return "", "", schema.GroupVersionKind{}, 0, fmt.Errorf("rename resource file is not used by this sync")
}

func (w *gitSyncWorld) Client(context.Context, repository.ReaderWriter, ...resources.RepositoryResourcesOption) (resources.RepositoryResources, error) {
	return w, nil
}

func (w *gitSyncWorld) Clients(context.Context, string) (resources.ResourceClients, error) {
	return gitSyncClients{world: w}, nil
}

// authorizeStorage applies the decision authlib's ClientImpl.Check makes for a
// service caller, then the folder decision for a user. ClientImpl returns the
// token result immediately when the caller is an access-policy identity and
// does not consult the user's folder permissions
// (authlib v0.0.0-20260814184937-0d62418c2815 authz/client.go).
func (w *gitSyncWorld) authorizeStorage(ctx context.Context, verb, folder string) error {
	requester, err := identity.GetRequester(ctx)
	if err != nil {
		return apierrors.NewUnauthorized("no identity")
	}
	decision := authz.CheckServicePermissions(requester, resources.DashboardResource.Group, resources.DashboardResource.Resource, verb)
	if decision.ServiceCall {
		if decision.Allowed {
			return nil
		}
		return apierrors.NewForbidden(resources.DashboardResource.GroupResource(), folder, fmt.Errorf("service token cannot %s dashboards", verb))
	}
	if requester.GetOrgRole().Includes(identity.RoleAdmin) || folder == w.allowedFolder {
		return nil
	}
	return apierrors.NewForbidden(resources.DashboardResource.GroupResource(), folder, fmt.Errorf("editor cannot %s dashboards in this folder", verb))
}

func (w *gitSyncWorld) recordCreate(ctx context.Context, path string) {
	actor := "unknown"
	if requester, err := identity.GetRequester(ctx); err == nil {
		actor = requester.GetUID()
	}
	w.mu.Lock()
	w.created = append(w.created, gitSyncMutation{target: path, actor: actor})
	w.mu.Unlock()
}

func (w *gitSyncWorld) deleteGrafana(ctx context.Context, name string) error {
	w.mu.Lock()
	item, ok := w.grafana[name]
	w.mu.Unlock()
	if !ok {
		return apierrors.NewNotFound(resources.DashboardResource.GroupResource(), name)
	}
	if err := w.authorizeStorage(ctx, utils.VerbDelete, item.Folder); err != nil {
		return err
	}
	actor := "unknown"
	if requester, err := identity.GetRequester(ctx); err == nil {
		actor = requester.GetUID()
	}
	w.mu.Lock()
	delete(w.grafana, name)
	w.deleted = append(w.deleted, gitSyncMutation{target: name, actor: actor})
	w.mu.Unlock()
	return nil
}

func (w *gitSyncWorld) mutations(field func(*gitSyncWorld) []gitSyncMutation) []gitSyncMutation {
	w.mu.Lock()
	defer w.mu.Unlock()
	src := field(w)
	out := make([]gitSyncMutation, len(src))
	copy(out, src)
	return out
}

func (w *gitSyncWorld) hasFile(path string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.files[path]
	return ok
}

func (w *gitSyncWorld) hasGrafana(name string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.grafana[name]
	return ok
}

type gitSyncClients struct{ world *gitSyncWorld }

func (c gitSyncClients) ForResource(context.Context, schema.GroupVersionResource) (dynamic.ResourceInterface, schema.GroupVersionKind, error) {
	return &gitSyncResourceClient{world: c.world}, resources.DashboardKind, nil
}

func (c gitSyncClients) ForKind(context.Context, schema.GroupVersionKind) (dynamic.ResourceInterface, schema.GroupVersionResource, error) {
	return &gitSyncResourceClient{world: c.world}, resources.DashboardResource, nil
}

func (c gitSyncClients) Folder(context.Context) (dynamic.ResourceInterface, schema.GroupVersionKind, error) {
	return nil, schema.GroupVersionKind{}, fmt.Errorf("folder client is not used by this sync")
}

func (c gitSyncClients) User(context.Context) (dynamic.ResourceInterface, error) {
	return nil, fmt.Errorf("user client is not used by this sync")
}

func (c gitSyncClients) SupportedResources() []resources.SupportedResource {
	return resources.SupportedProvisioningResources
}

type gitSyncResourceClient struct{ world *gitSyncWorld }

func (c *gitSyncResourceClient) Delete(ctx context.Context, name string, _ metav1.DeleteOptions, _ ...string) error {
	return c.world.deleteGrafana(ctx, name)
}

func (c *gitSyncResourceClient) Get(context.Context, string, metav1.GetOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, apierrors.NewNotFound(resources.DashboardResource.GroupResource(), "unused")
}
func (c *gitSyncResourceClient) Create(context.Context, *unstructured.Unstructured, metav1.CreateOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, fmt.Errorf("dynamic create is not used by full sync file writes")
}
func (c *gitSyncResourceClient) Update(context.Context, *unstructured.Unstructured, metav1.UpdateOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, fmt.Errorf("dynamic update is not used by this sync")
}
func (c *gitSyncResourceClient) UpdateStatus(context.Context, *unstructured.Unstructured, metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	return nil, fmt.Errorf("dynamic update status is not used by this sync")
}
func (c *gitSyncResourceClient) DeleteCollection(context.Context, metav1.DeleteOptions, metav1.ListOptions) error {
	return fmt.Errorf("delete collection is not used by this sync")
}
func (c *gitSyncResourceClient) List(context.Context, metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return &unstructured.UnstructuredList{}, nil
}
func (c *gitSyncResourceClient) Watch(context.Context, metav1.ListOptions) (watch.Interface, error) {
	return nil, fmt.Errorf("watch is not used by this sync")
}
func (c *gitSyncResourceClient) Patch(context.Context, string, types.PatchType, []byte, metav1.PatchOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, fmt.Errorf("patch is not used by this sync")
}
func (c *gitSyncResourceClient) Apply(context.Context, string, *unstructured.Unstructured, metav1.ApplyOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, fmt.Errorf("apply is not used by this sync")
}
func (c *gitSyncResourceClient) ApplyStatus(context.Context, string, *unstructured.Unstructured, metav1.ApplyOptions) (*unstructured.Unstructured, error) {
	return nil, fmt.Errorf("apply status is not used by this sync")
}

type gitSyncQueue struct {
	mu  sync.Mutex
	job *provisioning.Job
}

func (q *gitSyncQueue) Insert(_ context.Context, namespace string, spec provisioning.JobSpec) (*provisioning.Job, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.job = &provisioning.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "job-1", Namespace: namespace, ResourceVersion: "1"},
		Spec:       spec,
	}
	return q.job.DeepCopy(), nil
}

func (q *gitSyncQueue) CleanupQueue(context.Context, string, string) (int, error) { return 0, nil }

func (q *gitSyncQueue) GetJobQueue() jobs.Queue { return q }

type gitSyncStore struct {
	queue     *gitSyncQueue
	completed chan struct{}
	once      sync.Once
}

func (s *gitSyncStore) Claim(context.Context, string, string, string) (*provisioning.Job, func(), error) {
	s.queue.mu.Lock()
	defer s.queue.mu.Unlock()
	if s.queue.job == nil {
		return nil, nil, fmt.Errorf("no job to claim")
	}
	return s.queue.job.DeepCopy(), func() {}, nil
}

func (s *gitSyncStore) Update(_ context.Context, job *provisioning.Job) (*provisioning.Job, error) {
	s.queue.mu.Lock()
	defer s.queue.mu.Unlock()
	s.queue.job = job.DeepCopy()
	return s.queue.job.DeepCopy(), nil
}

func (s *gitSyncStore) Complete(context.Context, *provisioning.Job) error {
	s.once.Do(func() { close(s.completed) })
	return nil
}

func (s *gitSyncStore) RenewLease(context.Context, *provisioning.Job) error { return nil }

func (s *gitSyncStore) Get(context.Context, string, string) (*provisioning.Job, error) {
	s.queue.mu.Lock()
	defer s.queue.mu.Unlock()
	if s.queue.job == nil {
		return nil, apierrors.NewNotFound(provisioning.JobResourceInfo.GroupResource(), "job-1")
	}
	return s.queue.job.DeepCopy(), nil
}

func (s *gitSyncStore) ListExpiredJobs(context.Context, time.Time, int) ([]*provisioning.Job, error) {
	return nil, nil
}

type gitSyncHistory struct{}

func (gitSyncHistory) WriteJob(context.Context, *provisioning.Job) error { return nil }

type gitSyncDriverRepos struct{ repo repository.Repository }

func (g gitSyncDriverRepos) GetRepository(context.Context, string, string) (repository.Repository, error) {
	return g.repo, nil
}

type gitSyncAdmissionRepos struct{ repo repository.Repository }

func (g gitSyncAdmissionRepos) GetRepository(context.Context, string) (repository.Repository, error) {
	return g.repo, nil
}

func (g gitSyncAdmissionRepos) GetHealthyRepository(context.Context, string) (repository.Repository, error) {
	if !g.repo.Config().Status.Health.Healthy {
		return nil, &apierrors.StatusError{ErrStatus: metav1.Status{
			Code:    http.StatusFailedDependency,
			Message: "The repository configuration is not healthy",
		}}
	}
	return g.repo, nil
}

func editorContext(role identity.RoleType) context.Context {
	requester := &identity.StaticRequester{
		Type:      authlib.TypeUser,
		UserID:    7,
		UserUID:   strings.ToLower(string(role)),
		OrgID:     1,
		OrgRole:   role,
		Namespace: gitSyncNamespace,
		Name:      string(role),
	}
	return identity.WithRequester(request.WithNamespace(context.Background(), gitSyncNamespace), requester)
}

func postGitSyncJob(t *testing.T, ctx context.Context, world *gitSyncWorld, access auth.AccessChecker, body string) (*fakeResponder, *gitSyncQueue) {
	t.Helper()
	queue := &gitSyncQueue{}
	connector := NewJobsConnector(
		gitSyncAdmissionRepos{repo: world},
		nil,
		queue,
		nil,
		access,
		newJobAuthClients(t),
		false,
		nil,
	)
	responder := &fakeResponder{}
	handler, err := connector.Connect(ctx, gitSyncRepoName, nil, responder)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/"+gitSyncRepoName+"/jobs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	return responder, queue
}

func runQueuedJob(t *testing.T, world *gitSyncWorld, queue *gitSyncQueue) {
	t.Helper()
	require.NotNil(t, queue.job, "job was accepted but not queued")
	registry := prometheus.NewRegistry()
	metrics := jobs.RegisterJobMetrics(registry)
	syncWorker := syncjob.NewSyncWorker(
		world,
		world,
		func(context.Context, *provisioning.Repository, ...map[string]interface{}) error { return nil },
		syncjob.NewSyncer(syncjob.Compare, syncjob.FullSync, syncjob.IncrementalSync, tracing.NewNoopTracerService(), 2, metrics, false, 0),
		metrics,
		tracing.NewNoopTracerService(),
		2,
		0,
	)
	store := &gitSyncStore{queue: queue, completed: make(chan struct{})}
	driver, err := jobs.NewConcurrentJobDriver(
		1,
		time.Minute,
		30*time.Second,
		15*time.Second,
		store,
		gitSyncDriverRepos{repo: world},
		gitSyncHistory{},
		registry,
		&metrics,
		false,
		deletejob.NewWorker(syncWorker, repository.WrapWithStageAndPushIfPossible, nil, metrics),
		movejob.NewWorker(syncWorker, repository.WrapWithStageAndPushIfPossible, nil, metrics),
		syncWorker,
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- driver.Run(ctx) }()
	driver.EventHandler().AddFunc(&provisioning.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: queue.job.Namespace, Name: queue.job.Name, ResourceVersion: "1"},
	}, false)

	select {
	case <-store.completed:
	case <-time.After(20 * time.Second):
		t.Fatal("queued job did not finish")
	}
	cancel()
	require.NoError(t, <-runDone)
}

func assertNoUnauthorizedSync(t *testing.T, world *gitSyncWorld, authorizedGitPaths ...string) {
	t.Helper()
	allowed := map[string]struct{}{}
	for _, path := range authorizedGitPaths {
		allowed[path] = struct{}{}
	}
	var unexpected []string
	world.mu.Lock()
	for _, path := range world.gitDeleted {
		if _, ok := allowed[path]; !ok {
			unexpected = append(unexpected, "delete "+path)
		}
	}
	for _, path := range world.gitMoved {
		if _, ok := allowed[path]; !ok {
			unexpected = append(unexpected, "move "+path)
		}
	}
	created := append([]gitSyncMutation(nil), world.created...)
	deleted := append([]gitSyncMutation(nil), world.deleted...)
	world.mu.Unlock()
	require.Empty(t, unexpected, "git changes landed for paths the job did not name")

	for _, change := range deleted {
		require.NotEqualf(t, gitSyncRestricted, change.target,
			"full sync deleted %s as %s", change.target, change.actor)
	}
	for _, change := range created {
		require.Falsef(t, strings.HasPrefix(change.target, "restricted/"),
			"full sync created %s as %s", change.target, change.actor)
	}
	require.True(t, world.hasGrafana(gitSyncRestricted), "restricted dashboard is gone")
	require.True(t, world.hasFile(gitSyncIncoming), "incoming git file is gone")
	require.True(t, world.hasFile(gitSyncSecret), "restricted git file is gone")
}

func TestEditorGitSyncJobCannotFullSyncUnauthorizedResources(t *testing.T) {
	access := auth.NewSessionAccessChecker(folderScopedAccess{
		allowedFolder: resources.ParseFolder("allowed/", gitSyncRepoName).ID,
	})
	editorCtx := editorContext(identity.RoleEditor)

	t.Run("jobs route allows an editor to create a job", func(t *testing.T) {
		decision, _, err := (&APIBuilder{
			accessWithAdmin:  access.WithFallbackRole(identity.RoleAdmin),
			accessWithEditor: access.WithFallbackRole(identity.RoleEditor),
		}).authorizeRepositorySubresource(editorCtx, authorizer.AttributesRecord{
			Verb:            utils.VerbCreate,
			Subresource:     "jobs",
			Name:            gitSyncRepoName,
			Namespace:       gitSyncNamespace,
			ResourceRequest: true,
		})
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision)
	})

	t.Run("editor pull is rejected", func(t *testing.T) {
		world := newGitSyncWorld(t)
		responder, queue := postGitSyncJob(t, editorCtx, world, access, `{"action":"pull","pull":{"incremental":false}}`)
		require.Error(t, responder.err)
		require.True(t, apierrors.IsForbidden(responder.err))
		require.Nil(t, queue.job)
		assertNoUnauthorizedSync(t, world)
	})

	t.Run("editor migrate is rejected before a sync", func(t *testing.T) {
		world := newGitSyncWorld(t)
		responder, queue := postGitSyncJob(t, editorCtx, world, access, `{"action":"migrate","migrate":{}}`)
		require.Error(t, responder.err)
		require.Nil(t, queue.job)
		assertNoUnauthorizedSync(t, world)
	})

	t.Run("editor cannot delete a file outside the allowed folder", func(t *testing.T) {
		world := newGitSyncWorld(t)
		responder, queue := postGitSyncJob(t, editorCtx, world, access,
			`{"action":"delete","delete":{"paths":["restricted/secret.json"]}}`)
		require.Error(t, responder.err)
		require.Nil(t, queue.job)
		assertNoUnauthorizedSync(t, world)
	})

	editorJobs := []struct {
		name          string
		body          string
		authorizedGit []string
	}{
		{
			name: "empty delete",
			body: `{"action":"delete","delete":{}}`,
		},
		{
			name:          "delete of one allowed file",
			body:          `{"action":"delete","delete":{"paths":["allowed/mine.json"]}}`,
			authorizedGit: []string{gitSyncAllowed},
		},
		{
			name: "empty move",
			body: `{"action":"move","move":{"targetPath":"allowed/dest/"}}`,
		},
		{
			name:          "move of one allowed file",
			body:          `{"action":"move","move":{"paths":["allowed/mine.json"],"targetPath":"allowed/dest/"}}`,
			authorizedGit: []string{gitSyncAllowed},
		},
	}
	for _, tc := range editorJobs {
		t.Run(tc.name, func(t *testing.T) {
			world := newGitSyncWorld(t)
			responder, queue := postGitSyncJob(t, editorCtx, world, access, tc.body)
			if responder.err != nil {
				require.Nil(t, queue.job)
				assertNoUnauthorizedSync(t, world, tc.authorizedGit...)
				return
			}
			require.Equal(t, http.StatusAccepted, responder.statusCode)
			runQueuedJob(t, world, queue)
			assertNoUnauthorizedSync(t, world, tc.authorizedGit...)
		})
	}

	t.Run("admin empty delete still full syncs", func(t *testing.T) {
		world := newGitSyncWorld(t)
		responder, queue := postGitSyncJob(t, editorContext(identity.RoleAdmin), world, access, `{"action":"delete","delete":{}}`)
		require.NoError(t, responder.err)
		require.Equal(t, http.StatusAccepted, responder.statusCode)
		runQueuedJob(t, world, queue)
		var deletedRestricted bool
		var createdIncoming bool
		for _, change := range world.mutations(func(w *gitSyncWorld) []gitSyncMutation { return w.deleted }) {
			if change.target == gitSyncRestricted {
				deletedRestricted = true
			}
		}
		for _, change := range world.mutations(func(w *gitSyncWorld) []gitSyncMutation { return w.created }) {
			if change.target == gitSyncIncoming {
				createdIncoming = true
			}
		}
		require.True(t, deletedRestricted, "admin full sync did not delete the dashboard that is missing from git")
		require.True(t, createdIncoming, "admin full sync did not create the dashboard that is present in git")
	})
}
