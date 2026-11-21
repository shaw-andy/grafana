package provisioning

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/fullstorydev/grpchan/inprocgrpc"
	grpcAuth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	authnlib "github.com/grafana/authlib/authn"
	authzlib "github.com/grafana/authlib/authz"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	authlib "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/apps/provisioning/pkg/apis/auth"
	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/quotas"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/local"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs"
	deletejob "github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs/delete"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs/sync"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/resources"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/authz"
	"github.com/grafana/grafana/pkg/services/authz/rbac"
	"github.com/grafana/grafana/pkg/services/authz/rbac/store"
)

// A caller who holds folders:delete on a Git Sync folder, and not dashboards:delete
// on the dashboards in it, must not be able to remove those dashboards by posting a
// directory delete job. The job is refused before the repository directory or the
// Grafana dashboard is deleted. A file delete of the same dashboard is already refused.
func TestDirectoryDeleteJobDoesNotRemoveUndeletableDashboards(t *testing.T) {
	const (
		namespace = "org-12"
		userUID   = "editor"
		repoName  = "git-sync"
		hidden    = "hidden-dash"
		other     = "other-dash"
		dirPath   = "team/secret/"
		hiddenRel = "team/secret/hidden.json"
		otherRel  = "team/other/ok.json"
	)

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "team", "secret"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "team", "other"), 0o700))
	dashboardBody := []byte(`{"uid":"hidden-dash","title":"Hidden","schemaVersion":7,"panels":[],"tags":[]}`)
	require.NoError(t, os.WriteFile(filepath.Join(root, hiddenRel), dashboardBody, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, otherRel), []byte(`{"uid":"other-dash","title":"Other","schemaVersion":7,"panels":[],"tags":[]}`), 0o600))

	cfg := &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: repoName, Namespace: namespace},
		Spec: provisioning.RepositorySpec{
			Title: "Git Sync",
			Type:  provisioning.LocalRepositoryType,
			Local: &provisioning.LocalRepositoryConfig{Path: root},
			Workflows: []provisioning.Workflow{
				provisioning.WriteWorkflow,
			},
			Sync: provisioning.SyncOptions{Target: provisioning.SyncTargetTypeFolder},
		},
	}
	repo := local.NewRepository(cfg, &local.LocalFolderResolver{PermittedPrefixes: []string{root}}, repository.RegisterOperationMetrics(prometheus.NewPedanticRegistry()))

	// Same write gate the job connector applies to an empty ref. A git repository
	// with the write workflow is accepted the same way; the worker then calls Delete.
	gitCfg := cfg.DeepCopy()
	gitCfg.Spec.Type = provisioning.GitRepositoryType
	gitCfg.Spec.Git = &provisioning.GitRepositoryConfig{Branch: "main"}
	require.NoError(t, repository.IsWriteAllowed(gitCfg, ""))
	require.NoError(t, repository.IsWriteAllowed(cfg, ""))

	secretID := resources.ParseFolder(dirPath, repoName).ID
	teamID := resources.ParseFolder("team", repoName).ID
	parent := teamID
	authzSvc := rbac.NewTestService(userUID, []accesscontrol.Permission{{
		Action: "folders:delete",
		Scope:  "folders:uid:" + secretID,
	}}, []store.Folder{{UID: teamID}, {UID: secretID, ParentUID: &parent}})

	channel := &inprocgrpc.Channel{}
	authenticate := func(ctx context.Context) (context.Context, error) {
		// The in-process authz server authenticates as the Grafana service, which
		// may act in any namespace. The user check is the request subject.
		ctx = authlib.WithAuthInfo(ctx, authnlib.NewAccessTokenAuthInfo(authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{Namespace: "*"},
		}))
		return ctx, nil
	}
	channel.WithServerUnaryInterceptor(grpcAuth.UnaryServerInterceptor(authenticate))
	authzv1.RegisterAuthzServiceServer(channel, authzSvc)
	accessClient := authzlib.NewClient(channel, authzlib.WithCacheClientOption(&authz.NoopCache{}))

	// A session user has no access token. AccessClaimsHook fills the delegated
	// permissions the authz client requires before it will consult RBAC.
	requester := &identity.StaticRequester{
		Type:      authlib.TypeUser,
		UserUID:   userUID,
		UserID:    1,
		OrgRole:   identity.RoleEditor,
		Namespace: namespace,
		AccessTokenClaims: &authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{
				DelegatedPermissions: identity.ServiceIdentityClaims.Rest.DelegatedPermissions,
			},
		},
	}
	ctx := identity.WithRequester(context.Background(), requester)

	session := auth.NewSessionAccessChecker(accessClient)
	connector := &jobsConnector{
		access:                session,
		clients:               newJobAuthClients(t),
		folderMetadataEnabled: false,
	}

	// The jobs subresource admits an Editor through the role fallback.
	editorGate := session.WithFallbackRole(identity.RoleEditor)
	require.NoError(t, editorGate.Check(ctx, authlib.CheckRequest{
		Verb:      utils.VerbCreate,
		Group:     provisioning.GROUP,
		Resource:  provisioning.JobResourceInfo.GetName(),
		Namespace: namespace,
	}, ""))

	// The same caller cannot delete the dashboard file. The directory job must
	// not do it for them.
	fileErr := connector.authorizeDeleteJob(ctx, repo, cfg, []string{hiddenRel}, nil)
	require.Error(t, fileErr, "file delete must stay denied when the caller has no dashboards:delete")

	// Moving the directory asks for folder update, which this grant does not include.
	moveErr := connector.authorizeMoveJob(ctx, repo, cfg, &provisioning.MoveJobOptions{
		Paths:      []string{dirPath},
		TargetPath: "elsewhere/",
	})
	require.Error(t, moveErr, "folders:delete does not authorize a directory move")

	spec := provisioning.JobSpec{
		Action: provisioning.JobActionDelete,
		Delete: &provisioning.DeleteJobOptions{Paths: []string{dirPath}},
	}
	require.NoError(t, connector.validateWriteAccess(cfg, spec))
	authErr := connector.authorizeDeleteJob(ctx, repo, cfg, spec.Delete.Paths, nil)

	hiddenOnDisk := filepath.Join(root, hiddenRel)
	otherOnDisk := filepath.Join(root, otherRel)
	dashClient := newDashboardClient(namespace, hidden, other)
	var dashClientHolder *dashboardClients
	var processErr error
	if authErr == nil {
		// The driver switches to the provisioning identity before the worker runs.
		jobCtx, prov, err := identity.WithProvisioningIdentity(context.Background(), namespace)
		require.NoError(t, err)
		require.Equal(t, authlib.TypeAccessPolicy, prov.GetIdentityType())
		require.Equal(t, "provisioning", prov.GetIdentifier())

		metrics := jobs.RegisterJobMetrics(prometheus.NewPedanticRegistry())
		tracer := tracing.NewNoopTracerService()
		factory := &listingResourcesFactory{items: []provisioning.ResourceListItem{
			{Path: hiddenRel, Group: resources.DashboardResource.Group, Resource: resources.DashboardResource.Resource, Name: hidden, Folder: secretID},
			{Path: otherRel, Group: resources.DashboardResource.Group, Resource: resources.DashboardResource.Resource, Name: other, Folder: teamID},
		}}
		clients := &dashboardClients{client: dashClient, namespace: namespace}
		dashClientHolder = clients
		syncWorker := sync.NewSyncWorker(
			clients,
			factory,
			func(context.Context, *provisioning.Repository, ...map[string]interface{}) error { return nil },
			sync.NewSyncer(sync.Compare, sync.FullSync, func(context.Context, repository.Versioned, string, string, resources.RepositoryResources, jobs.JobProgressRecorder, tracing.Tracer, jobs.JobMetrics, quotas.QuotaTracker, bool) error {
				return fmt.Errorf("incremental sync is not used for an empty ref")
			}, tracer, 1, metrics, false, 0),
			metrics,
			tracer,
			1,
			0,
		)
		worker := deletejob.NewWorker(syncWorker, repository.WrapWithStageAndPushIfPossible, factory, metrics)
		progress := jobs.NewJobProgressRecorder(func(context.Context, provisioning.JobStatus) error { return nil }, &metrics, provisioning.JobActionDelete)
		job := provisioning.Job{ObjectMeta: metav1.ObjectMeta{Name: "delete-secret", Namespace: namespace}, Spec: spec}
		processErr = worker.Process(jobCtx, repo, job, progress)
	}

	_, hiddenStat := os.Stat(hiddenOnDisk)
	_, otherStat := os.Stat(otherOnDisk)
	_, hiddenGet := dashClient.Resource(resources.DashboardResource).Namespace(namespace).Get(context.Background(), hidden, metav1.GetOptions{})
	_, otherGet := dashClient.Resource(resources.DashboardResource).Namespace(namespace).Get(context.Background(), other, metav1.GetOptions{})
	var deleted []string
	if dashClientHolder != nil {
		deleted = dashClientHolder.deleted
	}
	if authErr != nil || hiddenStat != nil || otherStat != nil || hiddenGet != nil || otherGet != nil || len(deleted) > 0 {
		t.Fatalf("directory delete must be refused before any repository or dashboard delete\n"+
			"auth=%v\nworker=%v\nsecret file=%v\nother file=%v\nsecret dashboard=%v\nother dashboard=%v\ndeleted=%v",
			authErr, processErr, hiddenStat, otherStat, hiddenGet, otherGet, deleted)
	}
}

type dashboardClients struct {
	client    *dynamicfake.FakeDynamicClient
	namespace string
	deleted   []string
}

func (c *dashboardClients) Clients(context.Context, string) (resources.ResourceClients, error) {
	return c, nil
}

func (c *dashboardClients) ForResource(_ context.Context, gvr schema.GroupVersionResource) (dynamic.ResourceInterface, schema.GroupVersionKind, error) {
	if gvr.Group != resources.DashboardResource.Group || gvr.Resource != resources.DashboardResource.Resource {
		return nil, schema.GroupVersionKind{}, fmt.Errorf("unexpected resource %s/%s", gvr.Group, gvr.Resource)
	}
	return &recordingDeleter{
		ResourceInterface: c.client.Resource(resources.DashboardResource).Namespace(c.namespace),
		deleted:           &c.deleted,
	}, resources.DashboardKind, nil
}

func (c *dashboardClients) ForKind(ctx context.Context, gvk schema.GroupVersionKind) (dynamic.ResourceInterface, schema.GroupVersionResource, error) {
	if gvk.Group != resources.DashboardKind.Group || gvk.Kind != resources.DashboardKind.Kind {
		return nil, schema.GroupVersionResource{}, fmt.Errorf("unexpected kind %s/%s", gvk.Group, gvk.Kind)
	}
	client, _, err := c.ForResource(ctx, resources.DashboardResource)
	return client, resources.DashboardResource, err
}

func (c *dashboardClients) Folder(context.Context) (dynamic.ResourceInterface, schema.GroupVersionKind, error) {
	return nil, schema.GroupVersionKind{}, fmt.Errorf("folder client is not used")
}

func (c *dashboardClients) User(context.Context) (dynamic.ResourceInterface, error) {
	return nil, fmt.Errorf("user client is not used")
}

func (c *dashboardClients) SupportedResources() []resources.SupportedResource {
	return resources.SupportedProvisioningResources
}

type recordingDeleter struct {
	dynamic.ResourceInterface
	deleted *[]string
}

func (d *recordingDeleter) Delete(ctx context.Context, name string, options metav1.DeleteOptions, subresources ...string) error {
	*d.deleted = append(*d.deleted, name)
	return d.ResourceInterface.Delete(ctx, name, options, subresources...)
}

func newDashboardClient(namespace, hidden, other string) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(),
		dashboardObject(namespace, hidden),
		dashboardObject(namespace, other),
	)
}

func dashboardObject(namespace, name string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(resources.DashboardKind)
	obj.SetNamespace(namespace)
	obj.SetName(name)
	return obj
}

type listingResourcesFactory struct {
	items []provisioning.ResourceListItem
}

func (f *listingResourcesFactory) Client(context.Context, repository.ReaderWriter, ...resources.RepositoryResourcesOption) (resources.RepositoryResources, error) {
	return &listingResources{items: f.items}, nil
}

type listingResources struct {
	items []provisioning.ResourceListItem
}

func (l *listingResources) List(context.Context) (*provisioning.ResourceList, error) {
	return &provisioning.ResourceList{Items: append([]provisioning.ResourceListItem(nil), l.items...)}, nil
}

func (l *listingResources) Stats(context.Context) (*provisioning.ResourceStats, error) {
	return &provisioning.ResourceStats{}, nil
}

func (l *listingResources) SetTree(resources.FolderTree) {}

func (l *listingResources) EnsureFolderExists(context.Context, resources.Folder, string) error {
	return nil
}

func (l *listingResources) EnsureFolderPathExist(context.Context, string, string, ...resources.EnsurePathOption) (string, error) {
	return "", fmt.Errorf("not used")
}

func (l *listingResources) EnsureFolderTreeExists(context.Context, resources.FolderTree, resources.EnsureFolderTreeExistsOptions) error {
	return fmt.Errorf("not used")
}

func (l *listingResources) RemoveFolderFromTree(string) {}

func (l *listingResources) RemoveFolder(context.Context, string) error {
	return fmt.Errorf("not used")
}

func (l *listingResources) RenameFolderPath(context.Context, string, string, string, string, ...resources.EnsurePathOption) (string, error) {
	return "", fmt.Errorf("not used")
}

func (l *listingResources) WriteResourceFileFromObject(context.Context, *unstructured.Unstructured, resources.WriteOptions) (string, int, error) {
	return "", 0, fmt.Errorf("not used")
}

func (l *listingResources) WriteResourceFromFile(context.Context, string, string, ...resources.WriteResourceOption) (string, schema.GroupVersionKind, int, error) {
	return "", schema.GroupVersionKind{}, 0, fmt.Errorf("not used")
}

func (l *listingResources) ReplaceResourceFromFile(context.Context, string, string, string, schema.GroupVersionResource, ...resources.WriteResourceOption) (string, schema.GroupVersionKind, int, error) {
	return "", schema.GroupVersionKind{}, 0, fmt.Errorf("not used")
}

func (l *listingResources) ReplaceResourceFromFileByRef(context.Context, string, string, string, ...resources.WriteResourceOption) (string, schema.GroupVersionKind, int, error) {
	return "", schema.GroupVersionKind{}, 0, fmt.Errorf("not used")
}

func (l *listingResources) RemoveResourceFromFile(context.Context, string, string) (string, string, schema.GroupVersionKind, int, error) {
	return "", "", schema.GroupVersionKind{}, 0, fmt.Errorf("not used")
}

func (l *listingResources) FindResourcePath(context.Context, string, schema.GroupVersionKind) (string, error) {
	return "", fmt.Errorf("not used")
}

func (l *listingResources) RenameResourceFile(context.Context, string, string, string, string, ...resources.EnsurePathOption) (string, string, schema.GroupVersionKind, int, error) {
	return "", "", schema.GroupVersionKind{}, 0, fmt.Errorf("not used")
}
