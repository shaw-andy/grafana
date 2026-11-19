package pullrequest

import (
	"context"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/client-go/dynamic"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	grafanaregistry "github.com/grafana/grafana/pkg/apiserver/registry/generic"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/resources"
)

// linkName is a Kubernetes name a pull-request author can put in dashboard
// metadata. It is not a path segment (it contains '/'), and it is also a
// Markdown link. imageName is the same trick with an image.
const (
	linkName  = "[click](https://evil.example/phish)"
	imageName = "![pixel](https://evil.example/pixel.png)"
)

// TestPullRequestCommentDoesNotRenderUntrustedDryRunErrorsAsMarkdown follows
// the Git Sync preview path: a repository file is parsed, dry-run through the
// same name check the dashboard apiserver runs before admission, and the
// resulting error is rendered into the pull-request comment.
//
// The comment is posted as a GitHub issue comment body. These tests fail while
// that body still contains the attacker's Markdown link or image outside a
// fenced code block.
func TestPullRequestCommentDoesNotRenderUntrustedDryRunErrorsAsMarkdown(t *testing.T) {
	t.Run("single dashboard resource", func(t *testing.T) {
		comment := renderPreviewComment(t, []previewFile{{
			path:   "overview.json",
			action: repository.FileActionCreated,
			data:   dashboardResource(linkName, "Overview"),
		}})
		assertUntrustedErrorIsNotMarkdown(t, comment, linkName)
		require.Contains(t, comment, "Validation failed")
	})

	t.Run("single classic dashboard", func(t *testing.T) {
		comment := renderPreviewComment(t, []previewFile{{
			path:   "classic.json",
			action: repository.FileActionCreated,
			data:   classicDashboard(linkName, "Classic"),
		}})
		assertUntrustedErrorIsNotMarkdown(t, comment, linkName)
		require.Contains(t, comment, "Validation failed")
	})

	t.Run("single dashboard image", func(t *testing.T) {
		comment := renderPreviewComment(t, []previewFile{{
			path:   "image.json",
			action: repository.FileActionCreated,
			data:   dashboardResource(imageName, "Image"),
		}})
		assertUntrustedErrorIsNotMarkdown(t, comment, imageName)
		require.Contains(t, comment, "Validation failed")
	})

	t.Run("validation table for several files", func(t *testing.T) {
		comment := renderPreviewComment(t, []previewFile{
			{
				path:   "evil.json",
				action: repository.FileActionCreated,
				data:   dashboardResource(linkName, "Evil"),
			},
			{
				path:   "ok.json",
				action: repository.FileActionCreated,
				data:   dashboardResource("ok-dashboard", "Ok"),
			},
		})
		assertUntrustedErrorIsNotMarkdown(t, comment, linkName)
		require.Contains(t, comment, "Validation Issues")
		// The safe file is still identified. Its own name is a valid path
		// segment, so it must not be rejected by the name check.
		require.Contains(t, comment, "ok.json")
		require.NotContains(t, comment, "ok-dashboard is invalid")
	})

	t.Run("validation table image", func(t *testing.T) {
		comment := renderPreviewComment(t, []previewFile{
			{
				path:   "pixel.json",
				action: repository.FileActionCreated,
				data:   dashboardResource(imageName, "Pixel"),
			},
			{
				path:   "other.json",
				action: repository.FileActionCreated,
				data:   classicDashboard("other-dashboard", "Other"),
			},
		})
		assertUntrustedErrorIsNotMarkdown(t, comment, imageName)
		require.Contains(t, comment, "Validation Issues")
	})
}

// previewFile is one changed file in the pull request, as Read would return
// it after loading the blob from the pull-request head.
type previewFile struct {
	path   string
	action repository.FileAction
	data   []byte
}

func renderPreviewComment(t *testing.T, files []previewFile) string {
	t.Helper()

	reader := repository.NewMockReader(t)
	reader.On("Config").Return(&provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: "test-repo", Namespace: "stacks-123"},
		Spec: provisioning.RepositorySpec{
			Title: "Test Repo",
			Type:  provisioning.GitHubRepositoryType,
			Sync:  provisioning.SyncOptions{Target: provisioning.SyncTargetTypeInstance},
		},
	})
	for _, file := range files {
		info := &repository.FileInfo{Path: file.path, Ref: "refs/heads/pr", Data: file.data}
		reader.On("Read", mock.Anything, file.path, "refs/heads/pr").Return(info, nil).Once()
	}

	client := &apiserverNameClient{}
	clients := resources.NewMockResourceClients(t)
	clients.On("ForKind", mock.Anything, mock.Anything).Return(client, resources.DashboardResource, nil)
	clients.On("SupportedResources").Return(resources.SupportedProvisioningResources)
	factory := resources.NewMockClientFactory(t)
	factory.On("Clients", mock.Anything, "stacks-123").Return(clients, nil)

	parsers := resources.NewParserFactory(factory, false)
	renderer := NewMockScreenshotRenderer(t)
	renderer.On("IsAvailable", mock.Anything).Return(false)
	urls := URLProvider{
		Internal: func(context.Context, string) string { return "https://grafana.example/" },
		Public:   func(context.Context, string) string { return "https://grafana.example/" },
	}
	evaluator := NewEvaluator(renderer, parsers, urls, prometheus.NewRegistry())

	progress := jobs.NewMockJobProgressRecorder(t)
	stubPreviewProgress(progress)
	progress.On("SetMessage", mock.Anything, mock.Anything).Return().Maybe()

	changes := make([]repository.VersionedFileChange, 0, len(files))
	for _, file := range files {
		changes = append(changes, repository.VersionedFileChange{
			Path:   file.path,
			Ref:    "refs/heads/pr",
			Action: file.action,
		})
	}

	info, err := evaluator.Evaluate(context.Background(), reader, provisioning.PullRequestJobOptions{
		Ref: "refs/heads/pr",
		PR:  7,
	}, changes, progress)
	require.NoError(t, err)

	var posted string
	prRepo := repository.NewMockPullRequestRepo(t)
	prRepo.On("CommentPullRequest", mock.Anything, 7, mock.Anything).Run(func(args mock.Arguments) {
		posted = args.String(2)
	}).Return(nil)
	require.NoError(t, NewCommenter(false, urls).Comment(context.Background(), prRepo, 7, info))
	return posted
}

// assertUntrustedErrorIsNotMarkdown fails when attacker-controlled text is
// still an inline Markdown link or image in the comment GitHub will render.
// A fenced code block is not rendered as a link, and escaping the brackets
// breaks the link syntax. Either fix satisfies this check.
func assertUntrustedErrorIsNotMarkdown(t *testing.T, comment, raw string) {
	t.Helper()
	visible := stripFencedCodeBlocks(comment)
	require.NotContains(t, visible, raw, "pull request comment renders untrusted dry-run text as Markdown:\n%s", comment)
}

func stripFencedCodeBlocks(s string) string {
	var b strings.Builder
	for {
		start := strings.Index(s, "```")
		if start < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:start])
		rest := s[start+3:]
		end := strings.Index(rest, "```")
		if end < 0 {
			return b.String()
		}
		s = rest[end+3:]
	}
}

func dashboardResource(name, title string) []byte {
	return []byte(`{
  "apiVersion": "dashboard.grafana.app/v0alpha1",
  "kind": "Dashboard",
  "metadata": {"name": ` + jsonString(name) + `},
  "spec": {"title": ` + jsonString(title) + `, "schemaVersion": 39}
}`)
}

func classicDashboard(uid, title string) []byte {
	return []byte(`{
  "uid": ` + jsonString(uid) + `,
  "title": ` + jsonString(title) + `,
  "schemaVersion": 39,
  "panels": [],
  "tags": []
}`)
}

func jsonString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// apiserverNameClient is the dashboard create handler's name check.
//
// handlers/create.go runs mutating admission (which does not rewrite
// metadata.name) and then registry.Store.create. That calls rest.BeforeCreate
// before validating admission. The dashboard strategy's Validate returns no
// field errors, so BeforeCreate rejects a name that is not a safe path segment
// and apierrors.NewInvalid quotes the name into the status message.
type apiserverNameClient struct{}

var _ dynamic.ResourceInterface = (*apiserverNameClient)(nil)

func (c *apiserverNameClient) Create(ctx context.Context, obj *unstructured.Unstructured, _ metav1.CreateOptions, _ ...string) (*unstructured.Unstructured, error) {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return nil, err
	}
	rest.FillObjectMetaSystemFields(accessor)
	ctx = request.WithNamespace(ctx, accessor.GetNamespace())

	gvk := obj.GroupVersionKind()
	strategy := grafanaregistry.NewStrategy(fixedGVKTyper{gvk: gvk}, gvk.GroupVersion())
	if err := rest.BeforeCreate(strategy, ctx, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

func (c *apiserverNameClient) Get(_ context.Context, name string, _ metav1.GetOptions, _ ...string) (*unstructured.Unstructured, error) {
	return nil, apierrors.NewNotFound(schema.GroupResource{Group: "dashboard.grafana.app", Resource: "dashboards"}, name)
}

func (c *apiserverNameClient) Update(context.Context, *unstructured.Unstructured, metav1.UpdateOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, apierrors.NewMethodNotSupported(schema.GroupResource{Resource: "dashboards"}, "update")
}
func (c *apiserverNameClient) UpdateStatus(context.Context, *unstructured.Unstructured, metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	return nil, apierrors.NewMethodNotSupported(schema.GroupResource{Resource: "dashboards"}, "update")
}
func (c *apiserverNameClient) Delete(context.Context, string, metav1.DeleteOptions, ...string) error {
	return apierrors.NewMethodNotSupported(schema.GroupResource{Resource: "dashboards"}, "delete")
}
func (c *apiserverNameClient) DeleteCollection(context.Context, metav1.DeleteOptions, metav1.ListOptions) error {
	return apierrors.NewMethodNotSupported(schema.GroupResource{Resource: "dashboards"}, "deletecollection")
}
func (c *apiserverNameClient) List(context.Context, metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return nil, apierrors.NewMethodNotSupported(schema.GroupResource{Resource: "dashboards"}, "list")
}
func (c *apiserverNameClient) Watch(context.Context, metav1.ListOptions) (watch.Interface, error) {
	return nil, apierrors.NewMethodNotSupported(schema.GroupResource{Resource: "dashboards"}, "watch")
}
func (c *apiserverNameClient) Patch(context.Context, string, types.PatchType, []byte, metav1.PatchOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, apierrors.NewMethodNotSupported(schema.GroupResource{Resource: "dashboards"}, "patch")
}
func (c *apiserverNameClient) Apply(context.Context, string, *unstructured.Unstructured, metav1.ApplyOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, apierrors.NewMethodNotSupported(schema.GroupResource{Resource: "dashboards"}, "apply")
}
func (c *apiserverNameClient) ApplyStatus(context.Context, string, *unstructured.Unstructured, metav1.ApplyOptions) (*unstructured.Unstructured, error) {
	return nil, apierrors.NewMethodNotSupported(schema.GroupResource{Resource: "dashboards"}, "apply")
}

// fixedGVKTyper reports the object's declared GVK. The apiserver typer does
// the same for a decoded dashboard before BeforeCreate builds the status error.
type fixedGVKTyper struct {
	gvk schema.GroupVersionKind
}

func (t fixedGVKTyper) ObjectKinds(runtime.Object) ([]schema.GroupVersionKind, bool, error) {
	return []schema.GroupVersionKind{t.gvk}, false, nil
}

func (t fixedGVKTyper) Recognizes(schema.GroupVersionKind) bool { return true }
