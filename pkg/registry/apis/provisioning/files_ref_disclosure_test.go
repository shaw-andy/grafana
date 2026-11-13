package provisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	authlib "github.com/grafana/authlib/types"
	"github.com/grafana/grafana-app-sdk/logging"
	dashboardv0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/apis/auth"
	provisioningapi "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/git"
	githubrepo "github.com/grafana/grafana/apps/provisioning/pkg/repository/github"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/local"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/resources"
)

// placeholderToken is the repository credential the git server accepts.
// It is a test placeholder, not a real credential.
const placeholderToken = "placeholder-token"

const (
	configuredBranch = "main"
	otherBranch      = "develop"
	releaseBranch    = "release/2026"
	repoPathPrefix   = "grafana"

	syncedMarker      = "synced-only-target"
	unpublishedPromQL = "unpublished-promql-expr"
	unpublishedNote   = "unpublished-markdown-note"
	unpublishedYAML   = "unpublished-yaml-query"
	unpublishedSecret = "unpublished-secret-dashboard"
	releaseOnlyNote   = "release-only-note"
	outsidePrefixMark = "outside-prefix-secret"
	secretDashboard   = "secret-dashboard.json"
)

// TestFilesRouteAllowsAnyAuthenticatedCaller records the route gate the files
// subresource uses: the authorizer allows the request before the connector
// runs, for every caller. Viewers are not rejected here.
func TestFilesRouteAllowsAnyAuthenticatedCaller(t *testing.T) {
	b := &APIBuilder{}
	decision, _, err := b.authorizeRepositorySubresource(context.Background(), authorizer.AttributesRecord{
		Subresource: "files",
		Verb:        "get",
		Name:        "git-sync-repo",
		Namespace:   "default",
	})
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision)
}

// TestFilesRefIsLimitedToConfiguredBranch is the spec for who may read a git
// ref other than the repository's configured branch through the files API.
//
// Callers who only have repository read access (the Viewer role) may use an
// empty ref or the configured branch. Every other branch name and every commit
// id must be rejected before the git client is called. Editors and admins, who
// can already call the refs API, may still read other branches and commit ids.
// The body of an allowed read is the file at that ref. A rejection must not
// create or delete a file, and must not ask the git server for the refused ref.
func TestFilesRefIsLimitedToConfiguredBranch(t *testing.T) {
	server := startRecordingGitServer(t)
	shas := seedRemote(t, server.projectRoot)

	metrics := repository.RegisterOperationMetrics(prometheus.NewRegistry())
	decrypter := repository.ProvideDecrypter(nil, nil)
	gitRepo := buildGitRepo(t, server.gitURL(), decrypter, metrics, placeholderToken)
	githubRepo := buildGitHubRepo(t, server.githubURL(), decrypter, metrics, placeholderToken)

	viewer := filesCaller(t, identity.RoleViewer, gitRepo)
	editor := filesCaller(t, identity.RoleEditor, gitRepo)
	admin := filesCaller(t, identity.RoleAdmin, gitRepo)
	githubViewer := filesCaller(t, identity.RoleViewer, githubRepo)
	githubEditor := filesCaller(t, identity.RoleEditor, githubRepo)

	t.Run("viewer lists and reads the configured branch", func(t *testing.T) {
		for _, ref := range []string{"", configuredBranch} {
			t.Run("ref="+refLabel(ref), func(t *testing.T) {
				body := viewer.get(t, "", ref)
				require.Contains(t, body, "overview.json")
				require.Contains(t, body, "notes.md")
				require.Contains(t, body, "board.yaml")
				require.NotContains(t, body, secretDashboard)
				require.NotContains(t, body, outsidePrefixMark)
				require.NotContains(t, body, unpublishedPromQL)

				dash := viewer.get(t, "overview.json", ref)
				require.Contains(t, dash, syncedMarker)
				require.NotContains(t, dash, unpublishedPromQL)

				note := viewer.get(t, "notes.md", ref)
				require.Contains(t, note, "synced note")
				require.NotContains(t, note, unpublishedNote)

				yamlBody := viewer.get(t, "board.yaml", ref)
				require.Contains(t, yamlBody, "synced-yaml-query")
				require.NotContains(t, yamlBody, unpublishedYAML)
			})
		}
	})

	t.Run("viewer cannot read another branch or commit", func(t *testing.T) {
		refs := []string{
			otherBranch,
			releaseBranch,
			shas.develop,
			shas.release,
			shas.main,
			shas.develop[:7],
			"not-the-sync-branch",
		}
		for _, ref := range refs {
			t.Run(ref, func(t *testing.T) {
				before := server.count()
				viewer.reject(t, server, before, "", ref)
				viewer.reject(t, server, server.count(), "overview.json", ref)
				viewer.reject(t, server, server.count(), "notes.md", ref)
				viewer.reject(t, server, server.count(), "board.yaml", ref)
				viewer.reject(t, server, server.count(), secretDashboard, ref)
			})
		}
	})

	t.Run("editor and admin can read another branch and its commit", func(t *testing.T) {
		for _, caller := range []filesFixture{editor, admin} {
			t.Run(string(caller.role), func(t *testing.T) {
				listed := caller.get(t, "", otherBranch)
				require.Contains(t, listed, secretDashboard)
				require.NotContains(t, listed, outsidePrefixMark)

				dash := caller.get(t, "overview.json", otherBranch)
				require.Contains(t, dash, unpublishedPromQL)
				require.NotContains(t, dash, syncedMarker)

				note := caller.get(t, "notes.md", otherBranch)
				require.Contains(t, note, unpublishedNote)

				yamlBody := caller.get(t, "board.yaml", otherBranch)
				require.Contains(t, yamlBody, unpublishedYAML)

				secret := caller.get(t, secretDashboard, shas.develop)
				require.Contains(t, secret, unpublishedSecret)

				release := caller.get(t, "notes.md", releaseBranch)
				require.Contains(t, release, releaseOnlyNote)
			})
		}
	})

	t.Run("github repositories use the same ref rule", func(t *testing.T) {
		before := server.count()
		githubViewer.reject(t, server, before, "", otherBranch)
		githubViewer.reject(t, server, server.count(), "notes.md", otherBranch)
		githubViewer.reject(t, server, server.count(), "overview.json", shas.develop)

		note := githubEditor.get(t, "notes.md", otherBranch)
		require.Contains(t, note, unpublishedNote)
		secret := githubEditor.get(t, secretDashboard, shas.develop)
		require.Contains(t, secret, unpublishedSecret)
	})

	t.Run("a wrong stored token cannot read the other branch", func(t *testing.T) {
		wrong := buildGitRepo(t, server.gitURL(), decrypter, metrics, "wrong-placeholder")
		caller := filesCaller(t, identity.RoleEditor, wrong)
		responder := caller.do(t, http.MethodGet, "notes.md", otherBranch)
		require.Error(t, responder.err)
		if responder.object != nil {
			require.NotContains(t, mustJSON(t, responder.object), unpublishedNote)
		}
	})

	t.Run("viewer writes do not change the other branch", func(t *testing.T) {
		before := server.count()
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			responder := viewer.do(t, method, "overview.json", otherBranch)
			require.Error(t, responder.err, method)
			if responder.object != nil {
				require.NotContains(t, mustJSON(t, responder.object), unpublishedPromQL)
			}
		}
		for _, ex := range server.since(before) {
			require.NotContains(t, ex.Path, "git-receive-pack", "a refused write must not push")
			require.NotContains(t, ex.Body, "refs/heads/"+otherBranch)
		}
		note := editor.get(t, "notes.md", otherBranch)
		require.Contains(t, note, unpublishedNote)
	})

	t.Run("local repositories reject a ref", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.md"), []byte("local synced note"), 0o600))
		cfg := repositoryConfig(provisioningapi.LocalRepositoryType)
		cfg.Spec.Local = &provisioningapi.LocalRepositoryConfig{Path: dir}
		resolver := &local.LocalFolderResolver{PermittedPrefixes: []string{dir}, HomePath: dir}
		repo := local.NewRepository(cfg, resolver, metrics)
		caller := filesCaller(t, identity.RoleViewer, repo)
		responder := caller.do(t, http.MethodGet, "notes.md", otherBranch)
		require.Error(t, responder.err)
		require.True(t, apierrors.IsBadRequest(responder.err), "got %v", responder.err)
		if responder.object != nil {
			require.NotContains(t, mustJSON(t, responder.object), "local synced note")
		}
		ok := caller.get(t, "notes.md", "")
		require.Contains(t, ok, "local synced note")
	})
}

type commitSHAs struct {
	main    string
	develop string
	release string
}

type filesFixture struct {
	role      identity.RoleType
	connector *filesConnector
	repoName  string
}

func filesCaller(t *testing.T, role identity.RoleType, repo repository.Repository) filesFixture {
	t.Helper()
	base := auth.NewSessionAccessChecker(fixedRoleAccess{})
	access := auth.NewVerbAwareAccessChecker(
		base.WithFallbackRole(identity.RoleViewer),
		base.WithFallbackRole(identity.RoleEditor),
	)
	clients := &dashboardClients{dyn: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())}
	connector := NewFilesConnector(
		&fakeRepoGetter{repo: repo},
		resources.NewParserFactory(&staticClientFactory{clients: clients}, false),
		&staticClientFactory{clients: clients},
		access,
		false,
		0,
	)
	return filesFixture{role: role, connector: connector, repoName: repo.Config().Name}
}

func (f filesFixture) get(t *testing.T, path, ref string) string {
	t.Helper()
	responder := f.do(t, http.MethodGet, path, ref)
	require.NoError(t, responder.err, "GET %s ref=%q", path, ref)
	require.NotNil(t, responder.object)
	return mustJSON(t, responder.object)
}

// reject fails the test when a read-only caller can see another ref, or when
// the handler asks the git server for it before refusing.
func (f filesFixture) reject(t *testing.T, server *recordingGitServer, before int, path, ref string) {
	t.Helper()
	responder := f.do(t, http.MethodGet, path, ref)
	require.Error(t, responder.err, "GET %s ref=%q must be rejected", path, ref)
	status, ok := responder.err.(apierrors.APIStatus)
	require.True(t, ok, "rejection must be an API status, got %T (%v)", responder.err, responder.err)
	code := status.Status().Code
	require.Contains(t, []int32{http.StatusBadRequest, http.StatusForbidden}, code, "status for ref %q", ref)
	combined := responder.err.Error()
	if responder.object != nil {
		combined += mustJSON(t, responder.object)
	}
	for _, marker := range []string{unpublishedPromQL, unpublishedNote, unpublishedYAML, unpublishedSecret, releaseOnlyNote, secretDashboard} {
		require.NotContains(t, combined, marker, "rejected response still contains %s", marker)
	}
	seen := server.since(before)
	require.Empty(t, seen, "git was called while rejecting ref %q: %+v", ref, exchangePaths(seen))
}

func (f filesFixture) do(t *testing.T, method, path, ref string) *fakeResponder {
	t.Helper()
	u := "/" + f.repoName + "/files/" + path
	if ref != "" {
		q := url.Values{}
		q.Set("ref", ref)
		u += "?" + q.Encode()
	}
	var body io.Reader
	if method == http.MethodPost || method == http.MethodPut {
		body = strings.NewReader(`{"uid":"viewer-write","title":"nope","tags":[],"schemaVersion":39,"panels":[]}`)
	}
	req := httptest.NewRequest(method, u, body)
	ctx := identity.WithRequester(context.Background(), &identity.StaticRequester{
		Type:      authlib.TypeUser,
		UserID:    7,
		UserUID:   "user-" + string(f.role),
		OrgID:     1,
		OrgRole:   f.role,
		Login:     string(f.role),
		Namespace: "default",
	})
	responder := &fakeResponder{}
	logger := logging.NewSLogLogger(slog.NewTextHandler(io.Discard, nil))
	f.connector.handleRequest(ctx, f.repoName, req, responder, logger)
	return responder
}

func refLabel(ref string) string {
	if ref == "" {
		return "empty"
	}
	return ref
}

func mustJSON(t *testing.T, obj runtime.Object) string {
	t.Helper()
	raw, err := json.Marshal(obj)
	require.NoError(t, err)
	return string(raw)
}

func exchangePaths(exchanges []gitExchange) []string {
	out := make([]string, 0, len(exchanges))
	for _, ex := range exchanges {
		out = append(out, ex.Method+" "+ex.Path+"?"+ex.Query)
	}
	return out
}

// fixedRoleAccess grants the provisioning fixed roles from accesscontrol.go,
// plus the default org-role grants a Viewer has on folders and dashboards.
// Verb-to-action mapping matches pkg/services/authz/rbac/mapper.go
// newResourceTranslation: get/list/watch -> :read, create -> :create,
// update/patch -> :write.
type fixedRoleAccess struct{}

func (fixedRoleAccess) Check(_ context.Context, info authlib.AuthInfo, req authlib.CheckRequest, _ string) (authlib.CheckResponse, error) {
	role := identity.RoleNone
	if requester, ok := info.(identity.Requester); ok {
		role = requester.GetOrgRole()
	}
	if fixedRoleAllows(role, req) {
		return authlib.CheckResponse{Allowed: true}, nil
	}
	return authlib.CheckResponse{Allowed: false}, nil
}

func fixedRoleAllows(role identity.RoleType, req authlib.CheckRequest) bool {
	resource, ok := rbacResource(req)
	if !ok {
		return false
	}
	action := resource + ":" + rbacVerb(req.Verb)
	if role.Includes(identity.RoleViewer) && (action == "provisioning.repositories:read" ||
		action == "provisioning.settings:read" ||
		action == "dashboards:read" ||
		action == "folders:read") {
		return true
	}
	if role.Includes(identity.RoleEditor) && strings.HasPrefix(action, "provisioning.jobs:") {
		return true
	}
	if role.Includes(identity.RoleAdmin) && (strings.HasPrefix(action, "provisioning.repositories:") ||
		strings.HasPrefix(action, "provisioning.connections:") ||
		action == "provisioning.historicjobs:read" ||
		action == "provisioning.stats:read") {
		return true
	}
	return false
}

func rbacResource(req authlib.CheckRequest) (string, bool) {
	switch req.Group {
	case provisioningapi.GROUP:
		switch req.Resource {
		case "repositories":
			return "provisioning.repositories", true
		case "jobs":
			return "provisioning.jobs", true
		case "settings":
			return "provisioning.settings", true
		case "connections":
			return "provisioning.connections", true
		case "historicjobs":
			return "provisioning.historicjobs", true
		case "stats":
			return "provisioning.stats", true
		}
	case dashboardv0.GROUP:
		if req.Resource == "dashboards" {
			return "dashboards", true
		}
	case resources.FolderKind.Group:
		if req.Resource == resources.FolderKind.Kind || req.Resource == "folders" {
			return "folders", true
		}
	}
	return "", false
}

func rbacVerb(verb string) string {
	switch verb {
	case utils.VerbGet, utils.VerbList, utils.VerbWatch:
		return "read"
	case utils.VerbCreate:
		return "create"
	case utils.VerbUpdate, utils.VerbPatch:
		return "write"
	case utils.VerbDelete, utils.VerbDeleteCollection:
		return "delete"
	default:
		return verb
	}
}

type staticClientFactory struct {
	clients resources.ResourceClients
}

func (f *staticClientFactory) Clients(context.Context, string) (resources.ResourceClients, error) {
	return f.clients, nil
}

// dashboardClients is the dry-run gate in front of the real parser. DryRun
// calls Get and then Create with DryRun=All; the fake apiserver echoes the
// parsed object so a successful parse is returned to the caller. The file
// bytes themselves come from the git read, not from this client.
type dashboardClients struct {
	dyn dynamic.Interface
}

func (c *dashboardClients) ForKind(_ context.Context, gvk schema.GroupVersionKind) (dynamic.ResourceInterface, schema.GroupVersionResource, error) {
	gvr := dashboardv0.DashboardResourceInfo.GroupVersionResource()
	if gvk.Group != "" && gvk.Group != gvr.Group {
		return nil, schema.GroupVersionResource{}, fmt.Errorf("unsupported kind %s", gvk.String())
	}
	return c.dyn.Resource(gvr).Namespace("default"), gvr, nil
}

func (c *dashboardClients) ForResource(context.Context, schema.GroupVersionResource) (dynamic.ResourceInterface, schema.GroupVersionKind, error) {
	return nil, schema.GroupVersionKind{}, fmt.Errorf("not used")
}

func (c *dashboardClients) Folder(context.Context) (dynamic.ResourceInterface, schema.GroupVersionKind, error) {
	gvr := resources.FolderResource
	return c.dyn.Resource(gvr).Namespace("default"), resources.FolderKind, nil
}

func (c *dashboardClients) User(context.Context) (dynamic.ResourceInterface, error) {
	return nil, fmt.Errorf("not used")
}

func (c *dashboardClients) SupportedResources() []resources.SupportedResource {
	return resources.SupportedProvisioningResources
}

func buildGitRepo(t *testing.T, rawURL string, decrypter repository.Decrypter, metrics *repository.OperationMetrics, token string) repository.Repository {
	t.Helper()
	cfg := repositoryConfig(provisioningapi.GitRepositoryType)
	cfg.Spec.Git = &provisioningapi.GitRepositoryConfig{
		URL:       rawURL,
		Branch:    configuredBranch,
		Path:      repoPathPrefix,
		TokenUser: "git",
	}
	cfg.Secure.Token = common.InlineSecureValue{Create: common.RawSecureValue(token)}
	repo, err := git.Extra(decrypter, true, metrics, nil).Build(context.Background(), cfg)
	require.NoError(t, err)
	return repo
}

func buildGitHubRepo(t *testing.T, rawURL string, decrypter repository.Decrypter, metrics *repository.OperationMetrics, token string) repository.Repository {
	t.Helper()
	cfg := repositoryConfig(provisioningapi.GitHubRepositoryType)
	cfg.Spec.GitHub = &provisioningapi.GitHubRepositoryConfig{
		URL:    rawURL,
		Branch: configuredBranch,
		Path:   repoPathPrefix,
	}
	cfg.Secure.Token = common.InlineSecureValue{Create: common.RawSecureValue(token)}
	repo, err := githubrepo.Extra(decrypter, githubrepo.ProvideFactory(), nil, true, metrics, nil).Build(context.Background(), cfg)
	require.NoError(t, err)
	return repo
}

func repositoryConfig(kind provisioningapi.RepositoryType) *provisioningapi.Repository {
	return &provisioningapi.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: "git-sync-repo", Namespace: "default"},
		Spec: provisioningapi.RepositorySpec{
			Title: "Git Sync",
			Type:  kind,
			Sync: provisioningapi.SyncOptions{
				Enabled: true,
				Target:  provisioningapi.SyncTargetTypeFolder,
			},
			Workflows: []provisioningapi.Workflow{provisioningapi.WriteWorkflow, provisioningapi.BranchWorkflow},
		},
	}
}

func seedRemote(t *testing.T, root string) commitSHAs {
	t.Helper()
	work := filepath.Join(t.TempDir(), "work")
	bare := filepath.Join(root, "gitsync", "project.git")
	require.NoError(t, os.MkdirAll(filepath.Dir(bare), 0o750))
	runGit(t, "", "init", "--bare", bare)
	runGit(t, bare, "config", "uploadpack.allowReachableSHA1InWant", "true")
	runGit(t, bare, "config", "uploadpack.allowAnySHA1InWant", "true")
	runGit(t, bare, "config", "uploadpack.allowFilter", "true")
	runGit(t, bare, "config", "http.receivepack", "true")

	runGit(t, "", "init", "--initial-branch=main", work)
	writeRepoFile(t, work, "grafana/overview.json", classicDashboard("synced-dash", "Synced", syncedMarker))
	writeRepoFile(t, work, "grafana/notes.md", "synced note\n")
	writeRepoFile(t, work, "grafana/board.yaml", k8sDashboard("yaml-board", "Synced YAML", "synced-yaml-query"))
	writeRepoFile(t, work, "hidden/outside.txt", outsidePrefixMark+"\n")
	runGit(t, work, "add", "-A")
	runGit(t, work, "commit", "-m", "sync main")

	runGit(t, work, "checkout", "-b", otherBranch)
	writeRepoFile(t, work, "grafana/overview.json", classicDashboard("synced-dash", "Unpublished", unpublishedPromQL))
	writeRepoFile(t, work, "grafana/notes.md", unpublishedNote+"\n")
	writeRepoFile(t, work, "grafana/board.yaml", k8sDashboard("yaml-board", "Unpublished YAML", unpublishedYAML))
	writeRepoFile(t, work, "grafana/secret-dashboard.json", classicDashboard("secret-dash", "Secret", unpublishedSecret))
	runGit(t, work, "add", "-A")
	runGit(t, work, "commit", "-m", "unpublished develop")

	runGit(t, work, "checkout", "-b", releaseBranch)
	writeRepoFile(t, work, "grafana/notes.md", releaseOnlyNote+"\n")
	runGit(t, work, "add", "-A")
	runGit(t, work, "commit", "-m", "release notes")

	runGit(t, work, "remote", "add", "origin", bare)
	runGit(t, work, "push", "origin", configuredBranch, otherBranch, releaseBranch)

	return commitSHAs{
		main:    strings.TrimSpace(runGit(t, work, "rev-parse", configuredBranch)),
		develop: strings.TrimSpace(runGit(t, work, "rev-parse", otherBranch)),
		release: strings.TrimSpace(runGit(t, work, "rev-parse", releaseBranch)),
	}
}

func classicDashboard(uid, title, panel string) string {
	return fmt.Sprintf(`{
		"uid": %q,
		"title": %q,
		"tags": [],
		"schemaVersion": 39,
		"panels": [{"title": %q, "targets": [{"expr": %q}]}]
	}`, uid, title, panel, panel)
}

func k8sDashboard(name, title, panel string) string {
	return fmt.Sprintf(`apiVersion: dashboard.grafana.app/v0alpha1
kind: Dashboard
metadata:
  name: %s
spec:
  title: %s
  tags: []
  schemaVersion: 39
  panels:
    - title: %s
      targets:
        - expr: %s
`, name, title, panel, panel)
}

func writeRepoFile(t *testing.T, root, rel, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmdArgs := []string{
		"-c", "user.email=grafana-test@example.com",
		"-c", "user.name=grafana-test",
	}
	if dir != "" {
		cmdArgs = append(cmdArgs, "-C", dir)
	}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("git", cmdArgs...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %s\n%s", strings.Join(args, " "), out)
	return string(out)
}

type gitExchange struct {
	Method     string
	Path       string
	Query      string
	Body       string
	Authorized bool
}

// recordingGitServer is git's http-backend. It accepts only the repository
// placeholder credential and records every request, including ones it rejects.
type recordingGitServer struct {
	projectRoot string
	url         string

	mu        sync.Mutex
	exchanges []gitExchange
}

func startRecordingGitServer(t *testing.T) *recordingGitServer {
	t.Helper()
	backend, err := exec.LookPath("git-http-backend")
	if err != nil {
		backend = "/usr/lib/git-core/git-http-backend"
	}
	server := &recordingGitServer{projectRoot: t.TempDir()}
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		user, pass, ok := r.BasicAuth()
		authorized := ok && user == "git" && pass == placeholderToken
		server.mu.Lock()
		server.exchanges = append(server.exchanges, gitExchange{
			Method:     r.Method,
			Path:       r.URL.Path,
			Query:      r.URL.RawQuery,
			Body:       string(body),
			Authorized: authorized,
		})
		server.mu.Unlock()
		if !authorized {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		serveGitCGI(w, r, backend, server.projectRoot, body)
	}))
	t.Cleanup(httpServer.Close)
	server.url = httpServer.URL
	return server
}

func (s *recordingGitServer) gitURL() string {
	return s.url + "/gitsync/project.git"
}

func (s *recordingGitServer) githubURL() string {
	return s.url + "/gitsync/project"
}

func (s *recordingGitServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.exchanges)
}

func (s *recordingGitServer) since(n int) []gitExchange {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > len(s.exchanges) {
		n = len(s.exchanges)
	}
	out := make([]gitExchange, len(s.exchanges)-n)
	copy(out, s.exchanges[n:])
	return out
}

func serveGitCGI(w http.ResponseWriter, r *http.Request, backend, root string, body []byte) {
	cmd := exec.Command(backend)
	cmd.Env = append(os.Environ(),
		"GIT_PROJECT_ROOT="+root,
		"GIT_HTTP_EXPORT_ALL=1",
		"REQUEST_METHOD="+r.Method,
		"PATH_INFO="+r.URL.Path,
		"QUERY_STRING="+r.URL.RawQuery,
		"CONTENT_TYPE="+r.Header.Get("Content-Type"),
		fmt.Sprintf("CONTENT_LENGTH=%d", len(body)),
		"REMOTE_USER=git",
		"AUTH_TYPE=Basic",
		"GIT_TERMINAL_PROMPT=0",
		// CGI exposes the Git-Protocol request header as HTTP_GIT_PROTOCOL.
		// nanogit sends version=2; without it upload-pack does not answer ls-refs.
		"HTTP_GIT_PROTOCOL="+r.Header.Get("Git-Protocol"),
	)
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil && stdout.Len() == 0 {
		http.Error(w, strings.TrimSpace(stderr.String()), http.StatusBadGateway)
		return
	}
	writeCGI(w, stdout.Bytes())
}

func writeCGI(w http.ResponseWriter, raw []byte) {
	sep := []byte("\r\n\r\n")
	headerEnd := bytes.Index(raw, sep)
	width := 4
	if headerEnd < 0 {
		sep = []byte("\n\n")
		headerEnd = bytes.Index(raw, sep)
		width = 2
	}
	if headerEnd < 0 {
		http.Error(w, "git response", http.StatusBadGateway)
		return
	}
	status := http.StatusOK
	for _, line := range bytes.Split(raw[:headerEnd], []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		key, val, found := bytes.Cut(line, []byte(":"))
		if !found {
			continue
		}
		name := strings.TrimSpace(string(key))
		value := strings.TrimSpace(string(val))
		if strings.EqualFold(name, "Status") {
			_, _ = fmt.Sscanf(value, "%d", &status)
			continue
		}
		w.Header().Add(name, value)
	}
	w.WriteHeader(status)
	_, _ = w.Write(raw[headerEnd+width:])
}
