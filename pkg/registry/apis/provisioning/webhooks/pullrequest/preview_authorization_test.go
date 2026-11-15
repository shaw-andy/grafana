package pullrequest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"

	authnlib "github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/types"
	dashboardv1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/resources"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/authz/rbac"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/rendering"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/tests/testsuite"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

const (
	previewNamespace = "org-12"
	previewRepoName  = "connected-repo"
	// previewAuthorID is the Grafana user id of the pull-request author. The job
	// itself runs as the provisioning identity, matching the job driver.
	previewAuthorID       = "42"
	previewHiddenSource   = "hidden-datasource"
	previewVictimUID      = "victim-uid"
	previewSwappedUID     = "swapped-secret"
	previewAllowedUID     = "allowed-uid"
	previewDashboardPath  = "secret.json"
	previewGrafanaBaseURL = "http://grafana.example/"
)

// TestPullRequestDashboardPreviewAuthorization locks the pull-request screenshot
// path. A changed dashboard file names a live dashboard by metadata.name. The
// job loads that dashboard as the provisioning identity, and a failed ownership
// check must not leave the live dashboard in place for a screenshot. Any
// screenshot of /d/<uid> must be of a dashboard the pull-request author can
// already view, captured by an identity that cannot read or query anything the
// author cannot. A later lookup of the same file or name must not switch the
// screenshot onto a different dashboard.
func TestPullRequestDashboardPreviewAuthorization(t *testing.T) {
	env := newPreviewEnv(t)
	env.requireRenderServiceCanReadVictim(t)

	ownedHere := manager(previewRepoName)
	ownedElsewhere := manager("other-repo")

	t.Run("unmanaged dashboard is not screenshotted after the ownership check fails", func(t *testing.T) {
		env.run(t, previewCase{
			repo:     githubRepo(true),
			file:     dashboardFile(previewVictimUID, "Secret board"),
			later:    dashboardFile(previewSwappedUID, "Swapped board"),
			firstGet: liveDashboard(previewVictimUID, "Secret board", nil),
			laterGet: liveDashboard(previewSwappedUID, "Swapped board", &ownedHere),
		})
	})

	t.Run("dashboard managed by another repository is not screenshotted", func(t *testing.T) {
		env.run(t, previewCase{
			repo:     githubRepo(true),
			file:     dashboardFile(previewVictimUID, "Secret board"),
			later:    dashboardFile(previewSwappedUID, "Swapped board"),
			firstGet: liveDashboard(previewVictimUID, "Secret board", &ownedElsewhere),
			laterGet: liveDashboard(previewSwappedUID, "Swapped board", &ownedHere),
		})
	})

	t.Run("git repository previews use the same authorization", func(t *testing.T) {
		env.run(t, previewCase{
			repo:     gitRepo(true),
			file:     dashboardFile(previewVictimUID, "Secret board"),
			later:    dashboardFile(previewSwappedUID, "Swapped board"),
			firstGet: liveDashboard(previewVictimUID, "Secret board", nil),
			laterGet: liveDashboard(previewSwappedUID, "Swapped board", &ownedHere),
		})
	})

	t.Run("dashboard this repository owns is not screenshotted for an author who cannot view it", func(t *testing.T) {
		env.run(t, previewCase{
			repo:     githubRepo(true),
			file:     dashboardFile(previewVictimUID, "Secret board"),
			later:    dashboardFile(previewSwappedUID, "Swapped board"),
			firstGet: liveDashboard(previewVictimUID, "Secret board", &ownedHere),
			laterGet: liveDashboard(previewSwappedUID, "Swapped board", &ownedElsewhere),
		})
	})

	t.Run("a later lookup cannot switch the screenshot to a dashboard the author cannot view", func(t *testing.T) {
		env.run(t, previewCase{
			repo:          githubRepo(true),
			authorCanView: []string{previewAllowedUID},
			file:          dashboardFile(previewAllowedUID, "Visible board"),
			later:         dashboardFile(previewVictimUID, "Secret board"),
			firstGet:      liveDashboard(previewAllowedUID, "Visible board", &ownedHere),
			laterGet:      liveDashboard(previewVictimUID, "Secret board", nil),
		})
	})

	t.Run("a dashboard that does not exist has no live screenshot", func(t *testing.T) {
		env.run(t, previewCase{
			repo:    githubRepo(true),
			file:    dashboardFile(previewVictimUID, "New board"),
			later:   dashboardFile(previewSwappedUID, "Swapped board"),
			missing: true,
		})
	})

	t.Run("previews stay off when the repository did not enable them", func(t *testing.T) {
		env.run(t, previewCase{
			repo:     githubRepo(false),
			file:     dashboardFile(previewVictimUID, "Secret board"),
			firstGet: liveDashboard(previewVictimUID, "Secret board", nil),
		})
	})
}

type previewCase struct {
	repo          *provisioning.Repository
	authorCanView []string
	file          []byte
	later         []byte
	firstGet      *unstructured.Unstructured
	laterGet      *unstructured.Unstructured
	missing       bool
}

type dashboardCapture struct {
	rawURL        string
	uid           string
	dashboardView bool
	subject       string
	userID        int64
	orgRole       string
	blobUID       string
	canReadSecret bool
	canQuery      bool
}

type previewEnv struct {
	t          *testing.T
	worker     *PullRequestWorker
	repo       *scriptedPullRepo
	client     *scriptedDashboardClient
	renderer   *clients.Render
	renderSvc  *rbac.Service
	adminSvc   *rbac.Service
	caller     types.AuthInfo
	blob       *scriptedBlobStore
	mu         sync.Mutex
	captures   []dashboardCapture
	pending    *dashboardCapture
	authorView map[string]bool
	forbidden  []string
}

func newPreviewEnv(t *testing.T) *previewEnv {
	t.Helper()

	env := &previewEnv{
		t: t,
		repo: &scriptedPullRepo{
			cfg: githubRepo(true),
		},
		client: &scriptedDashboardClient{},
		caller: authnlib.NewAccessTokenAuthInfo(authnlib.Claims[authnlib.AccessTokenClaims]{
			Claims: jwt.Claims{
				Subject:  types.NewTypeID(types.TypeAccessPolicy, "some-service"),
				Audience: []string{"authzservice"},
			},
			Rest: authnlib.AccessTokenClaims{Namespace: previewNamespace},
		}),
		renderSvc: rbac.NewTestService("0", nil, nil),
		adminSvc: rbac.NewTestService("1", []accesscontrol.Permission{
			{Action: dashboards.ActionDashboardsRead, Scope: "dashboards:uid:*"},
			{Action: "datasources:query", Scope: "datasources:uid:*"},
		}, nil),
	}
	env.blob = &scriptedBlobStore{env: env}

	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"version":"3.12.0"}`)
	})
	mux.HandleFunc("/", env.serveRenderer)
	rendererServer := httptest.NewServer(mux)
	t.Cleanup(rendererServer.Close)

	cfg := setting.NewCfg()
	cfg.AppURL = previewGrafanaBaseURL
	cfg.RendererCallbackUrl = previewGrafanaBaseURL
	cfg.RendererServerUrl = rendererServer.URL
	cfg.RendererRenderKeyLifeTime = 5 * time.Minute
	cfg.ImagesDir = t.TempDir()
	cfg.CSVsDir = t.TempDir()
	cfg.PDFsDir = t.TempDir()

	rs, err := rendering.ProvideService(cfg, featuremgmt.WithFeatures(), remotecache.NewFakeStore(t))
	require.NoError(t, err)
	runCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = rs.Run(runCtx)
	}()
	env.renderer = clients.ProvideRender(rs)
	env.waitUntilRendererAcceptsJobs(rs)

	urls := URLProvider{
		Internal: func(context.Context, string) string { return previewGrafanaBaseURL },
		Public:   func(context.Context, string) string { return previewGrafanaBaseURL },
	}
	reg := prometheus.NewPedanticRegistry()
	parsers := &scriptedParserFactory{repo: env.repo, client: env.client}
	evaluator := NewEvaluator(NewScreenshotRenderer(rs, env.blob), parsers, urls, reg)
	env.worker = NewPullRequestWorker(evaluator, NewCommenter(false, urls), reg)
	return env
}

func (e *previewEnv) waitUntilRendererAcceptsJobs(rs rendering.Service) {
	e.t.Helper()
	require.Eventually(e.t, func() bool {
		defer func() { _ = recover() }()
		_, err := rs.Render(context.Background(), rendering.RenderPNG, rendering.Opts{
			CommonOpts: rendering.CommonOpts{
				Path: "health",
				AuthOpts: rendering.AuthOpts{
					OrgID:   1,
					UserID:  0,
					OrgRole: identity.RoleAdmin,
				},
				TimeoutOpts: rendering.TimeoutOpts{Timeout: time.Second},
			},
			Width:  8,
			Height: 8,
		})
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)
	e.mu.Lock()
	e.captures = nil
	e.pending = nil
	e.mu.Unlock()
}

func (e *previewEnv) requireRenderServiceCanReadVictim(t *testing.T) {
	t.Helper()
	ctx := types.WithAuthInfo(context.Background(), e.caller)
	dash, err := e.renderSvc.Check(ctx, &authzv1.CheckRequest{
		Namespace: previewNamespace,
		Subject:   "render:0",
		Group:     dashboardv1.GROUP,
		Resource:  dashboardv1.DASHBOARD_RESOURCE,
		Verb:      utils.VerbGet,
		Name:      previewVictimUID,
	})
	require.NoError(t, err)
	require.True(t, dash.GetAllowed(), "render service must be able to read a dashboard it was never granted")

	query, err := e.renderSvc.Check(ctx, &authzv1.CheckRequest{
		Namespace: previewNamespace,
		Subject:   "render:0",
		Group:     "query.grafana.app",
		Resource:  "query",
		Verb:      utils.VerbCreate,
		Name:      previewHiddenSource,
	})
	require.NoError(t, err)
	require.True(t, query.GetAllowed(), "render service must be able to query datasources")
}

func (e *previewEnv) run(t *testing.T, tc previewCase) {
	t.Helper()
	e.mu.Lock()
	e.captures = nil
	e.pending = nil
	e.authorView = map[string]bool{}
	for _, uid := range tc.authorCanView {
		e.authorView[uid] = true
	}
	e.forbidden = []string{previewVictimUID, previewSwappedUID}
	e.mu.Unlock()

	e.repo.reset(tc.repo, tc.file, tc.later)
	e.client.reset(tc.firstGet, tc.laterGet, tc.missing)

	ctx, _, err := identity.WithProvisioningIdentity(context.Background(), previewNamespace)
	require.NoError(t, err)
	job := provisioning.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "preview-job", Namespace: previewNamespace},
		Spec: provisioning.JobSpec{
			Action: provisioning.JobActionPullRequest,
			PullRequest: &provisioning.PullRequestJobOptions{
				PR:  7,
				Ref: "attacker-branch",
				URL: "https://example.com/pull/7",
			},
		},
	}
	progress := jobs.NewJobProgressRecorder(func(context.Context, provisioning.JobStatus) error {
		return nil
	}, nil, provisioning.JobActionPullRequest)
	processErr := e.worker.Process(ctx, e.repo, job, progress)

	require.GreaterOrEqual(t, e.client.gets(), 1, "evaluation never loaded the dashboard named by the pull request file: %v", processErr)
	e.requireCapturesAuthorized(t)
}

func (e *previewEnv) requireCapturesAuthorized(t *testing.T) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()

	var problems []string
	for _, capture := range e.captures {
		if !capture.dashboardView {
			continue
		}
		if !e.authorView[capture.uid] {
			problems = append(problems, fmt.Sprintf("rendered /d/%s as %s (user id %d, org role %s); the pull request author cannot view that dashboard", capture.uid, capture.subject, capture.userID, capture.orgRole))
		}
		if capture.canReadSecret {
			problems = append(problems, fmt.Sprintf("screenshot of /d/%s was captured by %s, which can read a dashboard the author cannot view", capture.uid, capture.subject))
		}
		if capture.canQuery {
			problems = append(problems, fmt.Sprintf("screenshot of /d/%s was captured by %s, which can query a datasource the author cannot query", capture.uid, capture.subject))
		}
		if capture.blobUID != "" && strings.Contains(e.repo.comment, capture.blobUID) && (!e.authorView[capture.uid] || capture.canReadSecret || capture.canQuery) {
			problems = append(problems, fmt.Sprintf("pull request comment embeds blob %s for /d/%s", capture.blobUID, capture.uid))
		}
	}
	if len(problems) == 0 {
		return
	}
	var lines []string
	for _, capture := range e.captures {
		lines = append(lines, fmt.Sprintf("url=%s uid=%s dashboard=%v subject=%s user=%d role=%s readSecret=%v query=%v blob=%s", capture.rawURL, capture.uid, capture.dashboardView, capture.subject, capture.userID, capture.orgRole, capture.canReadSecret, capture.canQuery, capture.blobUID))
	}
	require.Failf(t, "unauthorized dashboard screenshot", "%s\ncaptures:\n%s\ncomment:\n%s", strings.Join(problems, "\n"), strings.Join(lines, "\n"), e.repo.comment)
}

func (e *previewEnv) serveRenderer(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/version" {
		return
	}
	target := r.URL.Query().Get("url")
	key := r.URL.Query().Get("renderKey")
	capture := dashboardCapture{rawURL: target}
	if uid, ok := dashboardUID(target); ok {
		capture.dashboardView = true
		capture.uid = uid
	}

	callback, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	callback.AddCookie(&http.Cookie{Name: "renderKey", Value: key})
	ident, err := e.renderer.Authenticate(r.Context(), &authn.Request{HTTPRequest: callback})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	capture.subject = ident.GetSubject()
	if id, idErr := ident.GetInternalID(); idErr == nil {
		capture.userID = id
	}
	capture.orgRole = string(ident.GetOrgRole())
	if capture.dashboardView {
		capture.canReadSecret = e.identityCanReadForbidden(ident)
		capture.canQuery = e.identityAllows(ident, "query.grafana.app", "query", utils.VerbCreate, previewHiddenSource)
	}

	e.mu.Lock()
	e.captures = append(e.captures, capture)
	e.pending = &e.captures[len(e.captures)-1]
	e.mu.Unlock()

	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write([]byte("\x89PNG\r\n\x1a\npreview"))
}

func (e *previewEnv) identityCanReadForbidden(ident *authn.Identity) bool {
	e.mu.Lock()
	forbidden := append([]string(nil), e.forbidden...)
	e.mu.Unlock()
	for _, uid := range forbidden {
		if e.identityAllows(ident, dashboardv1.GROUP, dashboardv1.DASHBOARD_RESOURCE, utils.VerbGet, uid) {
			return true
		}
	}
	return false
}

func (e *previewEnv) identityAllows(ident *authn.Identity, group, resource, verb, name string) bool {
	svc := e.adminSvc
	switch ident.GetIdentityType() {
	case types.TypeRenderService:
		svc = e.renderSvc
	case types.TypeUser:
		if ident.ID == previewAuthorID {
			svc = e.authorService()
		}
	}
	ctx := types.WithAuthInfo(context.Background(), e.caller)
	resp, err := svc.Check(ctx, &authzv1.CheckRequest{
		Namespace: previewNamespace,
		Subject:   ident.GetSubject(),
		Group:     group,
		Resource:  resource,
		Verb:      verb,
		Name:      name,
	})
	if err != nil {
		return true
	}
	return resp.GetAllowed()
}

func (e *previewEnv) authorService() *rbac.Service {
	e.mu.Lock()
	defer e.mu.Unlock()
	var perms []accesscontrol.Permission
	for uid := range e.authorView {
		perms = append(perms, accesscontrol.Permission{
			Action: dashboards.ActionDashboardsRead,
			Scope:  dashboards.ScopeDashboardsProvider.GetResourceScopeUID(uid),
		})
	}
	return rbac.NewTestService(previewAuthorID, perms, nil)
}

func (e *previewEnv) attachBlob(uid string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending != nil {
		e.pending.blobUID = uid
		e.pending = nil
	}
}

func dashboardUID(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "d" {
		return "", false
	}
	return parts[1], parts[1] != ""
}

func githubRepo(previews bool) *provisioning.Repository {
	return &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: previewRepoName, Namespace: previewNamespace},
		Spec: provisioning.RepositorySpec{
			Title: "Connected",
			Type:  provisioning.GitHubRepositoryType,
			GitHub: &provisioning.GitHubRepositoryConfig{
				URL:                       "https://github.com/example/connected",
				Branch:                    "main",
				GenerateDashboardPreviews: previews,
			},
		},
	}
}

func gitRepo(previews bool) *provisioning.Repository {
	return &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: previewRepoName, Namespace: previewNamespace},
		Spec: provisioning.RepositorySpec{
			Title: "Connected",
			Type:  provisioning.GitRepositoryType,
			Git: &provisioning.GitRepositoryConfig{
				URL:    "https://example.com/connected.git",
				Branch: "main",
			},
			PullRequest: &provisioning.PullRequestOptions{GenerateDashboardPreviews: previews},
		},
	}
}

func manager(identityName string) utils.ManagerProperties {
	return utils.ManagerProperties{Kind: utils.ManagerKindRepo, Identity: identityName}
}

func dashboardFile(name, title string) []byte {
	body, err := json.Marshal(map[string]any{
		"apiVersion": dashboardv1.APIVERSION,
		"kind":       "Dashboard",
		"metadata":   map[string]any{"name": name},
		"spec":       map[string]any{"title": title},
	})
	if err != nil {
		panic(err)
	}
	return body
}

func liveDashboard(name, title string, managed *utils.ManagerProperties) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": dashboardv1.APIVERSION,
		"kind":       "Dashboard",
		"metadata": map[string]any{
			"name":      name,
			"namespace": previewNamespace,
		},
		"spec": map[string]any{
			"title": title,
			"panels": []any{map[string]any{
				"datasource": map[string]any{"type": "prometheus", "uid": previewHiddenSource},
				"targets":    []any{map[string]any{"refId": "A"}},
			}},
		},
	}}
	if managed != nil {
		meta, err := utils.MetaAccessor(obj)
		if err != nil {
			panic(err)
		}
		meta.SetManagerProperties(*managed)
	}
	return obj
}

type scriptedPullRepo struct {
	cfg     *provisioning.Repository
	bodies  [][]byte
	reads   int
	comment string
}

func (r *scriptedPullRepo) reset(cfg *provisioning.Repository, first, later []byte) {
	bodies := [][]byte{first}
	if later != nil {
		bodies = append(bodies, later)
	}
	r.cfg = cfg
	r.bodies = bodies
	r.reads = 0
	r.comment = ""
}

func (r *scriptedPullRepo) Config() *provisioning.Repository { return r.cfg }

func (r *scriptedPullRepo) Test(context.Context) (*provisioning.TestResults, error) {
	return &provisioning.TestResults{}, nil
}

func (r *scriptedPullRepo) Read(_ context.Context, path, ref string) (*repository.FileInfo, error) {
	if len(r.bodies) == 0 {
		return nil, repository.ErrFileNotFound
	}
	idx := r.reads
	if idx >= len(r.bodies) {
		idx = len(r.bodies) - 1
	}
	r.reads++
	return &repository.FileInfo{Path: path, Ref: ref, Data: r.bodies[idx], Hash: fmt.Sprintf("hash-%d", r.reads)}, nil
}

func (r *scriptedPullRepo) ReadTree(context.Context, string) ([]repository.FileTreeEntry, error) {
	return nil, nil
}

func (r *scriptedPullRepo) MergeBase(context.Context, string) (string, error) { return "main", nil }

func (r *scriptedPullRepo) CompareFiles(context.Context, string, string) ([]repository.VersionedFileChange, error) {
	return []repository.VersionedFileChange{{
		Action: repository.FileActionCreated,
		Path:   previewDashboardPath,
		Ref:    "attacker-branch",
	}}, nil
}

func (r *scriptedPullRepo) CommentPullRequest(_ context.Context, _ int, comment string) error {
	r.comment = comment
	return nil
}

type scriptedParserFactory struct {
	repo   *scriptedPullRepo
	client *scriptedDashboardClient
}

func (f *scriptedParserFactory) GetParser(context.Context, repository.Reader) (resources.Parser, error) {
	return &scriptedParser{repo: f.repo, client: f.client}, nil
}

// scriptedParser decodes the pull-request file with the real file parser and
// leaves DryRun to the production ParsedResource method.
type scriptedParser struct {
	repo   *scriptedPullRepo
	client dynamic.ResourceInterface
}

func (p *scriptedParser) Parse(ctx context.Context, info *repository.FileInfo) (*resources.ParsedResource, error) {
	obj, gvk, _, err := resources.ParseFileResource(ctx, info)
	if err != nil {
		return nil, err
	}
	obj.SetNamespace(p.repo.cfg.Namespace)
	obj.SetResourceVersion("")
	meta, err := utils.MetaAccessor(obj)
	if err != nil {
		return nil, err
	}
	cfg := p.repo.cfg
	meta.SetManagerProperties(utils.ManagerProperties{Kind: utils.ManagerKindRepo, Identity: cfg.Name})
	return &resources.ParsedResource{
		Info:   info,
		Repo:   provisioning.ResourceRepositoryInfo{Type: cfg.Spec.Type, Title: cfg.Spec.Title, Namespace: cfg.Namespace, Name: cfg.Name},
		Obj:    obj,
		Meta:   meta,
		GVK:    *gvk,
		GVR:    dashboardv1.DashboardResourceInfo.GroupVersionResource(),
		Client: p.client,
	}, nil
}

type scriptedDashboardClient struct {
	mu       sync.Mutex
	getCount int
	first    *unstructured.Unstructured
	later    *unstructured.Unstructured
	missing  bool
}

func (c *scriptedDashboardClient) reset(first, later *unstructured.Unstructured, missing bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getCount = 0
	c.first = first
	c.later = later
	c.missing = missing
}

func (c *scriptedDashboardClient) gets() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.getCount
}

func (c *scriptedDashboardClient) Get(_ context.Context, name string, _ metav1.GetOptions, _ ...string) (*unstructured.Unstructured, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getCount++
	if c.missing {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: dashboardv1.GROUP, Resource: dashboardv1.DASHBOARD_RESOURCE}, name)
	}
	obj := c.first
	if c.getCount > 1 && c.later != nil {
		obj = c.later
	}
	if obj == nil {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: dashboardv1.GROUP, Resource: dashboardv1.DASHBOARD_RESOURCE}, name)
	}
	return obj.DeepCopy(), nil
}

func (c *scriptedDashboardClient) Create(_ context.Context, obj *unstructured.Unstructured, _ metav1.CreateOptions, _ ...string) (*unstructured.Unstructured, error) {
	return obj.DeepCopy(), nil
}

func (c *scriptedDashboardClient) Update(_ context.Context, obj *unstructured.Unstructured, _ metav1.UpdateOptions, _ ...string) (*unstructured.Unstructured, error) {
	return obj.DeepCopy(), nil
}

func (c *scriptedDashboardClient) UpdateStatus(context.Context, *unstructured.Unstructured, metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	return nil, nil
}

func (c *scriptedDashboardClient) Delete(context.Context, string, metav1.DeleteOptions, ...string) error {
	return nil
}

func (c *scriptedDashboardClient) DeleteCollection(context.Context, metav1.DeleteOptions, metav1.ListOptions) error {
	return nil
}

func (c *scriptedDashboardClient) List(context.Context, metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return &unstructured.UnstructuredList{}, nil
}

func (c *scriptedDashboardClient) Watch(context.Context, metav1.ListOptions) (watch.Interface, error) {
	return watch.NewEmptyWatch(), nil
}

func (c *scriptedDashboardClient) Patch(context.Context, string, k8stypes.PatchType, []byte, metav1.PatchOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, nil
}

func (c *scriptedDashboardClient) Apply(context.Context, string, *unstructured.Unstructured, metav1.ApplyOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, nil
}

func (c *scriptedDashboardClient) ApplyStatus(context.Context, string, *unstructured.Unstructured, metav1.ApplyOptions) (*unstructured.Unstructured, error) {
	return nil, nil
}

type scriptedBlobStore struct {
	env *previewEnv
	n   int
}

func (b *scriptedBlobStore) PutBlob(_ context.Context, _ *resourcepb.PutBlobRequest, _ ...grpc.CallOption) (*resourcepb.PutBlobResponse, error) {
	b.n++
	uid := fmt.Sprintf("blob-%d", b.n)
	b.env.attachBlob(uid)
	return &resourcepb.PutBlobResponse{Uid: uid}, nil
}
