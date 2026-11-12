package webhooks

import (
	"context"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	genericfilters "k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/handlers"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	authlib "github.com/grafana/authlib/types"
	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/middleware"
	provisioningapis "github.com/grafana/grafana/pkg/registry/apis/provisioning"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/webhooks/pullrequest"
	grafanauthenticator "github.com/grafana/grafana/pkg/services/apiserver/auth/authenticator"
	grafanaauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl/sync"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/web"
)

// previewMarkerA and previewMarkerB are the rendered image bodies. They are
// stand-ins for dashboard screenshots, not credentials.
var (
	previewMarkerA = []byte("dashboard-preview-org-default-repo-a")
	previewMarkerB = []byte("dashboard-preview-org-default-repo-b")
)

const (
	previewRepoA = "repo-a"
	previewRepoB = "repo-b"
	previewBlobA = "11111111-1111-1111-1111-111111111111"
	previewBlobB = "22222222-2222-2222-2222-222222222222"
)

// TestUnauthenticatedDashboardPreviewRequiresAuthorization drives the Git Sync
// preview URL through the production authentication middleware, the apiserver
// authorizer chain, and the render connector. A caller with no session and no
// signature bound to that namespace, repository, and blob must not receive the
// image bytes.
func TestUnauthenticatedDashboardPreviewRequiresAuthorization(t *testing.T) {
	h := newPreviewHarness(t)

	cases := []struct {
		name string
		path string
	}{
		{
			name: "no signature",
			path: previewPath("v0alpha1", "default", previewRepoA, previewBlobA),
		},
		{
			name: "signature for a different blob",
			path: previewPath("v0alpha1", "default", previewRepoA, previewBlobA) + "?exp=9999999999&sig=00",
		},
		{
			name: "expired signature",
			path: previewPath("v0alpha1", "default", previewRepoA, previewBlobA) + "?exp=1&sig=00",
		},
		{
			name: "second organization",
			path: previewPath("v0alpha1", "org-2", previewRepoA, previewBlobA),
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			rec := h.get(t, tt.path)
			requirePreviewDenied(t, rec, h.blobs)
		})
	}

	t.Run("other repository does not return this image", func(t *testing.T) {
		rec := h.get(t, previewPath("v0alpha1", "default", previewRepoB, previewBlobA))
		body := rec.Body.Bytes()
		require.NotContains(t, body, previewMarkerA)
		require.NotContains(t, body, previewMarkerB)
		require.Zero(t, h.blobs.mutations, "reading a preview must not write or delete a blob")
	})

	t.Run("v1beta1 url is not anonymously readable", func(t *testing.T) {
		rec := h.get(t, previewPath("v1beta1", "default", previewRepoA, previewBlobA))
		body := rec.Body.Bytes()
		require.NotContains(t, body, previewMarkerA)
		require.NotContains(t, body, previewMarkerB)
		require.NotEqual(t, http.StatusOK, rec.Code, "body=%q", rec.Body.String())
	})
}

func requirePreviewDenied(t *testing.T, rec *httptest.ResponseRecorder, blobs *memBlobs) {
	t.Helper()
	body := rec.Body.Bytes()
	require.NotContains(t, body, previewMarkerA, "status=%d body=%q", rec.Code, rec.Body.String())
	require.NotContains(t, body, previewMarkerB, "status=%d body=%q", rec.Code, rec.Body.String())
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, rec.Code, "status=%d body=%q", rec.Code, rec.Body.String())
	require.Zero(t, blobs.mutations, "a refused preview request must not write or delete a blob")
}

func previewPath(version, namespace, repo, blobID string) string {
	return "/apis/" + provisioning.GROUP + "/" + version + "/namespaces/" + namespace + "/repositories/" + repo + "/render/" + blobID
}

type previewHarness struct {
	server *web.Macaron
	blobs  *memBlobs
}

func (h previewHarness) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	// No cookie, no authorization header, no client certificate.
	req := httptest.NewRequest(http.MethodGet, "http://grafana.example"+path, nil)
	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)
	return rec
}

func newPreviewHarness(t *testing.T) previewHarness {
	t.Helper()

	blobs := &memBlobs{items: map[string]memBlob{}}
	blobs.seed("default", previewRepoA, previewBlobA, "image/png", previewMarkerA)
	blobs.seed("default", previewRepoB, previewBlobB, "image/png", previewMarkerB)
	blobs.seed("org-2", previewRepoA, previewBlobA, "image/png", previewMarkerA)

	srv, err := resource.NewUninitializedResourceServer(resource.ResourceServerOptions{
		Backend: unusedStorage{},
		Blob:    resource.BlobConfig{Backend: blobs},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	})

	client := blobClient{server: srv}
	reg := prometheus.NewRegistry()
	tracer := tracing.NewNoopTracerService()
	features := featuremgmt.WithFeatures()

	build := func(version string) (*provisioningapis.APIBuilder, rest.Connecter) {
		var connecter rest.Connecter
		b, err := provisioningapis.NewAPIBuilder(
			schema.GroupVersion{Group: provisioning.GROUP, Version: version},
			version == "v0alpha1",
			true,
			nil,
			nil,
			features,
			client,
			nil,
			nil,
			noopUsage{},
			nil,
			tracer,
			[]provisioningapis.ExtraBuilder{func(b *provisioningapis.APIBuilder) provisioningapis.Extra {
				render := NewRenderConnector(client, b)
				webhook := NewWebhookConnector(true, b, pullrequest.NewNoOpRenderer(), reg, nil)
				extra := NewWebhookExtraWithImages(render, webhook, nil, nil)
				storage := map[string]rest.Storage{}
				require.NoError(t, extra.UpdateStorage(storage))
				stored, ok := storage[provisioning.RepositoryResourceInfo.StoragePath("render")].(rest.Connecter)
				require.True(t, ok)
				connecter = stored
				return extra
			}},
			nil,
			nil,
			nil,
			nil,
			nil,
			true,
			0,
			reg,
			nil,
			false,
			nil,
			false,
			repository.IncrementalSyncPolicy{},
			0,
		)
		require.NoError(t, err)
		require.NotNil(t, connecter)
		return b, connecter
	}

	v0, connectV0 := build("v0alpha1")
	v1, connectV1 := build("v1beta1")

	chain := grafanaauthorizer.NewGrafanaBuiltInSTAuthorizer()
	chain.Register(schema.GroupVersion{Group: provisioning.GROUP, Version: "v0alpha1"}, v0.GetAuthorizer())
	chain.Register(schema.GroupVersion{Group: provisioning.GROUP, Version: "v1beta1"}, v1.GetAuthorizer())

	scheme := runtime.NewScheme()
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})
	codecs := serializer.NewCodecFactory(scheme)
	infoFactory := &request.RequestInfoFactory{
		APIPrefixes:          sets.NewString("apis"),
		GrouplessAPIPrefixes: sets.NewString(),
	}
	connect := map[string]rest.Connecter{
		"v0alpha1": connectV0,
		"v1beta1":  connectV1,
	}
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		namespace, name, err := (handlers.ContextBasedNaming{}).Name(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		info, ok := request.RequestInfoFrom(r.Context())
		if !ok {
			http.Error(w, "missing request info", http.StatusInternalServerError)
			return
		}
		connecter := connect[info.APIVersion]
		if connecter == nil {
			http.NotFound(w, r)
			return
		}
		ctx := request.WithNamespace(r.Context(), namespace)
		handler, err := connecter.Connect(ctx, name, nil, statusResponder{w: w})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		handler.ServeHTTP(w, r)
	})
	// Same filter order as kube-apiserver: request info, then authentication, then authorization.
	// With* wraps the handler, so the last wrap runs first.
	handler := genericfilters.WithAuthorization(api, chain, codecs)
	handler = genericfilters.WithAuthentication(handler, grafanauthenticator.NewAuthenticator(), genericfilters.Unauthorized(codecs), authenticator.Audiences(nil), nil)
	handler = genericfilters.WithRequestInfo(handler, infoFactory)

	cfg := setting.NewCfg()
	// conf/defaults.ini enables Git Sync. Registration only installs this client when that is set.
	cfg.ProvisioningEnabled = true
	cfg.Anonymous.Enabled = false
	authnSvc := newProvisioningAuthn(t, cfg)

	ctxHandler := contexthandler.ProvideService(cfg, authnSvc, features)
	m := web.New()
	m.UseMiddleware(ctxHandler.Middleware)
	m.Get("/apis/*", middleware.ReqSignedIn, func(c *contextmodel.ReqContext) {
		req := c.Req
		if c.SignedInUser != nil && !c.IsSignedIn {
			// Same binding the /apis proxy applies before the request reaches the apiserver.
			applyAnonymousNamespaceFromPath(req.URL.Path, c.SignedInUser)
		}
		if c.SignedInUser != nil {
			req = req.WithContext(identity.WithRequester(req.Context(), c.SignedInUser))
		}
		handler.ServeHTTP(c.Resp, req)
	})

	return previewHarness{server: m, blobs: blobs}
}

func newProvisioningAuthn(t *testing.T, cfg *setting.Cfg) *authnimpl.Service {
	t.Helper()
	tracer := tracing.NewNoopTracerService()
	svc := authnimpl.ProvideService(cfg, tracer, nil, noopUsage{}, prometheus.NewRegistry(), nil)
	require.True(t, cfg.ProvisioningEnabled)
	svc.RegisterClient(clients.ProvideProvisioning())

	features := featuremgmt.WithFeatures()
	userSync := sync.ProvideUserSync(nil, nil, nil, nil, tracer, features, cfg, nil)
	orgSync := sync.ProvideOrgSync(nil, nil, nil, cfg, tracer)
	rbacSync := sync.ProvideRBACSync(cfg, nil, tracer, nil)
	svc.RegisterPostAuthHook(userSync.SyncUserHook, 10)
	svc.RegisterPostAuthHook(userSync.EnableUserHook, 20)
	svc.RegisterPostAuthHook(orgSync.SyncOrgRolesHook, 40)
	svc.RegisterPostAuthHook(userSync.SyncLastSeenHook, 130)
	svc.RegisterPostAuthHook(sync.ProvideOAuthTokenSync(nil, nil, nil, tracer, features).SyncOauthTokenHook, 60)
	svc.RegisterPostAuthHook(userSync.FetchSyncedUserHook, 100)
	svc.RegisterPostAuthHook(sync.ProvideGroupsClaimSync(cfg).SyncGroupsClaimHook, 115)
	svc.RegisterPostAuthHook(rbacSync.SyncCloudRoles, 110)
	svc.RegisterPostAuthHook(rbacSync.SyncPermissionsHook, 120)
	svc.RegisterPostAuthHook(sync.ProvideNamespaceSync(cfg).SyncNamespace, 150)
	svc.RegisterPostAuthHook(sync.AccessClaimsHook, 160)
	return svc
}

// applyAnonymousNamespaceFromPath is the /apis proxy binding in
// pkg/services/apiserver/service.go. It is unexported there; this is that function.
func applyAnonymousNamespaceFromPath(path string, user *user.SignedInUser) {
	if strings.HasPrefix(path, "/apis/") && len(path) > 6 {
		parts := strings.Split(path[6:], "/")
		if len(parts) >= 4 && parts[2] == "namespaces" {
			ns, err := authlib.ParseNamespace(parts[3])
			if err == nil {
				user.Namespace = ns.Value
				user.OrgID = ns.OrgID
			}
		}
	}
}

type statusResponder struct {
	w http.ResponseWriter
}

func (r statusResponder) Object(statusCode int, _ runtime.Object) {
	r.w.WriteHeader(statusCode)
}

func (r statusResponder) Error(err error) {
	code := http.StatusInternalServerError
	var status apierrors.APIStatus
	if errors.As(err, &status) && status.Status().Code != 0 {
		code = int(status.Status().Code)
	}
	http.Error(r.w, err.Error(), code)
}

type blobClient struct {
	resource.ResourceClient
	server resource.ResourceServer
}

func (c blobClient) GetBlob(ctx context.Context, in *resourcepb.GetBlobRequest, _ ...grpc.CallOption) (*resourcepb.GetBlobResponse, error) {
	return c.server.GetBlob(ctx, in)
}

type memBlob struct {
	contentType string
	value       []byte
}

// memBlobs applies the resource_blob lookup filters from
// pkg/storage/unified/sql/data/resource_blob_query.sql: namespace, group,
// resource, name, and uuid. Rows have no expiry column.
type memBlobs struct {
	items     map[string]memBlob
	mutations int
}

func blobKey(namespace, name, uid string) string {
	return strings.Join([]string{namespace, provisioning.GROUP, provisioning.RepositoryResourceInfo.GroupResource().Resource, name, uid}, "\x00")
}

func (b *memBlobs) seed(namespace, name, uid, contentType string, value []byte) {
	b.items[blobKey(namespace, name, uid)] = memBlob{contentType: contentType, value: append([]byte(nil), value...)}
}

func (b *memBlobs) SupportsSignedURLs() bool { return false }

func (b *memBlobs) PutResourceBlob(context.Context, *resourcepb.PutBlobRequest) (*resourcepb.PutBlobResponse, error) {
	b.mutations++
	return nil, errors.New("preview read must not store a blob")
}

func (b *memBlobs) GetResourceBlob(_ context.Context, key *resourcepb.ResourceKey, info *utils.BlobInfo, _ bool) (*resourcepb.GetBlobResponse, error) {
	if key == nil || info == nil || info.UID == "" || key.Name == "" {
		return &resourcepb.GetBlobResponse{Error: &resourcepb.ErrorResult{Code: http.StatusBadRequest, Message: "missing blob key"}}, nil
	}
	item, ok := b.items[blobKey(key.Namespace, key.Name, info.UID)]
	if !ok || key.Group != provisioning.GROUP || key.Resource != provisioning.RepositoryResourceInfo.GroupResource().Resource {
		return &resourcepb.GetBlobResponse{Error: &resourcepb.ErrorResult{Code: http.StatusNotFound, Message: "not found"}}, nil
	}
	return &resourcepb.GetBlobResponse{ContentType: item.contentType, Value: append([]byte(nil), item.value...)}, nil
}

type unusedStorage struct{}

func (unusedStorage) WriteEvent(context.Context, resource.WriteEvent) (int64, error) {
	return 0, errors.New("not used")
}
func (unusedStorage) ReadResource(context.Context, *resourcepb.ReadRequest) *resource.BackendReadResponse {
	return &resource.BackendReadResponse{Error: &resourcepb.ErrorResult{Code: http.StatusNotFound}}
}
func (unusedStorage) BatchReadResource(context.Context, []*resourcepb.ReadRequest) (iter.Seq[*resource.BackendReadResponse], error) {
	return nil, errors.New("not used")
}
func (unusedStorage) ListIterator(context.Context, *resourcepb.ListRequest, func(resource.ListIterator) error) (int64, error) {
	return 0, errors.New("not used")
}
func (unusedStorage) ListHistory(context.Context, *resourcepb.ListRequest, func(resource.ListIterator) error) (int64, error) {
	return 0, errors.New("not used")
}
func (unusedStorage) ListModifiedSince(context.Context, resource.NamespacedResource, int64, *time.Time) (int64, iter.Seq2[*resource.ModifiedResource, error]) {
	return 0, nil
}
func (unusedStorage) WatchWriteEvents(context.Context) (<-chan *resource.WrittenEvent, error) {
	return nil, errors.New("not used")
}
func (unusedStorage) GetResourceStats(context.Context, resource.NamespacedResource, int) ([]resource.ResourceStats, error) {
	return nil, errors.New("not used")
}
func (unusedStorage) GetResourceStatsWithLimit(context.Context, resource.NamespacedResource, int, int) ([]resource.ResourceStats, error) {
	return nil, errors.New("not used")
}
func (unusedStorage) ListStoredResources(context.Context, resource.NamespacedResource) ([]resource.NamespacedResource, error) {
	return nil, errors.New("not used")
}
func (unusedStorage) GetResourceLastImportTime(context.Context, resource.NamespacedResource) (time.Time, error) {
	return time.Time{}, errors.New("not used")
}

type noopUsage struct{}

func (noopUsage) GetUsageReport(context.Context) (usagestats.Report, error) {
	return usagestats.Report{}, nil
}
func (noopUsage) RegisterMetricsFunc(usagestats.MetricsFunc)                   {}
func (noopUsage) RegisterSendReportCallback(usagestats.SendReportCallbackFunc) {}
func (noopUsage) SetReadyToReport(context.Context)                             {}
