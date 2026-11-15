package webhooks

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	appcontroller "github.com/grafana/grafana/apps/provisioning/pkg/controller"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	gh "github.com/grafana/grafana/apps/provisioning/pkg/repository/github"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs"
	grafanauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// placeholderWebhookSecret is not a credential. ValidatePayload only needs a
// non-empty key so an unsigned body is hashed and then rejected.
const placeholderWebhookSecret = "placeholder"

func TestShippedProvisioningWebhookRateLimitIsPositive(t *testing.T) {
	cfg := loadShippedDefaults(t)
	require.True(t, cfg.ProvisioningEnabled, "Git Sync is on in the shipped config, so the webhook route is registered")
	require.Positive(t, cfg.ProvisioningWebhookRateLimitRPS, "shipped webhook_rate_limit_rps must be a positive limit")
}

func TestNonPositiveWebhookRateLimitUsesFallback(t *testing.T) {
	now := time.Unix(0, 0)
	for _, rps := range []int{0, -1} {
		limiter := NewConfiguredRateLimiter(rps, "")
		require.NotNilf(t, limiter, "rps %d must still install the fallback limiter", rps)

		impl, ok := limiter.(*ipRateLimiterImpl)
		require.True(t, ok)
		require.Equal(t, rate.Limit(defaultWebhookRPS), impl.rps)
		require.Equal(t, defaultWebhookBurst, impl.burst)

		for i := range defaultWebhookBurst {
			require.Truef(t, impl.Allow("default|203.0.113.5", now), "fallback burst request %d", i)
		}
		require.False(t, impl.Allow("default|203.0.113.5", now), "the request after the fallback burst must be rejected")
	}
}

func TestAnonymousWebhookDeliveryIsLimitedBeforeTheBodyIsHashed(t *testing.T) {
	cfg := loadShippedDefaults(t)
	webhookPath := "/apis/" + provisioning.APIVERSION + "/namespaces/default/repositories/repo/webhook"

	prov := clients.ProvideProvisioning()
	req := httptest.NewRequest(http.MethodPost, webhookPath, nil)
	authReq := &authn.Request{HTTPRequest: req}
	require.True(t, prov.Test(t.Context(), authReq), "a request with no session must match the provisioning client")
	ident, err := prov.Authenticate(t.Context(), authReq)
	require.NoError(t, err)
	require.Equal(t, "anonymous", string(ident.GetIdentityType()))
	require.False(t, ident.ClientParams.SyncUser, "post-auth user sync must not run for this client")

	signedIn := ident.SignedInUser()
	resp := web.NewResponseWriter(http.MethodPost, httptest.NewRecorder())
	reqCtx := &contextmodel.ReqContext{
		Context: &web.Context{
			Req:  req,
			Resp: resp,
		},
		SignedInUser:   signedIn,
		IsSignedIn:     !signedIn.IsAnonymous,
		AllowAnonymous: signedIn.IsAnonymous,
		Logger:         log.New("test"),
	}
	middleware.ReqSignedIn.(func(*contextmodel.ReqContext))(reqCtx)
	require.False(t, resp.Written(), "ReqSignedIn must let the anonymous provisioning identity through")

	csrfCalled := false
	csrf.ProvideCSRFFilter(cfg).Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		csrfCalled = true
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, webhookPath, nil))
	require.True(t, csrfCalled, "a POST with no login cookie must pass the shipped CSRF filter")

	repoCfg := &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: "repo", Namespace: "default"},
		Spec: provisioning.RepositorySpec{
			Type:   provisioning.GitHubRepositoryType,
			GitHub: &provisioning.GitHubRepositoryConfig{Branch: "main"},
			Sync:   provisioning.SyncOptions{Enabled: true},
		},
		Status: provisioning.RepositoryStatus{
			Health:  provisioning.HealthStatus{Healthy: true},
			Webhook: &provisioning.WebhookStatus{},
		},
	}
	base := gh.NewMockGithubRepository(t)
	base.EXPECT().Config().Return(repoCfg).Maybe()
	base.EXPECT().Owner().Return("example-owner").Maybe()
	base.EXPECT().Repo().Return("example-repo").Maybe()
	hooks := gh.NewGithubWebhookRepository(base, "https://grafana.example.com/webhook", common.RawSecureValue(placeholderWebhookSecret))

	core := &dosCore{repo: hooks}
	connector := NewWebhookConnector(
		true, // public https URL: ProvideWebhooksWithImages sets webhooksEnabled from isPublicURL
		core,
		nil,
		prometheus.NewRegistry(),
		// Same call ProvideWebhooksWithImages and the standalone operator make.
		NewConfiguredRateLimiter(cfg.ProvisioningWebhookRateLimitRPS, cfg.ProvisioningWebhookTrustedIPHeader),
	)

	ctx := identity.WithRequester(t.Context(), ident)
	chain := grafanauthorizer.NewGrafanaBuiltInSTAuthorizer()
	// APIBuilder.GetAuthorizer returns an AuthorizerFunc that delegates to this connector.
	delegated := authorizer.AuthorizerFunc(connector.Authorize)
	for _, version := range []string{provisioning.VERSION, "v1beta1"} {
		chain.Register(schema.GroupVersion{Group: provisioning.GROUP, Version: version}, delegated)
		decision, reason, authzErr := chain.Authorize(ctx, authorizer.AttributesRecord{
			User:            ident,
			Verb:            "connect",
			Namespace:       "default",
			APIGroup:        provisioning.GROUP,
			APIVersion:      version,
			Resource:        provisioning.RepositoryResourceInfo.GetName(),
			Subresource:     "webhook",
			Name:            "repo",
			ResourceRequest: true,
		})
		require.NoError(t, authzErr)
		require.Equalf(t, authorizer.DecisionAllow, decision, "version %s reason %s", version, reason)
	}

	require.Equal(t, 25*1024*1024, webhookMaxBodySize)

	responder := &captureResponder{}
	handler, err := connector.Connect(request.WithNamespace(ctx, "default"), "repo", nil, responder)
	require.NoError(t, err)

	body := bytes.Repeat([]byte("x"), 64*1024)
	// One past the fallback burst. With the limiter absent, every request is hashed.
	for i := range defaultWebhookBurst + 1 {
		reader := &countingReader{r: bytes.NewReader(body)}
		delivery := httptest.NewRequest(http.MethodPost, webhookPath, reader)
		delivery.RemoteAddr = "203.0.113.5:4242"
		delivery.Header.Set("Content-Type", "application/json")
		delivery.Header.Set("X-Hub-Signature-256", "sha256=00")
		before := responder.calls
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, delivery)

		if i < defaultWebhookBurst {
			require.Equal(t, len(body), reader.n, "an admitted delivery must be read in full so the signature can be hashed")
			require.Greater(t, responder.calls, before, "the invalid signature is rejected only after the body is read")
			require.NotEqual(t, http.StatusTooManyRequests, rw.Code)
			continue
		}
		require.Equal(t, http.StatusTooManyRequests, rw.Code)
		require.Zero(t, reader.n, "a limited delivery must be rejected before the body is read")
		require.Equal(t, before, responder.calls, "a limited delivery must not reach signature verification")
	}
	require.Zero(t, core.jobs, "an invalid signature must not enqueue a sync")
}

type dosCore struct {
	repo repository.Repository
	jobs int
}

func (c *dosCore) GetGroupVersion() schema.GroupVersion {
	return schema.GroupVersion{Group: provisioning.GROUP, Version: provisioning.VERSION}
}

func (c *dosCore) GetHealthyRepository(context.Context, string) (repository.Repository, error) {
	return c.repo, nil
}

func (c *dosCore) GetJobQueue() jobs.Queue {
	return jobCounter{core: c}
}

func (c *dosCore) GetStatusPatcher() *appcontroller.RepositoryStatusPatcher { return nil }

func (c *dosCore) GetIncrementalPolicy() repository.IncrementalSyncPolicy {
	return repository.IncrementalSyncPolicy{}
}

// jobCounter records an insert. The rest of the queue is unused on this path.
type jobCounter struct {
	core *dosCore
}

func (j jobCounter) Insert(context.Context, string, provisioning.JobSpec) (*provisioning.Job, error) {
	j.core.jobs++
	return &provisioning.Job{}, nil
}

func (j jobCounter) CleanupQueue(context.Context, string, string) (int, error) {
	return 0, nil
}

type captureResponder struct {
	calls int
	last  error
}

func (c *captureResponder) Object(int, runtime.Object) {}

func (c *captureResponder) Error(err error) {
	c.calls++
	c.last = err
}

var _ rest.Responder = (*captureResponder)(nil)

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func loadShippedDefaults(t *testing.T) *setting.Cfg {
	t.Helper()
	root := filepath.Join("..", "..", "..", "..", "..")
	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: root,
		Config:   filepath.Join(root, "conf", "defaults.ini"),
	}))
	return cfg
}
