package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	// #nosec G505 -- builds the SHA-1 signature GitHub sends so the test can require the handler to reject it
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/grafana/authlib/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8suser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/authorization/union"
	"k8s.io/apiserver/pkg/endpoints/request"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	appcontroller "github.com/grafana/grafana/apps/provisioning/pkg/controller"
	fakeclientset "github.com/grafana/grafana/apps/provisioning/pkg/generated/clientset/versioned/fake"
	client "github.com/grafana/grafana/apps/provisioning/pkg/generated/clientset/versioned/typed/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	githubrepo "github.com/grafana/grafana/apps/provisioning/pkg/repository/github"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs"
	grafanauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
)

const (
	// webhookSecretPlaceholder is a stand-in for the repository webhook secret.
	// The tests sign bodies with it the way GitHub would; it is not a live credential.
	webhookSecretPlaceholder = "webhook-secret"
	replayNamespace          = "default"
	replayRepositoryName     = "git-sync"
	replayGitHubOwner        = "grafana"
	replayGitHubRepo         = "grafana"
)

// pushBody is a push for the configured branch. The added path is a dashboard
// file so a pull job created from this delivery is one that syncs repository
// contents into the organization.
const pushBody = `{
	"ref": "refs/heads/main",
	"repository": {"full_name": "grafana/grafana"},
	"commits": [{"added": ["dashboards/example.json"], "modified": [], "removed": []}],
	"sender": {"login": "octocat", "id": 1}
}`

// otherPushBody differs by one field, so its HMAC is not the captured delivery.
const otherPushBody = `{
	"ref": "refs/heads/main",
	"after": "abc123",
	"repository": {"full_name": "grafana/grafana"},
	"commits": [{"added": ["dashboards/example.json"], "modified": [], "removed": []}],
	"sender": {"login": "octocat", "id": 1}
}`

const pullRequestBody = `{
	"action": "opened",
	"repository": {"full_name": "grafana/grafana"},
	"pull_request": {
		"number": 7,
		"html_url": "https://github.com/grafana/grafana/pull/7",
		"head": {"ref": "feature", "sha": "abc123", "repo": {"id": 1}},
		"base": {"ref": "main", "repo": {"id": 1}}
	},
	"sender": {"login": "octocat", "id": 1}
}`

const mismatchedPushBody = `{
	"ref": "refs/heads/main",
	"repository": {"full_name": "other/repo"},
	"commits": [{"added": ["dashboards/example.json"], "modified": [], "removed": []}],
	"sender": {"login": "octocat", "id": 1}
}`

// replayHarness is the Git Sync webhook path: the real GitHub signature check,
// the connector replay cache, and the real job store. The embedded repository
// only supplies the configured owner, name, and branch.
type replayHarness struct {
	t         *testing.T
	connector *webhookConnector
	client    client.ProvisioningV0alpha1Interface
	store     jobs.Store
}

func newReplayHarness(t *testing.T) *replayHarness {
	t.Helper()

	cfg := &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: replayRepositoryName, Namespace: replayNamespace},
		Spec: provisioning.RepositorySpec{
			Type: provisioning.GitHubRepositoryType,
			GitHub: &provisioning.GitHubRepositoryConfig{
				URL:    "https://github.com/grafana/grafana",
				Branch: "main",
			},
			Sync: provisioning.SyncOptions{Enabled: true},
		},
		Status: provisioning.RepositoryStatus{
			Health:  provisioning.HealthStatus{Healthy: true},
			Webhook: &provisioning.WebhookStatus{},
		},
	}

	base := githubrepo.NewMockGithubRepository(t)
	base.EXPECT().Config().Return(cfg).Maybe()
	base.EXPECT().Owner().Return(replayGitHubOwner).Maybe()
	base.EXPECT().Repo().Return(replayGitHubRepo).Maybe()

	hooks := githubrepo.NewGithubWebhookRepository(base, "https://grafana.example/webhook", common.RawSecureValue(webhookSecretPlaceholder))

	//nolint:staticcheck // NewSimpleClientset is needed; NewClientset requires schema registration not available for this type.
	jobClient := fakeclientset.NewSimpleClientset().ProvisioningV0alpha1()
	store, err := jobs.NewJobStore(jobClient, 30*time.Second, prometheus.NewRegistry())
	require.NoError(t, err)

	// The shipped default is webhook_rate_limit_rps = 0, which builds no limiter.
	limiter := NewConfiguredRateLimiter(0, "")
	require.Nil(t, limiter)

	connector := NewWebhookConnector(true, &replayCore{repo: hooks, queue: store}, nil, prometheus.NewRegistry(), limiter)
	require.Nil(t, connector.rateLimiter)

	return &replayHarness{
		t:         t,
		connector: connector,
		client:    jobClient,
		store:     store,
	}
}

type replayCore struct {
	repo  repository.Repository
	queue jobs.Queue
}

func (c *replayCore) GetGroupVersion() schema.GroupVersion {
	return schema.GroupVersion{Group: provisioning.GROUP, Version: provisioning.VERSION}
}

func (c *replayCore) GetHealthyRepository(context.Context, string) (repository.Repository, error) {
	return c.repo, nil
}

func (c *replayCore) GetJobQueue() jobs.Queue { return c.queue }

func (c *replayCore) GetStatusPatcher() *appcontroller.RepositoryStatusPatcher { return nil }

func (c *replayCore) GetIncrementalPolicy() repository.IncrementalSyncPolicy {
	return repository.IncrementalSyncPolicy{}
}

type recordedResponse struct {
	code int
	obj  runtime.Object
	err  error
}

type recordingResponder struct {
	last recordedResponse
}

func (r *recordingResponder) Object(statusCode int, obj runtime.Object) {
	r.last = recordedResponse{code: statusCode, obj: obj}
}

func (r *recordingResponder) Error(err error) {
	r.last = recordedResponse{err: err}
}

func (h *replayHarness) deliver(body string, mutate func(http.Header)) recordedResponse {
	h.t.Helper()

	responder := &recordingResponder{}
	ctx := request.WithNamespace(context.Background(), replayNamespace)
	handler, err := h.connector.Connect(ctx, replayRepositoryName, nil, responder)
	require.NoError(h.t, err)

	req := httptest.NewRequest(http.MethodPost, webhookPath(), bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-GitHub-Delivery", "delivery-captured")
	req.Header.Set(githubSignature256Header, sign(sha256.New, webhookSecretPlaceholder, body))
	req.Header.Set(githubSignature1Header, sign(sha1.New, webhookSecretPlaceholder, body))
	require.Empty(h.t, req.Header.Values("Authorization"))
	require.Empty(h.t, req.Header.Values("Cookie"))
	if mutate != nil {
		mutate(req.Header)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	require.NotEqual(h.t, http.StatusTooManyRequests, recorder.Code)
	return responder.last
}

func (h *replayHarness) jobs() []provisioning.Job {
	h.t.Helper()
	list, err := h.client.Jobs(replayNamespace).List(context.Background(), metav1.ListOptions{})
	require.NoError(h.t, err)
	return list.Items
}

// finishJobs runs the worker's claim-and-complete path, which deletes the job
// from the active store. Pull and pull-request names are deterministic, so a
// later delivery can create the same name only after this delete.
func (h *replayHarness) finishJobs() {
	h.t.Helper()
	for _, job := range h.jobs() {
		claimed, rollback, err := h.store.Claim(context.Background(), replayNamespace, job.Name, "replay-test")
		require.NoError(h.t, err)
		require.NoError(h.t, h.store.Complete(context.Background(), claimed))
		rollback()
	}
	require.Empty(h.t, h.jobs())
}

func webhookPath() string {
	return "/apis/" + provisioning.APIVERSION + "/namespaces/" + replayNamespace + "/repositories/" + replayRepositoryName + "/webhook"
}

const (
	githubSignature256Header = "X-Hub-Signature-256"
	githubSignature1Header   = "X-Hub-Signature"
)

func sign(newHash func() hash.Hash, secret, body string) string {
	mac := hmac.New(newHash, []byte(secret))
	_, _ = mac.Write([]byte(body))
	sum := mac.Sum(nil)
	prefix := "sha256="
	if len(sum) == sha1.Size {
		prefix = "sha1="
	}
	return prefix + hex.EncodeToString(sum)
}

func uppercaseHexSignature(t *testing.T, signature string) string {
	t.Helper()
	return rewriteHex(t, signature, func(r rune) rune {
		if r >= 'a' && r <= 'f' {
			return r - 'a' + 'A'
		}
		return r
	})
}

func flipFirstHexLetter(t *testing.T, signature string) string {
	t.Helper()
	flipped := false
	return rewriteHex(t, signature, func(r rune) rune {
		if !flipped && r >= 'a' && r <= 'f' {
			flipped = true
			return r - 'a' + 'A'
		}
		if !flipped && r >= 'A' && r <= 'F' {
			flipped = true
			return r - 'A' + 'a'
		}
		return r
	})
}

func rewriteHex(t *testing.T, signature string, mapRune func(rune) rune) string {
	t.Helper()
	prefix, hexPart, ok := strings.Cut(signature, "=")
	require.True(t, ok, "signature %q has no hex payload", signature)
	var b strings.Builder
	changed := false
	for _, r := range hexPart {
		mapped := mapRune(r)
		if mapped != r {
			changed = true
		}
		b.WriteRune(mapped)
	}
	require.True(t, changed, "signature %q has no hex letter whose case can change", signature)
	rewritten := prefix + "=" + b.String()
	require.NotEqual(t, signature, rewritten)
	return rewritten
}

func requirePullJob(t *testing.T, got recordedResponse) {
	t.Helper()
	require.NoError(t, got.err)
	require.Equal(t, http.StatusAccepted, got.code)
	job, ok := got.obj.(*provisioning.Job)
	require.True(t, ok, "expected a job, got %T", got.obj)
	require.Equal(t, replayRepositoryName, job.Spec.Repository)
	require.Equal(t, provisioning.JobActionPull, job.Spec.Action)
}

func requirePullRequestJob(t *testing.T, got recordedResponse) {
	t.Helper()
	require.NoError(t, got.err)
	require.Equal(t, http.StatusAccepted, got.code)
	job, ok := got.obj.(*provisioning.Job)
	require.True(t, ok, "expected a job, got %T", got.obj)
	require.Equal(t, replayRepositoryName, job.Spec.Repository)
	require.Equal(t, provisioning.JobActionPullRequest, job.Spec.Action)
	require.NotNil(t, job.Spec.PullRequest)
	require.Equal(t, 7, job.Spec.PullRequest.PR)
}

func requireReplayDropped(t *testing.T, got recordedResponse) {
	t.Helper()
	require.NoError(t, got.err)
	require.Equal(t, http.StatusOK, got.code)
	rsp, ok := got.obj.(*provisioning.WebhookResponse)
	require.True(t, ok, "expected a webhook response, got %T", got.obj)
	require.Nil(t, rsp.Job)
	require.Equal(t, "ok", rsp.Message)
}

func TestGitHubWebhookCaseVariantDoesNotEnqueueAnotherPull(t *testing.T) {
	h := newReplayHarness(t)

	requirePullJob(t, h.deliver(pushBody, nil))
	require.Len(t, h.jobs(), 1)

	// The sync job is still in the store. A second copy must be dropped before
	// insert, not rejected because the deterministic job name is taken.
	upper := uppercaseHexSignature(t, sign(sha256.New, webhookSecretPlaceholder, pushBody))
	requireReplayDropped(t, h.deliver(pushBody, func(header http.Header) {
		header.Set(githubSignature256Header, upper)
	}))
	require.Len(t, h.jobs(), 1)
}

func TestGitHubWebhookCaseVariantAfterPullJobCompletedDoesNotEnqueue(t *testing.T) {
	h := newReplayHarness(t)

	requirePullJob(t, h.deliver(pushBody, nil))
	h.finishJobs()

	// The worker has deleted the job, so the deterministic name is free. A
	// different hex casing of the captured signature must still not create one.
	upper := uppercaseHexSignature(t, sign(sha256.New, webhookSecretPlaceholder, pushBody))
	flipped := flipFirstHexLetter(t, sign(sha256.New, webhookSecretPlaceholder, pushBody))
	require.NotEqual(t, upper, flipped)

	requireReplayDropped(t, h.deliver(pushBody, func(header http.Header) {
		header.Set(githubSignature256Header, flipped)
	}))
	require.Empty(t, h.jobs())

	requireReplayDropped(t, h.deliver(pushBody, func(header http.Header) {
		header.Set(githubSignature256Header, upper)
	}))
	require.Empty(t, h.jobs())
}

func TestGitHubWebhookSHA1OnlyDoesNotEnqueuePull(t *testing.T) {
	h := newReplayHarness(t)

	requirePullJob(t, h.deliver(pushBody, nil))
	h.finishJobs()

	got := h.deliver(pushBody, func(header http.Header) {
		header.Del(githubSignature256Header)
	})
	require.Truef(t, apierrors.IsUnauthorized(got.err), "sha1-only replay status %d err %v object %T", got.code, got.err, got.obj)
	require.Empty(t, h.jobs())
}

func TestGitHubWebhookSHA1OnlyIsRejectedWithoutPriorDelivery(t *testing.T) {
	h := newReplayHarness(t)

	got := h.deliver(pushBody, func(header http.Header) {
		header.Del(githubSignature256Header)
	})
	require.Truef(t, apierrors.IsUnauthorized(got.err), "sha1-only delivery status %d err %v object %T", got.code, got.err, got.obj)
	require.Empty(t, h.jobs())
}

func TestGitHubWebhookCaseVariantDoesNotEnqueueAnotherPullRequest(t *testing.T) {
	h := newReplayHarness(t)

	first := h.deliver(pullRequestBody, func(header http.Header) {
		header.Set("X-GitHub-Event", "pull_request")
	})
	requirePullRequestJob(t, first)
	require.Len(t, h.jobs(), 1)
	h.finishJobs()

	upper := uppercaseHexSignature(t, sign(sha256.New, webhookSecretPlaceholder, pullRequestBody))
	requireReplayDropped(t, h.deliver(pullRequestBody, func(header http.Header) {
		header.Set("X-GitHub-Event", "pull_request")
		header.Set(githubSignature256Header, upper)
	}))
	require.Empty(t, h.jobs())
}

func TestGitHubWebhookExactReplayAndDeliveryIDDoNotEnqueue(t *testing.T) {
	h := newReplayHarness(t)

	requirePullJob(t, h.deliver(pushBody, nil))
	h.finishJobs()

	requireReplayDropped(t, h.deliver(pushBody, nil))
	require.Empty(t, h.jobs())

	requireReplayDropped(t, h.deliver(pushBody, func(header http.Header) {
		header.Set("X-GitHub-Delivery", "delivery-fresh")
	}))
	require.Empty(t, h.jobs())
}

func TestGitHubWebhookDistinctPushStillEnqueuesAfterPriorJob(t *testing.T) {
	h := newReplayHarness(t)

	requirePullJob(t, h.deliver(pushBody, nil))
	h.finishJobs()

	requirePullJob(t, h.deliver(otherPushBody, nil))
	require.Len(t, h.jobs(), 1)
	require.Equal(t, provisioning.JobActionPull, h.jobs()[0].Spec.Action)
	require.Equal(t, replayRepositoryName, h.jobs()[0].Spec.Repository)
}

func TestGitHubWebhookInvalidSignatureDoesNotEnqueue(t *testing.T) {
	h := newReplayHarness(t)

	got := h.deliver(pushBody, func(header http.Header) {
		header.Set(githubSignature256Header, "sha256=0000000000000000000000000000000000000000000000000000000000000000")
		header.Del(githubSignature1Header)
	})
	require.Error(t, got.err)
	require.True(t, apierrors.IsUnauthorized(got.err), "invalid signature returned %v", got.err)
	require.Empty(t, h.jobs())
}

func TestGitHubWebhookMismatchedRepositoryDoesNotEnqueue(t *testing.T) {
	h := newReplayHarness(t)

	got := h.deliver(mismatchedPushBody, nil)
	require.Error(t, got.err)
	require.True(t, apierrors.IsBadRequest(got.err), "mismatched repository returned %v", got.err)
	require.Empty(t, h.jobs())
}

func TestGitHubWebhookAnonymousDeliveryIsAuthorizedAndEnqueues(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, webhookPath(), nil)
	require.Empty(t, req.Header.Values("Authorization"))
	require.Empty(t, req.Header.Values("Cookie"))

	authReq := &authn.Request{HTTPRequest: req, OrgID: 1}
	require.False(t, clients.ProvideAPIKey(nil, nil).Test(context.Background(), authReq))
	require.False(t, clients.ProvideBasic(nil).Test(context.Background(), authReq))

	provisioningClient := clients.ProvideProvisioning()
	require.True(t, provisioningClient.Test(context.Background(), authReq))
	ident, err := provisioningClient.Authenticate(context.Background(), authReq)
	require.NoError(t, err)
	require.True(t, ident.IsIdentityType(types.TypeAnonymous))

	ctx := identity.WithRequester(context.Background(), ident)
	require.False(t, identity.IsServiceIdentity(ctx))

	attrs := authorizer.AttributesRecord{
		ResourceRequest: true,
		Namespace:       replayNamespace,
		Resource:        provisioning.RepositoryResourceInfo.GetName(),
		Subresource:     "webhook",
		Name:            replayRepositoryName,
		Verb:            "create",
	}
	extra := NewWebhookExtra(NewWebhookConnector(true, &replayCore{}, nil, prometheus.NewRegistry(), nil))
	// Same order as Grafana's authorizer chain: impersonation, privileged groups,
	// namespace, then the API authorizer. The API authorizer allows the webhook
	// subresource before any repository RBAC check.
	apiAuth := authorizer.AuthorizerFunc(func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
		if identity.IsServiceIdentity(ctx) {
			return authorizer.DecisionAllow, "", nil
		}
		return extra.Authorize(ctx, a)
	})
	chain, err := union.New(
		union.NamedAuthorizer{AuthorizerName: "impersonation", Authorizer: grafanauthorizer.NewImpersonationAuthorizer()},
		union.NamedAuthorizer{AuthorizerName: "privileged-groups", Authorizer: authorizerfactory.NewPrivilegedGroups(k8suser.SystemPrivilegedGroup)},
		union.NamedAuthorizer{AuthorizerName: "namespace", Authorizer: grafanauthorizer.NewNamespaceAuthorizer()},
		union.NamedAuthorizer{AuthorizerName: "api", Authorizer: apiAuth},
	)
	require.NoError(t, err)

	decision, _, err := chain.Authorize(ctx, attrs)
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision)

	h := newReplayHarness(t)
	requirePullJob(t, h.deliver(pushBody, nil))
	require.Len(t, h.jobs(), 1)
}
