package githuboauth_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/connection"
	"github.com/grafana/grafana/apps/provisioning/pkg/connection/githuboauth"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/github"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/infra/tracing"
)

// placeholderAccessToken stands in for the GitHub user access token stored on
// the OAuth connection. It is not a credential.
const placeholderAccessToken = "PLACEHOLDER_ACCESS_TOKEN"

// placeholderPAT stands in for a personal access token typed onto a repository.
// It is not a credential.
const placeholderPAT = "PLACEHOLDER_PAT"

// placeholderClientSecret stands in for the OAuth app client secret.
const placeholderClientSecret = "PLACEHOLDER_CLIENT_SECRET"

// placeholderWebhookSecret stands in for a webhook secret passed to hook registration.
const placeholderWebhookSecret = "PLACEHOLDER_WEBHOOK_SECRET"

// TestGitHubOAuthRepositoryToken_AllowsGitHubHost keeps the authorized host working:
// github.com and www.github.com are the hosts the GitHub OAuth endpoints belong to.
func TestGitHubOAuthRepositoryToken_AllowsGitHubHost(t *testing.T) {
	t.Parallel()
	conn := githubOAuthConnection(t)

	for _, rawURL := range []string{
		"https://github.com/owner/repo",
		"https://www.github.com/owner/repo",
		"https://github.com:443/owner/repo",
	} {
		t.Run(rawURL, func(t *testing.T) {
			t.Parallel()
			issued, err := conn.GenerateRepositoryToken(t.Context(), githubRepo(rawURL))
			require.NoError(t, err)
			require.NotNil(t, issued)
			require.Equal(t, placeholderAccessToken, string(issued.Token))
		})
	}
}

// TestGitHubOAuthRepositoryToken_RefusesForeignHost covers repository URLs an
// organization administrator can store. Admission accepts a public HTTPS host
// that parses as owner/repo; the connection must still refuse to hand back the
// authorizing user's access token for any host other than the OAuth provider.
func TestGitHubOAuthRepositoryToken_RefusesForeignHost(t *testing.T) {
	t.Parallel()
	conn := githubOAuthConnection(t)
	repos := repositoryFactory(t)
	admission := repository.NewValidator(false, repos, repository.WithURLValidator(publicURLValidator()))

	publicURL := "https://public.example/owner/repo"
	repo := githubRepo(publicURL)
	require.Empty(t, admission.Validate(t.Context(), repo),
		"a public owner/repo URL is accepted for a github repository that uses a connection")

	foreign := []string{
		publicURL,
		"https://github.com.public.example/owner/repo",
		"https://github.com@public.example/owner/repo",
		"https://public.example/github.com/owner",
		"https://acme.ghe.com/owner/repo",
		"https://1.2.3.4/owner/repo",
		"http://public.example/owner/repo",
		"https://api.github.com.public.example/owner/repo",
	}
	for _, rawURL := range foreign {
		t.Run(rawURL, func(t *testing.T) {
			t.Parallel()
			issued, err := conn.GenerateRepositoryToken(t.Context(), githubRepo(rawURL))
			require.Error(t, err)
			if issued != nil {
				require.NotContains(t, string(issued.Token), placeholderAccessToken)
			}
		})
	}
}

// TestGitHubOAuthCopiedToken_NotSentToRepositoryHostAfterURLChange is the path
// the repository controller and the repository test connector share: the
// connection issues a token, that token is written onto the repository, then
// the git client and the GitHub API client use it.
//
// The token is issued while the URL is github.com. The URL is then changed to
// the host that will actually be dialed, including a form whose string starts
// with the GitHub origin while its host is the test server. A check of the URL
// from the issuance call, or a prefix check of the same string, still sends
// the token. The clients must not present it.
func TestGitHubOAuthCopiedToken_NotSentToRepositoryHostAfterURLChange(t *testing.T) {
	srv, saw := newRepositoryHost(t)
	conn := githubOAuthConnection(t)
	repos := repositoryFactory(t)

	issued, err := conn.GenerateRepositoryToken(t.Context(), githubRepo("https://github.com/owner/repo"))
	require.NoError(t, err)
	require.NotNil(t, issued)
	require.Equal(t, placeholderAccessToken, string(issued.Token))

	target, err := url.Parse(srv.URL)
	require.NoError(t, err)
	target.Path = "/owner/repo"
	prefixed := *target
	prefixed.User = url.User("github.com")

	for _, rawURL := range []string{target.String(), prefixed.String()} {
		t.Run(rawURL, func(t *testing.T) {
			saw.reset()
			repo := githubRepo("https://github.com/owner/repo")
			// Same assignment as RepositoryController.generateRepositoryToken and
			// the repository test connector: the issued value is stored on the
			// repository, then the repository is built and used.
			repo.Secure.Token.Create = issued.Token
			repo.Spec.GitHub.URL = rawURL
			repo.Spec.Workflows = []provisioning.Workflow{provisioning.WriteWorkflow}

			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()

			built, buildErr := repos.Build(ctx, repo)
			if buildErr == nil {
				exerciseRepository(ctx, built)
			}
			require.Falsef(t, saw.presented(placeholderAccessToken),
				"git or GitHub API request presented the connection access token to %s", rawURL)
		})
	}
}

// TestGitHubPAT_CustomHostReceivesConfiguredToken is the supported case: a token
// configured on the repository itself is sent to that repository's host. OAuth
// host checks must leave this path in place.
func TestGitHubPAT_CustomHostReceivesConfiguredToken(t *testing.T) {
	srv, saw := newRepositoryHost(t)
	repos := repositoryFactory(t)

	rawURL := srv.URL + "/owner/repo"
	repo := githubRepo(rawURL)
	repo.Spec.Connection = nil
	repo.Secure.Token.Create = common.RawSecureValue(placeholderPAT)
	repo.Spec.Workflows = []provisioning.Workflow{provisioning.WriteWorkflow}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	built, err := repos.Build(ctx, repo)
	require.NoError(t, err)
	exerciseRepository(ctx, built)
	require.True(t, saw.presented(placeholderPAT))
}

func githubOAuthConnection(t *testing.T) connection.Connection {
	t.Helper()
	stored, err := json.Marshal(&oauth2.Token{AccessToken: placeholderAccessToken})
	require.NoError(t, err)

	factory, err := connection.ProvideFactory(
		map[provisioning.ConnectionType]struct{}{
			provisioning.GithubOAuthConnectionType: {},
		},
		[]connection.Extra{
			githuboauth.Extra(connection.ProvideDecrypter(nil, nil), github.ProvideFactory()),
		},
		tracing.NewNoopTracerService(),
	)
	require.NoError(t, err)

	conn, err := factory.Build(t.Context(), &provisioning.Connection{
		ObjectMeta: metav1.ObjectMeta{Name: "user-oauth", Namespace: "org"},
		Spec: provisioning.ConnectionSpec{
			Title: "GitHub",
			Type:  provisioning.GithubOAuthConnectionType,
			OAuth: &provisioning.ConnectionOAuthConfig{ClientID: "placeholder-client-id"},
		},
		Secure: provisioning.ConnectionSecure{
			ClientSecret: common.InlineSecureValue{Create: common.RawSecureValue(placeholderClientSecret)},
			Token:        common.InlineSecureValue{Create: common.RawSecureValue(stored)},
		},
	})
	require.NoError(t, err)
	return conn
}

func repositoryFactory(t *testing.T) repository.Factory {
	t.Helper()
	factory, err := repository.ProvideFactory(
		map[provisioning.RepositoryType]struct{}{
			provisioning.GitHubRepositoryType: {},
		},
		[]repository.Extra{
			github.Extra(repository.ProvideDecrypter(nil, nil), github.ProvideFactory(), nil, false, nil, nil),
		},
		tracing.NewNoopTracerService(),
	)
	require.NoError(t, err)
	return factory
}

func githubRepo(rawURL string) *provisioning.Repository {
	return &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "dashboards",
			Namespace:  "org",
			Finalizers: []string{repository.CleanFinalizer, repository.RemoveOrphanResourcesFinalizer},
		},
		Spec: provisioning.RepositorySpec{
			Title: "Dashboards",
			Type:  provisioning.GitHubRepositoryType,
			GitHub: &provisioning.GitHubRepositoryConfig{
				URL: rawURL,
			},
			Connection: &provisioning.ConnectionInfo{Name: "user-oauth"},
			Workflows:  []provisioning.Workflow{provisioning.WriteWorkflow},
		},
	}
}

func publicURLValidator() *repository.URLValidator {
	allowlist, err := repository.NewAllowlist(nil)
	if err != nil {
		panic(err)
	}
	return repository.NewURLValidator(allowlist, func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
}

// exerciseRepository runs the calls that follow a token copy: empty-branch
// reconciliation asks the GitHub API for the default branch, health checks call
// Test (git, then branch protection), sync lists refs and commit history, and
// hook setup registers a webhook. All of them share the copied token.
func exerciseRepository(ctx context.Context, built repository.Repository) {
	gh, ok := built.(github.GithubRepository)
	if !ok {
		_, _ = built.Test(ctx)
		return
	}
	_, _ = gh.GetDefaultBranch(ctx)
	_, _ = gh.ListRefs(ctx)
	_, _ = gh.Test(ctx)
	_, _ = gh.History(ctx, "dashboards/example.json", "main")
	client := gh.Client()
	_, _ = client.GetRepository(ctx)
	_, _ = client.GetBranchProtection(ctx, "main")
	_, _ = client.GetRulesets(ctx, "main")
	_, _ = client.Commits(ctx, "dashboards/example.json", "main")
	_, _ = client.CreateWebhook(ctx, "https://grafana.example/hook", []string{"push"}, placeholderWebhookSecret)
	_, _ = client.ListRepositories(ctx)
	_ = client.CreatePullRequestComment(ctx, 1, "note")
	_, _ = client.MergeBase(ctx, "main", "topic")
}

type requestLog struct {
	mu       sync.Mutex
	headers  []string
	urlUsers []string
}

func (l *requestLog) add(r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.headers = append(l.headers, r.Header.Get("Authorization"))
	if r.URL != nil && r.URL.User != nil {
		password, _ := r.URL.User.Password()
		l.urlUsers = append(l.urlUsers, r.URL.User.Username()+"\n"+password)
	}
}

func (l *requestLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.headers = nil
	l.urlUsers = nil
}

func (l *requestLog) presented(placeholder string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, header := range l.headers {
		if headerCarries(header, placeholder) {
			return true
		}
	}
	for _, user := range l.urlUsers {
		if strings.Contains(user, placeholder) {
			return true
		}
	}
	return false
}

func headerCarries(header, placeholder string) bool {
	if header == "" || placeholder == "" {
		return false
	}
	if strings.Contains(header, placeholder) {
		return true
	}
	req := &http.Request{Header: http.Header{"Authorization": []string{header}}}
	user, password, ok := req.BasicAuth()
	if !ok {
		return false
	}
	return strings.Contains(user, placeholder) || strings.Contains(password, placeholder)
}

// newRepositoryHost is the repository URL host. TLS matches the HTTPS URLs the
// git and GitHub API clients accept; the test trust pool is installed as the
// default transport those clients use when none is injected.
func newRepositoryHost(t *testing.T) (*httptest.Server, *requestLog) {
	t.Helper()
	log := &requestLog{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	previous := http.DefaultTransport
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	t.Cleanup(func() { http.DefaultTransport = previous })
	return srv, log
}
