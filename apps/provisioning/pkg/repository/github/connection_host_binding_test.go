package github_test

import (
	"context"
	"encoding/base64"
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
	"go.opentelemetry.io/otel/trace/noop"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/connection"
	ghconnection "github.com/grafana/grafana/apps/provisioning/pkg/connection/github"
	"github.com/grafana/grafana/apps/provisioning/pkg/connection/githuboauth"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/github"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
)

const (
	// Obvious placeholders. They are not credentials; the stand-in below chooses
	// them so a test can recognise a value the product copied onto a request.
	placeholderAppJWT        = "placeholder-app-jwt"
	placeholderInstallation  = "placeholder-installation-token"
	placeholderExistingToken = "placeholder-existing-token"
	placeholderOAuthAccess   = "placeholder-oauth-access-token"
	placeholderOAuthClient   = "placeholder-oauth-client-secret"
	placeholderUserToken     = "placeholder-user-token"
	placeholderPrivateKey    = "placeholder-private-key"
	installationID           = "456"
	repositoryOwner          = "acme"
	repositoryName           = "real-repo"
)

// connectionCredentialHosts records where real clients present a connection
// credential. The transport is only a stand-in for the network: go-github
// (v82.0.0) and nanogit (v1.6.0) still build the request, including the
// Authorization header, and this type forwards that request to a local server.
type connectionCredentialHosts struct {
	mu sync.Mutex

	mintRepos       []string
	credentialPaths map[string][]string
	watched         []string
}

func newCredentialObserver(watched ...string) *connectionCredentialHosts {
	return &connectionCredentialHosts{
		credentialPaths: map[string][]string{},
		watched:         watched,
	}
}

func (o *connectionCredentialHosts) observe(host, method, path, auth string, body []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if method == http.MethodPost && strings.HasSuffix(path, "/app/installations/"+installationID+"/access_tokens") {
		var payload struct {
			Repositories []string `json:"repositories"`
		}
		_ = json.Unmarshal(body, &payload)
		o.mintRepos = append(o.mintRepos, payload.Repositories...)
	}
	if !authorizationCarries(auth, o.watched...) {
		return
	}
	o.credentialPaths[host] = append(o.credentialPaths[host], method+" "+path)
}

func (o *connectionCredentialHosts) minted() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.mintRepos) > 0
}

func (o *connectionCredentialHosts) pathsOutside(allowed ...string) map[string][]string {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := map[string][]string{}
	for host, paths := range o.credentialPaths {
		if !hostAllowed(host, allowed) {
			out[host] = append([]string(nil), paths...)
		}
	}
	return out
}

func (o *connectionCredentialHosts) pathsOn(host string) []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.credentialPaths[host]...)
}

func hostAllowed(host string, allowed []string) bool {
	for _, candidate := range allowed {
		if host == candidate {
			return true
		}
	}
	return false
}

// authorizationCarries reports whether auth presents one of the watched values.
// nanogit sets HTTP basic authentication (rawclient.go sets the header from the
// password), so the value is recovered from that encoding. The recovered bytes
// are not logged.
func authorizationCarries(auth string, watched ...string) bool {
	if auth == "" {
		return false
	}
	plain := auth
	const basic = "Basic "
	if strings.HasPrefix(auth, basic) {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, basic))
		if err != nil {
			return false
		}
		plain = string(decoded)
	}
	for _, secret := range watched {
		if secret != "" && strings.Contains(plain, secret) {
			return true
		}
	}
	return false
}

// hostRewriteTransport forwards the request the real client built to a local
// server, preserving the path and headers. Hosts that are not in dest fail
// closed so a test cannot leave the machine.
type hostRewriteTransport struct {
	base http.RoundTripper
	dest map[string]string
	obs  *connectionCredentialHosts
}

func (t *hostRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	var body []byte
	if req.Body != nil && req.GetBody != nil {
		reader, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		body, err = io.ReadAll(reader)
		reader.Close()
		if err != nil {
			return nil, err
		}
	}
	if t.obs != nil {
		t.obs.observe(req.URL.Hostname(), req.Method, req.URL.EscapedPath(), req.Header.Get("Authorization"), body)
	}

	dest, ok := t.dest[host]
	if !ok {
		return nil, errUnexpectedHost(host)
	}
	target, err := url.Parse(dest)
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	clone.URL.Scheme = target.Scheme
	clone.URL.Host = target.Host
	clone.Host = target.Host
	return t.base.RoundTrip(clone)
}

type unexpectedHostError struct{ host string }

func (e unexpectedHostError) Error() string {
	return "refusing request to unexpected host " + e.host
}

func errUnexpectedHost(host string) error { return unexpectedHostError{host: host} }

func installTransport(t *testing.T, obs *connectionCredentialHosts, hosts map[string]string) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = &hostRewriteTransport{
		base: previous,
		dest: hosts,
		obs:  obs,
	}
	t.Cleanup(func() { http.DefaultTransport = previous })
}

func githubAPIServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.EscapedPath(), "/app/installations/"+installationID+"/access_tokens"):
			_, _ = io.WriteString(w, `{"token":"`+placeholderInstallation+`","expires_at":"2099-01-01T00:00:00Z"}`)
		case r.Method == http.MethodGet && strings.Contains(r.URL.EscapedPath(), "/repos/"+repositoryOwner+"/"+repositoryName) && !strings.Contains(r.URL.EscapedPath(), "/branches/"):
			_, _ = io.WriteString(w, `{"id":1,"name":"`+repositoryName+`","default_branch":"main"}`)
		case strings.Contains(r.URL.EscapedPath(), "info/refs"):
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"Not Found"}`)
		}
	}))
}

func useRepositoryClients(ctx context.Context, built repository.Repository) {
	gh, ok := built.(github.GithubRepository)
	if !ok {
		return
	}
	// Same order as RepositoryController.process: an empty branch is resolved
	// before the health check calls Test.
	if gh.GetCurrentBranch() == "" {
		if branch, err := gh.GetDefaultBranch(ctx); err == nil {
			gh.SetBranch(branch)
		}
	}
	tester := repository.NewTester()
	_, _ = tester.Test(ctx, gh)
	branch := gh.GetCurrentBranch()
	if branch == "" {
		branch = "main"
	}
	_, _ = gh.Client().GetBranchProtection(ctx, branch)
	_, _ = gh.Client().GetRulesets(ctx, branch)
	_, _ = gh.History(ctx, "dashboard.json", branch)
	_, _ = gh.ListRefs(ctx)
}

type harness struct {
	t     *testing.T
	obs   *connectionCredentialHosts
	repos repository.Factory
	conns connection.Factory
	ctx   context.Context
}

func newHarness(t *testing.T, watched []string, extraHosts ...string) *harness {
	t.Helper()
	server := githubAPIServer()
	t.Cleanup(server.Close)

	obs := newCredentialObserver(watched...)
	hosts := map[string]string{
		"api.github.com": server.URL,
		"github.com":     server.URL,
		"www.github.com": server.URL,
		"ghes.example":   server.URL,
	}
	for _, host := range extraHosts {
		hosts[host] = server.URL
	}
	installTransport(t, obs, hosts)

	tracer := noop.NewTracerProvider().Tracer("connection-host-binding")
	repoFactoryGH := github.ProvideFactory()
	repoExtra := github.Extra(repository.ProvideDecrypter(nil, nil), repoFactoryGH, nil, false, nil, nil)
	repos, err := repository.ProvideFactory(map[provisioning.RepositoryType]struct{}{
		provisioning.GitHubRepositoryType: {},
	}, []repository.Extra{repoExtra}, tracer)
	require.NoError(t, err)

	decrypter := connection.ProvideDecrypter(nil, nil)
	connExtra := ghconnection.Extra(decrypter, ghconnection.ProvideFactory())
	oauthExtra := githuboauth.Extra(decrypter, repoFactoryGH)
	conns, err := connection.ProvideFactory(map[provisioning.ConnectionType]struct{}{
		provisioning.GithubConnectionType:      {},
		provisioning.GithubOAuthConnectionType: {},
	}, []connection.Extra{connExtra, oauthExtra}, tracer)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return &harness{t: t, obs: obs, repos: repos, conns: conns, ctx: ctx}
}

func githubAppConnection() *provisioning.Connection {
	return &provisioning.Connection{
		ObjectMeta: metav1.ObjectMeta{Name: "gh-app", Namespace: "org"},
		Spec: provisioning.ConnectionSpec{
			Title: "GitHub App",
			Type:  provisioning.GithubConnectionType,
			GitHub: &provisioning.GitHubConnectionConfig{
				AppID:          "1",
				InstallationID: installationID,
			},
		},
		Secure: provisioning.ConnectionSecure{
			PrivateKey: common.InlineSecureValue{Create: common.NewSecretValue(placeholderPrivateKey)},
			Token:      common.InlineSecureValue{Create: common.NewSecretValue(placeholderAppJWT)},
		},
	}
}

func githubOAuthConnection() *provisioning.Connection {
	return &provisioning.Connection{
		ObjectMeta: metav1.ObjectMeta{Name: "gh-oauth", Namespace: "org"},
		Spec: provisioning.ConnectionSpec{
			Title: "GitHub OAuth",
			Type:  provisioning.GithubOAuthConnectionType,
			OAuth: &provisioning.ConnectionOAuthConfig{ClientID: "placeholder-client"},
		},
		Secure: provisioning.ConnectionSecure{
			ClientSecret: common.InlineSecureValue{Create: common.NewSecretValue(placeholderOAuthClient)},
			Token:        common.InlineSecureValue{Create: common.NewSecretValue(`{"access_token":"` + placeholderOAuthAccess + `","token_type":"Bearer"}`)},
		},
	}
}

func repositoryFor(rawURL, connectionName, existingToken string) *provisioning.Repository {
	repo := &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: "sync-repo", Namespace: "org", Generation: 1},
		Spec: provisioning.RepositorySpec{
			Title: "Sync",
			Type:  provisioning.GitHubRepositoryType,
			GitHub: &provisioning.GitHubRepositoryConfig{
				URL: rawURL,
			},
			Workflows: []provisioning.Workflow{provisioning.WriteWorkflow},
		},
	}
	if connectionName != "" {
		repo.Spec.Connection = &provisioning.ConnectionInfo{Name: connectionName}
	}
	if existingToken != "" {
		repo.Secure.Token.Create = common.NewSecretValue(existingToken)
	}
	return repo
}

func (h *harness) buildAndUse(repo *provisioning.Repository) {
	h.t.Helper()
	built, err := h.repos.Build(h.ctx, repo)
	if err != nil {
		outside := h.obs.pathsOutside()
		if len(outside) > 0 || h.obs.minted() {
			h.t.Fatalf("repository build refused only after a connection credential was minted or presented: minted=%v presentations=%v", h.obs.minted(), outside)
		}
		return
	}
	useRepositoryClients(h.ctx, built)
}

func (h *harness) requireNoCredentialOutside(allowed ...string) {
	h.t.Helper()
	outside := h.obs.pathsOutside(allowed...)
	if len(outside) > 0 {
		h.t.Fatalf("connection credential was presented outside the connection host: %v", outside)
	}
}

// TestGitHubAppRepositoryHostMustMatchConnection is the create path: the
// repository has a connection and no token yet, so reconciliation mints one
// and then looks up the default branch and runs the health check.
func TestGitHubAppRepositoryHostMustMatchConnection(t *testing.T) {
	urls := []string{
		"https://attacker.example/" + repositoryOwner + "/" + repositoryName,
		"https://github.com.attacker.example/" + repositoryOwner + "/" + repositoryName,
		"https://github.com@" + "attacker.example/" + repositoryOwner + "/" + repositoryName,
		"https://attacker.example:8443/" + repositoryOwner + "/" + repositoryName,
	}
	for _, rawURL := range urls {
		t.Run(rawURL, func(t *testing.T) {
			parsed, err := url.Parse(rawURL)
			require.NoError(t, err)
			h := newHarness(t, []string{placeholderInstallation}, parsed.Hostname(), parsed.Host)

			conn, err := h.conns.Build(h.ctx, githubAppConnection())
			require.NoError(t, err)
			repo := repositoryFor(rawURL, "gh-app", "")

			token, err := conn.GenerateRepositoryToken(h.ctx, repo)
			if err != nil {
				if h.obs.minted() || len(h.obs.pathsOutside()) > 0 {
					t.Fatalf("token request was refused only after minting or presenting a connection credential: minted=%v presentations=%v", h.obs.minted(), h.obs.pathsOutside())
				}
				return
			}
			t.Errorf("GenerateRepositoryToken accepted %s, whose host is not the connection GitHub host", rawURL)
			repo.Secure.Token.Create = token.Token
			h.buildAndUse(repo)
			if h.obs.minted() {
				t.Errorf("installation token was minted for %v from the URL path before the host was bound to the connection", h.obs.mintRepos)
			}
			h.requireNoCredentialOutside()
		})
	}
}

// TestExistingTokenIsNotReusedAgainstADifferentHost is the URL update path.
// Reconciliation keeps the stored token when it has not expired, then builds
// clients for the new URL.
func TestExistingTokenIsNotReusedAgainstADifferentHost(t *testing.T) {
	rawURL := "https://attacker.example/" + repositoryOwner + "/" + repositoryName
	h := newHarness(t, []string{placeholderExistingToken, placeholderInstallation}, "attacker.example")
	repo := repositoryFor(rawURL, "gh-app", placeholderExistingToken)
	repo.Generation = 2

	h.buildAndUse(repo)
	h.requireNoCredentialOutside()
}

// TestGitHubOAuthRepositoryHostMustMatchConnection covers an enabled GitHub
// OAuth connection, which returns the stored access token for any repository
// of the matching type.
func TestGitHubOAuthRepositoryHostMustMatchConnection(t *testing.T) {
	rawURL := "https://attacker.example/" + repositoryOwner + "/" + repositoryName
	h := newHarness(t, []string{placeholderOAuthAccess}, "attacker.example")

	conn, err := h.conns.Build(h.ctx, githubOAuthConnection())
	require.NoError(t, err)
	repo := repositoryFor(rawURL, "gh-oauth", "")

	token, err := conn.GenerateRepositoryToken(h.ctx, repo)
	if err != nil {
		h.requireNoCredentialOutside()
		return
	}
	t.Errorf("GenerateRepositoryToken returned the OAuth access token for %s", rawURL)
	repo.Secure.Token.Create = token.Token
	h.buildAndUse(repo)
	h.requireNoCredentialOutside()
}

// TestGitHubAppRepositoryOnGitHubHostStillReceivesInstallationToken keeps a
// matching github.com URL working: the installation token is minted and then
// used against api.github.com and github.com.
func TestGitHubAppRepositoryOnGitHubHostStillReceivesInstallationToken(t *testing.T) {
	cases := []string{
		"https://github.com/" + repositoryOwner + "/" + repositoryName,
		"https://www.github.com/" + repositoryOwner + "/" + repositoryName,
	}
	for _, rawURL := range cases {
		t.Run(rawURL, func(t *testing.T) {
			h := newHarness(t, []string{placeholderInstallation})
			conn, err := h.conns.Build(h.ctx, githubAppConnection())
			require.NoError(t, err)
			repo := repositoryFor(rawURL, "gh-app", "")

			token, err := conn.GenerateRepositoryToken(h.ctx, repo)
			require.NoError(t, err)
			require.False(t, token.Token.IsZero())
			h.obs.mu.Lock()
			mintedFor := append([]string(nil), h.obs.mintRepos...)
			h.obs.mu.Unlock()
			require.Equal(t, []string{repositoryName}, mintedFor)

			repo.Secure.Token.Create = token.Token
			h.buildAndUse(repo)
			require.NotEmpty(t, h.obs.pathsOn("api.github.com"), "GitHub API client did not present the installation token to api.github.com")
			gitHost := "github.com"
			if strings.Contains(rawURL, "www.github.com") {
				gitHost = "www.github.com"
			}
			require.NotEmpty(t, h.obs.pathsOn(gitHost), "git client did not present the installation token to %s", gitHost)
			h.requireNoCredentialOutside("api.github.com", "github.com", "www.github.com")
		})
	}
}

type enterpriseConfig struct {
	serverURL string
}

func (c enterpriseConfig) AppID() string          { return "1" }
func (c enterpriseConfig) InstallationID() string { return installationID }
func (c enterpriseConfig) CustomServerURL() string {
	return c.serverURL
}

// TestEnterpriseServerURLBindsRepositoryHost uses Connection.GenerateRepositoryToken
// with the ConnectionConfig enterprise code supplies. An empty CustomServerURL
// is the github.com config; a non-empty one is the enterprise server.
func TestEnterpriseServerURLBindsRepositoryHost(t *testing.T) {
	const serverURL = "https://ghes.example"
	connObj := githubAppConnection()
	conn := ghconnection.NewConnectionWithCustomConfig(connObj, ghconnection.ProvideFactory(), ghconnection.ConnectionSecrets{
		PrivateKey: common.NewSecretValue(placeholderPrivateKey),
		Token:      common.NewSecretValue(placeholderAppJWT),
	}, enterpriseConfig{serverURL: serverURL})

	t.Run("matching server", func(t *testing.T) {
		h := newHarness(t, []string{placeholderInstallation})
		repo := repositoryFor(serverURL+"/"+repositoryOwner+"/"+repositoryName, "gh-app", "")
		token, err := conn.GenerateRepositoryToken(h.ctx, repo)
		require.NoError(t, err)
		repo.Secure.Token.Create = token.Token
		h.buildAndUse(repo)
		require.NotEmpty(t, h.obs.pathsOn("ghes.example"))
		h.requireNoCredentialOutside("ghes.example")
	})

	t.Run("different host", func(t *testing.T) {
		rawURL := "https://attacker.example/" + repositoryOwner + "/" + repositoryName
		h := newHarness(t, []string{placeholderInstallation}, "attacker.example")
		repo := repositoryFor(rawURL, "gh-app", "")
		token, err := conn.GenerateRepositoryToken(h.ctx, repo)
		if err != nil {
			if h.obs.minted() || len(h.obs.pathsOutside("ghes.example")) > 0 {
				t.Fatalf("refused only after a credential side effect: minted=%v presentations=%v", h.obs.minted(), h.obs.pathsOutside("ghes.example"))
			}
			return
		}
		t.Errorf("GenerateRepositoryToken accepted %s for a connection bound to %s", rawURL, serverURL)
		repo.Secure.Token.Create = token.Token
		h.buildAndUse(repo)
		if h.obs.minted() {
			t.Errorf("installation token was minted for %v", h.obs.mintRepos)
		}
		h.requireNoCredentialOutside("ghes.example")
	})
}

// TestUserTokenStillFollowsRepositoryURL guards a repository that carries its
// own token and no connection: that token is meant for the URL the user typed.
func TestUserTokenStillFollowsRepositoryURL(t *testing.T) {
	rawURL := "https://ghes.example/" + repositoryOwner + "/" + repositoryName
	h := newHarness(t, []string{placeholderUserToken})
	repo := repositoryFor(rawURL, "", placeholderUserToken)

	h.buildAndUse(repo)
	require.NotEmpty(t, h.obs.pathsOn("ghes.example"), "user token was not presented to the repository URL host")
	require.False(t, h.obs.minted(), "a user token must not mint an installation token")
}

func TestAdmissionRejectsMismatchedConnectionHost(t *testing.T) {
	tracer := noop.NewTracerProvider().Tracer("connection-host-binding")
	extra := github.Extra(nil, nil, nil, false, nil, nil)
	factory, err := repository.ProvideFactory(map[provisioning.RepositoryType]struct{}{
		provisioning.GitHubRepositoryType: {},
	}, []repository.Extra{extra}, tracer)
	require.NoError(t, err)
	validator := repository.NewValidator(false, factory, repository.WithURLValidator(
		repository.NewURLValidator(repository.Allowlist{}, func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
		}),
	))

	cases := []struct {
		name       string
		rawURL     string
		connection bool
		userToken  bool
		generation int64
		wantErr    bool
	}{
		{name: "create connection on github.com", rawURL: "https://github.com/acme/real-repo", connection: true},
		{name: "create connection on www.github.com", rawURL: "https://www.github.com/acme/real-repo", connection: true},
		{name: "create connection on another host", rawURL: "https://attacker.example/acme/real-repo", connection: true, wantErr: true},
		{name: "create connection on lookalike host", rawURL: "https://github.com.attacker.example/acme/real-repo", connection: true, wantErr: true},
		{name: "update connection url to another host", rawURL: "https://attacker.example/acme/real-repo", connection: true, userToken: true, generation: 2, wantErr: true},
		{name: "user token on another host", rawURL: "https://ghes.example/acme/real-repo", userToken: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &provisioning.Repository{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "sync-repo",
					Namespace:  "org",
					Generation: tc.generation,
					Finalizers: []string{repository.CleanFinalizer},
				},
				Spec: provisioning.RepositorySpec{
					Title:     "Sync",
					Type:      provisioning.GitHubRepositoryType,
					Workflows: []provisioning.Workflow{provisioning.WriteWorkflow},
					GitHub:    &provisioning.GitHubRepositoryConfig{URL: tc.rawURL, Branch: "main"},
				},
			}
			if tc.connection {
				repo.Spec.Connection = &provisioning.ConnectionInfo{Name: "gh-app"}
			}
			if tc.userToken {
				repo.Secure.Token.Create = common.NewSecretValue(placeholderUserToken)
			}

			list := validator.Validate(context.Background(), repo)
			if tc.wantErr {
				require.NotEmpty(t, list, "admission accepted a connection repository whose URL host is not the connection GitHub host")
				return
			}
			require.Empty(t, list)
		})
	}
}
