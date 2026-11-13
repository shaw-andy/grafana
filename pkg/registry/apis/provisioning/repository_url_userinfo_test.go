package provisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	jsonserializer "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	authlib "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/apps/provisioning/pkg/apis/auth"
	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/quotas"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/git"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/github"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	apiutils "github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/services/authz/rbac"
)

const (
	// Obvious placeholders. These are not credentials.
	cloneURLUser     = "placeholder-user"
	cloneURLPassword = "placeholder-secret"
	cloneURLToken    = "placeholder-token"
	secureTokenField = "placeholder-token-field"
)

// fixedDecisionAccessChecker is the access client the session checker consults.
// Production wires that client in front of the Viewer role fallback.
type fixedDecisionAccessChecker struct {
	allowed bool
}

func (c fixedDecisionAccessChecker) Check(context.Context, authlib.AuthInfo, authlib.CheckRequest, string) (authlib.CheckResponse, error) {
	return authlib.CheckResponse{Allowed: c.allowed}, nil
}

func (c fixedDecisionAccessChecker) Compile(context.Context, authlib.AuthInfo, authlib.ListRequest) (authlib.ItemChecker, authlib.Zookie, error) {
	return nil, nil, nil
}

type emptyRepositoryLister struct{}

func (emptyRepositoryLister) List(context.Context) ([]provisioning.Repository, error) {
	return nil, nil
}

// publicGitHostResolver stands in for DNS of a public git host. url_validator.go
// allows the URL when every resolved address is public. 8.8.8.8 is a public address,
// so the private-endpoint check takes the same branch it takes for a public git host.
func publicGitHostResolver(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
}

type repositoryAdmission struct {
	mutator   *repository.AdmissionMutator
	validator *repository.AdmissionValidator
	codec     runtime.Codec
}

func newRepositoryAdmission(t *testing.T) repositoryAdmission {
	t.Helper()

	// Same extras and defaults as ProvideProvisioningOSSRepositoryExtras and
	// ProvideFactoryFromConfig when [provisioning] repository_types is empty:
	// git and github are enabled, and http together with a token is rejected.
	enabled := map[provisioning.RepositoryType]struct{}{
		provisioning.GitRepositoryType:    {},
		provisioning.GitHubRepositoryType: {},
		provisioning.LocalRepositoryType:  {},
	}
	factory, err := repository.ProvideFactory(enabled, []repository.Extra{
		git.Extra(nil, false, nil, nil),
		github.Extra(nil, nil, nil, false, nil, nil),
	}, noop.NewTracerProvider().Tracer("test"))
	require.NoError(t, err)

	allowlist, err := repository.NewAllowlist(nil)
	require.NoError(t, err)
	structural := repository.NewValidator(
		true,
		factory,
		repository.WithURLValidator(repository.NewURLValidator(allowlist, publicGitHostResolver)),
	)
	quota := quotas.NewFixedQuotaGetter(provisioning.QuotaStatus{MaxRepositories: 10})

	scheme := runtime.NewScheme()
	require.NoError(t, provisioning.AddKnownTypes(provisioning.SchemeGroupVersion, scheme))
	metav1.AddToGroupVersion(scheme, provisioning.SchemeGroupVersion)

	return repositoryAdmission{
		mutator: repository.NewAdmissionMutator(factory, 10*time.Second),
		validator: repository.NewAdmissionValidator(
			[]provisioning.SyncTargetType{
				provisioning.SyncTargetTypeFolder,
				provisioning.SyncTargetTypeFolderless,
			},
			structural,
			repository.NewVerifyAgainstExistingRepositoriesValidator(emptyRepositoryLister{}, quota),
			github.NewConnectionWebhookValidator(nil),
		),
		codec: jsonserializer.NewSerializerWithOptions(
			jsonserializer.DefaultMetaFactory,
			scheme,
			scheme,
			jsonserializer.SerializerOptions{},
		),
	}
}

func cloneURL(scheme, host, path, user, password string) string {
	u := &url.URL{Scheme: scheme, Host: host, Path: path}
	switch {
	case user != "" && password != "":
		u.User = url.UserPassword(user, password)
	case user != "":
		u.User = url.User(user)
	}
	return u.String()
}

func (a repositoryAdmission) admit(t *testing.T, obj, old *provisioning.Repository, op admission.Operation) error {
	t.Helper()
	attrs := admission.NewAttributesRecord(
		obj,
		old,
		provisioning.RepositoryResourceInfo.GroupVersionKind(),
		obj.Namespace,
		obj.Name,
		provisioning.RepositoryResourceInfo.GroupVersionResource(),
		"",
		op,
		nil,
		false,
		&user.DefaultInfo{},
	)
	// Mutating admission runs before validating admission. Both see the same object.
	if err := a.mutator.Mutate(context.Background(), attrs, nil); err != nil {
		return err
	}
	return a.validator.Validate(context.Background(), attrs, nil)
}

func (a repositoryAdmission) encode(t *testing.T, obj runtime.Object) string {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, a.codec.Encode(obj, &buf))
	return buf.String()
}

func (a repositoryAdmission) decodeRepository(t *testing.T, body string) *provisioning.Repository {
	t.Helper()
	repo := &provisioning.Repository{}
	_, _, err := a.codec.Decode([]byte(body), nil, repo)
	require.NoError(t, err)
	return repo
}

func encodeTable(t *testing.T, obj runtime.Object) string {
	t.Helper()
	table, err := provisioning.RepositoryResourceInfo.TableConverter().ConvertToTable(context.Background(), obj, &metav1.TableOptions{})
	require.NoError(t, err)
	body, err := json.Marshal(table)
	require.NoError(t, err)
	return string(body)
}

func bodyContainsSubmittedUserinfo(body, rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.User == nil {
		return strings.Contains(body, rawURL)
	}
	if name := parsed.User.Username(); name != "" && strings.Contains(body, name) {
		return true
	}
	if pass, ok := parsed.User.Password(); ok && pass != "" && strings.Contains(body, pass) {
		return true
	}
	if info := parsed.User.String(); info != "" && strings.Contains(body, info) {
		return true
	}
	return false
}

func requireStoredURLHasNoUserinfo(t *testing.T, repo *provisioning.Repository) {
	t.Helper()
	parsed, err := url.Parse(repo.URL())
	require.NoError(t, err)
	require.True(t, parsed.User == nil, "stored repository URL still has userinfo")
	require.NotEmpty(t, parsed.Host, "stored repository URL lost its host")
	require.NotEmpty(t, parsed.Path, "stored repository URL lost its path")
}

func requireResponsesOmitUserinfo(t *testing.T, admission repositoryAdmission, repo *provisioning.Repository, submitted string) {
	t.Helper()
	repo.SetGroupVersionKind(provisioning.SchemeGroupVersion.WithKind("Repository"))

	// GET and WATCH use this codec. A viewer decodes the body into a Repository.
	objectBody := admission.encode(t, repo)
	require.False(t, bodyContainsSubmittedUserinfo(objectBody, submitted), "repository GET body still includes clone URL userinfo")
	require.NotContains(t, objectBody, secureTokenField, "secure token field must stay write-only")
	requireStoredURLHasNoUserinfo(t, admission.decodeRepository(t, objectBody))

	list := &provisioning.RepositoryList{
		TypeMeta: metav1.TypeMeta{APIVersion: provisioning.APIVERSION, Kind: "RepositoryList"},
		Items:    []provisioning.Repository{*repo},
	}
	listBody := admission.encode(t, list)
	require.False(t, bodyContainsSubmittedUserinfo(listBody, submitted), "repository LIST body still includes clone URL userinfo")

	// Table conversion is the other GET/LIST representation. v1beta1 only re-stamps apiVersion.
	tableBody := encodeTable(t, repo)
	require.False(t, bodyContainsSubmittedUserinfo(tableBody, submitted), "repository table GET/LIST still includes clone URL userinfo")
}

func newSyncRepository(name string, repoType provisioning.RepositoryType, rawURL string, withToken bool) *provisioning.Repository {
	repo := &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: provisioning.RepositorySpec{
			Title: "Dashboards",
			Type:  repoType,
			Sync: provisioning.SyncOptions{
				Enabled: true,
				Target:  provisioning.SyncTargetTypeFolder,
			},
		},
	}
	switch repoType {
	case provisioning.GitRepositoryType:
		repo.Spec.Git = &provisioning.GitRepositoryConfig{URL: rawURL, Branch: "main"}
	case provisioning.GitHubRepositoryType:
		repo.Spec.GitHub = &provisioning.GitHubRepositoryConfig{URL: rawURL, Branch: "main"}
	case provisioning.GitHubEnterpriseRepositoryType:
		repo.Spec.GitHubEnterprise = &provisioning.GitHubEnterpriseRepositoryConfig{URL: rawURL, Branch: "main"}
	case provisioning.BitbucketRepositoryType:
		repo.Spec.Bitbucket = &provisioning.BitbucketRepositoryConfig{URL: rawURL, Branch: "main"}
	case provisioning.GitLabRepositoryType:
		repo.Spec.GitLab = &provisioning.GitLabRepositoryConfig{URL: rawURL, Branch: "main"}
	}
	if withToken {
		repo.Spec.Workflows = []provisioning.Workflow{provisioning.WriteWorkflow}
		repo.Secure.Token = common.InlineSecureValue{Create: common.NewSecretValue(secureTokenField)}
	}
	return repo
}

func TestCleanCloneURLStillAdmitted(t *testing.T) {
	chain := newRepositoryAdmission(t)
	for _, tc := range []struct {
		name     string
		repoType provisioning.RepositoryType
		rawURL   string
	}{
		{
			name:     "git https",
			repoType: provisioning.GitRepositoryType,
			rawURL:   cloneURL("https", "git.example.com", "/org/repo.git", "", ""),
		},
		{
			name:     "github https",
			repoType: provisioning.GitHubRepositoryType,
			rawURL:   cloneURL("https", "github.com", "/org/repo.git", "", ""),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newSyncRepository("git-sync", tc.repoType, tc.rawURL, false)
			require.NoError(t, chain.admit(t, repo, nil, admission.Create))
			requireStoredURLHasNoUserinfo(t, repo)
		})
	}
}

func withoutUserinfo(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.User = nil
	return parsed.String()
}

func setCloneURL(repo *provisioning.Repository, rawURL string) {
	switch repo.Spec.Type {
	case provisioning.GitRepositoryType:
		repo.Spec.Git.URL = rawURL
	case provisioning.GitHubRepositoryType:
		repo.Spec.GitHub.URL = rawURL
	case provisioning.GitHubEnterpriseRepositoryType:
		repo.Spec.GitHubEnterprise.URL = rawURL
	case provisioning.BitbucketRepositoryType:
		repo.Spec.Bitbucket.URL = rawURL
	case provisioning.GitLabRepositoryType:
		repo.Spec.GitLab.URL = rawURL
	}
}

// admitCredentialedURL passes when admission refuses this object because of the
// URL userinfo, or when the object it would store no longer carries that userinfo.
// A refusal for any other reason fails the test: the same admission without
// userinfo must succeed.
func admitCredentialedURL(t *testing.T, chain repositoryAdmission, repo, old *provisioning.Repository, op admission.Operation, submitted string) {
	t.Helper()
	err := chain.admit(t, repo, old, op)
	if err == nil {
		requireResponsesOmitUserinfo(t, chain, repo, submitted)
		return
	}

	clean := repo.DeepCopy()
	setCloneURL(clean, withoutUserinfo(submitted))
	var cleanOld *provisioning.Repository
	if old != nil {
		cleanOld = old.DeepCopy()
		if bodyContainsSubmittedUserinfo(cleanOld.URL(), submitted) {
			setCloneURL(cleanOld, withoutUserinfo(cleanOld.URL()))
		}
	}
	require.NoError(t, chain.admit(t, clean, cleanOld, op), "admission refused the clone URL for a reason other than userinfo: %v", err)
}

func TestCloneURLUserinfoIsNotPersistedOrReturned(t *testing.T) {
	chain := newRepositoryAdmission(t)

	type shape struct {
		name     string
		scheme   string
		user     string
		password string
		token    bool
	}
	shapes := []shape{
		{name: "user and password", scheme: "https", user: cloneURLUser, password: cloneURLPassword},
		{name: "username only", scheme: "https", user: cloneURLToken},
		{name: "password containing at sign", scheme: "https", user: cloneURLUser, password: cloneURLPassword + "@extra"},
		{name: "http user and password", scheme: "http", user: cloneURLUser, password: cloneURLPassword},
	}

	for _, repoType := range []provisioning.RepositoryType{
		provisioning.GitRepositoryType,
		provisioning.GitHubRepositoryType,
	} {
		host := "git.example.com"
		if repoType == provisioning.GitHubRepositoryType {
			host = "github.com"
		}
		t.Run(string(repoType), func(t *testing.T) {
			for _, shape := range shapes {
				// No trailing slash or .git suffix: the git and GitHub mutators only
				// trim those, and an update must not look like a URL change.
				rawURL := cloneURL(shape.scheme, host, "/org/repo", shape.user, shape.password)
				// Create also covers the mutators' slash and .git trimming.
				createURL := cloneURL(shape.scheme, host, "/org/repo.git/", shape.user, shape.password)

				t.Run("create/"+shape.name, func(t *testing.T) {
					repo := newSyncRepository("git-sync", repoType, createURL, false)
					admitCredentialedURL(t, chain, repo, nil, admission.Create, createURL)
				})

				t.Run("update keeps credentialed url/"+shape.name, func(t *testing.T) {
					repo := newSyncRepository("git-sync", repoType, rawURL, false)
					repo.Generation = 1
					old := repo.DeepCopy()
					repo.Spec.Title = "Dashboards renamed"
					admitCredentialedURL(t, chain, repo, old, admission.Update, rawURL)
				})

				// Replacing the URL requires a new secure token. That token travels
				// over TLS here; http with a token is a separate rule.
				if shape.scheme == "https" {
					t.Run("update replaces clean url/"+shape.name, func(t *testing.T) {
						repo := newSyncRepository("git-sync", repoType, rawURL, true)
						repo.Generation = 1
						old := newSyncRepository("git-sync", repoType, withoutUserinfo(rawURL), true)
						old.Generation = 1
						admitCredentialedURL(t, chain, repo, old, admission.Update, rawURL)
					})
				}
			}
		})
	}
}

func TestStoredRepositoryReadRedactsCloneURLUserinfo(t *testing.T) {
	chain := newRepositoryAdmission(t)
	rawURL := cloneURL("https", "git.example.com", "/org/repo.git", cloneURLUser, cloneURLPassword)

	// Objects already stored before admission learned to reject userinfo.
	// GET, LIST, and the table converter must not return that userinfo.
	// GitHub Enterprise, Bitbucket, and GitLab have no repository extra in this
	// module; their URL fields are still returned by the shared read path.
	for _, repoType := range []provisioning.RepositoryType{
		provisioning.GitRepositoryType,
		provisioning.GitHubRepositoryType,
		provisioning.GitHubEnterpriseRepositoryType,
		provisioning.BitbucketRepositoryType,
		provisioning.GitLabRepositoryType,
	} {
		t.Run(string(repoType), func(t *testing.T) {
			repo := newSyncRepository("git-sync", repoType, rawURL, true)
			requireResponsesOmitUserinfo(t, chain, repo, rawURL)
		})
	}

	t.Run("list of stored repositories", func(t *testing.T) {
		gitRepo := newSyncRepository("git-sync", provisioning.GitRepositoryType, rawURL, false)
		githubRepo := newSyncRepository("github-sync", provisioning.GitHubRepositoryType, rawURL, false)
		list := &provisioning.RepositoryList{
			TypeMeta: metav1.TypeMeta{APIVersion: provisioning.APIVERSION, Kind: "RepositoryList"},
			Items:    []provisioning.Repository{*gitRepo, *githubRepo},
		}
		body := chain.encode(t, list)
		require.False(t, bodyContainsSubmittedUserinfo(body, rawURL), "LIST body still includes clone URL userinfo")
		require.False(t, bodyContainsSubmittedUserinfo(encodeTable(t, list), rawURL), "LIST table still includes clone URL userinfo")
	})
}

func TestViewerCanReadRepositories(t *testing.T) {
	// Inner access check denies. The single-tenant authorizer still falls back
	// to the Viewer org role for repository get, list, and watch.
	viewer := auth.NewSessionAccessChecker(fixedDecisionAccessChecker{allowed: false}).WithFallbackRole(identity.RoleViewer)
	builder := &APIBuilder{accessWithViewer: viewer}
	ctx := identity.WithRequester(context.Background(), &identity.StaticRequester{
		Type:      authlib.TypeUser,
		UserID:    2,
		UserUID:   "viewer",
		OrgID:     1,
		OrgRole:   identity.RoleViewer,
		Namespace: "default",
	})

	for _, verb := range []string{apiutils.VerbGet, apiutils.VerbList, apiutils.VerbWatch} {
		t.Run(verb, func(t *testing.T) {
			decision, reason, err := builder.GetAuthorizer().Authorize(ctx, authorizer.AttributesRecord{
				Verb:            verb,
				APIGroup:        provisioning.GROUP,
				Resource:        provisioning.RepositoryResourceInfo.GetName(),
				Name:            "git-sync",
				Namespace:       "default",
				ResourceRequest: true,
			})
			require.NoError(t, err)
			require.Equal(t, authorizer.DecisionAllow, decision, "viewer %s denied: %s", verb, reason)
		})
	}

	var readerFound bool
	for _, registration := range FixedRoleRegistrations() {
		if registration.Role.Name != "fixed:provisioning.repositories:reader" {
			continue
		}
		readerFound = true
		require.Contains(t, registration.Grants, string(identity.RoleViewer))
		require.Equal(t, []string{ActionProvisioningRepositoriesRead}, []string{registration.Role.Permissions[0].Action})
	}
	require.True(t, readerFound, "repositories reader role must be registered")

	mapping, ok := rbac.NewMapperRegistry().Get(provisioning.GROUP, provisioning.RepositoryResourceInfo.GetName(), "")
	require.True(t, ok)
	for _, verb := range []string{apiutils.VerbGet, apiutils.VerbList, apiutils.VerbWatch} {
		action, mapped := mapping.Action(verb)
		require.True(t, mapped, "verb %s has no provisioning action", verb)
		require.Equal(t, ActionProvisioningRepositoriesRead, action)
		require.True(t, mapping.SkipScope(verb), "verb %s is scoped to one repository", verb)
	}
}
