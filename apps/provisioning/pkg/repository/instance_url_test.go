package repository_test

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"k8s.io/apimachinery/pkg/util/validation/field"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/git"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/github"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Admission runs the provider mutator and then RepositoryValidator, which is the
// validator wired with the public-address URL check. A repository URL that the
// browser will request as this instance's logout endpoint must be rejected there.
// The public-address check is stubbed to a public IP so it cannot be what stops the URL.
func TestRepositoryAdmissionRejectsLogoutURL(t *testing.T) {
	validator := newPublicURLRepositoryValidator(t)

	t.Run("allows a repository on another host", func(t *testing.T) {
		for _, repo := range []*provisioning.Repository{
			gitRepository("https://github.com/grafana/grafana"),
			gitRepository("https://git.example.com/team/project.git"),
			githubRepository("https://github.com/grafana/grafana"),
			githubRepository("https://github.com/org/logout"),
		} {
			rejected, errs := admissionRejects(t, validator, repo)
			require.Falsef(t, rejected, "url %s errors: %v", repo.URL(), errs)
		}
	})

	t.Run("rejects a url whose browser path is this instance logout", func(t *testing.T) {
		cases := []*provisioning.Repository{
			gitRepository("https://grafana.example/logout"),
			gitRepository("https://grafana.example:443/logout"),
			gitRepository("https://Grafana.Example/logout"),
			githubRepository("https://grafana.example/foo/../logout?"),
			githubRepository("https://grafana.example/foo/../logout"),
		}
		for _, repo := range cases {
			t.Run(repo.URL(), func(t *testing.T) {
				rejected, errs := admissionRejects(t, validator, repo)
				require.Truef(t, rejected, "url %s was accepted: %v", repo.URL(), errs)
				for _, err := range errs {
					require.Contains(t, err.Field, "url")
				}
			})
		}
	})
}

func newPublicURLRepositoryValidator(t *testing.T) repository.Validator {
	t.Helper()

	enabled := map[provisioning.RepositoryType]struct{}{
		provisioning.GitRepositoryType:    {},
		provisioning.GitHubRepositoryType: {},
	}
	factory, err := repository.ProvideFactory(enabled, []repository.Extra{
		git.Extra(nil, false, nil, nil),
		github.Extra(nil, nil, nil, false, nil, nil),
	}, noop.NewTracerProvider().Tracer("test"))
	require.NoError(t, err)

	allowlist, err := repository.NewAllowlist(nil)
	require.NoError(t, err)
	// Every host resolves to a public address. Loopback and RFC1918 rejection
	// must not be what decides these cases.
	urlValidator := repository.NewURLValidator(allowlist, func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	return repository.NewValidator(false, factory, repository.WithURLValidator(urlValidator))
}

func admissionRejects(t *testing.T, validator repository.Validator, repo *provisioning.Repository) (bool, field.ErrorList) {
	t.Helper()

	var mutateErr error
	switch repo.Spec.Type {
	case provisioning.GitRepositoryType:
		mutateErr = git.Mutate(context.Background(), repo)
	case provisioning.GitHubRepositoryType:
		mutateErr = github.Mutate(context.Background(), repo)
	default:
		t.Fatalf("unsupported type %s", repo.Spec.Type)
	}
	if mutateErr != nil {
		return true, nil
	}
	errs := validator.Validate(context.Background(), repo)
	return len(errs) > 0, errs
}

func gitRepository(rawURL string) *provisioning.Repository {
	return &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "git-repo",
			Finalizers: []string{repository.CleanFinalizer},
		},
		Spec: provisioning.RepositorySpec{
			Title: "Git",
			Type:  provisioning.GitRepositoryType,
			Git: &provisioning.GitRepositoryConfig{
				URL:    rawURL,
				Branch: "main",
			},
		},
	}
}

func githubRepository(rawURL string) *provisioning.Repository {
	return &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "github-repo",
			Finalizers: []string{repository.CleanFinalizer},
		},
		Spec: provisioning.RepositorySpec{
			Title: "GitHub",
			Type:  provisioning.GitHubRepositoryType,
			GitHub: &provisioning.GitHubRepositoryConfig{
				URL:    rawURL,
				Branch: "main",
			},
		},
	}
}
