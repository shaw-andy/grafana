package github

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/git"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
)

// TestNewRepository_ServerURL verifies the REST API base URL on the underlying client is resolved
// from the repo URL's host per GitHub deployment type.
func TestNewRepository_ServerURL(t *testing.T) {
	tests := []struct {
		name     string
		repoURL  string
		expected string
	}{
		{
			name:     "plain github.com uses default api.github.com",
			repoURL:  "https://github.com/grafana/grafana",
			expected: "https://api.github.com/",
		},
		{
			name:     "GHES appends /api/v3",
			repoURL:  "https://custom-ghe-url.com/owner/repo",
			expected: "https://custom-ghe-url.com/api/v3/",
		},
		{
			name:     "data residency rewrites to api host without /api/v3",
			repoURL:  "https://acme.ghe.com/owner/repo",
			expected: "https://api.acme.ghe.com/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gitRepo := git.NewMockGitRepository(t)
			gitRepo.EXPECT().URL().Return(tt.repoURL).Maybe()

			repo, err := NewRepository(context.Background(), &provisioning.Repository{}, gitRepo, ProvideFactory(), common.RawSecureValue(""))
			require.NoError(t, err)

			gr, ok := repo.(*githubRepository)
			require.True(t, ok, "expected *githubRepository")
			gc, ok := gr.gh.(*githubClient)
			require.True(t, ok, "expected *githubClient")
			require.Equal(t, tt.expected, gc.gh.BaseURL.String())
		})
	}
}

func TestIsDotComURL(t *testing.T) {
	for rawURL, expected := range map[string]bool{
		"https://github.com/owner/repo":                 true,
		"https://www.github.com/owner/repo":             true,
		"https://GitHub.com/owner/repo":                 true,
		"https://github.com:443/owner/repo":             true,
		"http://github.com/owner/repo":                  false,
		"https://github.com:8443/owner/repo":            false,
		"https://github.com@git.example.com/owner/repo": false,
		"https://user@github.com/owner/repo":            false,
		"https://github.com.git.example.com/owner/repo": false,
		"https://git.example.com/github.com/owner":      false,
		"https://acme.ghe.com/owner/repo":               false,
		"https://api.github.com/owner/repo":             false,
		"github.com/owner/repo":                         false,
		"":                                              false,
	} {
		t.Run(rawURL, func(t *testing.T) {
			require.Equal(t, expected, IsDotComURL(rawURL))
		})
	}
}
