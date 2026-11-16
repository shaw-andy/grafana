package controller

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/connection"
	"github.com/grafana/grafana/apps/provisioning/pkg/connection/githuboauth"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/github"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/infra/tracing"
)

// placeholderAccessToken stands in for the GitHub user access token stored on
// the OAuth connection. It is not a credential.
const placeholderAccessToken = "PLACEHOLDER_ACCESS_TOKEN"

// placeholderClientSecret stands in for the OAuth app client secret.
const placeholderClientSecret = "PLACEHOLDER_CLIENT_SECRET"

func TestRepositoryController_generateRepositoryToken_GitHubOAuthKeepsGitHubHost(t *testing.T) {
	t.Parallel()
	rc, connObj := githubOAuthController(t)
	token, ops, err := rc.generateRepositoryToken(t.Context(), githubOAuthRepo("https://github.com/owner/repo"), connObj)
	require.NoError(t, err)
	require.Equal(t, placeholderAccessToken, string(token))
	require.True(t, patchCarries(ops, placeholderAccessToken))
}

func TestRepositoryController_generateRepositoryToken_GitHubOAuthRefusesForeignHost(t *testing.T) {
	t.Parallel()
	rc, connObj := githubOAuthController(t)

	for _, rawURL := range []string{
		"https://public.example/owner/repo",
		"https://github.com.public.example/owner/repo",
		"https://github.com@public.example/owner/repo",
		"https://public.example/github.com/owner",
		"https://acme.ghe.com/owner/repo",
		"https://1.2.3.4/owner/repo",
	} {
		t.Run(rawURL, func(t *testing.T) {
			t.Parallel()
			token, ops, err := rc.generateRepositoryToken(t.Context(), githubOAuthRepo(rawURL), connObj)
			require.Error(t, err)
			require.NotContains(t, string(token), placeholderAccessToken)
			require.False(t, patchCarries(ops, placeholderAccessToken))
		})
	}
}

func githubOAuthController(t *testing.T) (*RepositoryController, *provisioning.Connection) {
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

	return &RepositoryController{
			tracer:            tracing.NewNoopTracerService(),
			connectionFactory: factory,
		}, &provisioning.Connection{
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
		}
}

func githubOAuthRepo(rawURL string) *provisioning.Repository {
	return &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: "dashboards", Namespace: "org"},
		Spec: provisioning.RepositorySpec{
			Title: "Dashboards",
			Type:  provisioning.GitHubRepositoryType,
			GitHub: &provisioning.GitHubRepositoryConfig{
				URL: rawURL,
			},
			Connection: &provisioning.ConnectionInfo{Name: "user-oauth"},
		},
	}
}

func patchCarries(ops []map[string]any, placeholder string) bool {
	var walk func(any) bool
	walk = func(v any) bool {
		switch value := v.(type) {
		case string:
			return strings.Contains(value, placeholder)
		case map[string]any:
			for _, item := range value {
				if walk(item) {
					return true
				}
			}
		case map[string]string:
			for _, item := range value {
				if strings.Contains(item, placeholder) {
					return true
				}
			}
		case []any:
			for _, item := range value {
				if walk(item) {
					return true
				}
			}
		}
		return false
	}
	for _, op := range ops {
		if walk(op) {
			return true
		}
	}
	return false
}
