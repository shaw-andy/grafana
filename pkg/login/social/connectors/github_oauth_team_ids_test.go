package connectors

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	ssoModels "github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/setting"
)

// These tests describe the GitHub team_ids allowlist. They fail while a non-numeric
// token is parsed into an empty list and isTeamMember treats that empty list as
// allow-all. They pass when NewGitHubProvider and Reload reject that value and a
// provider that is still returned keeps enforcing every numeric id from the list.

func TestGitHubTeamIDs_NonNumericValueDoesNotAllowEveryUser(t *testing.T) {
	t.Parallel()

	for _, teamIDs := range []string{
		"123,engineering",
		"123, engineering",
		"engineering,123",
		`["123","engineering"]`,
	} {
		t.Run(teamIDs, func(t *testing.T) {
			t.Parallel()
			api := githubAPIServer(t)
			provider, err := newGitHubProviderWithTeamIDs(t, api.URL, teamIDs)
			if provider != nil {
				// Login is attempted even when construction also returns an error.
				// An error returned after teamIds is replaced with an empty list
				// still admits every GitHub user.
				_, outsiderErr := githubUserInfo(provider, outsiderToken())
				require.ErrorIs(t, outsiderErr, ErrMissingTeamMembership)
				require.Equal(t, []int{123}, provider.teamIds)

				info, memberErr := githubUserInfo(provider, memberToken())
				require.NoError(t, memberErr)
				require.Equal(t, map[int64]org.RoleType{1: org.RoleViewer}, info.OrgRoles)
			}
			require.Error(t, err)
		})
	}
}

func TestGitHubTeamIDs_ReloadRejectsNonNumericAndKeepsPreviousAllowlist(t *testing.T) {
	t.Parallel()

	for _, teamIDs := range []string{
		"123,engineering",
		"engineering,123",
		`["123","engineering"]`,
	} {
		t.Run(teamIDs, func(t *testing.T) {
			t.Parallel()
			api := githubAPIServer(t)
			provider, err := newGitHubProviderWithTeamIDs(t, api.URL, "123")
			require.NoError(t, err)
			require.Equal(t, []int{123}, provider.teamIds)

			_, outsiderBefore := githubUserInfo(provider, outsiderToken())
			require.ErrorIs(t, outsiderBefore, ErrMissingTeamMembership)
			memberBefore, memberBeforeErr := githubUserInfo(provider, memberToken())
			require.NoError(t, memberBeforeErr)
			require.Equal(t, map[int64]org.RoleType{1: org.RoleViewer}, memberBefore.OrgRoles)

			reloadErr := provider.Reload(context.Background(), ssoModels.SSOSettings{
				Provider: social.GitHubProviderName,
				Settings: map[string]any{
					"api_url":               api.URL + "/user",
					"team_ids":              teamIDs,
					"allowed_organizations": "",
					"allow_sign_up":         true,
				},
			})

			// Checked after Reload returns. Replacing the allowlist and then
			// returning an error still admits the outsider.
			_, outsiderAfter := githubUserInfo(provider, outsiderToken())
			memberAfter, memberAfterErr := githubUserInfo(provider, memberToken())
			require.ErrorIs(t, outsiderAfter, ErrMissingTeamMembership)
			require.Equal(t, []int{123}, provider.teamIds)
			require.NoError(t, memberAfterErr)
			require.Equal(t, map[int64]org.RoleType{1: org.RoleViewer}, memberAfter.OrgRoles)
			require.Error(t, reloadErr)
		})
	}
}

func TestGitHubTeamIDs_EmptyListStillAllowsLogin(t *testing.T) {
	t.Parallel()
	api := githubAPIServer(t)
	provider, err := newGitHubProviderWithTeamIDs(t, api.URL, "")
	require.NoError(t, err)

	info, userErr := githubUserInfo(provider, outsiderToken())
	require.NoError(t, userErr)
	require.Equal(t, "outsider", info.Login)
	require.Equal(t, map[int64]org.RoleType{1: org.RoleViewer}, info.OrgRoles)
}

func TestGitHubTeamIDs_NumericListRestrictsLogin(t *testing.T) {
	t.Parallel()
	api := githubAPIServer(t)
	provider, err := newGitHubProviderWithTeamIDs(t, api.URL, "123,456")
	require.NoError(t, err)
	require.Equal(t, []int{123, 456}, provider.teamIds)

	_, outsiderErr := githubUserInfo(provider, outsiderToken())
	require.ErrorIs(t, outsiderErr, ErrMissingTeamMembership)

	info, memberErr := githubUserInfo(provider, memberToken())
	require.NoError(t, memberErr)
	require.Equal(t, map[int64]org.RoleType{1: org.RoleViewer}, info.OrgRoles)
}

func newGitHubProviderWithTeamIDs(t *testing.T, apiURL, teamIDs string) (*SocialGithub, error) {
	t.Helper()
	cfg := &setting.Cfg{AutoAssignOrgRole: "Viewer"}
	return NewGitHubProvider(
		context.Background(),
		&social.OAuthInfo{
			ApiUrl:      apiURL + "/user",
			AllowSignup: true,
			Enabled:     true,
			Extra: map[string]string{
				"team_ids":              teamIDs,
				"allowed_organizations": "",
			},
		},
		testConfigProvider(t, cfg),
		mustProvideOrgRoleMapper(t, cfg, nil),
		nil,
		featuremgmt.WithFeatures(),
	)
}

func githubUserInfo(provider *SocialGithub, token *oauth2.Token) (*social.BasicUserInfo, error) {
	ctx := context.Background()
	// Same client the OAuth login handler passes into UserInfo.
	return provider.UserInfo(ctx, provider.Client(ctx, token), token)
}

func outsiderToken() *oauth2.Token {
	return &oauth2.Token{AccessToken: "outsider"}
}

func memberToken() *oauth2.Token {
	return &oauth2.Token{AccessToken: "member"}
}

// githubAPIServer serves the GitHub user and team endpoints UserInfo calls.
// The access token selects the team list: "member" is on team 123, anything else is on team 1.
func githubAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user/teams":
			if bearerToken(r) == "member" {
				_, _ = fmt.Fprint(w, teamsJSON(123, "engineering"))
				return
			}
			_, _ = fmt.Fprint(w, teamsJSON(1, "other"))
		case "/user":
			login := "outsider"
			if bearerToken(r) == "member" {
				login = "member"
			}
			_, _ = fmt.Fprintf(w, `{"id":7,"login":%q,"name":%q,"email":"person@example.com"}`, login, login)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func bearerToken(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func teamsJSON(id int, slug string) string {
	return fmt.Sprintf(`[{
		"id": %d,
		"slug": %q,
		"html_url": "https://github.com/orgs/acme/teams/%s",
		"organization": {"login": "acme"}
	}]`, id, slug, slug)
}
