package strategies

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	ssoModels "github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/setting"
)

// grafana.ini [auth.github] team_ids is loaded by OAuthStrategy and applied by
// NewGitHubProvider on each login. A non-numeric token must not become an empty
// allowlist that accepts every GitHub user as a Viewer.

func TestGitHubTeamIDsFromIni_NonNumericDoesNotAllowEveryUser(t *testing.T) {
	t.Parallel()
	api := githubLoginAPI(t)
	provider, info, err := githubProviderFromIni(t, api.URL, "123,engineering")
	require.Equal(t, "123,engineering", info.Extra["team_ids"])
	require.True(t, info.Enabled)
	require.Empty(t, info.Extra["allowed_organizations"])

	if provider != nil {
		_, outsiderErr := githubLoginUserInfo(provider, "outsider")
		require.ErrorIs(t, outsiderErr, connectors.ErrMissingTeamMembership)
	}
	require.Error(t, err)
}

func TestGitHubTeamIDsFromIni_ReloadKeepsNumericAllowlist(t *testing.T) {
	t.Parallel()
	api := githubLoginAPI(t)
	provider, _, err := githubProviderFromIni(t, api.URL, "123")
	require.NoError(t, err)

	_, outsiderBefore := githubLoginUserInfo(provider, "outsider")
	require.ErrorIs(t, outsiderBefore, connectors.ErrMissingTeamMembership)
	memberBefore, memberBeforeErr := githubLoginUserInfo(provider, "member")
	require.NoError(t, memberBeforeErr)
	require.Equal(t, map[int64]org.RoleType{1: org.RoleViewer}, memberBefore.OrgRoles)

	reloaded, reloadErr := providerSettingsFromIni(t, api.URL, "123,engineering")
	require.NoError(t, reloadErr)
	err = provider.Reload(context.Background(), ssoModels.SSOSettings{
		Provider: social.GitHubProviderName,
		Settings: reloaded,
	})

	_, outsiderAfter := githubLoginUserInfo(provider, "outsider")
	memberAfter, memberAfterErr := githubLoginUserInfo(provider, "member")
	require.ErrorIs(t, outsiderAfter, connectors.ErrMissingTeamMembership)
	require.NoError(t, memberAfterErr)
	require.Equal(t, map[int64]org.RoleType{1: org.RoleViewer}, memberAfter.OrgRoles)
	require.Error(t, err)
}

func TestGitHubTeamIDsFromIni_NumericListRestrictsLogin(t *testing.T) {
	t.Parallel()
	api := githubLoginAPI(t)
	provider, _, err := githubProviderFromIni(t, api.URL, "123,456")
	require.NoError(t, err)

	_, outsiderErr := githubLoginUserInfo(provider, "outsider")
	require.ErrorIs(t, outsiderErr, connectors.ErrMissingTeamMembership)
	info, memberErr := githubLoginUserInfo(provider, "member")
	require.NoError(t, memberErr)
	require.Equal(t, "member", info.Login)
	require.Equal(t, map[int64]org.RoleType{1: org.RoleViewer}, info.OrgRoles)
}

func githubProviderFromIni(t *testing.T, apiURL, teamIDs string) (*connectors.SocialGithub, *social.OAuthInfo, error) {
	t.Helper()
	settings, err := providerSettingsFromIni(t, apiURL, teamIDs)
	require.NoError(t, err)

	info, err := connectors.CreateOAuthInfoFromKeyValuesWithLogging(log.New("test"), social.GitHubProviderName, settings)
	require.NoError(t, err)

	cfg := &setting.Cfg{AutoAssignOrgRole: "Viewer"}
	cfgProvider := staticConfigProvider(t, cfg)
	provider, err := connectors.NewGitHubProvider(
		context.Background(),
		info,
		cfgProvider,
		connectors.ProvideOrgRoleMapper(cfgProvider, nil),
		nil,
		featuremgmt.WithFeatures(),
	)
	return provider, info, err
}

func providerSettingsFromIni(t *testing.T, apiURL, teamIDs string) (map[string]any, error) {
	t.Helper()
	raw := fmt.Sprintf(`
[auth.github]
enabled = true
allow_sign_up = true
api_url = %s
team_ids = %s
allowed_organizations =
`, apiURL+"/user", teamIDs)
	parsed, err := ini.Load([]byte(raw))
	require.NoError(t, err)

	cfg := setting.NewCfg()
	cfg.Raw = parsed
	strategy := NewOAuthStrategy(staticConfigProvider(t, cfg))
	return strategy.GetProviderConfig(context.Background(), social.GitHubProviderName)
}

func githubLoginUserInfo(provider *connectors.SocialGithub, accessToken string) (*social.BasicUserInfo, error) {
	ctx := context.Background()
	token := &oauth2.Token{AccessToken: accessToken}
	return provider.UserInfo(ctx, provider.Client(ctx, token), token)
}

func githubLoginAPI(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		member := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") == "member"
		switch r.URL.Path {
		case "/user/teams":
			if member {
				_, _ = fmt.Fprint(w, `[{"id":123,"slug":"engineering","html_url":"https://github.com/orgs/acme/teams/engineering","organization":{"login":"acme"}}]`)
				return
			}
			_, _ = fmt.Fprint(w, `[{"id":1,"slug":"other","html_url":"https://github.com/orgs/acme/teams/other","organization":{"login":"acme"}}]`)
		case "/user":
			login := "outsider"
			if member {
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
