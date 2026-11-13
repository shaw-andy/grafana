package connectors_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl/sync"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/login/authinfotest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	ssoModels "github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/ssosettings/strategies"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
)

// oauthAccessTokenPlaceholder is not a credential. The test only checks that the
// OAuth client attaches a bearer value to the GitHub API requests.
const oauthAccessTokenPlaceholder = "placeholder"

const (
	allowlistedTeamID = 99
	childTeamID       = 1
	otherTeamID       = 50
	githubUserID      = 4242
	createdUserID     = int64(77)
)

func TestGitHubOAuthTeamAllowlist(t *testing.T) {
	t.Run("child team parent id does not admit a user who is not a direct member", func(t *testing.T) {
		// The second page is empty, so the allowlisted id is not a direct
		// membership waiting on a later page. Every teams request returns this
		// same pair of pages.
		pages := [][]githubTeamPayload{
			{childTeam(childTeamID, "child-team", allowlistedTeamID)},
			{},
		}
		result := runGitHubSignup(t, fmt.Sprintf("%d", allowlistedTeamID), pages)

		require.GreaterOrEqual(t, result.pagesFetched[2], 1, "team lookup must follow the teams list Link header")
		require.Empty(t, result.created, "signup must not create a user when the only match is a parent team id")
		require.Empty(t, result.added, "signup must not grant an organization role when the only match is a parent team id")
		require.ErrorIs(t, result.err, connectors.ErrMissingTeamMembership)
	})

	t.Run("reloading the allowlist to a parent team id does not admit a child member", func(t *testing.T) {
		pages := [][]githubTeamPayload{
			{childTeam(childTeamID, "child-team", allowlistedTeamID)},
		}
		api := newGitHubAPI(t, pages)
		gh, _, settings := newGitHubProviderFromDefaults(t, api.baseURL, fmt.Sprintf("%d", childTeamID))

		direct, err := githubUserInfo(t, gh, api.client)
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("%d", githubUserID), direct.Id)

		reloaded := cloneSettings(settings)
		reloaded["team_ids"] = fmt.Sprintf("%d", allowlistedTeamID)
		require.NoError(t, gh.Reload(context.Background(), ssoModels.SSOSettings{Settings: reloaded}))

		result := signupFromProvider(t, gh, api.client, loadedCfg(t))
		require.Empty(t, result.created)
		require.Empty(t, result.added)
		require.ErrorIs(t, result.err, connectors.ErrMissingTeamMembership)
	})

	t.Run("parent id among several allowlisted ids does not admit a child member", func(t *testing.T) {
		pages := [][]githubTeamPayload{
			{childTeam(childTeamID, "child-team", allowlistedTeamID)},
		}
		result := runGitHubSignup(t, fmt.Sprintf("%d,%d", allowlistedTeamID, otherTeamID), pages)

		require.Empty(t, result.created)
		require.Empty(t, result.added)
		require.ErrorIs(t, result.err, connectors.ErrMissingTeamMembership)
	})

	t.Run("direct member of the allowlisted team is admitted with the default org role", func(t *testing.T) {
		pages := [][]githubTeamPayload{
			{childTeam(allowlistedTeamID, "parent-team", 0)},
		}
		result := runGitHubSignup(t, fmt.Sprintf("%d", allowlistedTeamID), pages)

		require.NoError(t, result.err)
		require.Len(t, result.created, 1)
		require.Equal(t, "child-member", result.created[0].Login)
		require.Equal(t, "child-member@example.com", result.created[0].Email)
		require.True(t, result.created[0].SkipOrgSetup)
		require.Len(t, result.added, 1)
		require.Equal(t, createdUserID, result.added[0].UserID)
		require.Equal(t, int64(1), result.added[0].OrgID)
		require.Equal(t, org.RoleViewer, result.added[0].Role)
	})

	t.Run("direct member is admitted when that team also names a different parent", func(t *testing.T) {
		pages := [][]githubTeamPayload{
			{childTeam(allowlistedTeamID, "parent-team", otherTeamID)},
		}
		result := runGitHubSignup(t, fmt.Sprintf("%d", allowlistedTeamID), pages)

		require.NoError(t, result.err)
		require.Len(t, result.added, 1)
		require.Equal(t, createdUserID, result.added[0].UserID)
		require.Equal(t, int64(1), result.added[0].OrgID)
		require.Equal(t, org.RoleViewer, result.added[0].Role)
	})

	t.Run("unrelated team is rejected", func(t *testing.T) {
		pages := [][]githubTeamPayload{
			{childTeam(otherTeamID, "other-team", 0)},
		}
		result := runGitHubSignup(t, fmt.Sprintf("%d", allowlistedTeamID), pages)

		require.ErrorIs(t, result.err, connectors.ErrMissingTeamMembership)
		require.Empty(t, result.created)
		require.Empty(t, result.added)
	})

	t.Run("child of a team other than the allowlisted team is rejected", func(t *testing.T) {
		pages := [][]githubTeamPayload{
			{childTeam(childTeamID, "child-team", otherTeamID)},
		}
		result := runGitHubSignup(t, fmt.Sprintf("%d", allowlistedTeamID), pages)

		require.ErrorIs(t, result.err, connectors.ErrMissingTeamMembership)
		require.Empty(t, result.created)
		require.Empty(t, result.added)
	})
}

type signupResult struct {
	err          error
	created      []*user.CreateUserCommand
	added        []*org.AddOrgUserCommand
	pagesFetched map[int]int
}

func runGitHubSignup(t *testing.T, teamIDs string, pages [][]githubTeamPayload) signupResult {
	t.Helper()
	api := newGitHubAPI(t, pages)
	gh, cfg, _ := newGitHubProviderFromDefaults(t, api.baseURL, teamIDs)
	require.True(t, gh.IsSignupAllowed())
	require.True(t, gh.GetOAuthInfo().Enabled)
	require.False(t, gh.GetOAuthInfo().RoleAttributeStrict)
	require.False(t, gh.GetOAuthInfo().SkipOrgRoleSync)
	require.Empty(t, gh.GetOAuthInfo().Extra["allowed_organizations"])
	require.Equal(t, teamIDs, gh.GetOAuthInfo().Extra["team_ids"])
	require.Equal(t, "Viewer", cfg.AutoAssignOrgRole)
	require.True(t, cfg.AutoAssignOrg)
	require.Equal(t, 1, cfg.AutoAssignOrgId)
	require.Equal(t, api.baseURL+"/user", gh.GetOAuthInfo().ApiUrl)

	result := signupFromProvider(t, gh, api.client, cfg)
	result.pagesFetched = api.pagesFetched
	return result
}

func signupFromProvider(t *testing.T, gh *connectors.SocialGithub, client *http.Client, cfg *setting.Cfg) signupResult {
	t.Helper()
	info, err := githubUserInfo(t, gh, client)
	if err != nil {
		return signupResult{err: err}
	}

	require.True(t, gh.IsEmailAllowed(info.Email))
	require.NotEmpty(t, info.OrgRoles)

	// Fields copied from the OAuth client's identity after UserInfo succeeds.
	// Post-auth hooks run only when that client returns a nil error.
	identity := &authn.Identity{
		Login:           info.Login,
		Name:            info.Name,
		Email:           info.Email,
		IsGrafanaAdmin:  info.IsGrafanaAdmin,
		AuthenticatedBy: login.GithubAuthModule,
		AuthID:          info.Id,
		ExternalGroups:  info.Groups,
		OrgRoles:        info.OrgRoles,
		ClientParams: authn.ClientParams{
			SyncUser:        true,
			SyncTeams:       true,
			FetchSyncedUser: true,
			SyncPermissions: true,
			AllowSignUp:     gh.IsSignupAllowed(),
			SyncOrgRoles:    len(info.OrgRoles) > 0,
		},
	}

	created, added, syncErr := runSignupHooks(t, cfg, identity)
	return signupResult{err: syncErr, created: created, added: added}
}

func githubUserInfo(t *testing.T, gh *connectors.SocialGithub, client *http.Client) (*social.BasicUserInfo, error) {
	t.Helper()
	token := &oauth2.Token{AccessToken: oauthAccessTokenPlaceholder, TokenType: "Bearer"}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	return gh.UserInfo(ctx, gh.Client(ctx, token), token)
}

func runSignupHooks(t *testing.T, cfg *setting.Cfg, identity *authn.Identity) ([]*user.CreateUserCommand, []*org.AddOrgUserCommand, error) {
	t.Helper()
	var created []*user.CreateUserCommand
	userSvc := &usertest.FakeUserService{
		CreateFn: func(_ context.Context, cmd *user.CreateUserCommand) (*user.User, error) {
			copied := *cmd
			created = append(created, &copied)
			return &user.User{
				ID:    createdUserID,
				UID:   "user-77",
				Login: cmd.Login,
				Email: cmd.Email,
				Name:  cmd.Name,
			}, nil
		},
		UpdateFn: func(_ context.Context, _ *user.UpdateUserCommand) error {
			return nil
		},
	}
	authInfo := &authinfotest.FakeService{
		ExpectedError: user.ErrUserNotFound,
		SetAuthInfoFn: func(_ context.Context, _ *login.SetAuthInfoCommand) error {
			return nil
		},
	}
	userSync := sync.ProvideUserSync(
		userSvc,
		nil,
		authInfo,
		quotatest.New(false, nil),
		tracing.InitializeTracerForTest(),
		featuremgmt.WithFeatures(),
		cfg,
		nil,
	)
	if err := userSync.SyncUserHook(context.Background(), identity, nil); err != nil {
		return created, nil, err
	}

	orgs := &recordingOrgService{FakeOrgService: orgtest.NewOrgServiceFake()}
	orgSync := sync.ProvideOrgSync(userSvc, orgs, nil, cfg, tracing.InitializeTracerForTest())
	if err := orgSync.SyncOrgRolesHook(context.Background(), identity, nil); err != nil {
		return created, orgs.added, err
	}
	return created, orgs.added, nil
}

type recordingOrgService struct {
	*orgtest.FakeOrgService
	added []*org.AddOrgUserCommand
}

func (r *recordingOrgService) AddOrgUser(_ context.Context, cmd *org.AddOrgUserCommand) error {
	copied := *cmd
	r.added = append(r.added, &copied)
	return nil
}

type githubAPI struct {
	client       *http.Client
	baseURL      string
	pagesFetched map[int]int
}

func newGitHubAPI(t *testing.T, pages [][]githubTeamPayload) *githubAPI {
	t.Helper()
	api := &githubAPI{pagesFetched: map[int]int{}}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "missing authorization", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/user":
			_, _ = w.Write(githubUserJSON)
		case r.URL.Path == "/user/teams":
			page := 1
			if r.URL.Query().Get("page") == "2" {
				page = 2
			}
			api.pagesFetched[page]++
			if page == 1 && len(pages) > 1 {
				w.Header().Set("Link", "<"+server.URL+"/user/teams?per_page=100&page=2>; rel=\"next\"")
			}
			payload := []githubTeamPayload{}
			if page-1 < len(pages) {
				payload = pages[page-1]
			}
			encoded, err := json.Marshal(payload)
			require.NoError(t, err)
			_, _ = w.Write(encoded)
		case r.URL.Path == "/user/emails":
			_, _ = w.Write([]byte(`[{"email":"child-member@example.com","primary":true,"verified":true}]`))
		case r.URL.Path == "/user/orgs":
			_, _ = w.Write([]byte(`[{"login":"example-org"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	api.client = server.Client()
	api.baseURL = server.URL
	return api
}

func newGitHubProviderFromDefaults(t *testing.T, apiBaseURL string, teamIDs string) (*connectors.SocialGithub, *setting.Cfg, map[string]any) {
	t.Helper()
	cfg := loadedCfg(t)
	section := cfg.Raw.Section("auth.github")
	section.Key("enabled").SetValue("true")
	section.Key("team_ids").SetValue(teamIDs)
	section.Key("api_url").SetValue(apiBaseURL + "/user")

	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	settings, err := strategies.NewOAuthStrategy(cfgProvider).GetProviderConfig(context.Background(), social.GitHubProviderName)
	require.NoError(t, err)
	require.Equal(t, true, settings["enabled"])
	require.Equal(t, true, settings["allow_sign_up"])
	require.Equal(t, false, settings["role_attribute_strict"])
	require.Equal(t, false, settings["skip_org_role_sync"])
	require.Equal(t, teamIDs, settings["team_ids"])
	require.Empty(t, settings["allowed_organizations"])

	info, err := connectors.CreateOAuthInfoFromKeyValues(settings)
	require.NoError(t, err)
	gh, err := connectors.NewGitHubProvider(
		context.Background(),
		info,
		cfgProvider,
		connectors.ProvideOrgRoleMapper(cfgProvider, orgtest.NewOrgServiceFake()),
		nil,
		featuremgmt.WithFeatures(),
	)
	require.NoError(t, err)
	return gh, cfg, settings
}

func loadedCfg(t *testing.T) *setting.Cfg {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{HomePath: root}))
	return cfg
}

func cloneSettings(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

type githubTeamParent struct {
	ID              int    `json:"id"`
	NodeID          string `json:"node_id"`
	URL             string `json:"url"`
	MembersURL      string `json:"members_url"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	Permission      string `json:"permission"`
	HTMLURL         string `json:"html_url"`
	RepositoriesURL string `json:"repositories_url"`
	Slug            string `json:"slug"`
	Type            string `json:"type"`
}

type githubTeamPayload struct {
	ID           int    `json:"id"`
	Slug         string `json:"slug"`
	HTMLURL      string `json:"html_url"`
	Organization struct {
		Login string `json:"login"`
	} `json:"organization"`
	Parent *githubTeamParent `json:"parent"`
}

func childTeam(id int, slug string, parentID int) githubTeamPayload {
	team := githubTeamPayload{
		ID:      id,
		Slug:    slug,
		HTMLURL: "https://github.com/orgs/example-org/teams/" + slug,
	}
	team.Organization.Login = "example-org"
	if parentID != 0 {
		team.Parent = &githubTeamParent{
			ID:              parentID,
			NodeID:          "parent-node",
			URL:             fmt.Sprintf("https://api.github.com/organizations/1/team/%d", parentID),
			MembersURL:      fmt.Sprintf("https://api.github.com/organizations/1/team/%d/members{/member}", parentID),
			Name:            "Parent",
			Description:     "parent team",
			Permission:      "pull",
			HTMLURL:         "https://github.com/orgs/example-org/teams/parent",
			RepositoriesURL: fmt.Sprintf("https://api.github.com/organizations/1/team/%d/repos", parentID),
			Slug:            "parent",
			Type:            "organization",
		}
	}
	return team
}

var githubUserJSON = []byte(fmt.Sprintf(`{
  "login": "child-member",
  "id": %d,
  "name": "Child Member",
  "email": "child-member@example.com"
}`, githubUserID))
