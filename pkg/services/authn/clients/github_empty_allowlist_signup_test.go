package clients_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/login/social/socialtest"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl/sync"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/login/authinfoimpl"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	secretsdb "github.com/grafana/grafana/pkg/services/secrets/database"
	secretsManager "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/ssosettings/strategies"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
)

// GitHub login must not create a Grafana account when team_ids and
// allowed_organizations are left empty. An empty list is not an allow-all.
func TestGitHubEmptyAllowlistsDoNotSignUpViewer(t *testing.T) {
	ctx := context.Background()
	root, err := filepath.Abs("../../../../")
	require.NoError(t, err)

	cfg, err := setting.NewCfgFromArgs(setting.CommandLineArgs{
		HomePath: root,
		Config:   filepath.Join(root, "conf", "defaults.ini"),
	})
	require.NoError(t, err)
	// State hashing reads this field. Keep the test off the value shipped in defaults.ini.
	cfg.SecretKey = "test-secret-key"

	github := cfg.Raw.Section("auth.github")
	require.Equal(t, "false", github.Key("enabled").Value())
	require.Equal(t, "true", github.Key("allow_sign_up").Value())
	require.Empty(t, github.Key("team_ids").Value())
	require.Empty(t, github.Key("allowed_organizations").Value())
	require.Equal(t, "Viewer", cfg.AutoAssignOrgRole)
	require.True(t, cfg.AutoAssignOrg)
	require.Equal(t, 1, cfg.AutoAssignOrgId)

	idp := &githubIDP{}
	server := httptest.NewServer(idp)
	t.Cleanup(server.Close)

	// The only operator changes in the reported attack: turn the provider on
	// and set OAuth client credentials. Lists stay at the shipped empty values.
	// URLs point at the test server so the connector parses the same JSON shape
	// it parses from GitHub.
	const (
		clientID     = "test-client-id"
		clientSecret = "test-client-secret"
	)
	github.Key("enabled").SetValue("true")
	github.Key("client_id").SetValue(clientID)
	github.Key("client_secret").SetValue(clientSecret)
	github.Key("auth_url").SetValue(server.URL + "/login/oauth/authorize")
	github.Key("token_url").SetValue(server.URL + "/login/oauth/access_token")
	github.Key("api_url").SetValue(server.URL + "/user")

	cfg.Raw.DeleteSection("database")
	store := sqlstore.NewTestStore(t, sqlstore.WithCfg(cfg))
	sqlstore.SeedDefaultOrgAndUser(t, store)

	sql := legacysql.NewDatabaseProvider(store)
	quota := quotatest.New(false, nil)
	orgSvc, err := orgimpl.ProvideService(sql, cfg, quota)
	require.NoError(t, err)
	tracer := tracing.InitializeTracerForTest()
	userSvc, err := userimpl.ProvideService(
		sql, orgSvc, cfg, nil, nil, tracer, quota, supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)
	secretsSvc := secretsManager.SetupTestService(t, secretsdb.ProvideSecretsStore(store))
	authInfoStore, err := authinfoimpl.ProvideStore(ctx, sql, secretsSvc)
	require.NoError(t, err)
	authInfoSvc := authinfoimpl.ProvideService(authInfoStore, remotecache.NewFakeCacheStorage(), secretsSvc)

	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	features := featuremgmt.WithFeatures()
	mapper := connectors.ProvideOrgRoleMapper(cfgProvider, orgSvc)
	userSync := sync.ProvideUserSync(
		userSvc, authinfoimpl.ProvideOSSUserProtectionService(), authInfoSvc, quota, tracer, features, cfg, nil,
	)
	orgSync := sync.ProvideOrgSync(userSvc, orgSvc, actest.FakeService{}, cfg, tracer)

	shipped := func(t *testing.T, overrides map[string]any) *social.OAuthInfo {
		t.Helper()
		settings, err := strategies.NewOAuthStrategy(cfgProvider).GetProviderConfig(ctx, social.GitHubProviderName)
		require.NoError(t, err)
		for key, value := range overrides {
			settings[key] = value
		}
		info, err := connectors.CreateOAuthInfoFromKeyValues(settings)
		require.NoError(t, err)
		return info
	}

	loginAs := func(t *testing.T, info *social.OAuthInfo, connector *connectors.SocialGithub, ghUser githubUser) {
		t.Helper()
		idp.set(ghUser)
		fakeSocial := &socialtest.FakeSocialService{
			ExpectedAuthInfoProvider: info,
			ExpectedConnector:        connector,
			ExpectedHttpClient:       server.Client(),
		}
		client := clients.ProvideOAuth(
			authn.ClientWithPrefix(social.GitHubProviderName),
			cfgProvider, nil, fakeSocial, nil, features, tracer,
		)

		state := "test-oauth-state"
		req := &authn.Request{HTTPRequest: httptest.NewRequest(
			http.MethodGet,
			"/login/github?state="+state+"&code=test-auth-code",
			nil,
		)}
		req.HTTPRequest.AddCookie(&http.Cookie{
			Name:  "oauth_state",
			Value: hashOAuthState(state, cfg.SecretKey, info.ClientSecret),
		})

		identity, authErr := client.Authenticate(ctx, req)
		if authErr == nil {
			hookReq := &authn.Request{HTTPRequest: req.HTTPRequest}
			if err := userSync.SyncUserHook(ctx, identity, hookReq); err == nil {
				_ = userSync.EnableUserHook(ctx, identity, hookReq)
				_ = orgSync.SyncOrgRolesHook(ctx, identity, hookReq)
			}
		}

		created, lookupErr := userSvc.GetByLogin(ctx, &user.GetUserByLoginQuery{LoginOrEmail: ghUser.login})
		if lookupErr == nil {
			memberships, orgErr := orgSvc.GetUserOrgList(ctx, &org.GetUserOrgListQuery{UserID: created.ID})
			require.NoError(t, orgErr)
			t.Fatalf("GitHub user %q was signed up (id=%d, grafanaAdmin=%v, orgRoles=%v, memberships=%s, allowSignUp=%v)",
				ghUser.login, created.ID, created.IsAdmin, identityOrgRoles(identity), formatMemberships(memberships), identity != nil && identity.ClientParams.AllowSignUp)
		}
		require.ErrorIs(t, lookupErr, user.ErrUserNotFound)
		require.Greater(t, idp.userHits.Load(), int32(0), "login never reached the GitHub user endpoint")
		require.Greater(t, idp.teamHits.Load(), int32(0), "login never reached the GitHub teams endpoint")
		require.Greater(t, idp.tokenHits.Load(), int32(0), "login never exchanged the OAuth code")
	}

	t.Run("shipped empty allowlists", func(t *testing.T) {
		info := shipped(t, nil)
		require.True(t, info.Enabled)
		require.True(t, info.AllowSignup)
		require.Empty(t, info.Extra["team_ids"])
		require.Empty(t, info.Extra["allowed_organizations"])
		connector := newGitHubConnector(t, ctx, info, cfgProvider, mapper, features)
		loginAs(t, info, connector, githubUser{
			id: 1001, login: "outsider", email: "outsider@example.com", name: "Outsider",
			teamID: 4242, orgLogin: "unrelated-org",
		})
	})

	t.Run("shipped empty allowlists and no github org or team", func(t *testing.T) {
		info := shipped(t, nil)
		connector := newGitHubConnector(t, ctx, info, cfgProvider, mapper, features)
		loginAs(t, info, connector, githubUser{
			id: 1002, login: "solo", email: "solo@example.com", name: "Solo",
		})
	})

	t.Run("skip org role sync still must not sign up", func(t *testing.T) {
		info := shipped(t, map[string]any{"skip_org_role_sync": true})
		require.True(t, info.SkipOrgRoleSync)
		require.Empty(t, info.Extra["team_ids"])
		require.Empty(t, info.Extra["allowed_organizations"])
		connector := newGitHubConnector(t, ctx, info, cfgProvider, mapper, features)
		loginAs(t, info, connector, githubUser{
			id: 1003, login: "skipped", email: "skipped@example.com", name: "Skipped",
			teamID: 4242, orgLogin: "unrelated-org",
		})
	})

	t.Run("reload back to shipped empty allowlists", func(t *testing.T) {
		restricted := shipped(t, map[string]any{"team_ids": "9999"})
		connector := newGitHubConnector(t, ctx, restricted, cfgProvider, mapper, features)
		empty := shipped(t, nil)
		require.Empty(t, empty.Extra["team_ids"])
		require.Empty(t, empty.Extra["allowed_organizations"])
		require.NoError(t, connector.Reload(ctx, models.SSOSettings{Provider: social.GitHubProviderName, Settings: oauthInfoToSettings(t, cfgProvider)}))
		loginAs(t, connector.GetOAuthInfo(), connector, githubUser{
			id: 1004, login: "reloaded", email: "reloaded@example.com", name: "Reloaded",
			teamID: 4242, orgLogin: "unrelated-org",
		})
	})

	t.Run("configured team the user is not in", func(t *testing.T) {
		info := shipped(t, map[string]any{"team_ids": "9999"})
		connector := newGitHubConnector(t, ctx, info, cfgProvider, mapper, features)
		loginAs(t, info, connector, githubUser{
			id: 1005, login: "wrongteam", email: "wrongteam@example.com", name: "Wrong Team",
			teamID: 4242, orgLogin: "unrelated-org",
		})
	})

	t.Run("configured organization the user is not in", func(t *testing.T) {
		info := shipped(t, map[string]any{"allowed_organizations": "expected-org"})
		connector := newGitHubConnector(t, ctx, info, cfgProvider, mapper, features)
		loginAs(t, info, connector, githubUser{
			id: 1006, login: "wrongorg", email: "wrongorg@example.com", name: "Wrong Org",
			teamID: 4242, orgLogin: "unrelated-org",
		})
	})
}

func newGitHubConnector(t *testing.T, ctx context.Context, info *social.OAuthInfo, cfgProvider configprovider.ConfigProvider, mapper *connectors.OrgRoleMapper, features featuremgmt.FeatureToggles) *connectors.SocialGithub {
	t.Helper()
	connector, err := connectors.NewGitHubProvider(ctx, info, cfgProvider, mapper, nil, features)
	require.NoError(t, err)
	return connector
}

// oauthInfoToSettings reloads the connector from the same ini values the
// strategy just parsed, including the test server URLs and empty allowlists.
func oauthInfoToSettings(t *testing.T, cfgProvider configprovider.ConfigProvider) map[string]any {
	t.Helper()
	settings, err := strategies.NewOAuthStrategy(cfgProvider).GetProviderConfig(context.Background(), social.GitHubProviderName)
	require.NoError(t, err)
	return settings
}

// hashOAuthState matches OAuth.Authenticate, which compares the callback state
// to sha256(state + secret key + client secret).
func hashOAuthState(state, secret, seed string) string {
	sum := sha256.Sum256([]byte(state + secret + seed))
	return hex.EncodeToString(sum[:])
}

func formatMemberships(memberships []*org.UserOrgDTO) string {
	if len(memberships) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(memberships))
	for _, membership := range memberships {
		parts = append(parts, fmt.Sprintf("org=%d role=%s", membership.OrgID, membership.Role))
	}
	return strings.Join(parts, ", ")
}

func identityOrgRoles(identity *authn.Identity) map[int64]org.RoleType {
	if identity == nil {
		return nil
	}
	return identity.OrgRoles
}

type githubUser struct {
	id       int
	login    string
	email    string
	name     string
	teamID   int
	orgLogin string
}

type githubIDP struct {
	mu        atomic.Value // githubUser
	userHits  atomic.Int32
	teamHits  atomic.Int32
	orgHits   atomic.Int32
	tokenHits atomic.Int32
}

func (g *githubIDP) set(user githubUser) {
	g.userHits.Store(0)
	g.teamHits.Store(0)
	g.orgHits.Store(0)
	g.tokenHits.Store(0)
	g.mu.Store(user)
}

func (g *githubIDP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/login/oauth/access_token":
		g.tokenHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-access-token","token_type":"bearer","expires_in":3600}`))
	case r.URL.Path == "/user":
		g.userHits.Add(1)
		user := g.mu.Load().(githubUser)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%d,"login":%q,"email":%q,"name":%q}`, user.id, user.login, user.email, user.name)
	case r.URL.Path == "/user/teams":
		g.teamHits.Add(1)
		user := g.mu.Load().(githubUser)
		w.Header().Set("Content-Type", "application/json")
		if user.teamID == 0 {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		fmt.Fprintf(w, `[{"id":%d,"slug":"personal","html_url":"https://github.com/orgs/%s/teams/personal","organization":{"login":%q}}]`,
			user.teamID, user.orgLogin, user.orgLogin)
	case r.URL.Path == "/user/orgs":
		g.orgHits.Add(1)
		user := g.mu.Load().(githubUser)
		w.Header().Set("Content-Type", "application/json")
		if user.orgLogin == "" {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		fmt.Fprintf(w, `[{"login":%q}]`, user.orgLogin)
	case r.URL.Path == "/user/emails":
		user := g.mu.Load().(githubUser)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `[{"email":%q,"primary":true,"verified":true}]`, user.email)
	default:
		http.NotFound(w, r)
	}
}
