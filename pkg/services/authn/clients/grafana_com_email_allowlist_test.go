package clients_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/socialimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl/sync"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/login/authinfoimpl"
	"github.com/grafana/grafana/pkg/services/login/authinfotest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	ssomodels "github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/ssosettings/ssosettingstests"
	"github.com/grafana/grafana/pkg/services/ssosettings/strategies"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	grafanaComUserID       = 42
	grafanaComUsername     = "exampleuser"
	grafanaComDisplayName  = "Example User"
	grafanaComOrgID        = int64(1)
	grafanaComClientID     = "test-client-id"
	grafanaComClientSecret = "test-client-secret"
	grafanaComSecretKey    = "test-secret-key"
	grafanaComState        = "test-state"
	grafanaComCode         = "test-code"
	grafanaComAccessToken  = "test-access-token"
)

// grafanaComIDP is a stand-in for the Grafana.com token and userinfo endpoints.
// The second and later userinfo responses return a different email than the first.
// Sign-in has to accept or reject the first address, which is also the address
// placed on the identity. Checking a later response and then using an earlier one
// still fails these tests.
type grafanaComIDP struct {
	server   *httptest.Server
	emails   []string
	orgLogin string
	username string
	calls    int
}

func newGrafanaComIDP(t *testing.T) *grafanaComIDP {
	t.Helper()
	idp := &grafanaComIDP{}
	idp.server = httptest.NewServer(http.HandlerFunc(idp.serve))
	t.Cleanup(idp.server.Close)
	return idp
}

func (g *grafanaComIDP) prepare(emails []string, orgLogin, username string) {
	g.emails = emails
	g.orgLogin = orgLogin
	g.username = username
	g.calls = 0
}

func (g *grafanaComIDP) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/oauth2/token":
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": grafanaComAccessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	case "/api/oauth2/user":
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		email := g.emails[len(g.emails)-1]
		if g.calls < len(g.emails) {
			email = g.emails[g.calls]
		}
		g.calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":       grafanaComUserID,
			"name":     grafanaComDisplayName,
			"username": g.username,
			"email":    email,
			"role":     string(org.RoleAdmin),
			"orgs":     []map[string]string{{"login": g.orgLogin}},
		})
	default:
		http.NotFound(w, r)
	}
}

type recordingUsers struct {
	*usertest.FakeUserService
	created []*user.CreateUserCommand
	updated []*user.UpdateUserCommand
}

func newRecordingUsers(existing *user.User) *recordingUsers {
	users := &recordingUsers{FakeUserService: usertest.NewUserServiceFake(), created: nil, updated: nil}
	users.ExpectedUser = existing
	users.CreateFn = func(_ context.Context, cmd *user.CreateUserCommand) (*user.User, error) {
		copied := *cmd
		users.created = append(users.created, &copied)
		return &user.User{ID: grafanaComUserID, UID: "uid-42", Login: cmd.Login, Email: cmd.Email, Name: cmd.Name}, nil
	}
	users.UpdateFn = func(_ context.Context, cmd *user.UpdateUserCommand) error {
		copied := *cmd
		users.updated = append(users.updated, &copied)
		return nil
	}
	return users
}

type recordingOrgs struct {
	*orgtest.FakeOrgService
	added []*org.AddOrgUserCommand
}

func newRecordingOrgs() *recordingOrgs {
	orgs := &recordingOrgs{FakeOrgService: orgtest.NewOrgServiceFake()}
	return orgs
}

func (o *recordingOrgs) AddOrgUser(_ context.Context, cmd *org.AddOrgUserCommand) error {
	copied := *cmd
	o.added = append(o.added, &copied)
	return nil
}

type grafanaComLoginHarness struct {
	idp      *grafanaComIDP
	client   *clients.OAuth
	social   *socialimpl.SocialService
	users    *recordingUsers
	orgs     *recordingOrgs
	userSync *sync.UserSync
	orgSync  *sync.OrgSync
	cfg      *setting.Cfg
	stored   *ssomodels.SSOSettings
}

func newGrafanaComLoginHarness(t *testing.T, idp *grafanaComIDP, sectionOverrides map[string]map[string]string, existing *user.User) *grafanaComLoginHarness {
	t.Helper()

	cfg := setting.NewCfg()
	parsed, err := ini.Load(filepath.Join(repoRoot(t), "conf", "defaults.ini"))
	require.NoError(t, err)
	for sectionName, keys := range sectionOverrides {
		section := parsed.Section(sectionName)
		for key, value := range keys {
			section.Key(key).SetValue(value)
		}
	}
	cfg.Raw = parsed
	// The connector builds its userinfo URL from this field. Production copies it
	// out of the grafana_com url setting; the test points that host at the local IDP.
	cfg.GrafanaComURL = idp.server.URL
	cfg.SecretKey = grafanaComSecretKey
	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgId = int(grafanaComOrgID)
	cfg.AutoAssignOrgRole = string(org.RoleViewer)

	provider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	strategy := strategies.NewOAuthStrategy(provider)
	settings, err := strategy.GetProviderConfig(context.Background(), social.GrafanaComProviderName)
	require.NoError(t, err)

	stored := &ssomodels.SSOSettings{Provider: social.GrafanaComProviderName, Settings: settings}
	sso := ssosettingstests.NewFakeService()
	sso.ExpectedSSOSetting = stored
	sso.ExpectedSSOSettings = []*ssomodels.SSOSettings{stored}

	socialService := socialimpl.ProvideService(
		context.Background(),
		provider,
		featuremgmt.WithFeatures(),
		&usagestats.UsageStatsMock{T: t},
		supportbundlestest.NewFakeBundleService(),
		nil,
		nil,
		sso,
	)

	users := newRecordingUsers(existing)
	authInfo := &authinfotest.FakeService{ExpectedError: user.ErrUserNotFound}
	authInfo.SetAuthInfoFn = func(context.Context, *login.SetAuthInfoCommand) error { return nil }
	authInfo.UpdateAuthInfoFn = func(context.Context, *login.UpdateAuthInfoCommand) error { return nil }
	if existing != nil {
		authInfo.ExpectedError = nil
		authInfo.ExpectedUserAuth = &login.UserAuth{UserId: existing.ID, AuthModule: login.GrafanaComAuthModule}
	}

	userSync := sync.ProvideUserSync(
		users,
		authinfoimpl.ProvideOSSUserProtectionService(),
		authInfo,
		quotatest.New(false, nil),
		tracing.InitializeTracerForTest(),
		featuremgmt.WithFeatures(),
		cfg,
		nil,
	)
	orgs := newRecordingOrgs()
	orgSync := sync.ProvideOrgSync(users, orgs, &actest.FakeService{}, cfg, tracing.InitializeTracerForTest())

	return &grafanaComLoginHarness{
		idp:      idp,
		client:   clients.ProvideOAuth(authn.ClientWithPrefix(social.GrafanaComProviderName), provider, nil, socialService, nil, featuremgmt.WithFeatures(), tracing.InitializeTracerForTest()),
		social:   socialService,
		users:    users,
		orgs:     orgs,
		userSync: userSync,
		orgSync:  orgSync,
		cfg:      cfg,
		stored:   stored,
	}
}

func (h *grafanaComLoginHarness) login(t *testing.T, emails []string, orgLogin, username string) (*authn.Identity, error) {
	t.Helper()
	h.users.created = nil
	h.users.updated = nil
	h.orgs.added = nil
	h.idp.prepare(emails, orgLogin, username)

	info, err := h.social.GetOAuthInfoProvider(context.Background(), social.GrafanaComProviderName)
	require.NoError(t, err)

	callback, err := url.Parse(h.idp.server.URL + "/login/grafana_com?state=" + grafanaComState + "&code=" + grafanaComCode)
	require.NoError(t, err)
	req := &authn.Request{HTTPRequest: &http.Request{
		Header: http.Header{},
		URL:    callback,
	}}
	// Same cookie the OAuth client stores: sha256(state + secret key + client secret).
	req.HTTPRequest.AddCookie(&http.Cookie{
		Name:  "oauth_state",
		Value: oauthStateHash(grafanaComState, h.cfg.SecretKey, info.ClientSecret),
	})

	identity, err := h.client.Authenticate(context.Background(), req)
	if err != nil {
		return nil, err
	}

	// The auth service runs these hooks only after the OAuth client returns an identity.
	if err := h.userSync.SyncUserHook(context.Background(), identity, req); err != nil {
		return identity, err
	}
	if err := h.orgSync.SyncOrgRolesHook(context.Background(), identity, req); err != nil {
		return identity, err
	}
	return identity, nil
}

func requireEmailNotAllowed(t *testing.T, err error) {
	t.Helper()
	require.ErrorContains(t, err, "[auth.oauth.email.not-allowed]")
	require.ErrorContains(t, err, "provided email is not allowed")
}

func requireSignInRejected(t *testing.T, h *grafanaComLoginHarness, signedIn *authn.Identity, err error) {
	t.Helper()
	if err == nil || signedIn != nil || len(h.users.created) > 0 || len(h.users.updated) > 0 || len(h.orgs.added) > 0 {
		t.Fatalf("sign-in continued: err=%v identity=%+v created=%+v updated=%+v orgAdds=%+v", err, signedIn, h.users.created, h.users.updated, h.orgs.added)
	}
	requireEmailNotAllowed(t, err)
}

// oauthStateHash matches OAuth.hashOAuthState: sha256(state + secret key + client secret).
func oauthStateHash(state, secret, seed string) string {
	sum := sha256.Sum256([]byte(state + secret + seed))
	return hex.EncodeToString(sum[:])
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "conf", "defaults.ini")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "conf/defaults.ini not found")
		dir = parent
	}
}

func enabledGrafanaComOverrides(allowedDomains, allowedOrgs string) map[string]map[string]string {
	return map[string]map[string]string{
		"auth.grafana_com": {
			"enabled":               "true",
			"client_id":             grafanaComClientID,
			"client_secret":         grafanaComClientSecret,
			"allowed_domains":       allowedDomains,
			"allowed_organizations": allowedOrgs,
		},
	}
}

func TestGrafanaComLogin_AllowedDomains(t *testing.T) {
	const (
		companyDomain = "company.example"
		outsider      = "outside@attacker.test"
		insider       = "person@company.example"
		partner       = "person@partner.example"
		subdomain     = "person@extra.company.example"
		lookalike     = "person@notcompany.example"
	)

	t.Run("rejects an email outside allowed_domains without creating or updating a user", func(t *testing.T) {
		idp := newGrafanaComIDP(t)
		h := newGrafanaComLoginHarness(t, idp, enabledGrafanaComOverrides(companyDomain, ""), nil)
		info, err := h.social.GetOAuthInfoProvider(context.Background(), social.GrafanaComProviderName)
		require.NoError(t, err)
		require.Equal(t, []string{companyDomain}, info.AllowedDomains)
		require.True(t, info.Enabled)
		require.True(t, info.AllowSignup, "shipped auth.grafana_com allow_sign_up stays enabled")

		// A later userinfo read returns an address inside the allowlist. The sign-in
		// decision has to use the first address.
		identity, err := h.login(t, []string{outsider, insider}, "acme", grafanaComUsername)
		requireSignInRejected(t, h, identity, err)
	})

	t.Run("creates a local user and assigns the provider role when the email is allowed", func(t *testing.T) {
		idp := newGrafanaComIDP(t)
		h := newGrafanaComLoginHarness(t, idp, enabledGrafanaComOverrides(companyDomain+", partner.example", ""), nil)

		identity, err := h.login(t, []string{partner, outsider}, "acme", grafanaComUsername)
		require.NoError(t, err)
		require.Equal(t, partner, identity.Email)
		require.Equal(t, grafanaComUsername, identity.Login)
		require.Equal(t, login.GrafanaComAuthModule, identity.AuthenticatedBy)
		require.Equal(t, "42", identity.AuthID)
		require.True(t, identity.ClientParams.AllowSignUp)
		require.True(t, identity.ClientParams.SyncUser)
		require.True(t, identity.ClientParams.SyncOrgRoles)
		require.Equal(t, org.RoleAdmin, identity.OrgRoles[grafanaComOrgID])

		require.Len(t, h.users.created, 1)
		require.Equal(t, partner, h.users.created[0].Email)
		require.Equal(t, grafanaComUsername, h.users.created[0].Login)
		require.Len(t, h.orgs.added, 1)
		require.Equal(t, int64(grafanaComUserID), h.orgs.added[0].UserID)
		require.Equal(t, grafanaComOrgID, h.orgs.added[0].OrgID)
		require.Equal(t, org.RoleAdmin, h.orgs.added[0].Role)
	})

	t.Run("matches the allowed domain case-insensitively", func(t *testing.T) {
		idp := newGrafanaComIDP(t)
		h := newGrafanaComLoginHarness(t, idp, enabledGrafanaComOverrides(companyDomain, ""), nil)

		identity, err := h.login(t, []string{"Person@Company.Example", outsider}, "acme", grafanaComUsername)
		require.NoError(t, err)
		require.Equal(t, "Person@Company.Example", identity.Email)
		require.Equal(t, "Person@Company.Example", h.users.created[0].Email)
	})

	t.Run("rejects an address that only shares a domain suffix", func(t *testing.T) {
		idp := newGrafanaComIDP(t)
		h := newGrafanaComLoginHarness(t, idp, enabledGrafanaComOverrides(companyDomain, ""), nil)

		for _, email := range []string{subdomain, lookalike} {
			identity, err := h.login(t, []string{email, insider}, "acme", grafanaComUsername)
			requireSignInRejected(t, h, identity, err)
		}
	})

	t.Run("rejects an allowed organization member whose email is outside allowed_domains", func(t *testing.T) {
		idp := newGrafanaComIDP(t)
		h := newGrafanaComLoginHarness(t, idp, enabledGrafanaComOverrides(companyDomain, "acme"), nil)

		identity, err := h.login(t, []string{outsider, insider}, "acme", grafanaComUsername)
		requireSignInRejected(t, h, identity, err)
	})

	t.Run("still rejects a user who is not in allowed_organizations", func(t *testing.T) {
		idp := newGrafanaComIDP(t)
		h := newGrafanaComLoginHarness(t, idp, enabledGrafanaComOverrides(companyDomain, "acme"), nil)

		identity, err := h.login(t, []string{insider, outsider}, "other-org", grafanaComUsername)
		require.ErrorContains(t, err, "[auth.oauth.userinfo.error]")
		require.ErrorContains(t, err, "allowed organizations")
		require.Nil(t, identity)
		require.Empty(t, h.users.created)
		require.Empty(t, h.orgs.added)
	})

	t.Run("does not update an existing user when the email is outside allowed_domains", func(t *testing.T) {
		idp := newGrafanaComIDP(t)
		existing := &user.User{ID: 7, UID: "uid-7", Login: "exampleuser", Email: "old@company.example", Name: grafanaComDisplayName}
		h := newGrafanaComLoginHarness(t, idp, enabledGrafanaComOverrides(companyDomain, ""), existing)

		identity, err := h.login(t, []string{outsider, insider}, "acme", grafanaComUsername)
		requireSignInRejected(t, h, identity, err)
		require.Equal(t, "old@company.example", existing.Email)
	})

	t.Run("applies allowed_domains from the settings read for that sign-in", func(t *testing.T) {
		idp := newGrafanaComIDP(t)
		h := newGrafanaComLoginHarness(t, idp, enabledGrafanaComOverrides(companyDomain, ""), nil)

		identity, err := h.login(t, []string{outsider, insider}, "acme", grafanaComUsername)
		requireSignInRejected(t, h, identity, err)

		h.stored.Settings["allowed_domains"] = "attacker.test"
		identity, err = h.login(t, []string{outsider, insider}, "acme", grafanaComUsername)
		require.NoError(t, err)
		require.Equal(t, outsider, identity.Email)
		require.Equal(t, outsider, h.users.created[0].Email)
		require.Equal(t, org.RoleAdmin, h.orgs.added[0].Role)

		h.stored.Settings["allowed_domains"] = companyDomain
		identity, err = h.login(t, []string{outsider, insider}, "acme", grafanaComUsername)
		requireSignInRejected(t, h, identity, err)
	})

	t.Run("allows any email when allowed_domains is unset", func(t *testing.T) {
		idp := newGrafanaComIDP(t)
		h := newGrafanaComLoginHarness(t, idp, map[string]map[string]string{
			"auth.grafana_com": {
				"enabled":       "true",
				"client_id":     grafanaComClientID,
				"client_secret": grafanaComClientSecret,
			},
		}, nil)
		info, err := h.social.GetOAuthInfoProvider(context.Background(), social.GrafanaComProviderName)
		require.NoError(t, err)
		require.Empty(t, info.AllowedDomains)

		identity, err := h.login(t, []string{outsider}, "acme", grafanaComUsername)
		require.NoError(t, err)
		require.Equal(t, outsider, identity.Email)
		require.Equal(t, outsider, h.users.created[0].Email)
	})

	t.Run("enforces allowed_domains copied from the legacy grafananet section", func(t *testing.T) {
		idp := newGrafanaComIDP(t)
		h := newGrafanaComLoginHarness(t, idp, map[string]map[string]string{
			"auth.grafana_com": {
				"enabled": "false",
			},
			"auth.grafananet": {
				"enabled":         "true",
				"client_id":       "test-grafananet-client-id",
				"client_secret":   grafanaComClientSecret,
				"allowed_domains": companyDomain,
			},
		}, nil)
		info, err := h.social.GetOAuthInfoProvider(context.Background(), social.GrafanaComProviderName)
		require.NoError(t, err)
		require.Equal(t, []string{companyDomain}, info.AllowedDomains)
		require.Equal(t, "test-grafananet-client-id", info.ClientId)
		require.True(t, info.AllowSignup)

		identity, err := h.login(t, []string{outsider, insider}, "acme", grafanaComUsername)
		requireSignInRejected(t, h, identity, err)
		require.Empty(t, h.orgs.added)
	})
}
