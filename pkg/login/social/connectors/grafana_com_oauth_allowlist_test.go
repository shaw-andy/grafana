package connectors_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	claims "github.com/grafana/authlib/types"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/authn"
	orgsync "github.com/grafana/grafana/pkg/services/authn/authnimpl/sync"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	ssoModels "github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/ssosettings/ssosettingstests"
	"github.com/grafana/grafana/pkg/services/ssosettings/strategies"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
)

const grafanaComUserPath = "/api/oauth2/user"

// shippedGrafanaComINI is the shipped auth.grafana_com section with the provider
// enabled and allowed_organizations left empty.
const shippedGrafanaComINI = `
[users]
allow_sign_up = true
auto_assign_org = true
auto_assign_org_id = 1
auto_assign_org_role = Viewer

[auth.grafana_com]
enabled = true
allow_sign_up = true
auto_login = false
client_id = client-id
scopes = user:email
allowed_organizations =
skip_org_role_sync = false
use_refresh_token = false

[auth.grafananet]
enabled = false
allow_sign_up = true
client_id = client-id
scopes = user:email
allowed_organizations =
skip_org_role_sync = false
`

func TestGrafanaComOrganizationAllowlist(t *testing.T) {
	attacker := grafanaComUserPayload(101, "Admin", "not-on-the-allowlist", "Viewer")
	// A second read of the user API must not authorize a different account or role
	// than the response the membership decision used.
	laterAccount := grafanaComUserPayload(202, "Admin", "allowed-org", "Admin")

	t.Run("empty allowlist does not accept an account or map its API role", func(t *testing.T) {
		assertGrafanaComLoginRefused(t, shippedGrafanaComINI, "", attacker, laterAccount)
	})

	t.Run("empty allowlist refuses an account that belongs to no organization", func(t *testing.T) {
		assertGrafanaComLoginRefused(t, shippedGrafanaComINI, "", grafanaComUserPayload(101, "Admin", "", ""), laterAccount)
	})

	t.Run("empty allowlist refuses a non-admin API role", func(t *testing.T) {
		assertGrafanaComLoginRefused(t, shippedGrafanaComINI, "", grafanaComUserPayload(101, "Editor", "not-on-the-allowlist", "Viewer"), laterAccount)
	})

	t.Run("empty allowlist refuses an API role that is not a Grafana role", func(t *testing.T) {
		assertGrafanaComLoginRefused(t, shippedGrafanaComINI, "", grafanaComUserPayload(101, "Owner", "not-on-the-allowlist", "Viewer"), laterAccount)
	})

	t.Run("empty allowlist refuses signup when org role sync is skipped", func(t *testing.T) {
		ini := `
[users]
allow_sign_up = true
auto_assign_org = true
auto_assign_org_id = 1
auto_assign_org_role = Viewer

[auth.grafana_com]
enabled = true
allow_sign_up = true
client_id = client-id
scopes = user:email
allowed_organizations =
skip_org_role_sync = true

[auth.grafananet]
enabled = false
`
		assertGrafanaComLoginRefused(t, ini, "", attacker, laterAccount)
	})

	t.Run("json empty allowlist refuses the account", func(t *testing.T) {
		ini := `
[users]
allow_sign_up = true
auto_assign_org = true
auto_assign_org_id = 1
auto_assign_org_role = Viewer

[auth.grafana_com]
enabled = true
allow_sign_up = true
client_id = client-id
scopes = user:email
allowed_organizations = []
skip_org_role_sync = false

[auth.grafananet]
enabled = false
`
		assertGrafanaComLoginRefused(t, ini, "[]", attacker, laterAccount)
	})

	t.Run("legacy grafananet section with an empty allowlist refuses the account", func(t *testing.T) {
		ini := `
[users]
allow_sign_up = true
auto_assign_org = true
auto_assign_org_id = 1
auto_assign_org_role = Viewer

[auth.grafana_com]
enabled = false
allow_sign_up = true
client_id = client-id
allowed_organizations = kept-org
skip_org_role_sync = false

[auth.grafananet]
enabled = true
allow_sign_up = true
client_id = client-id
scopes = user:email
allowed_organizations =
skip_org_role_sync = false
`
		assertGrafanaComLoginRefused(t, ini, "", attacker, laterAccount)
	})

	t.Run("reloading an empty allowlist refuses an account that was previously outside it", func(t *testing.T) {
		ini := `
[users]
allow_sign_up = true
auto_assign_org = true
auto_assign_org_id = 1
auto_assign_org_role = Viewer

[auth.grafana_com]
enabled = true
allow_sign_up = true
client_id = client-id
scopes = user:email
allowed_organizations = allowed-org
skip_org_role_sync = false

[auth.grafananet]
enabled = false
`
		api := &sequencedGrafanaComAPI{userBodies: []string{attacker, laterAccount}}
		connector, cfg := grafanaComConnector(t, ini, api)
		require.Equal(t, "allowed-org", connector.GetOAuthInfo().Extra["allowed_organizations"])

		identity, info, err := loginGrafanaCom(t, connector, api)
		require.Error(t, err)
		require.Nil(t, info)
		require.Nil(t, identity)
		require.Equal(t, 1, api.userHitCount(), "membership has to be decided from the user payload that is acted on")
		api.reset()

		require.NoError(t, connector.Reload(context.Background(), ssoModels.SSOSettings{
			Settings: map[string]any{
				"client_id":             "client-id",
				"allow_sign_up":         true,
				"enabled":               true,
				"skip_org_role_sync":    false,
				"allowed_organizations": "",
			},
		}))
		require.Empty(t, connector.GetOAuthInfo().Extra["allowed_organizations"])

		identity, info, err = loginGrafanaCom(t, connector, api)
		added, updated := syncGrafanaComOrgRoles(t, cfg, identity)
		require.Error(t, err, "reloaded empty allowlist accepted user %#v info %#v adds %#v updates %#v", identity, info, added, updated)
		require.Nil(t, info)
		require.Nil(t, identity)
		requireNoAdminOrgRole(t, cfg.DefaultOrgID(), added, updated)
		require.Equal(t, 1, api.userHitCount(), "reloading must not authorize a later user-info response")
	})

	t.Run("an account outside the allowlist is not accepted from a later user-info response", func(t *testing.T) {
		ini := `
[users]
allow_sign_up = true
auto_assign_org = true
auto_assign_org_id = 1
auto_assign_org_role = Viewer

[auth.grafana_com]
enabled = true
allow_sign_up = true
client_id = client-id
scopes = user:email
allowed_organizations = allowed-org
skip_org_role_sync = false

[auth.grafananet]
enabled = false
`
		api := &sequencedGrafanaComAPI{userBodies: []string{attacker, laterAccount}}
		connector, cfg := grafanaComConnector(t, ini, api)
		identity, info, err := loginGrafanaCom(t, connector, api)
		added, updated := syncGrafanaComOrgRoles(t, cfg, identity)
		require.Error(t, err, "non-member accepted as %#v info %#v adds %#v updates %#v", identity, info, added, updated)
		require.Nil(t, info)
		require.Nil(t, identity)
		requireNoAdminOrgRole(t, cfg.DefaultOrgID(), added, updated)
		require.Equal(t, 1, api.userHitCount())
	})

	t.Run("a matching allowlist uses the role from that same user-info response", func(t *testing.T) {
		ini := `
[users]
allow_sign_up = true
auto_assign_org = true
auto_assign_org_id = 1
auto_assign_org_role = Viewer

[auth.grafana_com]
enabled = true
allow_sign_up = true
client_id = client-id
scopes = user:email
allowed_organizations = allowed-org
skip_org_role_sync = false

[auth.grafananet]
enabled = false
`
		member := grafanaComUserPayload(101, "Viewer", "allowed-org", "Viewer")
		api := &sequencedGrafanaComAPI{userBodies: []string{member, laterAccount}}
		connector, cfg := grafanaComConnector(t, ini, api)
		identity, info, err := loginGrafanaCom(t, connector, api)
		require.NoError(t, err)
		require.NotNil(t, info)
		require.NotNil(t, identity)
		require.Equal(t, "101", identity.AuthID)
		require.Equal(t, org.RoleViewer, identity.OrgRoles[cfg.DefaultOrgID()])
		require.Equal(t, org.RoleViewer, info.OrgRoles[cfg.DefaultOrgID()])
		require.Equal(t, 1, api.userHitCount())

		added, updated := syncGrafanaComOrgRoles(t, cfg, identity)
		for _, cmd := range added {
			require.Equal(t, cfg.DefaultOrgID(), cmd.OrgID)
			require.Equal(t, org.RoleViewer, cmd.Role)
		}
		for _, cmd := range updated {
			require.Equal(t, cfg.DefaultOrgID(), cmd.OrgID)
			require.Equal(t, org.RoleViewer, cmd.Role)
		}
	})
}

func assertGrafanaComLoginRefused(t *testing.T, iniText, allowedOrganizations, firstBody, secondBody string) {
	t.Helper()

	api := &sequencedGrafanaComAPI{userBodies: []string{firstBody, secondBody}}
	connector, cfg := grafanaComConnector(t, iniText, api)
	require.Equal(t, allowedOrganizations, connector.GetOAuthInfo().Extra["allowed_organizations"])
	require.True(t, connector.GetOAuthInfo().Enabled)
	require.True(t, connector.GetOAuthInfo().AllowSignup)
	require.True(t, connector.IsSignupAllowed())

	identity, info, err := loginGrafanaCom(t, connector, api)
	added, updated := syncGrafanaComOrgRoles(t, cfg, identity)
	require.Error(t, err, "empty allowlist accepted grafana.com user %#v info %#v adds %#v updates %#v", identity, info, added, updated)
	require.Nil(t, info)
	require.Nil(t, identity)
	requireNoAdminOrgRole(t, cfg.DefaultOrgID(), added, updated)
	require.Equal(t, 1, api.userHitCount(), "user info was read again after the membership decision")
}

func grafanaComConnector(t *testing.T, iniText string, api *sequencedGrafanaComAPI) (*connectors.SocialGrafanaCom, *setting.Cfg) {
	t.Helper()

	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	api.client = server.Client()

	cfg, err := setting.NewCfgFromBytesWithoutJSValidation([]byte(iniText))
	require.NoError(t, err)
	cfg.GrafanaComURL = server.URL

	cfgProvider := configProvider(t, cfg)
	settings, err := strategies.NewOAuthStrategy(cfgProvider).GetProviderConfig(context.Background(), social.GrafanaComProviderName)
	require.NoError(t, err)
	info, err := connectors.CreateOAuthInfoFromKeyValues(settings)
	require.NoError(t, err)

	connector, err := connectors.NewGrafanaComProvider(
		context.Background(),
		info,
		cfgProvider,
		connectors.ProvideOrgRoleMapper(cfgProvider, &orgtest.FakeOrgService{}),
		ssosettingstests.NewFakeService(),
		featuremgmt.WithFeatures(),
	)
	require.NoError(t, err)
	return connector, cfg
}

func configProvider(t *testing.T, cfg *setting.Cfg) configprovider.ConfigProvider {
	t.Helper()
	provider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	return provider
}

// loginGrafanaCom reads the user API through SocialGrafanaCom.UserInfo and, when
// that call accepts the account, copies the fields OAuth.Authenticate passes to
// org role sync.
func loginGrafanaCom(t *testing.T, connector *connectors.SocialGrafanaCom, api *sequencedGrafanaComAPI) (*authn.Identity, *social.BasicUserInfo, error) {
	t.Helper()

	info, err := connector.UserInfo(context.Background(), api.client, nil)
	if err != nil {
		return nil, info, err
	}
	return &authn.Identity{
		Login:           info.Login,
		Name:            info.Name,
		Email:           info.Email,
		IsGrafanaAdmin:  info.IsGrafanaAdmin,
		AuthenticatedBy: login.GrafanaComAuthModule,
		AuthID:          info.Id,
		ExternalGroups:  info.Groups,
		OrgRoles:        info.OrgRoles,
		ClientParams: authn.ClientParams{
			SyncUser:        true,
			SyncTeams:       true,
			FetchSyncedUser: true,
			SyncPermissions: true,
			AllowSignUp:     connector.IsSignupAllowed(),
			SyncOrgRoles:    len(info.OrgRoles) > 0,
		},
	}, info, nil
}

// syncGrafanaComOrgRoles applies the org roles from a successful login the way
// the post-auth hooks do. SyncUserHook assigns the internal id before org sync.
// A refused login has no identity, so nothing is written.
func syncGrafanaComOrgRoles(t *testing.T, cfg *setting.Cfg, identity *authn.Identity) ([]org.AddOrgUserCommand, []org.UpdateOrgUserCommand) {
	t.Helper()
	if identity == nil {
		return nil, nil
	}

	newUser := cloneAuthIdentity(identity)
	newUser.ID = "1"
	newUser.Type = claims.TypeUser
	newOrg := newRecordingOrgService(cfg.DefaultOrgID(), nil)
	require.NoError(t, newOrgSync(t, cfg, newOrg).SyncOrgRolesHook(context.Background(), newUser, nil))

	existing := cloneAuthIdentity(identity)
	existing.ID = "1"
	existing.Type = claims.TypeUser
	existing.OrgID = cfg.DefaultOrgID()
	existingOrg := newRecordingOrgService(cfg.DefaultOrgID(), []*org.UserOrgDTO{{
		OrgID: cfg.DefaultOrgID(),
		Name:  "Main Org.",
		Role:  org.RoleViewer,
	}})
	require.NoError(t, newOrgSync(t, cfg, existingOrg).SyncOrgRolesHook(context.Background(), existing, nil))

	return append(newOrg.added, existingOrg.added...), append(newOrg.updated, existingOrg.updated...)
}

func newOrgSync(t *testing.T, cfg *setting.Cfg, orgService org.Service) *orgsync.OrgSync {
	t.Helper()
	return orgsync.ProvideOrgSync(&usertest.FakeUserService{}, orgService, &actest.FakeService{}, cfg, tracing.InitializeTracerForTest())
}

func requireNoAdminOrgRole(t *testing.T, orgID int64, added []org.AddOrgUserCommand, updated []org.UpdateOrgUserCommand) {
	t.Helper()
	for _, cmd := range added {
		require.False(t, cmd.OrgID == orgID && cmd.Role == org.RoleAdmin, "added org admin: %#v", cmd)
	}
	for _, cmd := range updated {
		require.False(t, cmd.OrgID == orgID && cmd.Role == org.RoleAdmin, "updated org admin: %#v", cmd)
	}
}

func cloneAuthIdentity(id *authn.Identity) *authn.Identity {
	cp := *id
	if id.OrgRoles != nil {
		cp.OrgRoles = make(map[int64]org.RoleType, len(id.OrgRoles))
		for orgID, role := range id.OrgRoles {
			cp.OrgRoles[orgID] = role
		}
	}
	return &cp
}

type recordingOrgService struct {
	*orgtest.FakeOrgService
	defaultOrgID int64
	added        []org.AddOrgUserCommand
	updated      []org.UpdateOrgUserCommand
}

func newRecordingOrgService(defaultOrgID int64, memberships []*org.UserOrgDTO) *recordingOrgService {
	return &recordingOrgService{
		FakeOrgService: &orgtest.FakeOrgService{ExpectedUserOrgDTO: memberships},
		defaultOrgID:   defaultOrgID,
	}
}

func (r *recordingOrgService) AddOrgUser(_ context.Context, cmd *org.AddOrgUserCommand) error {
	if cmd.OrgID != r.defaultOrgID {
		return org.ErrOrgNotFound
	}
	r.added = append(r.added, *cmd)
	return nil
}

func (r *recordingOrgService) UpdateOrgUser(_ context.Context, cmd *org.UpdateOrgUserCommand) error {
	for _, membership := range r.ExpectedUserOrgDTO {
		if membership.OrgID == cmd.OrgID {
			r.updated = append(r.updated, *cmd)
			return nil
		}
	}
	return org.ErrOrgUserNotFound
}

type sequencedGrafanaComAPI struct {
	mu         sync.Mutex
	userBodies []string
	userHits   int
	client     *http.Client
}

func (s *sequencedGrafanaComAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case grafanaComUserPath:
		s.mu.Lock()
		body := s.userBodies[len(s.userBodies)-1]
		if s.userHits < len(s.userBodies) {
			body = s.userBodies[s.userHits]
		}
		s.userHits++
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	default:
		http.NotFound(w, r)
	}
}

func (s *sequencedGrafanaComAPI) userHitCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.userHits
}

func (s *sequencedGrafanaComAPI) reset() {
	s.mu.Lock()
	s.userHits = 0
	s.mu.Unlock()
}

func grafanaComUserPayload(id int, role, orgLogin, orgRole string) string {
	orgs := "[]"
	if orgLogin != "" {
		orgs = fmt.Sprintf(`[{"login":%q,"role":%q}]`, orgLogin, orgRole)
	}
	return fmt.Sprintf(`{"id":%d,"name":"Example User","username":"example-user","email":"example-user@example.com","role":%q,"orgs":%s}`, id, role, orgs)
}
