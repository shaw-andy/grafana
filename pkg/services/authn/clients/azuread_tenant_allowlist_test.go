package clients_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/login/social/socialtest"
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
	ssoModels "github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/ssosettings/ssosettingstests"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	azureClientID      = "azure-client-id"
	azureClientSecret  = "test-client-secret"
	attackerTenantID   = "11111111-1111-1111-1111-111111111111"
	homeTenantID       = "22222222-2222-2222-2222-222222222222"
	attackerEmail      = "attacker@example.com"
	attackerObjectID   = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	accessTokenSubject = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

// recordingOrgService stores the organization memberships OrgSync asks the org
// service to add. The SQL store writes that command's role unchanged.
type recordingOrgService struct {
	*orgtest.FakeOrgService
	added []*org.AddOrgUserCommand
}

func (r *recordingOrgService) AddOrgUser(_ context.Context, cmd *org.AddOrgUserCommand) error {
	copied := *cmd
	r.added = append(r.added, &copied)
	return nil
}

type azureLoginHarness struct {
	cfg            *setting.Cfg
	connector      *connectors.SocialAzureAD
	idToken        string
	accessToken    string
	created        []*user.CreateUserCommand
	orgMemberships *recordingOrgService
}

func (h *azureLoginHarness) login(t *testing.T) (*authn.Identity, error) {
	t.Helper()

	state, stateHash, err := genOAuthState(h.cfg.SecretKey, azureClientSecret)
	require.NoError(t, err)

	loginURL := &url.URL{Scheme: "http", Host: "grafana.example", Path: "/login/azuread"}
	query := loginURL.Query()
	query.Set("state", state)
	query.Set("code", "authorization-code")
	loginURL.RawQuery = query.Encode()

	req := &authn.Request{
		HTTPRequest: &http.Request{
			Header: http.Header{},
			URL:    loginURL,
		},
	}
	req.HTTPRequest.AddCookie(&http.Cookie{Name: oauthStateCookieName, Value: stateHash})
	req.HTTPRequest.AddCookie(&http.Cookie{Name: oauthPKCECookieName, Value: "test-pkce-verifier"})

	oauthInfo := h.connector.GetOAuthInfo()
	client := clients.ProvideOAuth(
		authn.ClientWithPrefix(social.AzureADProviderName),
		newTestConfigProvider(t, h.cfg),
		nil,
		&socialtest.FakeSocialService{
			ExpectedAuthInfoProvider: oauthInfo,
			ExpectedConnector:        h.connector,
			ExpectedHttpClient:       http.DefaultClient,
		},
		nil,
		featuremgmt.WithFeatures(),
		tracing.InitializeTracerForTest(),
	)

	identity, err := client.Authenticate(context.Background(), req)
	if err != nil || identity == nil {
		return identity, err
	}

	userService := &usertest.FakeUserService{
		CreateFn: func(_ context.Context, cmd *user.CreateUserCommand) (*user.User, error) {
			copied := *cmd
			h.created = append(h.created, &copied)
			return &user.User{
				ID:    7,
				UID:   "user-7",
				Login: cmd.Login,
				Email: cmd.Email,
				Name:  cmd.Name,
			}, nil
		},
	}
	userSync := sync.ProvideUserSync(
		userService,
		&authinfoimpl.OSSUserProtectionImpl{},
		&authinfotest.FakeService{
			ExpectedError: user.ErrUserNotFound,
			SetAuthInfoFn: func(context.Context, *login.SetAuthInfoCommand) error { return nil },
		},
		quotatest.New(false, nil),
		tracing.InitializeTracerForTest(),
		featuremgmt.WithFeatures(),
		h.cfg,
		nil,
	)
	orgSync := sync.ProvideOrgSync(userService, h.orgMemberships, nil, h.cfg, tracing.InitializeTracerForTest())

	require.NoError(t, userSync.SyncUserHook(context.Background(), identity, req))
	require.NoError(t, orgSync.SyncOrgRolesHook(context.Background(), identity, req))
	return identity, nil
}

func newAzureLoginHarness(t *testing.T, allowedOrganizations string, idTokenTenant string) *azureLoginHarness {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithHeader("kid", "test-key"))
	require.NoError(t, err)

	webKey := jose.JSONWebKey{
		Key:       privateKey.Public(),
		KeyID:     "test-key",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	encodedKeys, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{webKey}})
	require.NoError(t, err)
	var jwksDoc map[string]any
	require.NoError(t, json.Unmarshal(encodedKeys, &jwksDoc))
	keys, ok := jwksDoc["keys"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, keys)
	key, ok := keys[0].(map[string]any)
	require.True(t, ok)
	// Tenant-independent Microsoft Entra signing keys publish this issuer template.
	// Signature verification accepts any tenant substituted into it.
	key["issuer"] = "https://login.microsoftonline.com/{tenantid}/v2.0"

	harness := &azureLoginHarness{
		orgMemberships: &recordingOrgService{FakeOrgService: orgtest.NewOrgServiceFake()},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/organizations/discovery/v2.0/keys":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(jwksDoc))
		case "/organizations/oauth2/v2.0/token":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"access_token": harness.accessToken,
				"token_type":   "Bearer",
				"id_token":     harness.idToken,
			}))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	authURL := server.URL + "/organizations/oauth2/v2.0/authorize"
	tokenURL := server.URL + "/organizations/oauth2/v2.0/token"

	cfg := setting.NewCfg()
	cfg.AppURL = "http://grafana.example/"
	cfg.SecretKey = "test-secret-key"
	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgId = 1
	cfg.AutoAssignOrgRole = "Viewer"
	harness.cfg = cfg

	info := &social.OAuthInfo{
		Enabled:         true,
		AllowSignup:     true,
		ClientId:        azureClientID,
		ClientSecret:    azureClientSecret,
		AuthUrl:         authURL,
		TokenUrl:        tokenURL,
		Scopes:          []string{"openid", "email", "profile"},
		UsePKCE:         true,
		SkipOrgRoleSync: false,
		UseRefreshToken: false,
		Extra: map[string]string{
			"allowed_organizations": allowedOrganizations,
		},
	}

	connector, err := connectors.NewAzureADProvider(
		context.Background(),
		info,
		newTestConfigProvider(t, cfg),
		connectors.ProvideOrgRoleMapper(newTestConfigProvider(t, cfg), orgtest.NewOrgServiceFake()),
		ssosettingstests.NewFakeService(),
		featuremgmt.WithFeatures(),
		remotecache.NewFakeCacheStorage(),
	)
	require.NoError(t, err)
	harness.connector = connector

	harness.idToken = signAzureToken(t, signer, map[string]any{
		"aud":                azureClientID,
		"iss":                "https://login.microsoftonline.com/" + idTokenTenant + "/v2.0",
		"tid":                idTokenTenant,
		"oid":                attackerObjectID,
		"sub":                "subject-in-id-token-tenant",
		"email":              attackerEmail,
		"preferred_username": attackerEmail,
		"name":               "Attacker",
		"roles":              []string{"Admin"},
		"ver":                "2.0",
	})
	// A different tenant, carried only by the access token. Role mapping must
	// follow the ID token that was signature-checked, not this value.
	harness.accessToken = signAzureToken(t, signer, map[string]any{
		"aud":  azureClientID,
		"iss":  "https://login.microsoftonline.com/" + homeTenantID + "/v2.0",
		"tid":  homeTenantID,
		"oid":  accessTokenSubject,
		"ver":  "2.0",
		"role": "Viewer",
	})
	return harness
}

func signAzureToken(t *testing.T, signer jose.Signer, claims map[string]any) string {
	t.Helper()
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

func assertNoOrgAdmin(t *testing.T, created []*user.CreateUserCommand, memberships []*org.AddOrgUserCommand) {
	t.Helper()
	if len(created) == 0 && len(memberships) == 0 {
		return
	}
	details := make([]string, 0, len(created)+len(memberships))
	for _, cmd := range created {
		details = append(details, fmt.Sprintf("create login=%s defaultOrgRole=%s skipOrgSetup=%v", cmd.Login, cmd.DefaultOrgRole, cmd.SkipOrgSetup))
	}
	for _, membership := range memberships {
		details = append(details, fmt.Sprintf("orgUser org=%d user=%d role=%s", membership.OrgID, membership.UserID, membership.Role))
	}
	t.Fatalf("tenant that was not allow-listed was provisioned: %s", strings.Join(details, "; "))
}

func TestAzureADEmptyAllowedOrganizationsRejectsForeignTenantAdmin(t *testing.T) {
	h := newAzureLoginHarness(t, "", attackerTenantID)

	identity, err := h.login(t)
	assertNoOrgAdmin(t, h.created, h.orgMemberships.added)
	require.Error(t, err)
	require.Nil(t, identity)
}

func TestAzureADBlankAllowedOrganizationsRejectsForeignTenantAdmin(t *testing.T) {
	h := newAzureLoginHarness(t, "   ", attackerTenantID)

	identity, err := h.login(t)
	assertNoOrgAdmin(t, h.created, h.orgMemberships.added)
	require.Error(t, err)
	require.Nil(t, identity)
}

func TestAzureADReloadToEmptyAllowedOrganizationsRejectsForeignTenantAdmin(t *testing.T) {
	h := newAzureLoginHarness(t, homeTenantID, attackerTenantID)

	identity, err := h.login(t)
	assertNoOrgAdmin(t, h.created, h.orgMemberships.added)
	require.Error(t, err)
	require.Nil(t, identity)

	info := h.connector.GetOAuthInfo()
	require.NoError(t, h.connector.Reload(context.Background(), ssoModels.SSOSettings{
		Settings: map[string]any{
			"enabled":               true,
			"allow_sign_up":         true,
			"client_id":             info.ClientId,
			"client_secret":         azureClientSecret,
			"auth_url":              info.AuthUrl,
			"token_url":             info.TokenUrl,
			"scopes":                "openid email profile",
			"use_pkce":              true,
			"skip_org_role_sync":    false,
			"use_refresh_token":     false,
			"allowed_organizations": "",
			"allowed_groups":        "",
		},
	}))

	identity, err = h.login(t)
	assertNoOrgAdmin(t, h.created, h.orgMemberships.added)
	require.Error(t, err)
	require.Nil(t, identity)
}

func TestAzureADAllowListDoesNotAuthorizeAccessTokenTenant(t *testing.T) {
	// The access token's tenant is allow-listed. The ID token's tenant is not.
	// Authorizing the access token and then mapping the ID token's Admin role
	// would grant the wrong tenant's role.
	h := newAzureLoginHarness(t, homeTenantID, attackerTenantID)

	identity, err := h.login(t)
	assertNoOrgAdmin(t, h.created, h.orgMemberships.added)
	require.Error(t, err)
	require.Nil(t, identity)
}

func TestAzureADAllowListedIDTokenTenantMapsAdminToDefaultOrg(t *testing.T) {
	h := newAzureLoginHarness(t, attackerTenantID, attackerTenantID)

	signedIn, err := h.login(t)
	require.NoError(t, err)
	require.NotNil(t, signedIn)
	require.Equal(t, org.RoleAdmin, signedIn.OrgRoles[h.cfg.DefaultOrgID()])
	require.Len(t, h.orgMemberships.added, 1)
	require.Equal(t, h.cfg.DefaultOrgID(), h.orgMemberships.added[0].OrgID)
	require.Equal(t, org.RoleAdmin, h.orgMemberships.added[0].Role)
	require.Equal(t, int64(7), h.orgMemberships.added[0].UserID)
}

func TestAzureADValidateEnabledSettingsRequireAllowedOrganization(t *testing.T) {
	cfg := setting.NewCfg()
	connector, err := connectors.NewAzureADProvider(
		context.Background(),
		&social.OAuthInfo{ClientId: azureClientID, ClientSecret: azureClientSecret, Extra: map[string]string{}},
		newTestConfigProvider(t, cfg),
		connectors.ProvideOrgRoleMapper(newTestConfigProvider(t, cfg), orgtest.NewOrgServiceFake()),
		ssosettingstests.NewFakeService(),
		featuremgmt.WithFeatures(),
		remotecache.NewFakeCacheStorage(),
	)
	require.NoError(t, err)

	requester := &user.SignedInUser{IsGrafanaAdmin: true}
	base := map[string]any{
		"client_authentication": "client_secret_post",
		"client_id":             azureClientID,
		"client_secret":         azureClientSecret,
		"auth_url":              "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
		"token_url":             "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
	}

	t.Run("enabled with an empty list is rejected", func(t *testing.T) {
		settings := cloneSettings(base)
		settings["enabled"] = true
		settings["allowed_organizations"] = ""
		require.Error(t, connector.Validate(context.Background(), ssoModels.SSOSettings{Settings: settings}, ssoModels.SSOSettings{}, requester))
	})

	t.Run("enabled with a tenant is accepted", func(t *testing.T) {
		settings := cloneSettings(base)
		settings["enabled"] = true
		settings["allowed_organizations"] = attackerTenantID
		require.NoError(t, connector.Validate(context.Background(), ssoModels.SSOSettings{Settings: settings}, ssoModels.SSOSettings{}, requester))
	})

	t.Run("disabled with an empty list is accepted", func(t *testing.T) {
		settings := cloneSettings(base)
		settings["enabled"] = false
		settings["allowed_organizations"] = ""
		require.NoError(t, connector.Validate(context.Background(), ssoModels.SSOSettings{Settings: settings}, ssoModels.SSOSettings{}, requester))
	})
}

const (
	oauthStateCookieName = "oauth_state"
	oauthPKCECookieName  = "oauth_code_verifier"
)

func genOAuthState(secret, seed string) (string, string, error) {
	rnd := make([]byte, 32)
	if _, err := rand.Read(rnd); err != nil {
		return "", "", err
	}
	state := base64.URLEncoding.EncodeToString(rnd)
	return state, hashOAuthState(state, secret, seed), nil
}

func hashOAuthState(state, secret, seed string) string {
	hashBytes := sha256.Sum256([]byte(state + secret + seed))
	return hex.EncodeToString(hashBytes[:])
}

func newTestConfigProvider(t *testing.T, cfg *setting.Cfg) configprovider.ConfigProvider {
	t.Helper()
	provider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	return provider
}

func cloneSettings(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
