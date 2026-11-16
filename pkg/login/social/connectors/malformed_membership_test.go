package connectors

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	ssoModels "github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/ssosettings/ssosettingstests"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

func TestMalformedOAuthMembership_GenericEmptyListsStayUnrestricted(t *testing.T) {
	srv := newGenericMembershipServer(t, []string{"other-team"}, []string{"other-org"}, []string{"other-group"})
	settings := genericMembershipSettings(srv)
	settings["team_ids"] = ""
	settings["allowed_organizations"] = ""
	settings["allowed_groups"] = ""
	settings["allowed_domains"] = ""

	provider, err := newGenericFromSettings(t, settings)
	require.NoError(t, err)

	userInfo, err := provider.UserInfo(context.Background(), srv.Client(), &oauth2.Token{})
	require.NoError(t, err)
	require.Equal(t, "outsider@example.com", userInfo.Email)
	require.True(t, provider.IsSignupAllowed())
	require.True(t, provider.IsEmailAllowed("person@other.example"))
}

func TestMalformedOAuthMembership_GenericValidListsStillRestrict(t *testing.T) {
	srv := newGenericMembershipServer(t, []string{"other-team"}, []string{"other-org"}, []string{"other-group"})
	settings := genericMembershipSettings(srv)
	settings["team_ids"] = `["team-a"]`
	settings["allowed_organizations"] = `["org-a"]`
	settings["allowed_groups"] = `["group-a"]`
	settings["groups_attribute_path"] = "groups"
	settings["allowed_domains"] = "corp.example"

	provider, err := newGenericFromSettings(t, settings)
	require.NoError(t, err)
	requireOutsiderDenied(t, provider, srv.Client())
	require.False(t, provider.IsEmailAllowed("person@other.example"))

	requester := &user.SignedInUser{IsGrafanaAdmin: true}
	require.NoError(t, provider.Validate(context.Background(), ssoModels.SSOSettings{Settings: settings}, ssoModels.SSOSettings{}, requester))
}

func TestMalformedOAuthMembership_GenericTeamIDsDoNotAdmitOutsider(t *testing.T) {
	srv := newGenericMembershipServer(t, []string{"other-team"}, []string{"other-org"}, nil)
	settings := genericMembershipSettings(srv)
	settings["team_ids"] = "[team-a, team-b]"

	provider, err := newGenericFromSettings(t, settings)
	if err != nil {
		return
	}
	requireOutsiderDenied(t, provider, srv.Client())
}

func TestMalformedOAuthMembership_GenericOrganizationsDoNotAdmitOutsider(t *testing.T) {
	srv := newGenericMembershipServer(t, []string{"other-team"}, []string{"other-org"}, nil)
	settings := genericMembershipSettings(srv)
	settings["allowed_organizations"] = "[org-a, org-b]"

	provider, err := newGenericFromSettings(t, settings)
	if err != nil {
		return
	}
	requireOutsiderDenied(t, provider, srv.Client())
}

func TestMalformedOAuthMembership_GenericGroupsDoNotAdmitOutsider(t *testing.T) {
	srv := newGenericMembershipServer(t, nil, nil, []string{"other-group"})
	settings := genericMembershipSettings(srv)
	settings["allowed_groups"] = "[group-a, group-b]"
	settings["groups_attribute_path"] = "groups"

	provider, err := newGenericFromSettings(t, settings)
	if err != nil {
		return
	}
	requireOutsiderDenied(t, provider, srv.Client())
}

func TestMalformedOAuthMembership_GenericDomainsDoNotAllowOtherDomain(t *testing.T) {
	srv := newGenericMembershipServer(t, nil, nil, nil)
	settings := genericMembershipSettings(srv)
	settings["allowed_domains"] = "[corp.example]"

	provider, err := newGenericFromSettings(t, settings)
	if err != nil {
		return
	}
	if provider.IsEmailAllowed("person@other.example") {
		t.Fatal("malformed allowed_domains was treated as no domain restriction")
	}
}

func TestMalformedOAuthMembership_GenericValidateRejectsUnparsedLists(t *testing.T) {
	srv := newGenericMembershipServer(t, nil, nil, nil)
	provider, err := newGenericFromSettings(t, genericMembershipSettings(srv))
	require.NoError(t, err)
	requester := &user.SignedInUser{IsGrafanaAdmin: true}

	cases := map[string]string{
		"team_ids":              "[team-a, team-b]",
		"allowed_organizations": "[org-a, org-b]",
		"allowed_groups":        "[group-a, group-b]",
		"allowed_domains":       "[corp.example]",
	}
	for key, value := range cases {
		t.Run(key, func(t *testing.T) {
			settings := genericMembershipSettings(srv)
			settings[key] = value
			if key == "allowed_groups" {
				settings["groups_attribute_path"] = "groups"
			}
			err := provider.Validate(context.Background(), ssoModels.SSOSettings{Settings: settings}, ssoModels.SSOSettings{}, requester)
			require.Error(t, err)
		})
	}

	t.Run("empty and valid json still validate", func(t *testing.T) {
		for _, teamIDs := range []string{"", "[]", `["team-a"]`} {
			settings := genericMembershipSettings(srv)
			settings["team_ids"] = teamIDs
			require.NoError(t, provider.Validate(context.Background(), ssoModels.SSOSettings{Settings: settings}, ssoModels.SSOSettings{}, requester))
		}
	})
}

func TestMalformedOAuthMembership_GenericReloadKeepsTeamRestriction(t *testing.T) {
	srv := newGenericMembershipServer(t, []string{"other-team"}, []string{"other-org"}, nil)
	settings := genericMembershipSettings(srv)
	settings["team_ids"] = `["team-a"]`
	provider, err := newGenericFromSettings(t, settings)
	require.NoError(t, err)
	requireOutsiderDenied(t, provider, srv.Client())

	reloaded := genericMembershipSettings(srv)
	reloaded["team_ids"] = "[team-a, team-b]"
	err = provider.Reload(context.Background(), ssoModels.SSOSettings{Settings: reloaded})
	require.Error(t, err)
	require.NotEmpty(t, provider.teamIds)
	requireOutsiderDenied(t, provider, srv.Client())
}

func TestMalformedOAuthMembership_GenericReloadKeepsOrganizationRestriction(t *testing.T) {
	srv := newGenericMembershipServer(t, nil, []string{"other-org"}, nil)
	settings := genericMembershipSettings(srv)
	settings["allowed_organizations"] = `["org-a"]`
	provider, err := newGenericFromSettings(t, settings)
	require.NoError(t, err)
	requireOutsiderDenied(t, provider, srv.Client())

	reloaded := genericMembershipSettings(srv)
	reloaded["allowed_organizations"] = "[org-a, org-b]"
	err = provider.Reload(context.Background(), ssoModels.SSOSettings{Settings: reloaded})
	require.Error(t, err)
	require.NotEmpty(t, provider.allowedOrganizations)
	requireOutsiderDenied(t, provider, srv.Client())
}

func TestMalformedOAuthMembership_GenericReloadKeepsGroupAndDomainRestrictions(t *testing.T) {
	srv := newGenericMembershipServer(t, nil, nil, []string{"other-group"})
	settings := genericMembershipSettings(srv)
	settings["allowed_groups"] = `["group-a"]`
	settings["groups_attribute_path"] = "groups"
	settings["allowed_domains"] = "corp.example"
	provider, err := newGenericFromSettings(t, settings)
	require.NoError(t, err)
	requireOutsiderDenied(t, provider, srv.Client())
	require.False(t, provider.IsEmailAllowed("person@other.example"))

	reloaded := genericMembershipSettings(srv)
	reloaded["allowed_groups"] = "[group-a, group-b]"
	reloaded["groups_attribute_path"] = "groups"
	reloaded["allowed_domains"] = "[corp.example]"
	err = provider.Reload(context.Background(), ssoModels.SSOSettings{Settings: reloaded})
	require.Error(t, err)
	require.NotEmpty(t, provider.info.AllowedGroups)
	require.NotEmpty(t, provider.info.AllowedDomains)
	requireOutsiderDenied(t, provider, srv.Client())
	require.False(t, provider.IsEmailAllowed("person@other.example"))
}

func TestMalformedOAuthMembership_GitHubTeamIDsDoNotAdmitOutsider(t *testing.T) {
	srv := newGitHubMembershipServer(t)
	settings := map[string]any{
		"client_id":          "client-id",
		"api_url":            srv.URL + "/user",
		"allow_sign_up":      true,
		"skip_org_role_sync": true,
		"team_ids":           "[150, 300]",
	}
	provider, err := newGitHubFromSettings(t, settings)
	if err != nil {
		return
	}
	userInfo, err := provider.UserInfo(context.Background(), srv.Client(), &oauth2.Token{AccessToken: "fake_token"})
	if err == nil {
		t.Fatalf("outsider completed GitHub OAuth login (allow_sign_up=%v): %+v", provider.IsSignupAllowed(), userInfo)
	}
}

func TestMalformedOAuthMembership_GitHubOrganizationsDoNotAdmitOutsider(t *testing.T) {
	srv := newGitHubMembershipServer(t)
	settings := map[string]any{
		"client_id":             "client-id",
		"api_url":               srv.URL + "/user",
		"allow_sign_up":         true,
		"skip_org_role_sync":    true,
		"allowed_organizations": "[acme, other]",
	}
	provider, err := newGitHubFromSettings(t, settings)
	if err != nil {
		return
	}
	userInfo, err := provider.UserInfo(context.Background(), srv.Client(), &oauth2.Token{AccessToken: "fake_token"})
	if err == nil {
		t.Fatalf("outsider completed GitHub OAuth login (allow_sign_up=%v): %+v", provider.IsSignupAllowed(), userInfo)
	}
}

func TestMalformedOAuthMembership_GitHubValidTeamStillRestricts(t *testing.T) {
	srv := newGitHubMembershipServer(t)
	settings := map[string]any{
		"client_id":          "client-id",
		"api_url":            srv.URL + "/user",
		"allow_sign_up":      true,
		"skip_org_role_sync": true,
		"team_ids":           "150",
	}
	provider, err := newGitHubFromSettings(t, settings)
	require.NoError(t, err)
	_, err = provider.UserInfo(context.Background(), srv.Client(), &oauth2.Token{AccessToken: "fake_token"})
	require.Error(t, err)
}

func TestMalformedOAuthMembership_GitHubValidateAndReloadRejectUnparsedLists(t *testing.T) {
	srv := newGitHubMembershipServer(t)
	initial := map[string]any{
		"client_id":             "client-id",
		"api_url":               srv.URL + "/user",
		"allow_sign_up":         true,
		"skip_org_role_sync":    true,
		"team_ids":              "150",
		"allowed_organizations": "acme",
	}
	provider, err := newGitHubFromSettings(t, initial)
	require.NoError(t, err)
	_, err = provider.UserInfo(context.Background(), srv.Client(), &oauth2.Token{AccessToken: "fake_token"})
	require.Error(t, err)

	requester := &user.SignedInUser{IsGrafanaAdmin: true}
	err = provider.Validate(context.Background(), ssoModels.SSOSettings{Settings: map[string]any{
		"client_id": "client-id",
		"team_ids":  "[150, 300]",
	}}, ssoModels.SSOSettings{}, requester)
	require.Error(t, err)
	err = provider.Validate(context.Background(), ssoModels.SSOSettings{Settings: map[string]any{
		"client_id":             "client-id",
		"allowed_organizations": "[acme, other]",
	}}, ssoModels.SSOSettings{}, requester)
	require.Error(t, err)

	reloaded := map[string]any{
		"client_id":             "client-id",
		"api_url":               srv.URL + "/user",
		"allow_sign_up":         true,
		"skip_org_role_sync":    true,
		"team_ids":              "[150, 300]",
		"allowed_organizations": "[acme, other]",
	}
	err = provider.Reload(context.Background(), ssoModels.SSOSettings{Settings: reloaded})
	require.Error(t, err)
	require.NotEmpty(t, provider.teamIds)
	require.NotEmpty(t, provider.allowedOrganizations)
	_, err = provider.UserInfo(context.Background(), srv.Client(), &oauth2.Token{AccessToken: "fake_token"})
	require.Error(t, err)
}

func TestMalformedOAuthMembership_AzureOrganizationsDoNotAdmitOtherTenant(t *testing.T) {
	token, client := azureTenantToken(t, "other-tenant")
	settings := azureMembershipSettings(token.authURL)
	settings["allowed_organizations"] = "[tenant-a, tenant-b]"

	provider, err := newAzureFromSettings(t, settings, token.cache)
	if err != nil {
		return
	}
	userInfo, err := provider.UserInfo(context.Background(), client, token.token)
	if err == nil {
		t.Fatalf("tenant outside the configured organizations completed Azure AD login (allow_sign_up=%v): %+v", provider.IsSignupAllowed(), userInfo)
	}
}

func TestMalformedOAuthMembership_AzureValidOrganizationStillRestricts(t *testing.T) {
	token, client := azureTenantToken(t, "other-tenant")
	settings := azureMembershipSettings(token.authURL)
	settings["allowed_organizations"] = "tenant-a"

	provider, err := newAzureFromSettings(t, settings, token.cache)
	require.NoError(t, err)
	_, err = provider.UserInfo(context.Background(), client, token.token)
	require.Error(t, err)
}

func TestMalformedOAuthMembership_AzureValidateAndReloadRejectUnparsedOrganizations(t *testing.T) {
	token, client := azureTenantToken(t, "other-tenant")
	initial := azureMembershipSettings(token.authURL)
	initial["allowed_organizations"] = "tenant-a"
	provider, err := newAzureFromSettings(t, initial, token.cache)
	require.NoError(t, err)
	_, err = provider.UserInfo(context.Background(), client, token.token)
	require.Error(t, err)

	requester := &user.SignedInUser{IsGrafanaAdmin: true}
	malformed := azureMembershipSettings(token.authURL)
	malformed["allowed_organizations"] = "[tenant-a, tenant-b]"
	err = provider.Validate(context.Background(), ssoModels.SSOSettings{Settings: malformed}, ssoModels.SSOSettings{}, requester)
	require.Error(t, err)

	err = provider.Reload(context.Background(), ssoModels.SSOSettings{Settings: malformed})
	require.Error(t, err)
	require.NotEmpty(t, provider.allowedOrganizations)
	_, err = provider.UserInfo(context.Background(), client, token.token)
	require.Error(t, err)
}

func TestMalformedOAuthMembership_GrafanaComOrganizationsDoNotAdmitOutsider(t *testing.T) {
	srv := newGrafanaComMembershipServer(t)
	cfg := membershipCfg()
	cfg.GrafanaComURL = srv.URL
	settings := map[string]any{
		"client_id":             "client-id",
		"allow_sign_up":         true,
		"skip_org_role_sync":    true,
		"allowed_organizations": "[kept-org, other-kept]",
	}
	provider, err := newGrafanaComFromSettings(t, cfg, settings)
	if err != nil {
		return
	}
	userInfo, err := provider.UserInfo(context.Background(), srv.Client(), nil)
	if err == nil {
		t.Fatalf("outsider completed Grafana.com OAuth login (allow_sign_up=%v): %+v", provider.IsSignupAllowed(), userInfo)
	}
}

func TestMalformedOAuthMembership_GrafanaComValidOrganizationStillRestricts(t *testing.T) {
	srv := newGrafanaComMembershipServer(t)
	cfg := membershipCfg()
	cfg.GrafanaComURL = srv.URL
	settings := map[string]any{
		"client_id":             "client-id",
		"allow_sign_up":         true,
		"skip_org_role_sync":    true,
		"allowed_organizations": "kept-org",
	}
	provider, err := newGrafanaComFromSettings(t, cfg, settings)
	require.NoError(t, err)
	_, err = provider.UserInfo(context.Background(), srv.Client(), nil)
	require.Error(t, err)
}

func TestMalformedOAuthMembership_GrafanaComValidateAndReloadRejectUnparsedOrganizations(t *testing.T) {
	srv := newGrafanaComMembershipServer(t)
	cfg := membershipCfg()
	cfg.GrafanaComURL = srv.URL
	initial := map[string]any{
		"client_id":             "client-id",
		"allow_sign_up":         true,
		"skip_org_role_sync":    true,
		"allowed_organizations": "kept-org",
	}
	provider, err := newGrafanaComFromSettings(t, cfg, initial)
	require.NoError(t, err)
	_, err = provider.UserInfo(context.Background(), srv.Client(), nil)
	require.Error(t, err)

	requester := &user.SignedInUser{IsGrafanaAdmin: true}
	malformed := map[string]any{
		"client_id":             "client-id",
		"allowed_organizations": "[kept-org, other-kept]",
	}
	err = provider.Validate(context.Background(), ssoModels.SSOSettings{Settings: malformed}, ssoModels.SSOSettings{}, requester)
	require.Error(t, err)

	reloaded := map[string]any{
		"client_id":             "client-id",
		"allow_sign_up":         true,
		"skip_org_role_sync":    true,
		"allowed_organizations": "[kept-org, other-kept]",
	}
	err = provider.Reload(context.Background(), ssoModels.SSOSettings{Settings: reloaded})
	require.Error(t, err)
	require.NotEmpty(t, provider.allowedOrganizations)
	_, err = provider.UserInfo(context.Background(), srv.Client(), nil)
	require.Error(t, err)
}

func requireOutsiderDenied(t *testing.T, provider *SocialGenericOAuth, client *http.Client) {
	t.Helper()
	userInfo, err := provider.UserInfo(context.Background(), client, &oauth2.Token{})
	if err == nil {
		t.Fatalf("outsider completed Generic OAuth login (allow_sign_up=%v): %+v", provider.IsSignupAllowed(), userInfo)
	}
}

func membershipCfg() *setting.Cfg {
	return &setting.Cfg{
		AutoAssignOrg:     true,
		AutoAssignOrgId:   1,
		AutoAssignOrgRole: "Viewer",
	}
}

func genericMembershipSettings(srv *httptest.Server) map[string]any {
	return map[string]any{
		"client_id":               "client-id",
		"auth_url":                "https://idp.example/authorize",
		"token_url":               "https://idp.example/token",
		"api_url":                 srv.URL + "/userinfo",
		"teams_url":               srv.URL + "/teams",
		"team_ids_attribute_path": "teams",
		"allow_sign_up":           true,
		"skip_org_role_sync":      true,
		"enabled":                 true,
	}
}

func newGenericFromSettings(t *testing.T, settings map[string]any) (*SocialGenericOAuth, error) {
	t.Helper()
	info, err := CreateOAuthInfoFromKeyValues(settings)
	if err != nil {
		return nil, err
	}
	cfg := membershipCfg()
	return NewGenericOAuthProvider(context.Background(), info, testConfigProvider(t, cfg), mustProvideOrgRoleMapper(t, cfg, &orgtest.FakeOrgService{}), ssosettingstests.NewFakeService(), featuremgmt.WithFeatures(), nil)
}

func newGitHubFromSettings(t *testing.T, settings map[string]any) (*SocialGithub, error) {
	t.Helper()
	info, err := CreateOAuthInfoFromKeyValues(settings)
	if err != nil {
		return nil, err
	}
	cfg := membershipCfg()
	return NewGitHubProvider(context.Background(), info, testConfigProvider(t, cfg), mustProvideOrgRoleMapper(t, cfg, &orgtest.FakeOrgService{}), ssosettingstests.NewFakeService(), featuremgmt.WithFeatures())
}

func newAzureFromSettings(t *testing.T, settings map[string]any, cache remotecache.CacheStorage) (*SocialAzureAD, error) {
	t.Helper()
	info, err := CreateOAuthInfoFromKeyValues(settings)
	if err != nil {
		return nil, err
	}
	cfg := membershipCfg()
	return NewAzureADProvider(context.Background(), info, testConfigProvider(t, cfg), mustProvideOrgRoleMapper(t, cfg, &orgtest.FakeOrgService{}), ssosettingstests.NewFakeService(), featuremgmt.WithFeatures(), cache)
}

func newGrafanaComFromSettings(t *testing.T, cfg *setting.Cfg, settings map[string]any) (*SocialGrafanaCom, error) {
	t.Helper()
	info, err := CreateOAuthInfoFromKeyValues(settings)
	if err != nil {
		return nil, err
	}
	return NewGrafanaComProvider(context.Background(), info, testConfigProvider(t, cfg), mustProvideOrgRoleMapper(t, cfg, &orgtest.FakeOrgService{}), ssosettingstests.NewFakeService(), featuremgmt.WithFeatures())
}

func newGenericMembershipServer(t *testing.T, teams []string, orgs []string, groups []string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/userinfo":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"sub":    "outsider",
				"email":  "outsider@example.com",
				"login":  "outsider",
				"name":   "Outsider",
				"groups": groups,
			}))
		case "/teams":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"teams": teams}))
		case "/userinfo/orgs":
			records := make([]map[string]string, 0, len(orgs))
			for _, orgLogin := range orgs {
				records = append(records, map[string]string{"login": orgLogin})
			}
			require.NoError(t, json.NewEncoder(w).Encode(records))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newGitHubMembershipServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.String(), "/user"):
			_, err := w.Write([]byte(testGHUserJSON))
			require.NoError(t, err)
		case strings.HasSuffix(r.URL.String(), "/user/teams?per_page=100"):
			_, err := w.Write([]byte(testGHUserTeamsJSON))
			require.NoError(t, err)
		case strings.HasSuffix(r.URL.String(), "/orgs?per_page=100"):
			_, err := w.Write([]byte(testGHOrgsJSON))
			require.NoError(t, err)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newGrafanaComMembershipServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/oauth2/user" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"id":       7,
			"name":     "Outsider",
			"username": "outsider",
			"email":    "outsider@example.com",
			"role":     "Viewer",
			"orgs":     []map[string]string{{"login": "other-org"}},
		}))
	}))
	t.Cleanup(srv.Close)
	return srv
}

type azureTenantFixture struct {
	token   *oauth2.Token
	authURL string
	cache   remotecache.CacheStorage
}

func azureTenantToken(t *testing.T, tenantID string) (azureTenantFixture, *http.Client) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: privateKey}, (&jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{"kid": "1"},
	}).WithType("JWT"))
	require.NoError(t, err)

	jwks, err := json.Marshal(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       privateKey.Public(),
		KeyID:     "1",
		Algorithm: string(jose.PS256),
		Use:       "sig",
	}}})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/discovery/v2.0/keys") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write(jwks)
		require.NoError(t, err)
	}))
	t.Cleanup(srv.Close)

	authURL := srv.URL + "/oauth2/v2.0/authorize"
	raw, err := jwt.Signed(sig).Claims(jwt.Claims{
		Audience: jwt.Audience{"client-id"},
		Subject:  "subject",
	}).Claims(&azureClaims{
		Audience: "client-id",
		Email:    "outsider@example.com",
		Name:     "Outsider",
		ID:       "outsider",
		TenantID: tenantID,
	}).Serialize()
	require.NoError(t, err)

	return azureTenantFixture{
		token:   (&oauth2.Token{AccessToken: "fake_token"}).WithExtra(map[string]any{"id_token": raw}),
		authURL: authURL,
		cache:   remotecache.NewFakeCacheStorage(),
	}, srv.Client()
}

func azureMembershipSettings(authURL string) map[string]any {
	return map[string]any{
		"client_id":             "client-id",
		"client_authentication": "none",
		"auth_url":              authURL,
		"token_url":             "https://idp.example/token",
		"allow_sign_up":         true,
		"skip_org_role_sync":    true,
		"enabled":               true,
	}
}
