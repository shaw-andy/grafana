package connectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/ssosettings"
	ssoModels "github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	intendedDomain = "good.example"
	outsiderEmail  = "person@outside.test"
	insiderEmail   = "person@good.example"
	intendedGroup  = "staff"
	outsiderGroup  = "contractors"
)

// malformedJSONLists are strings an administrator can store through the SSO
// settings API or an ini file. Each one starts like a JSON list and does not parse.
var malformedJSONLists = []string{
	`["good.example",]`,
	`[good.example]`,
	`["good.example"`,
	` ["staff",]`,
}

func TestMalformedSliceSettingsAreRejected(t *testing.T) {
	t.Parallel()

	requester := &user.SignedInUser{IsGrafanaAdmin: true}
	for _, provider := range allowlistProviders(t) {
		t.Run(provider.name, func(t *testing.T) {
			t.Parallel()
			for _, field := range []string{"allowed_domains", "allowed_groups", "scopes", "org_mapping"} {
				for _, malformed := range malformedJSONLists {
					t.Run(field+" "+malformed, func(t *testing.T) {
						t.Parallel()
						settings := cloneSettings(provider.base)
						settings[field] = malformed
						// Generic OAuth rejects a non-empty group list that has no
						// groups attribute path. Keep that path set so the only
						// reason to reject is that the list itself did not parse.
						if field == "allowed_groups" {
							settings["groups_attribute_path"] = "groups"
						}

						err := provider.reloadable.Validate(context.Background(), ssoModels.SSOSettings{
							Provider: provider.name,
							Settings: settings,
						}, ssoModels.SSOSettings{Settings: cloneSettings(provider.base)}, requester)
						require.Error(t, err)
					})
				}
			}
		})
	}
}

func TestMalformedExtraAllowlistsAreRejected(t *testing.T) {
	t.Parallel()

	requester := &user.SignedInUser{IsGrafanaAdmin: true}
	cases := []struct {
		provider string
		field    string
		value    string
		extra    map[string]any
	}{
		{provider: social.GenericOAuthProviderName, field: teamIdsKey, value: `["team-1",]`},
		{provider: social.GenericOAuthProviderName, field: allowedOrganizationsKey, value: `["acme",]`},
		{provider: social.GitHubProviderName, field: teamIdsKey, value: `["42",]`},
		{provider: social.GitHubProviderName, field: allowedOrganizationsKey, value: `["acme",]`},
		{provider: social.AzureADProviderName, field: allowedOrganizationsKey, value: `["tenant-1",]`},
		{provider: social.GrafanaComProviderName, field: allowedOrganizationsKey, value: `["acme",]`},
	}

	byName := allowlistProvidersByName(t)
	for _, tc := range cases {
		t.Run(tc.provider+" "+tc.field, func(t *testing.T) {
			t.Parallel()
			provider := byName[tc.provider]
			settings := cloneSettings(provider.base)
			settings[tc.field] = tc.value
			for key, value := range tc.extra {
				settings[key] = value
			}
			// A parsed team id list is only valid when the lookup settings exist.
			// The malformed value must be rejected before that rule can pass it
			// by treating the list as empty.
			if tc.field == teamIdsKey && tc.provider == social.GenericOAuthProviderName {
				settings["team_ids_attribute_path"] = "teams"
				settings["teams_url"] = "https://idp.example/teams"
			}

			err := provider.reloadable.Validate(context.Background(), ssoModels.SSOSettings{
				Provider: provider.name,
				Settings: settings,
			}, ssoModels.SSOSettings{Settings: cloneSettings(provider.base)}, requester)
			require.Error(t, err)
		})
	}
}

func TestReloadKeepsDomainAndGroupRestrictions(t *testing.T) {
	t.Parallel()

	for _, provider := range allowlistProviders(t) {
		if provider.name == social.GrafanaComProviderName {
			// Grafana.com does not consult allowed domains or allowed groups.
			continue
		}
		t.Run(provider.name, func(t *testing.T) {
			t.Parallel()
			connector := provider.connector
			require.False(t, connector.IsEmailAllowed(outsiderEmail))
			require.True(t, connector.IsEmailAllowed(insiderEmail))
			require.False(t, groupMember(t, connector, []string{outsiderGroup}))
			require.True(t, groupMember(t, connector, []string{intendedGroup}))

			settings := cloneSettings(provider.base)
			settings["allowed_domains"] = `["good.example",]`
			settings["allowed_groups"] = `["staff",]`
			settings["groups_attribute_path"] = "groups"
			settings["scopes"] = `["openid",]`
			settings["org_mapping"] = `["1:Viewer",]`

			err := provider.reloadable.Reload(context.Background(), ssoModels.SSOSettings{
				Provider: provider.name,
				Settings: settings,
			})
			require.Error(t, err)

			// Empty lists mean allow-all. A refused reload must not leave that
			// behind, whether or not the error is returned first.
			require.False(t, connector.IsEmailAllowed(outsiderEmail))
			require.False(t, groupMember(t, connector, []string{outsiderGroup}))
			require.NotEmpty(t, connector.GetOAuthInfo().AllowedDomains)
			require.NotEmpty(t, connector.GetOAuthInfo().AllowedGroups)
			require.NotEmpty(t, connector.GetOAuthInfo().Scopes)
		})
	}
}

func TestGenericOAuthLoginRejectsOutsiderAfterMalformedReload(t *testing.T) {
	t.Parallel()

	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"outsider","email":"` + outsiderEmail + `","groups":["` + outsiderGroup + `"]}`))
	}))
	t.Cleanup(userInfoServer.Close)

	provider := newAllowlistProvider(t, social.GenericOAuthProviderName, &social.OAuthInfo{
		ClientId:            "client-id",
		ClientSecret:        "",
		AuthUrl:             "https://idp.example/auth",
		TokenUrl:            "https://idp.example/token",
		ApiUrl:              userInfoServer.URL,
		Enabled:             true,
		AllowSignup:         true,
		AllowedDomains:      []string{intendedDomain},
		AllowedGroups:       []string{intendedGroup},
		GroupsAttributePath: "groups",
		Scopes:              []string{"openid", "email"},
		SkipOrgRoleSync:     true,
		Extra:               map[string]string{},
	})

	require.True(t, provider.connector.IsSignupAllowed())

	settings := cloneSettings(provider.base)
	settings["api_url"] = userInfoServer.URL
	settings["allowed_domains"] = `["good.example",]`
	settings["allowed_groups"] = `["staff",]`
	settings["scopes"] = `["openid",]`
	reloadErr := provider.reloadable.Reload(context.Background(), ssoModels.SSOSettings{
		Provider: provider.name,
		Settings: settings,
	})

	// UserInfo is the group gate on the connector. The OAuth client then calls
	// IsEmailAllowed on the returned address and copies IsSignupAllowed onto
	// the identity that user sync uses to create the account.
	_, userErr := provider.connector.UserInfo(context.Background(), userInfoServer.Client(), &oauth2.Token{})
	require.Error(t, userErr)
	require.Error(t, reloadErr)
	require.False(t, provider.connector.IsEmailAllowed(outsiderEmail))
	require.False(t, groupMember(t, provider.connector, []string{outsiderGroup}))
}

func TestStartupDecodeOfMalformedAllowlistDoesNotAllowEveryAccount(t *testing.T) {
	t.Parallel()

	settings := map[string]any{
		"enabled":               true,
		"allow_sign_up":         true,
		"client_id":             "client-id",
		"auth_url":              "https://idp.example/auth",
		"token_url":             "https://idp.example/token",
		"api_url":               "https://idp.example/userinfo",
		"groups_attribute_path": "groups",
		"allowed_domains":       `["good.example",]`,
		"allowed_groups":        `["staff",]`,
		"scopes":                `["openid",]`,
		"org_mapping":           `["1:Viewer",]`,
	}

	logger := log.New("test")
	for _, decode := range []func(map[string]any) (*social.OAuthInfo, error){
		CreateOAuthInfoFromKeyValues,
		func(settings map[string]any) (*social.OAuthInfo, error) {
			return CreateOAuthInfoFromKeyValuesWithLogging(logger, social.GenericOAuthProviderName, settings)
		},
	} {
		info, err := decode(cloneSettings(settings))
		if err != nil {
			// SocialService skips a provider when decoding its settings fails.
			continue
		}
		require.NotNil(t, info)
		// SocialService registers a connector when decoding succeeds. That
		// connector must not treat the malformed lists as allow-all.
		provider := newAllowlistProvider(t, social.GenericOAuthProviderName, info)
		require.False(t, provider.connector.IsEmailAllowed(outsiderEmail))
		require.False(t, groupMember(t, provider.connector, []string{outsiderGroup}))
		require.NotEmpty(t, info.AllowedDomains)
		require.NotEmpty(t, info.AllowedGroups)
		t.Fatal("malformed allowlist settings were accepted")
	}
}

func TestMalformedTeamAndOrganizationListsDoNotAllowEveryone(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	client := &http.Client{}

	t.Run("generic oauth", func(t *testing.T) {
		t.Parallel()
		provider := newAllowlistProvider(t, social.GenericOAuthProviderName, &social.OAuthInfo{
			ClientId: "client-id",
			AuthUrl:  "https://idp.example/auth",
			TokenUrl: "https://idp.example/token",
			ApiUrl:   "https://idp.example/userinfo",
			Extra: map[string]string{
				teamIdsKey:              "team-1",
				allowedOrganizationsKey: "acme",
			},
		})
		generic := provider.connector.(*SocialGenericOAuth)
		require.False(t, generic.isTeamMember(ctx, client))
		require.False(t, generic.isOrganizationMember(ctx, client))

		settings := cloneSettings(provider.base)
		settings[teamIdsKey] = `["team-1",]`
		settings[allowedOrganizationsKey] = `["acme",]`
		settings["team_ids_attribute_path"] = "teams"
		settings["teams_url"] = "https://idp.example/teams"
		err := provider.reloadable.Reload(ctx, ssoModels.SSOSettings{Provider: provider.name, Settings: settings})
		require.Error(t, err)
		require.False(t, generic.isTeamMember(ctx, client))
		require.False(t, generic.isOrganizationMember(ctx, client))
	})

	t.Run("github", func(t *testing.T) {
		t.Parallel()
		provider := newAllowlistProvider(t, social.GitHubProviderName, &social.OAuthInfo{
			ClientId: "client-id",
			Extra: map[string]string{
				teamIdsKey:              "42",
				allowedOrganizationsKey: "acme",
			},
		})
		github := provider.connector.(*SocialGithub)
		require.False(t, github.isTeamMember(ctx, client))
		require.False(t, github.isOrganizationMember(ctx, client, "https://idp.example/orgs"))

		settings := cloneSettings(provider.base)
		settings[teamIdsKey] = `["42",]`
		settings[allowedOrganizationsKey] = `["acme",]`
		err := provider.reloadable.Reload(ctx, ssoModels.SSOSettings{Provider: provider.name, Settings: settings})
		require.Error(t, err)
		require.False(t, github.isTeamMember(ctx, client))
		require.False(t, github.isOrganizationMember(ctx, client, "https://idp.example/orgs"))
	})

	t.Run("azuread", func(t *testing.T) {
		t.Parallel()
		provider := newAllowlistProvider(t, social.AzureADProviderName, &social.OAuthInfo{
			ClientId:             "client-id",
			ClientAuthentication: social.None,
			AuthUrl:              "https://idp.example/auth",
			TokenUrl:             "https://idp.example/token",
			Extra:                map[string]string{allowedOrganizationsKey: "tenant-1"},
		})
		azure := provider.connector.(*SocialAzureAD)
		require.False(t, azure.isAllowedTenant(log.New("test"), "other-tenant"))

		settings := cloneSettings(provider.base)
		settings[allowedOrganizationsKey] = `["tenant-1",]`
		err := provider.reloadable.Reload(ctx, ssoModels.SSOSettings{Provider: provider.name, Settings: settings})
		require.Error(t, err)
		require.False(t, azure.isAllowedTenant(log.New("test"), "other-tenant"))
	})

	t.Run("grafana.com", func(t *testing.T) {
		t.Parallel()
		provider := newAllowlistProvider(t, social.GrafanaComProviderName, &social.OAuthInfo{
			ClientId: "client-id",
			Extra:    map[string]string{allowedOrganizationsKey: "acme"},
		})
		grafanaCom := provider.connector.(*SocialGrafanaCom)
		require.False(t, grafanaCom.isOrganizationMember([]OrgRecord{{Login: "other"}}))

		settings := cloneSettings(provider.base)
		settings[allowedOrganizationsKey] = `["acme",]`
		err := provider.reloadable.Reload(ctx, ssoModels.SSOSettings{Provider: provider.name, Settings: settings})
		require.Error(t, err)
		require.False(t, grafanaCom.isOrganizationMember([]OrgRecord{{Login: "other"}}))
	})
}

func TestParsedAllowlistsStillRestrictAndEmptyListsStillAllow(t *testing.T) {
	t.Parallel()

	requester := &user.SignedInUser{IsGrafanaAdmin: true}
	provider := newAllowlistProvider(t, social.GenericOAuthProviderName, &social.OAuthInfo{
		ClientId:            "client-id",
		AuthUrl:             "https://idp.example/auth",
		TokenUrl:            "https://idp.example/token",
		Enabled:             true,
		AllowSignup:         true,
		AllowedDomains:      []string{intendedDomain},
		AllowedGroups:       []string{intendedGroup},
		GroupsAttributePath: "groups",
		Scopes:              []string{"openid"},
		Extra:               map[string]string{},
	})

	valid := cloneSettings(provider.base)
	valid["allowed_domains"] = `["good.example"]`
	valid["allowed_groups"] = `["staff"]`
	valid["groups_attribute_path"] = "groups"
	valid["scopes"] = `["openid","email"]`
	require.NoError(t, provider.reloadable.Validate(context.Background(), ssoModels.SSOSettings{
		Provider: provider.name,
		Settings: valid,
	}, ssoModels.SSOSettings{Settings: cloneSettings(provider.base)}, requester))
	require.NoError(t, provider.reloadable.Reload(context.Background(), ssoModels.SSOSettings{
		Provider: provider.name,
		Settings: valid,
	}))
	require.False(t, provider.connector.IsEmailAllowed(outsiderEmail))
	require.True(t, provider.connector.IsEmailAllowed(insiderEmail))
	require.False(t, groupMember(t, provider.connector, []string{outsiderGroup}))
	require.True(t, groupMember(t, provider.connector, []string{intendedGroup}))

	// A JSON array value, which is what encoding/json produces for a list field,
	// is a real list and must keep restricting.
	asArray := cloneSettings(provider.base)
	asArray["allowed_domains"] = []any{intendedDomain}
	asArray["allowed_groups"] = []any{intendedGroup}
	require.NoError(t, provider.reloadable.Reload(context.Background(), ssoModels.SSOSettings{
		Provider: provider.name,
		Settings: asArray,
	}))
	require.False(t, provider.connector.IsEmailAllowed(outsiderEmail))
	require.True(t, provider.connector.IsEmailAllowed(insiderEmail))

	// An unset list is the configured allow-all behavior and must stay that way.
	unset := cloneSettings(provider.base)
	unset["allowed_domains"] = ""
	unset["allowed_groups"] = ""
	require.NoError(t, provider.reloadable.Validate(context.Background(), ssoModels.SSOSettings{
		Provider: provider.name,
		Settings: unset,
	}, ssoModels.SSOSettings{Settings: cloneSettings(provider.base)}, requester))
	require.NoError(t, provider.reloadable.Reload(context.Background(), ssoModels.SSOSettings{
		Provider: provider.name,
		Settings: unset,
	}))
	require.True(t, provider.connector.IsEmailAllowed(outsiderEmail))
	require.True(t, groupMember(t, provider.connector, []string{outsiderGroup}))
}

type allowlistProvider struct {
	name       string
	base       map[string]any
	reloadable ssosettings.Reloadable
	connector  social.SocialConnector
}

func allowlistProviders(t *testing.T) []allowlistProvider {
	t.Helper()
	names := []string{
		social.GenericOAuthProviderName,
		social.GitHubProviderName,
		social.GitlabProviderName,
		social.GoogleProviderName,
		social.GrafanaComProviderName,
		social.AzureADProviderName,
		social.OktaProviderName,
	}
	providers := make([]allowlistProvider, 0, len(names))
	for _, name := range names {
		providers = append(providers, newAllowlistProvider(t, name, nil))
	}
	return providers
}

func allowlistProvidersByName(t *testing.T) map[string]allowlistProvider {
	t.Helper()
	providers := allowlistProviders(t)
	byName := make(map[string]allowlistProvider, len(providers))
	for _, provider := range providers {
		byName[provider.name] = provider
	}
	return byName
}

func newAllowlistProvider(t *testing.T, name string, info *social.OAuthInfo) allowlistProvider {
	t.Helper()

	base := baseAllowlistSettings(name)
	if info == nil {
		info = &social.OAuthInfo{
			ClientId:             "client-id",
			Enabled:              true,
			AllowSignup:          true,
			AllowedDomains:       []string{intendedDomain},
			AllowedGroups:        []string{intendedGroup},
			GroupsAttributePath:  "groups",
			Scopes:               []string{"openid", "email"},
			SkipOrgRoleSync:      true,
			Extra:                map[string]string{},
			AuthUrl:              stringSetting(base, "auth_url"),
			TokenUrl:             stringSetting(base, "token_url"),
			ApiUrl:               stringSetting(base, "api_url"),
			ClientAuthentication: stringSetting(base, "client_authentication"),
		}
	}

	cfg := &setting.Cfg{}
	cfgProvider := testConfigProvider(t, cfg)
	mapper := mustProvideOrgRoleMapper(t, cfg, nil)
	features := featuremgmt.WithFeatures()
	connector := newAllowlistConnector(t, name, info, cfgProvider, mapper, features)

	reloadable, ok := connector.(ssosettings.Reloadable)
	require.True(t, ok)
	return allowlistProvider{
		name:       name,
		base:       base,
		reloadable: reloadable,
		connector:  connector,
	}
}

func newAllowlistConnector(t *testing.T, name string, info *social.OAuthInfo, cfgProvider configprovider.ConfigProvider, mapper *OrgRoleMapper, features featuremgmt.FeatureToggles) social.SocialConnector {
	t.Helper()
	ctx := context.Background()
	var connector social.SocialConnector
	var err error
	switch name {
	case social.GenericOAuthProviderName:
		connector, err = NewGenericOAuthProvider(ctx, info, cfgProvider, mapper, nil, features, nil)
	case social.GitHubProviderName:
		connector, err = NewGitHubProvider(ctx, info, cfgProvider, mapper, nil, features)
	case social.GitlabProviderName:
		connector, err = NewGitLabProvider(ctx, info, cfgProvider, mapper, nil, features, nil)
	case social.GoogleProviderName:
		connector, err = NewGoogleProvider(ctx, info, cfgProvider, mapper, nil, features, nil)
	case social.GrafanaComProviderName:
		connector, err = NewGrafanaComProvider(ctx, info, cfgProvider, mapper, nil, features)
	case social.AzureADProviderName:
		connector, err = NewAzureADProvider(ctx, info, cfgProvider, mapper, nil, features, nil)
	case social.OktaProviderName:
		connector, err = NewOktaProvider(ctx, info, cfgProvider, mapper, nil, features, nil)
	default:
		t.Fatalf("unknown provider %s", name)
	}
	require.NoError(t, err)
	return connector
}

func baseAllowlistSettings(provider string) map[string]any {
	settings := map[string]any{
		"client_id":             "client-id",
		"enabled":               true,
		"allow_sign_up":         true,
		"allowed_domains":       `["good.example"]`,
		"allowed_groups":        `["staff"]`,
		"groups_attribute_path": "groups",
		"scopes":                `["openid","email"]`,
		"skip_org_role_sync":    true,
	}
	switch provider {
	case social.GitHubProviderName, social.GitlabProviderName, social.GoogleProviderName, social.GrafanaComProviderName:
		settings["auth_url"] = ""
		settings["token_url"] = ""
		settings["api_url"] = ""
	case social.AzureADProviderName:
		settings["client_authentication"] = social.None
		settings["auth_url"] = "https://idp.example/auth"
		settings["token_url"] = "https://idp.example/token"
		settings["api_url"] = ""
	default:
		settings["auth_url"] = "https://idp.example/auth"
		settings["token_url"] = "https://idp.example/token"
		settings["api_url"] = "https://idp.example/userinfo"
	}
	if provider == social.GrafanaComProviderName {
		settings["teams_url"] = ""
	}
	if provider == social.AzureADProviderName {
		// Azure AD rejects allowed groups that are not object IDs. A valid ID
		// keeps that check from failing before the malformed-list cases run.
		settings["allowed_groups"] = "0bb9c9cc-4945-418f-9b6a-c1d3b81141b0"
	}
	return settings
}

func groupMember(t *testing.T, connector social.SocialConnector, groups []string) bool {
	t.Helper()
	return embeddedBase(t, connector).isGroupMember(groups)
}

func embeddedBase(t *testing.T, connector social.SocialConnector) *SocialBase {
	t.Helper()
	switch c := connector.(type) {
	case *SocialGenericOAuth:
		return c.SocialBase
	case *SocialGithub:
		return c.SocialBase
	case *SocialGitlab:
		return c.SocialBase
	case *SocialGoogle:
		return c.SocialBase
	case *SocialGrafanaCom:
		return c.SocialBase
	case *SocialAzureAD:
		return c.SocialBase
	case *SocialOkta:
		return c.SocialBase
	default:
		t.Fatalf("connector %T has no social base", connector)
		return nil
	}
}

func stringSetting(settings map[string]any, key string) string {
	value, _ := settings[key].(string)
	return value
}

func cloneSettings(settings map[string]any) map[string]any {
	cloned := make(map[string]any, len(settings))
	for key, value := range settings {
		cloned[key] = value
	}
	return cloned
}
