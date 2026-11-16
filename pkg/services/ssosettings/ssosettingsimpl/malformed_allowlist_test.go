package ssosettingsimpl

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/ssosettings"
	"github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

func TestUpsertAndPatchRejectMalformedAllowlists(t *testing.T) {
	t.Parallel()

	requester := &user.SignedInUser{IsGrafanaAdmin: true}
	fallback := map[string]any{
		"enabled":               true,
		"allow_sign_up":         true,
		"client_id":             "client-id",
		"auth_url":              "https://idp.example/auth",
		"token_url":             "https://idp.example/token",
		"api_url":               "https://idp.example/userinfo",
		"groups_attribute_path": "groups",
		"allowed_domains":       `["good.example"]`,
		"allowed_groups":        `["staff"]`,
		"scopes":                `["openid","email"]`,
	}

	for _, action := range []string{"upsert", "patch"} {
		t.Run(action, func(t *testing.T) {
			t.Parallel()
			env := setupTestEnv(t, false, false, false)
			env.store.ExpectedError = ssosettings.ErrNotFound
			env.fallbackStrategy.ExpectedIsMatch = true
			env.fallbackStrategy.ExpectedConfigs = map[string]map[string]any{
				social.GenericOAuthProviderName: fallback,
			}
			env.store.UpsertFn = func(_ context.Context, _ *models.SSOSettings) error {
				t.Errorf("malformed allowlist settings were stored")
				return nil
			}

			cfg := &setting.Cfg{}
			cfgProvider := mustConfigProvider(t, cfg)
			provider, err := connectors.NewGenericOAuthProvider(
				context.Background(),
				&social.OAuthInfo{
					ClientId:            "client-id",
					AuthUrl:             "https://idp.example/auth",
					TokenUrl:            "https://idp.example/token",
					ApiUrl:              "https://idp.example/userinfo",
					Enabled:             true,
					AllowSignup:         true,
					AllowedDomains:      []string{"good.example"},
					AllowedGroups:       []string{"staff"},
					GroupsAttributePath: "groups",
					Scopes:              []string{"openid", "email"},
					SkipOrgRoleSync:     true,
					Extra:               map[string]string{},
				},
				cfgProvider,
				connectors.ProvideOrgRoleMapper(cfgProvider, nil),
				env.service,
				featuremgmt.WithFeatures(),
				nil,
			)
			require.NoError(t, err)
			require.False(t, provider.IsEmailAllowed("person@outside.test"))

			ctx := context.Background()
			if action == "upsert" {
				settings := map[string]any{}
				for key, value := range fallback {
					settings[key] = value
				}
				settings["allowed_domains"] = `["good.example",]`
				settings["allowed_groups"] = `["staff",]`
				settings["scopes"] = `["openid",]`
				err = env.service.Upsert(ctx, &models.SSOSettings{
					Provider: social.GenericOAuthProviderName,
					Settings: settings,
				}, requester)
			} else {
				err = env.service.Patch(ctx, social.GenericOAuthProviderName, map[string]any{
					"allowed_domains": `["good.example",]`,
					"allowed_groups":  `[staff]`,
				}, requester)
			}
			require.Error(t, err)
			require.Empty(t, env.store.ActualSSOSettings.Provider)
			require.False(t, provider.IsEmailAllowed("person@outside.test"))
			require.True(t, provider.IsEmailAllowed("person@good.example"))
		})
	}
}
