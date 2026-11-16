package strategies

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/setting"
)

func TestOAuthStrategyPassesMalformedAllowlistThroughToDecoder(t *testing.T) {
	t.Parallel()

	const raw = `
[auth.generic_oauth]
enabled = true
allow_sign_up = true
client_id = client-id
auth_url = https://idp.example/auth
token_url = https://idp.example/token
api_url = https://idp.example/userinfo
scopes = ["openid",]
allowed_domains = ["good.example",]
allowed_groups = ["staff",]
groups_attribute_path = groups
`

	cfg, err := setting.NewCfgFromBytes([]byte(raw))
	require.NoError(t, err)
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)

	settings, err := NewOAuthStrategy(cfgProvider).GetProviderConfig(context.Background(), social.GenericOAuthProviderName)
	require.NoError(t, err)

	// The ini value has to arrive at the decoder unchanged. The strategy must
	// not turn a broken list into an empty one before that.
	require.Equal(t, `["good.example",]`, settings["allowed_domains"])
	require.Equal(t, `["staff",]`, settings["allowed_groups"])
	require.Equal(t, `["openid",]`, settings["scopes"])

	_, err = connectors.CreateOAuthInfoFromKeyValues(settings)
	require.Error(t, err)

	file, err := ini.Load([]byte(raw))
	require.NoError(t, err)
	fromSection := loadSettingsFromSection(file.Section("auth."+social.GenericOAuthProviderName), social.GenericOAuthProviderName)
	require.Equal(t, `["good.example",]`, fromSection["allowed_domains"])
	_, err = connectors.CreateOAuthInfoFromKeyValuesWithLogging(cfg.Logger, social.GenericOAuthProviderName, fromSection)
	require.Error(t, err)
}
