package teamapi

import (
	"context"
	"testing"

	"github.com/open-feature/go-sdk/openfeature"
	"github.com/open-feature/go-sdk/openfeature/memprovider"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/api/routing"
	iamapi "github.com/grafana/grafana/pkg/registry/apis/iam"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
)

func TestProvideTeamAPIUsesIAMStartupConfiguration(t *testing.T) {
	api, err := ProvideTeamAPI(
		routing.NewRouteRegister(),
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		teamAPIConfig("users"),
		nil,
		nil,
		nil,
		featuremgmt.WithFeatures(),
		nil,
		nil,
	)
	require.NoError(t, err)
	require.True(t, api.usersAPIEnabled(context.Background()))
}

func TestProvideTeamAPIRejectsInvalidIAMStartupConfiguration(t *testing.T) {
	_, err := ProvideTeamAPI(nil, nil, nil, nil, nil, nil, nil, teamAPIConfig("unknown"), nil, nil, nil, nil, nil, nil)
	require.ErrorContains(t, err, `unknown iam api "unknown"`)
}

func TestUsersAPIEnabledUsesIAMStartupConfiguration(t *testing.T) {
	tests := []struct {
		name            string
		startupFeatures iamapi.StartupFeatures
		legacyUsers     bool
		want            bool
	}{
		{
			name:        "uses legacy toggle when startup configuration is absent",
			legacyUsers: true,
			want:        true,
		},
		{
			name:            "configured users API overrides disabled legacy toggle",
			startupFeatures: iamapi.NewStartupFeatures(iamapi.Features{UsersAPI: true}),
			legacyUsers:     false,
			want:            true,
		},
		{
			name:            "configured empty API surface overrides enabled legacy toggle",
			startupFeatures: iamapi.NewStartupFeatures(iamapi.Features{}),
			legacyUsers:     true,
			want:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &TeamAPI{
				iamFeatures:       tt.startupFeatures.Snapshot(),
				openFeatureClient: newUsersAPIFeatureClient(t, tt.legacyUsers),
			}
			require.Equal(t, tt.want, api.usersAPIEnabled(context.Background()))
		})
	}
}

func newUsersAPIFeatureClient(t *testing.T, usersAPI bool) *openfeature.Client {
	t.Helper()
	provider := memprovider.NewInMemoryProvider(map[string]memprovider.InMemoryFlag{
		featuremgmt.FlagKubernetesUsersApi: {
			Key:            featuremgmt.FlagKubernetesUsersApi,
			DefaultVariant: "default",
			Variants:       map[string]any{"default": usersAPI},
		},
	})
	domain := t.Name()
	require.NoError(t, openfeature.SetNamedProviderAndWait(domain, provider))
	t.Cleanup(func() {
		require.NoError(t, openfeature.SetNamedProviderAndWait(domain, openfeature.NoopProvider{}))
	})
	return openfeature.NewClient(domain)
}

func teamAPIConfig(apiConfig string) *setting.Cfg {
	raw := ini.Empty()
	raw.Section("iam").Key("api").SetValue(apiConfig)
	return &setting.Cfg{Raw: raw}
}
