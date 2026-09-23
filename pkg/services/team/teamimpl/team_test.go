package teamimpl

import (
	"context"
	"testing"

	"github.com/open-feature/go-sdk/openfeature"
	"github.com/open-feature/go-sdk/openfeature/memprovider"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
)

func TestIsK8sRedirectEnabledUsesIAMStartupConfiguration(t *testing.T) {
	tests := []struct {
		name          string
		apiConfig     string
		teamsRedirect bool
		legacyUsers   bool
		want          bool
	}{
		{
			name:          "uses legacy users toggle when startup configuration is absent",
			teamsRedirect: true,
			legacyUsers:   true,
			want:          true,
		},
		{
			name:          "configured users API overrides disabled legacy toggle",
			apiConfig:     "users",
			teamsRedirect: true,
			legacyUsers:   false,
			want:          true,
		},
		{
			name:          "configured empty API surface overrides enabled legacy toggle",
			apiConfig:     "none",
			teamsRedirect: true,
			legacyUsers:   true,
			want:          false,
		},
		{
			name:          "teams redirect remains dynamic",
			apiConfig:     "users",
			teamsRedirect: false,
			legacyUsers:   true,
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := ProvideService(nil, teamConfig(tt.apiConfig), tracing.InitializeTracerForTest(), nil)
			require.NoError(t, err)
			service.openFeatureClient = newTeamFeatureClient(t, tt.teamsRedirect, tt.legacyUsers)
			require.Equal(t, tt.want, service.isK8sRedirectEnabled(context.Background()))
		})
	}
}

func TestProvideServiceRejectsInvalidIAMStartupConfiguration(t *testing.T) {
	_, err := ProvideService(nil, teamConfig("unknown"), tracing.InitializeTracerForTest(), nil)
	require.ErrorContains(t, err, `unknown iam api "unknown"`)
}

func teamConfig(apiConfig string) *setting.Cfg {
	if apiConfig == "" {
		return setting.NewCfg()
	}
	raw := ini.Empty()
	raw.Section("iam").Key("api").SetValue(apiConfig)
	return &setting.Cfg{Raw: raw}
}

func newTeamFeatureClient(t *testing.T, teamsRedirect, usersAPI bool) *openfeature.Client {
	t.Helper()
	provider := memprovider.NewInMemoryProvider(map[string]memprovider.InMemoryFlag{
		featuremgmt.FlagKubernetesTeamsRedirect: {
			Key:            featuremgmt.FlagKubernetesTeamsRedirect,
			DefaultVariant: "default",
			Variants:       map[string]any{"default": teamsRedirect},
		},
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
