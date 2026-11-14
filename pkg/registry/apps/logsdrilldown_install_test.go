package appregistry

import (
	"testing"

	appsdkapiserver "github.com/grafana/grafana-app-sdk/k8s/apiserver"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/registry/apps/logsdrilldown"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
)

func TestLogsDrilldownAppInstalledOnlyWhenToggleEnabled(t *testing.T) {
	installer := &logsdrilldown.LogsDrilldownAppInstaller{}

	disabled := ProvideAppInstallers(featuremgmt.WithFeatures(), &setting.Cfg{}, nil, nil, nil, nil, nil, nil, nil, installer, nil, nil, nil, nil, nil, nil)
	require.False(t, logsDrilldownInstallerPresent(disabled, installer))

	enabled := ProvideAppInstallers(featuremgmt.WithFeatures(featuremgmt.FlagKubernetesLogsDrilldown), &setting.Cfg{}, nil, nil, nil, nil, nil, nil, nil, installer, nil, nil, nil, nil, nil, nil)
	require.True(t, logsDrilldownInstallerPresent(enabled, installer))
}

func logsDrilldownInstallerPresent(installers []appsdkapiserver.AppInstaller, want *logsdrilldown.LogsDrilldownAppInstaller) bool {
	for _, installer := range installers {
		if installer == appsdkapiserver.AppInstaller(want) {
			return true
		}
	}
	return false
}
