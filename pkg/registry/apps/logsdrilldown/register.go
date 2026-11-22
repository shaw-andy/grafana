package logsdrilldown

import (
	"io"

	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	restclient "k8s.io/client-go/rest"

	"github.com/grafana/grafana-app-sdk/app"
	appsdkapiserver "github.com/grafana/grafana-app-sdk/k8s/apiserver"
	"github.com/grafana/grafana-app-sdk/simple"
	"github.com/grafana/grafana/apps/logsdrilldown/pkg/apis"
	logsdrilldownapp "github.com/grafana/grafana/apps/logsdrilldown/pkg/app"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
)

var (
	_ appsdkapiserver.AppInstaller = (*LogsDrilldownAppInstaller)(nil)
)

type LogsDrilldownAppInstaller struct {
	appsdkapiserver.AppInstaller
	cfg *setting.Cfg
}

func (l *LogsDrilldownAppInstaller) GetAuthorizer() authorizer.Authorizer {
	return GetAuthorizer()
}

func (l *LogsDrilldownAppInstaller) AdmissionPlugin() admission.Factory {
	appFactory := l.AppInstaller.AdmissionPlugin()
	return func(cfg io.Reader) (admission.Interface, error) {
		owner := newOwnerAdmission()
		if appFactory == nil {
			return owner, nil
		}
		appAdmission, err := appFactory(cfg)
		if err != nil {
			return nil, err
		}
		return admission.NewChainHandler(appAdmission, owner), nil
	}
}

func RegisterAppInstaller(
	cfg *setting.Cfg,
	features featuremgmt.FeatureToggles,
) (*LogsDrilldownAppInstaller, error) {
	installer := &LogsDrilldownAppInstaller{
		cfg: cfg,
	}
	provider := simple.NewAppProvider(apis.LocalManifest(), nil, logsdrilldownapp.New)

	appConfig := app.Config{
		KubeConfig:   restclient.Config{}, // this will be overridden by the installer's InitializeApp method
		ManifestData: *apis.LocalManifest().ManifestData,
	}
	i, err := appsdkapiserver.NewDefaultAppInstaller(provider, appConfig, apis.NewGoTypeAssociator())
	if err != nil {
		return nil, err
	}
	installer.AppInstaller = i

	return installer, nil
}
