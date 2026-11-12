package app

import (
	"context"
	"errors"

	"github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/logging"
	"github.com/grafana/grafana-app-sdk/operator"
	"github.com/grafana/grafana-app-sdk/resource"
	"github.com/grafana/grafana-app-sdk/simple"
	"k8s.io/apimachinery/pkg/runtime/schema"

	logsdrilldownv1alpha1 "github.com/grafana/grafana/apps/logsdrilldown/pkg/apis/logsdrilldown/v1alpha1"
	logsdrilldownv1beta1 "github.com/grafana/grafana/apps/logsdrilldown/pkg/apis/logsdrilldown/v1beta1"
)

type Config struct {
	// LogsDrilldownValidator rejects LogsDrilldown writes the requester is not allowed to store,
	// such as another user's settings. It runs on the object that is about to be persisted,
	// because create authorization does not see the object name.
	LogsDrilldownValidator simple.KindValidator
}

func New(cfg app.Config) (app.App, error) {
	specificConfig, ok := cfg.SpecificConfig.(*Config)
	if !ok || specificConfig == nil || specificConfig.LogsDrilldownValidator == nil {
		return nil, errors.New("logsdrilldown app requires a LogsDrilldown validator")
	}

	simpleConfig := simple.AppConfig{
		Name:       "logsdrilldown",
		KubeConfig: cfg.KubeConfig,
		InformerConfig: simple.AppInformerConfig{
			InformerOptions: operator.InformerOptions{
				ErrorHandler: func(ctx context.Context, err error) {
					logging.FromContext(ctx).Error("Informer processing error", "error", err)
				},
			},
		},
		ManagedKinds: []simple.AppManagedKind{
			{
				Kind:      logsdrilldownv1alpha1.LogsDrilldownKind(),
				Validator: specificConfig.LogsDrilldownValidator,
			},
			{
				Kind: logsdrilldownv1alpha1.LogsDrilldownDefaultsKind(),
			},
			{
				Kind: logsdrilldownv1beta1.LogsDrilldownDefaultColumnsKind(),
			},
			{
				Kind: logsdrilldownv1beta1.LogsDrilldownDefaultLabelsKind(),
			},
		},
	}

	a, err := simple.NewApp(simpleConfig)
	if err != nil {
		return nil, err
	}

	err = a.ValidateManifest(cfg.ManifestData)
	if err != nil {
		return nil, err
	}

	return a, nil
}

func GetKinds() map[schema.GroupVersion][]resource.Kind {
	gv := schema.GroupVersion{
		Group:   logsdrilldownv1alpha1.LogsDrilldownKind().Group(),
		Version: logsdrilldownv1alpha1.LogsDrilldownKind().Version(),
	}
	return map[schema.GroupVersion][]resource.Kind{
		gv: {logsdrilldownv1alpha1.LogsDrilldownKind()},
	}
}
