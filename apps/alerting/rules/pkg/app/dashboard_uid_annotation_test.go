package app_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"

	appsdk "github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/resource"

	v1 "github.com/grafana/grafana/apps/alerting/rules/pkg/apis/alerting/v0alpha1"
	manifestdata "github.com/grafana/grafana/apps/alerting/rules/pkg/apis/manifestdata"
	"github.com/grafana/grafana/apps/alerting/rules/pkg/app/alertrule"
	"github.com/grafana/grafana/apps/alerting/rules/pkg/app/validation"
)

func TestAlertRuleAdmissionRejectsUnsafeDashboardUIDAnnotation(t *testing.T) {
	validator, err := validation.NewBuilder[*v1.AlertRule]().
		WithOpenAPIValidation(*manifestdata.LocalManifest().ManifestData, schema.GroupKind{Group: "rules.alerting.grafana.app", Kind: "AlertRule"}).
		OnWrite(alertrule.ValidateWrite(makeDefaultRuntimeConfig())).
		OnDelete(alertrule.ValidateDelete(makeDefaultRuntimeConfig())).
		Build()
	require.NoError(t, err)

	admit := func(t *testing.T, annotations map[string]v1.AlertRuleTemplateString) error {
		t.Helper()
		rule := baseAlertRule()
		rule.Spec.Annotations = annotations
		return validator.Validate(context.Background(), &appsdk.AdmissionRequest{
			Action: resource.AdmissionActionCreate,
			Object: rule,
		})
	}

	t.Run("letters digits underscore and hyphen are accepted", func(t *testing.T) {
		require.NoError(t, admit(t, map[string]v1.AlertRuleTemplateString{
			"__dashboardUid__": "abc-DEF_1",
			"__panelId__":      "5",
		}))
	})

	t.Run("dashboard uid without a panel id is still rejected when it leaves a path segment", func(t *testing.T) {
		require.Error(t, admit(t, map[string]v1.AlertRuleTemplateString{
			"__dashboardUid__": "../../logout",
		}))
	})

	for _, uid := range []string{
		"../../logout",
		"../../profile/switch-org/2",
		"foo/../../logout",
		"foo/bar",
		"..",
		"%2e%2e/%2e%2e/logout",
	} {
		t.Run(uid, func(t *testing.T) {
			require.Error(t, admit(t, map[string]v1.AlertRuleTemplateString{
				"__dashboardUid__": v1.AlertRuleTemplateString(uid),
				"__panelId__":      "1",
			}))
		})
	}
}
