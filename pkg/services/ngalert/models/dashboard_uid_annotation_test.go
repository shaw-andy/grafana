package models

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetDashboardAndPanelFromAnnotationsRejectsUnsafeDashboardUID(t *testing.T) {
	t.Run("letters digits underscore and hyphen are accepted", func(t *testing.T) {
		for _, uid := range []string{"cKy7f6Hk", "abc-DEF_1"} {
			rule := &AlertRule{Annotations: map[string]string{
				DashboardUIDAnnotation: uid,
				PanelIDAnnotation:      "65",
			}}
			require.NoError(t, rule.SetDashboardAndPanelFromAnnotations())
			require.NotNil(t, rule.DashboardUID)
			require.Equal(t, uid, *rule.DashboardUID)
		}
	})

	// A dashboard uid is placed after /d/ in notification links. Anything outside a
	// single path segment of letters, digits, underscore, and hyphen must be rejected
	// here, which is the check the ruler API and provisioning both call before save.
	for _, uid := range []string{
		"../../logout",
		"../../profile/switch-org/2",
		"foo/../../logout",
		"foo/bar",
		"..",
		".",
		"uid with space",
		"%2e%2e/%2e%2e/logout",
	} {
		t.Run(uid, func(t *testing.T) {
			rule := &AlertRule{Annotations: map[string]string{
				DashboardUIDAnnotation: uid,
				PanelIDAnnotation:      "1",
			}}
			err := rule.SetDashboardAndPanelFromAnnotations()
			require.Error(t, err)
			require.ErrorIs(t, err, ErrAlertRuleFailedValidation)
		})
	}
}
