package api

import (
	"testing"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/ngalert/api/validation"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
)

func TestValidateRuleGroupRejectsUnsafeDashboardUID(t *testing.T) {
	cfg := config(t)
	limits := makeLimits(cfg)
	folder := randFolder()
	const orgID int64 = 1

	t.Run("letters digits underscore and hyphen are accepted", func(t *testing.T) {
		rule := validRule()
		rule.Annotations = map[string]string{
			models.DashboardUIDAnnotation: "abc-DEF_1",
			models.PanelIDAnnotation:      "5",
		}
		group := validGroup(cfg, rule)
		group.Interval = model.Duration(cfg.BaseInterval)

		alerts, err := validation.ValidateRuleGroup(&group, orgID, folder.UID, limits)
		require.NoError(t, err)
		require.Len(t, alerts, 1)
		require.Equal(t, "abc-DEF_1", alerts[0].Annotations[models.DashboardUIDAnnotation])
		require.Equal(t, "5", alerts[0].Annotations[models.PanelIDAnnotation])
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
			rule := validRule()
			rule.Annotations = map[string]string{
				models.DashboardUIDAnnotation: uid,
				models.PanelIDAnnotation:      "1",
			}
			group := validGroup(cfg, rule)
			group.Interval = model.Duration(cfg.BaseInterval)

			_, err := validation.ValidateRuleGroup(&group, orgID, folder.UID, limits)
			require.Error(t, err)
		})
	}
}
