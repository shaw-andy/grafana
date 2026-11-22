package validation

import (
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	apimodels "github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/setting"
)

// The ruler save path copies annotations in ValidateRuleNode, which
// ValidateRuleGroup calls for every rule. A runbook that is this server's
// logout URL, a protocol-relative URL, or a site-relative path must be
// rejected there. An external http(s) runbook must still be stored.
func TestValidateRuleNodeRejectsRunbookLogout(t *testing.T) {
	const appURL = "http://grafana.example:3000/grafana/"
	previousAppURL := setting.AppUrl
	previousAppSubURL := setting.AppSubUrl
	setting.AppUrl = appURL
	setting.AppSubUrl = "/grafana"
	t.Cleanup(func() {
		setting.AppUrl = previousAppURL
		setting.AppSubUrl = previousAppSubURL
	})

	limits := RuleLimits{
		BaseInterval:                  10 * time.Second,
		DefaultRuleEvaluationInterval: 10 * time.Second,
	}

	rejected := []string{
		"/logout",
		"/grafana/logout",
		"//grafana.example:3000/grafana/logout",
		"http://grafana.example:3000/grafana/logout",
		"http://grafana.example:3000/grafana/logout?orgId=1",
		"http://grafana.example:3000/grafana/log%6Fut",
		"&#47;grafana/logout",
	}
	for _, runbook := range rejected {
		t.Run("alerting "+runbook, func(t *testing.T) {
			rule := alertingRuleWithRunbook(runbook)
			got, err := ValidateRuleNode(&rule, "group", 10*time.Second, 1, "folder", limits)
			require.Error(t, err)
			require.Nil(t, got)
		})
		t.Run("recording "+runbook, func(t *testing.T) {
			rule := recordingRuleWithRunbook(runbook)
			got, err := ValidateRuleNode(&rule, "group", 10*time.Second, 1, "folder", limits)
			require.Error(t, err)
			require.Nil(t, got)
		})
	}

	t.Run("external https runbook is kept", func(t *testing.T) {
		const runbook = "https://runbooks.example/oncall"
		rule := alertingRuleWithRunbook(runbook)
		got, err := ValidateRuleNode(&rule, "group", 10*time.Second, 1, "folder", limits)
		require.NoError(t, err)
		require.Equal(t, runbook, got.Annotations["runbook_url"])
	})
}

func alertingRuleWithRunbook(runbook string) apimodels.PostableExtendedRuleNode {
	forDuration := model.Duration(time.Minute)
	return apimodels.PostableExtendedRuleNode{
		ApiRuleNode: &apimodels.ApiRuleNode{
			For: &forDuration,
			Annotations: map[string]string{
				"runbook_url": runbook,
			},
		},
		GrafanaManagedAlert: &apimodels.PostableGrafanaRule{
			Title:        "cpu high",
			Condition:    "A",
			UID:          "ruleuid1",
			NoDataState:  apimodels.NoData,
			ExecErrState: apimodels.AlertingErrState,
			Data: []apimodels.AlertQuery{{
				RefID:         "A",
				DatasourceUID: "datasource",
				RelativeTimeRange: apimodels.RelativeTimeRange{
					From: 600,
					To:   0,
				},
			}},
		},
	}
}

func recordingRuleWithRunbook(runbook string) apimodels.PostableExtendedRuleNode {
	rule := alertingRuleWithRunbook(runbook)
	rule.GrafanaManagedAlert.Record = &apimodels.Record{Metric: "recorded_metric", From: "A"}
	return rule
}
