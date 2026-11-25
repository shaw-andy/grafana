package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/expr"
	apimodels "github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// TestIntegrationRecordingRuleTargetDatasourceEnforcement checks that an Editor
// cannot point a Grafana-managed recording rule at a Prometheus datasource whose
// allowAsRecordingRulesTarget flag an administrator set to false.
//
// The requests are the ruler, provisioning, and Prometheus conversion APIs. Each
// one must reject the rule and leave it unsaved. These assertions fail while the
// server ignores the flag.
func TestIntegrationRecordingRuleTargetDatasourceEnforcement(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)
	testinfra.SQLiteIntegrationTest(t)

	dir, cfgPath := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{
		DisableLegacyAlerting: true,
		EnableUnifiedAlerting: true,
		EnableRecordingRules:  true,
		DisableAnonymous:      true,
		AppModeProduction:     true,
	})
	grafanaListedAddr, env := testinfra.StartGrafanaEnv(t, dir, cfgPath)

	createUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleEditor),
		Password:       "editor",
		Login:          "editor",
	})
	createUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleViewer),
		Password:       "viewer",
		Login:          "viewer",
	})

	admin := newAlertingApiClient(grafanaListedAddr, "admin", "admin")
	editor := newAlertingApiClient(grafanaListedAddr, "editor", "editor")
	viewer := newAlertingApiClient(grafanaListedAddr, "viewer", "viewer")

	deniedFlag := false
	allowedFlag := true
	denied := createPrometheusDatasource(t, admin, "prom-denied", &deniedFlag)
	allowed := createPrometheusDatasource(t, admin, "prom-allowed", &allowedFlag)
	unset := createPrometheusDatasource(t, admin, "prom-unset", nil)

	const folderUID = "rec-target-folder"
	editor.CreateFolder(t, folderUID, "Recording target folder")

	t.Run("ruler rejects a new recording rule aimed at the excluded datasource", func(t *testing.T) {
		group := recordingRuleGroup("ruler-denied", "editor_ruler_denied", denied)
		_, status, body := editor.PostRulesGroupWithStatus(t, folderUID, &group, false)
		require.Equalf(t, http.StatusBadRequest, status, "body: %s", body)
		assertRulerGroupAbsent(t, editor, folderUID, group.Name)
		assertNoRecordingTarget(t, editor, denied)
	})

	t.Run("ruler rejects a group that mixes an alerting rule with an excluded recording target", func(t *testing.T) {
		group := recordingRuleGroup("ruler-mixed", "editor_ruler_mixed", denied)
		group.Rules = append([]apimodels.PostableExtendedRuleNode{mathAlertingRule("mixed-alert")}, group.Rules...)
		_, status, body := editor.PostRulesGroupWithStatus(t, folderUID, &group, false)
		require.Equalf(t, http.StatusBadRequest, status, "body: %s", body)
		assertRulerGroupAbsent(t, editor, folderUID, group.Name)
		assertNoRecordingTarget(t, editor, denied)
	})

	t.Run("ruler keeps the previous target when an update switches to the excluded datasource", func(t *testing.T) {
		group := recordingRuleGroup("ruler-update", "editor_ruler_update", allowed)
		created, status, body := editor.PostRulesGroupWithStatus(t, folderUID, &group, false)
		require.Equalf(t, http.StatusAccepted, status, "body: %s", body)
		require.NotEmpty(t, created.Created)
		group.Rules[0].GrafanaManagedAlert.UID = created.Created[0]
		group.Rules[0].GrafanaManagedAlert.Record.TargetDatasourceUID = denied

		_, status, body = editor.PostRulesGroupWithStatus(t, folderUID, &group, false)
		require.Equalf(t, http.StatusBadRequest, status, "body: %s", body)

		stored, status, raw := editor.GetRulesGroupWithStatus(t, folderUID, group.Name)
		require.Equalf(t, http.StatusAccepted, status, "body: %s", raw)
		require.Len(t, stored.Rules, 1)
		require.NotNil(t, stored.Rules[0].GrafanaManagedAlert.Record)
		require.Equal(t, allowed, stored.Rules[0].GrafanaManagedAlert.Record.TargetDatasourceUID)
		assertNoRecordingTarget(t, editor, denied)
	})

	t.Run("ruler still accepts an explicitly allowed target and an unset target", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			target string
		}{
			{name: "ruler-allowed", target: allowed},
			{name: "ruler-unset", target: unset},
		} {
			t.Run(tc.name, func(t *testing.T) {
				group := recordingRuleGroup(tc.name, "editor_"+tc.name, tc.target)
				_, status, body := editor.PostRulesGroupWithStatus(t, folderUID, &group, false)
				require.Equalf(t, http.StatusAccepted, status, "body: %s", body)
				stored, status, raw := editor.GetRulesGroupWithStatus(t, folderUID, group.Name)
				require.Equalf(t, http.StatusAccepted, status, "body: %s", raw)
				require.Equal(t, tc.target, stored.Rules[0].GrafanaManagedAlert.Record.TargetDatasourceUID)
			})
		}
	})

	t.Run("viewer cannot create a recording rule", func(t *testing.T) {
		group := recordingRuleGroup("viewer-denied", "viewer_metric", denied)
		_, status, body := viewer.PostRulesGroupWithStatus(t, folderUID, &group, false)
		require.Equalf(t, http.StatusForbidden, status, "body: %s", body)
		assertRulerGroupAbsent(t, editor, folderUID, group.Name)
	})

	t.Run("provisioning create rejects the excluded datasource", func(t *testing.T) {
		rule := provisionedRecordingRule(folderUID, "prov-denied", "editor_prov_denied", denied)
		status, body := postProvisioningRule(t, editor, rule)
		require.Equalf(t, http.StatusBadRequest, status, "body: %s", body)
		assertRulerGroupAbsent(t, editor, folderUID, rule.RuleGroup)
		assertNoRecordingTarget(t, editor, denied)
	})

	t.Run("provisioning update does not move an existing rule onto the excluded datasource", func(t *testing.T) {
		rule := provisionedRecordingRule(folderUID, "prov-update", "editor_prov_update", allowed)
		status, body := postProvisioningRule(t, editor, rule)
		require.Equalf(t, http.StatusCreated, status, "body: %s", body)
		var created apimodels.ProvisionedAlertRule
		require.NoError(t, json.Unmarshal([]byte(body), &created))
		require.NotEmpty(t, created.UID)

		created.Record.TargetDatasourceUID = denied
		status, body = putProvisioningRule(t, editor, created)
		require.Equalf(t, http.StatusBadRequest, status, "body: %s", body)

		stored, status, raw := editor.GetRulesGroupWithStatus(t, folderUID, rule.RuleGroup)
		require.Equalf(t, http.StatusAccepted, status, "body: %s", raw)
		require.Equal(t, allowed, stored.Rules[0].GrafanaManagedAlert.Record.TargetDatasourceUID)
		assertNoRecordingTarget(t, editor, denied)
	})

	t.Run("provisioning group replace rejects the excluded datasource", func(t *testing.T) {
		group := apimodels.AlertRuleGroup{
			Title:     "prov-group-denied",
			FolderUID: folderUID,
			Interval:  60,
			Rules:     []apimodels.ProvisionedAlertRule{provisionedRecordingRule(folderUID, "prov-group-denied", "editor_prov_group", denied)},
		}
		_, status, body := editor.CreateOrUpdateRuleGroupProvisioning(t, group)
		require.Equalf(t, http.StatusBadRequest, status, "body: %s", body)
		assertRulerGroupAbsent(t, editor, folderUID, group.Title)
		assertNoRecordingTarget(t, editor, denied)
	})

	t.Run("prometheus conversion rejects an excluded target header", func(t *testing.T) {
		const namespace = "conversion-denied-target"
		const namespaceUID = "conv-denied-folder"
		editor.CreateFolder(t, namespaceUID, namespace)
		group := prometheusRecordingGroup("conv-denied", "editor_conv_denied")
		_, status, body := editor.RawConvertPrometheusPostRuleGroup(t, namespace, allowed, group, map[string]string{
			"Content-Type":            "application/json",
			targetDatasourceUIDHeader: denied,
		})
		require.Equalf(t, http.StatusBadRequest, status, "body: %s", body)
		assertRulerGroupAbsent(t, editor, namespaceUID, group.Name)
		assertNoRecordingTarget(t, editor, denied)
	})

	t.Run("prometheus conversion rejects an excluded query datasource used as the target", func(t *testing.T) {
		const namespace = "conversion-denied-source"
		const namespaceUID = "conv-source-folder"
		editor.CreateFolder(t, namespaceUID, namespace)
		group := prometheusRecordingGroup("conv-source", "editor_conv_source")
		_, status, body := editor.RawConvertPrometheusPostRuleGroup(t, namespace, denied, group, map[string]string{
			"Content-Type": "application/json",
		})
		require.Equalf(t, http.StatusBadRequest, status, "body: %s", body)
		assertRulerGroupAbsent(t, editor, namespaceUID, group.Name)
		assertNoRecordingTarget(t, editor, denied)
	})
}

func createPrometheusDatasource(t *testing.T, client apiClient, name string, allow *bool) string {
	t.Helper()
	jsonData := map[string]any{"prometheusType": "Prometheus"}
	if allow != nil {
		jsonData["allowAsRecordingRulesTarget"] = *allow
	}
	payload := map[string]any{
		"name":     name,
		"uid":      name,
		"type":     "prometheus",
		"access":   "proxy",
		"url":      "http://127.0.0.1:1",
		"jsonData": jsonData,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	resp, err := http.Post(client.url+"/api/datasources", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equalf(t, http.StatusOK, resp.StatusCode, "create datasource %s: %s", name, raw)
	var created struct {
		Datasource struct {
			UID string `json:"uid"`
		} `json:"datasource"`
	}
	require.NoError(t, json.Unmarshal(raw, &created))
	require.Equal(t, name, created.Datasource.UID)
	return created.Datasource.UID
}

func recordingRuleGroup(name, metric, targetUID string) apimodels.PostableRuleGroupConfig {
	return apimodels.PostableRuleGroupConfig{
		Name:     name,
		Interval: model.Duration(time.Minute),
		Rules: []apimodels.PostableExtendedRuleNode{{
			GrafanaManagedAlert: &apimodels.PostableGrafanaRule{
				Title: name,
				Data:  []apimodels.AlertQuery{mathQuery()},
				Record: &apimodels.Record{
					Metric:              metric,
					From:                "A",
					TargetDatasourceUID: targetUID,
				},
			},
		}},
	}
}

func mathAlertingRule(title string) apimodels.PostableExtendedRuleNode {
	forDuration := model.Duration(time.Minute)
	return apimodels.PostableExtendedRuleNode{
		ApiRuleNode: &apimodels.ApiRuleNode{For: &forDuration},
		GrafanaManagedAlert: &apimodels.PostableGrafanaRule{
			Title:        title,
			Condition:    "A",
			Data:         []apimodels.AlertQuery{mathQuery()},
			NoDataState:  apimodels.NoData,
			ExecErrState: apimodels.ErrorErrState,
		},
	}
}

func mathQuery() apimodels.AlertQuery {
	return apimodels.AlertQuery{
		RefID:         "A",
		DatasourceUID: expr.DatasourceUID,
		RelativeTimeRange: apimodels.RelativeTimeRange{
			From: apimodels.Duration(10 * time.Minute),
		},
		Model: json.RawMessage(`{"type":"math","expression":"1 + 1","refId":"A"}`),
	}
}

func provisionedRecordingRule(folderUID, group, metric, targetUID string) apimodels.ProvisionedAlertRule {
	return apimodels.ProvisionedAlertRule{
		FolderUID:    folderUID,
		RuleGroup:    group,
		Title:        group,
		Condition:    "A",
		Data:         []apimodels.AlertQuery{mathQuery()},
		NoDataState:  apimodels.NoData,
		ExecErrState: apimodels.ErrorErrState,
		For:          model.Duration(0),
		Record: &apimodels.Record{
			Metric:              metric,
			From:                "A",
			TargetDatasourceUID: targetUID,
		},
	}
}

func prometheusRecordingGroup(name, metric string) apimodels.PrometheusRuleGroup {
	return apimodels.PrometheusRuleGroup{
		Name:     name,
		Interval: model.Duration(time.Minute),
		Rules: []apimodels.PrometheusRule{{
			Record: metric,
			Expr:   "sum(up)",
		}},
	}
}

func postProvisioningRule(t *testing.T, client apiClient, rule apimodels.ProvisionedAlertRule) (int, string) {
	t.Helper()
	return sendProvisioningRule(t, http.MethodPost, client.url+"/api/v1/provisioning/alert-rules", rule)
}

func putProvisioningRule(t *testing.T, client apiClient, rule apimodels.ProvisionedAlertRule) (int, string) {
	t.Helper()
	return sendProvisioningRule(t, http.MethodPut, fmt.Sprintf("%s/api/v1/provisioning/alert-rules/%s", client.url, rule.UID), rule)
}

func sendProvisioningRule(t *testing.T, method, rawURL string, rule apimodels.ProvisionedAlertRule) (int, string) {
	t.Helper()
	body, err := json.Marshal(rule)
	require.NoError(t, err)
	req, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(raw)
}

func assertRulerGroupAbsent(t *testing.T, client apiClient, folderUID, group string) {
	t.Helper()
	_, status, raw := client.GetRulesGroupWithStatus(t, folderUID, group)
	require.Equalf(t, http.StatusNotFound, status, "recording rule group was stored: %s", raw)
}

func assertNoRecordingTarget(t *testing.T, client apiClient, targetUID string) {
	t.Helper()
	all, status, raw := client.GetAllRulesWithStatus(t)
	require.Equalf(t, http.StatusOK, status, "body: %s", raw)
	for namespace, groups := range all {
		for _, group := range groups {
			for _, rule := range group.Rules {
				if rule.GrafanaManagedAlert == nil || rule.GrafanaManagedAlert.Record == nil {
					continue
				}
				require.NotEqualf(t, targetUID, rule.GrafanaManagedAlert.Record.TargetDatasourceUID,
					"namespace %s group %s stored a recording rule aimed at the excluded datasource", namespace, group.Name)
			}
		}
	}
}
