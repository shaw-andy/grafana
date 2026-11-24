package store

import (
	"context"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log/logtest"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/setting"
	tutil "github.com/grafana/grafana/pkg/util/testutil"
)

// A mixed rule_group filter (a real group name plus a no_group_for_rule_<uid>
// token) must stay inside the caller's org and folder predicates. These tests
// fail while that filter is attached with Session.Or, which ORs the uid match
// with every earlier condition.
func TestIntegration_CrossOrgRuleGroupFilter(t *testing.T) {
	tutil.SkipIntegrationTestInShortMode(t)

	const (
		attackerOrg      int64 = 1
		victimOrg        int64 = 2
		sharedFolder           = "sharedfolder01"
		publicFolder           = "publicfolder01"
		secretFolder           = "secretfolder01"
		victimUID              = "victimruleuid1"
		attackerUID            = "attackerrule01"
		ungroupedUID           = "attackerungrp1"
		secretUID              = "secretruleuid1"
		victimGroup            = "victim-group"
		attackerGroup          = "attacker-group"
		secretGroup            = "secret-group"
		victimQuery            = `count(victim_only_metric)`
		victimReceiver         = "victim-pager"
		victimLabel            = "victim-team"
		victimAnnotation       = "victim-secret-annotation"
		victimDatasource       = "victimdsuid"
	)

	cfg := setting.NewCfg()
	cfg.UnifiedAlerting.BaseInterval = 10 * time.Second
	sqlStore := db.InitTestDB(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	folderService := setupFolderService(t, sqlStore, cfg, featuremgmt.WithFeatures())
	store := createTestStore(sqlStore, folderService, &logtest.Fake{}, cfg.UnifiedAlerting, &fakeBus{})

	gen := models.RuleGen.With(models.RuleMuts.WithIntervalMatching(cfg.UnifiedAlerting.BaseInterval))
	victim := createRule(t, store, gen.With(
		models.RuleMuts.WithOrgID(victimOrg),
		models.RuleMuts.WithNamespaceUID(sharedFolder),
		models.RuleMuts.WithUID(victimUID),
		models.RuleMuts.WithGroupName(victimGroup),
		models.RuleMuts.WithTitle("victim-rule"),
		models.RuleMuts.WithLabels(data.Labels{"team": victimLabel}),
		models.RuleMuts.WithAnnotations(data.Labels{"summary": victimAnnotation}),
		models.RuleMuts.WithNotificationSettings(models.NotificationSettings{
			ContactPointRouting: &models.ContactPointRouting{Receiver: victimReceiver},
		}),
		models.RuleMuts.WithQuery(models.CreatePrometheusQuery("A", victimQuery, 1000, 100, true, victimDatasource)),
	))
	attacker := createRule(t, store, gen.With(
		models.RuleMuts.WithOrgID(attackerOrg),
		models.RuleMuts.WithNamespaceUID(sharedFolder),
		models.RuleMuts.WithUID(attackerUID),
		models.RuleMuts.WithGroupName(attackerGroup),
		models.RuleMuts.WithTitle("attacker-rule"),
		models.RuleMuts.WithNoNotificationSettings(),
		models.RuleMuts.WithQuery(models.CreatePrometheusQuery("A", `count(attacker_metric)`, 1000, 100, true, "attackerds")),
	))
	ungrouped := createRule(t, store, gen.With(
		models.RuleMuts.WithOrgID(attackerOrg),
		models.RuleMuts.WithNamespaceUID(sharedFolder),
		models.RuleMuts.WithUID(ungroupedUID),
		models.RuleMuts.WithGroupName(""),
		models.RuleMuts.WithTitle("attacker-ungrouped"),
		models.RuleMuts.WithNoNotificationSettings(),
		models.RuleMuts.WithQuery(models.CreatePrometheusQuery("A", `count(attacker_ungrouped_metric)`, 1000, 100, true, "attackerds")),
	))
	secret := createRule(t, store, gen.With(
		models.RuleMuts.WithOrgID(attackerOrg),
		models.RuleMuts.WithNamespaceUID(secretFolder),
		models.RuleMuts.WithUID(secretUID),
		models.RuleMuts.WithGroupName(secretGroup),
		models.RuleMuts.WithTitle("secret-folder-rule"),
		models.RuleMuts.WithNoNotificationSettings(),
		models.RuleMuts.WithQuery(models.CreatePrometheusQuery("A", `count(secret_folder_metric)`, 1000, 100, true, "secretds")),
	))

	victimNoGroup, err := models.NewNoGroupRuleGroup(victim.UID)
	require.NoError(t, err)
	ungroupedNoGroup, err := models.NewNoGroupRuleGroup(ungrouped.UID)
	require.NoError(t, err)
	secretNoGroup, err := models.NewNoGroupRuleGroup(secret.UID)
	require.NoError(t, err)

	// The caller knows the victim group name and builds the no-group token from
	// the victim uid. Their own group and ungrouped rule are included so a fix
	// still returns rules they are allowed to read.
	mixedGroups := []string{victim.RuleGroup, attacker.RuleGroup, victimNoGroup.String(), ungroupedNoGroup.String()}

	assertIsolated := func(t *testing.T, got models.RulesGroup) {
		t.Helper()
		gotUIDs := make([]string, 0, len(got))
		for _, rule := range got {
			gotUIDs = append(gotUIDs, rule.UID)
			require.Equal(t, attackerOrg, rule.OrgID, "list returned a rule from another organization")
			require.NotEqual(t, secret.NamespaceUID, rule.NamespaceUID, "list returned a rule from a folder outside the query")
			require.NotEqual(t, victimLabel, rule.Labels["team"])
			require.NotEqual(t, victimAnnotation, rule.Annotations["summary"])
			if rule.NotificationSettings != nil && rule.NotificationSettings.ContactPointRouting != nil {
				require.NotEqual(t, victimReceiver, rule.NotificationSettings.ContactPointRouting.Receiver)
			}
			for _, q := range rule.Data {
				expr, _ := q.GetQuery()
				require.NotContains(t, expr, "victim_only_metric")
				require.NotEqual(t, victimDatasource, q.DatasourceUID)
			}
		}
		require.ElementsMatch(t, []string{attacker.UID, ungrouped.UID}, gotUIDs)
	}

	t.Run("real group only stays inside the organization", func(t *testing.T) {
		got, err := store.ListAlertRules(context.Background(), &models.ListAlertRulesQuery{
			OrgID:         attackerOrg,
			NamespaceUIDs: []string{sharedFolder},
			RuleGroups:    []string{victim.RuleGroup, attacker.RuleGroup},
		})
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Equal(t, attacker.UID, got[0].UID)
	})

	t.Run("no-group token only stays inside the organization", func(t *testing.T) {
		got, err := store.ListAlertRules(context.Background(), &models.ListAlertRulesQuery{
			OrgID:         attackerOrg,
			NamespaceUIDs: []string{sharedFolder},
			RuleGroups:    []string{victimNoGroup.String()},
		})
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("ListAlertRules", func(t *testing.T) {
		got, err := store.ListAlertRules(context.Background(), &models.ListAlertRulesQuery{
			OrgID:         attackerOrg,
			NamespaceUIDs: []string{sharedFolder},
			RuleGroups:    mixedGroups,
		})
		require.NoError(t, err)
		assertIsolated(t, got)
	})

	t.Run("ListAlertRulesPaginated", func(t *testing.T) {
		got, token, err := store.ListAlertRulesPaginated(context.Background(), &models.ListAlertRulesExtendedQuery{
			ListAlertRulesQuery: models.ListAlertRulesQuery{
				OrgID:         attackerOrg,
				NamespaceUIDs: []string{sharedFolder},
				RuleGroups:    mixedGroups,
			},
			RuleType: models.RuleTypeFilterAll,
		})
		require.NoError(t, err)
		require.Empty(t, token)
		assertIsolated(t, got)
	})

	t.Run("ListAlertRulesByGroup", func(t *testing.T) {
		got, token, err := store.ListAlertRulesByGroup(context.Background(), &models.ListAlertRulesExtendedQuery{
			ListAlertRulesQuery: models.ListAlertRulesQuery{
				OrgID:         attackerOrg,
				NamespaceUIDs: []string{sharedFolder},
				RuleGroups:    mixedGroups,
			},
			RuleType: models.RuleTypeFilterAll,
		})
		require.NoError(t, err)
		require.Empty(t, token)
		assertIsolated(t, got)
	})

	t.Run("ungrouped rule in another org", func(t *testing.T) {
		// An empty stored group is presented as the no-group token, so that
		// token is enough to satisfy the post-query group-name check. Any real
		// group name triggers the mixed filter.
		foreignUngrouped := createRule(t, store, gen.With(
			models.RuleMuts.WithOrgID(victimOrg),
			models.RuleMuts.WithNamespaceUID(sharedFolder),
			models.RuleMuts.WithUID("victimungroup1"),
			models.RuleMuts.WithGroupName(""),
			models.RuleMuts.WithTitle("victim-ungrouped"),
			models.RuleMuts.WithNoNotificationSettings(),
			models.RuleMuts.WithQuery(models.CreatePrometheusQuery("A", `count(victim_ungrouped_metric)`, 1000, 100, true, victimDatasource)),
		))
		foreignNoGroup, err := models.NewNoGroupRuleGroup(foreignUngrouped.UID)
		require.NoError(t, err)

		got, err := store.ListAlertRules(context.Background(), &models.ListAlertRulesQuery{
			OrgID:         attackerOrg,
			NamespaceUIDs: []string{sharedFolder},
			RuleGroups:    []string{attacker.RuleGroup, foreignNoGroup.String()},
		})
		require.NoError(t, err)
		for _, rule := range got {
			require.NotEqual(t, foreignUngrouped.UID, rule.UID)
			require.Equal(t, attackerOrg, rule.OrgID)
		}
	})

	t.Run("folder outside the allowed namespaces", func(t *testing.T) {
		got, err := store.ListAlertRules(context.Background(), &models.ListAlertRulesQuery{
			OrgID:         attackerOrg,
			NamespaceUIDs: []string{publicFolder, sharedFolder},
			RuleGroups:    []string{secret.RuleGroup, attacker.RuleGroup, secretNoGroup.String()},
		})
		require.NoError(t, err)
		for _, rule := range got {
			require.NotEqual(t, secret.UID, rule.UID)
			require.NotEqual(t, secret.NamespaceUID, rule.NamespaceUID)
			for _, q := range rule.Data {
				expr, _ := q.GetQuery()
				require.NotContains(t, expr, "secret_folder_metric")
			}
		}
		require.NotEmpty(t, got)
	})
}
