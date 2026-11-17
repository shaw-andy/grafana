package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/setting"
)

// TestListAlertRulesPaginated_NonNilEmptyNamespaceUIDsMatchNoRows is the store
// half of the folder-filter bypass. A nil NamespaceUIDs means "do not filter by
// folder". A non-nil empty slice means the caller asked for folders and none
// remain after access control, so the query must match no rows.
func TestListAlertRulesPaginated_NonNilEmptyNamespaceUIDsMatchNoRows(t *testing.T) {
	sqlStore := db.InitTestDB(t)
	cfg := setting.NewCfg()
	cfg.UnifiedAlerting.BaseInterval = time.Second
	folderService := setupFolderService(t, sqlStore, cfg, featuremgmt.WithFeatures())
	st := createTestStore(sqlStore, folderService, log.New("test"), cfg.UnifiedAlerting, &fakeBus{})

	orgID := int64(1)
	gen := models.RuleGen.With(
		models.RuleMuts.WithOrgID(orgID),
		models.RuleMuts.WithIntervalMatching(cfg.UnifiedAlerting.BaseInterval),
	)
	visible := createRule(t, st, gen.With(models.RuleMuts.WithNamespaceUID("fldvisible")))
	secret := createRule(t, st, gen.With(models.RuleMuts.WithNamespaceUID("fldsecret")))

	all, _, err := st.ListAlertRulesPaginated(context.Background(), &models.ListAlertRulesExtendedQuery{
		ListAlertRulesQuery: models.ListAlertRulesQuery{OrgID: orgID},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{visible.UID, secret.UID}, ruleUIDs(all))

	none, _, err := st.ListAlertRulesPaginated(context.Background(), &models.ListAlertRulesExtendedQuery{
		ListAlertRulesQuery: models.ListAlertRulesQuery{
			OrgID:         orgID,
			NamespaceUIDs: []string{},
		},
	})
	require.NoError(t, err)
	require.Empty(t, none, "a non-nil empty NamespaceUIDs must match no rules, not every rule in the org")

	onlySecret, _, err := st.ListAlertRulesPaginated(context.Background(), &models.ListAlertRulesExtendedQuery{
		ListAlertRulesQuery: models.ListAlertRulesQuery{
			OrgID:         orgID,
			NamespaceUIDs: []string{"fldsecret"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, []string{secret.UID}, ruleUIDs(onlySecret))
}

func ruleUIDs(rules models.RulesGroup) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.UID)
	}
	return out
}
