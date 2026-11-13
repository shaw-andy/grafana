package accesscontrol

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/store"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/util/cmputil"
)

// An Editor who can create rules, query the rule's own datasource, and read the
// contact point they attach must still be refused when the dashboard annotation
// names a dashboard they cannot read. Rule save checks datasource query access
// and contact-point read access; it does not check dashboards:read.
func TestRuleSaveRejectsDashboardTheAuthorCannotRead(t *testing.T) {
	const (
		orgID       = int64(12)
		folderUID   = "folder-editor"
		ownDS       = "own-ds"
		allowedDash = "allowed-dash"
		secretDash  = "secret-dash"
		receiver    = "editor-hook"
		panelID     = int64(7)
	)

	author := editorWhoCannotRead(t, orgID, folderUID, ownDS, allowedDash, receiver)
	svc := NewRuleService(acimpl.ProvideAccessControl(featuremgmt.WithFeatures()))
	ctx := context.Background()

	t.Run("api create sets the dashboard from annotations before authorization", func(t *testing.T) {
		rule := newAnnotatedRule(orgID, folderUID, ownDS, receiver, secretDash, panelID)
		// api/validation copies annotations onto the rule, then the ruler authorizes that rule.
		require.NoError(t, rule.SetDashboardAndPanelFromAnnotations())
		err := svc.AuthorizeRuleChanges(ctx, author, newGroup(rule))
		requireDashboardRejected(t, err, rule, author)
	})

	t.Run("provisioning authorizes before annotations are copied onto the rule", func(t *testing.T) {
		// AlertRuleService.CreateAlertRule and UpdateAlertRule call
		// AuthorizeRuleGroupWrite before SetDashboardAndPanelFromAnnotations.
		rule := newAnnotatedRule(orgID, folderUID, ownDS, receiver, secretDash, panelID)
		require.Nil(t, rule.DashboardUID)
		err := svc.AuthorizeRuleChanges(ctx, author, newGroup(rule))
		if err == nil {
			require.NoError(t, rule.SetDashboardAndPanelFromAnnotations())
		}
		requireDashboardRejected(t, err, rule, author)
	})

	t.Run("authorization of one dashboard must not permit a different annotated dashboard", func(t *testing.T) {
		// The field names a dashboard the author can read. The annotation, which
		// provisioning copies onto the field after authorization, names one they cannot.
		rule := newAnnotatedRule(orgID, folderUID, ownDS, receiver, secretDash, panelID)
		allowed := allowedDash
		allowedPanel := panelID
		rule.DashboardUID = &allowed
		rule.PanelID = &allowedPanel
		err := svc.AuthorizeRuleChanges(ctx, author, newGroup(rule))
		if err == nil {
			require.NoError(t, rule.SetDashboardAndPanelFromAnnotations())
		}
		requireDashboardRejected(t, err, rule, author)
	})

	t.Run("update that only changes the dashboard annotation", func(t *testing.T) {
		existing := newAnnotatedRule(orgID, folderUID, ownDS, receiver, "", 0)
		existing.Annotations = nil
		existing.NotificationSettings = ruleNotification(receiver)
		updated := newAnnotatedRule(orgID, folderUID, ownDS, receiver, secretDash, panelID)
		updated.UID = existing.UID
		require.NoError(t, updated.SetDashboardAndPanelFromAnnotations())
		delta := &store.GroupDelta{
			GroupKey: existing.GetGroupKey(),
			AffectedGroups: map[models.AlertRuleGroupKey]models.RulesGroup{
				existing.GetGroupKey(): {existing},
			},
			Update: []store.RuleDelta{{
				Existing: existing,
				New:      updated,
				Diff:     cmputil.DiffReport{{Path: "Annotations"}},
			}},
		}
		err := svc.AuthorizeRuleChanges(ctx, author, delta)
		requireDashboardRejected(t, err, updated, author)
	})

	t.Run("dashboard the author can read is allowed", func(t *testing.T) {
		rule := newAnnotatedRule(orgID, folderUID, ownDS, receiver, allowedDash, panelID)
		require.NoError(t, rule.SetDashboardAndPanelFromAnnotations())
		err := svc.AuthorizeRuleChanges(ctx, author, newGroup(rule))
		require.NoError(t, err)
		require.Equal(t, allowedDash, rule.GetDashboardUID())
	})
}

func requireDashboardRejected(t *testing.T, err error, rule *models.AlertRule, author *user.SignedInUser) {
	t.Helper()
	require.Error(t, err)
	if uid := rule.GetDashboardUID(); uid != "" {
		require.Truef(t, authorCanReadDashboard(author, uid), "rule kept dashboard %s, which the author cannot read", uid)
	}
	anno := ""
	if rule.Annotations != nil {
		anno = rule.Annotations[models.DashboardUIDAnnotation]
	}
	if anno != "" {
		require.Truef(t, authorCanReadDashboard(author, anno), "rule kept annotation %s, which the author cannot read", anno)
	}
}

func authorCanReadDashboard(author *user.SignedInUser, uid string) bool {
	scopes := author.GetPermissions()[dashboards.ActionDashboardsRead]
	want := dashboards.ScopeDashboardsProvider.GetResourceScopeUID(uid)
	for _, scope := range scopes {
		if scope == want || scope == dashboards.ScopeDashboardsAll {
			return true
		}
	}
	return false
}

func editorWhoCannotRead(t *testing.T, orgID int64, folderUID, ownDS, allowedDash, receiver string) *user.SignedInUser {
	t.Helper()
	folderScope := folder.ScopeFoldersProvider.GetResourceScopeUID(folderUID)
	receiverScope := models.ScopeReceiversProvider.GetResourceScopeUID(models.NameToUid(receiver))
	return &user.SignedInUser{
		UserID:  42,
		OrgID:   orgID,
		OrgRole: "Editor",
		Permissions: map[int64]map[string][]string{
			orgID: {
				accesscontrol.ActionAlertingRuleCreate:    {folderScope},
				accesscontrol.ActionAlertingRuleRead:      {folderScope},
				accesscontrol.ActionAlertingRuleUpdate:    {folderScope},
				folder.ActionFoldersRead:                  {folderScope},
				datasources.ActionQuery:                   {datasources.ScopeProvider.GetResourceScopeUID(ownDS)},
				accesscontrol.ActionAlertingReceiversRead: {receiverScope},
				dashboards.ActionDashboardsRead:           {dashboards.ScopeDashboardsProvider.GetResourceScopeUID(allowedDash)},
			},
		},
	}
}

func newAnnotatedRule(orgID int64, folderUID, datasourceUID, receiver, dashboardUID string, panelID int64) *models.AlertRule {
	rule := &models.AlertRule{
		OrgID:        orgID,
		UID:          "rule-1",
		Title:        "editor rule",
		Condition:    "A",
		NamespaceUID: folderUID,
		RuleGroup:    "group-1",
		Data: []models.AlertQuery{{
			RefID:         "A",
			DatasourceUID: datasourceUID,
			Model:         []byte(`{}`),
		}},
		NotificationSettings: ruleNotification(receiver),
	}
	if dashboardUID != "" {
		rule.Annotations = map[string]string{
			models.DashboardUIDAnnotation: dashboardUID,
			models.PanelIDAnnotation:      "7",
		}
		if panelID != 7 && panelID > 0 {
			rule.Annotations[models.PanelIDAnnotation] = "7"
		}
	}
	return rule
}

func ruleNotification(receiver string) *models.NotificationSettings {
	return &models.NotificationSettings{
		ContactPointRouting: &models.ContactPointRouting{Receiver: receiver},
	}
}

func newGroup(rule *models.AlertRule) *store.GroupDelta {
	return &store.GroupDelta{
		GroupKey: rule.GetGroupKey(),
		New:      []*models.AlertRule{rule},
	}
}
