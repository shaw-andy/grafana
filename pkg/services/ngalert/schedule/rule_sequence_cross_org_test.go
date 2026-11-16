package schedule

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/grafana/grafana-app-sdk/resource"
	alertingv0alpha1 "github.com/grafana/grafana/apps/alerting/rules/pkg/apis/alerting/v0alpha1"
	"github.com/grafana/grafana/pkg/infra/log"
	reqns "github.com/grafana/grafana/pkg/services/apiserver/endpoints/request"
	"github.com/grafana/grafana/pkg/services/ngalert/eval"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	crossOrgVictimOrg   int64 = 1
	crossOrgAttackerOrg int64 = 2
	crossOrgOtherOrg    int64 = 3

	crossOrgSharedUID    = "shareduid"
	crossOrgControlUID   = "controluid"
	crossOrgLocalUID     = "localuid"
	crossOrgRecordingUID = "recrefuid"
	crossOrgSequenceUID  = "seqatk"

	crossOrgBaseInterval = 10 * time.Second
	// 8760h is a multiple of the 10s scheduler tick and is the interval from the report.
	crossOrgSequenceInterval = 8760 * time.Hour
)

// namespaceSequenceClient is the list result of an all-namespace RuleSequence
// list. An empty namespace returns every stored sequence. A non-empty namespace
// returns only sequences stored in that namespace.
type namespaceSequenceClient struct {
	resource.Client
	sequences []alertingv0alpha1.RuleSequence
	listed    []string
}

func (c *namespaceSequenceClient) List(_ context.Context, namespace string, _ resource.ListOptions) (resource.ListObject, error) {
	c.listed = append(c.listed, namespace)
	list := &alertingv0alpha1.RuleSequenceList{}
	for _, seq := range c.sequences {
		if namespace != "" && seq.Namespace != namespace {
			continue
		}
		list.Items = append(list.Items, seq)
	}
	return list, nil
}

// multiOrgRulesStore returns every rule it holds. Alert rule UIDs are unique
// per organization, so the key is the alert rule key rather than the UID.
type multiOrgRulesStore struct {
	rules []*models.AlertRule
}

func (s *multiOrgRulesStore) GetAlertRulesKeysForScheduling(context.Context) ([]models.AlertRuleKeyWithVersion, error) {
	out := make([]models.AlertRuleKeyWithVersion, 0, len(s.rules))
	for _, rule := range s.rules {
		out = append(out, models.AlertRuleKeyWithVersion{
			Version:      rule.Version,
			AlertRuleKey: rule.GetKey(),
		})
	}
	return out, nil
}

func (s *multiOrgRulesStore) GetAlertRulesForScheduling(_ context.Context, query *models.GetAlertRulesForSchedulingQuery) error {
	query.ResultRules = slices.Clone(s.rules)
	query.ResultFoldersTitles = map[models.FolderKey]string{}
	for _, rule := range s.rules {
		query.ResultFoldersTitles[rule.GetFolderKey()] = "folder"
	}
	return nil
}

func TestRuleSequenceFromOneOrgDoesNotRescheduleAnotherOrgsRule(t *testing.T) {
	mapper := reqns.GetNamespaceMapper(&setting.Cfg{})
	attackerNamespace := mapper(crossOrgAttackerOrg)

	t.Run("recording rule ref", func(t *testing.T) {
		rules := crossOrgRules(t, true)
		seq := crossOrgSequence(attackerNamespace, []string{crossOrgSharedUID}, nil)
		assertCrossOrgSchedule(t, seq, rules)
	})

	t.Run("alerting rule ref", func(t *testing.T) {
		rules := crossOrgRules(t, false)
		seq := crossOrgSequence(attackerNamespace, []string{crossOrgRecordingUID}, []string{crossOrgSharedUID})
		assertCrossOrgSchedule(t, seq, rules)
	})
}

func crossOrgRules(t *testing.T, sharedUIDIsRecording bool) []*models.AlertRule {
	t.Helper()
	gen := models.RuleGen.With(
		withQueryForState(t, eval.Normal),
		models.RuleGen.WithInterval(crossOrgBaseInterval),
		models.RuleGen.WithGroupName("original-group"),
	)
	shared := func(orgID int64, recording bool) *models.AlertRule {
		mutators := []models.AlertRuleMutator{
			models.RuleGen.WithOrgID(orgID),
			models.RuleGen.WithUID(crossOrgSharedUID),
			models.RuleGen.WithNamespaceUID("folder-" + attackerOrVictim(orgID)),
		}
		if recording {
			mutators = append(mutators, models.RuleGen.WithMetric("recorded_metric"))
		}
		return gen.With(mutators...).GenerateRef()
	}
	rules := []*models.AlertRule{
		shared(crossOrgAttackerOrg, sharedUIDIsRecording),
		shared(crossOrgVictimOrg, false),
		shared(crossOrgOtherOrg, false),
		gen.With(
			models.RuleGen.WithOrgID(crossOrgVictimOrg),
			models.RuleGen.WithUID(crossOrgControlUID),
			models.RuleGen.WithNamespaceUID("folder-victim"),
		).GenerateRef(),
		gen.With(
			models.RuleGen.WithOrgID(crossOrgAttackerOrg),
			models.RuleGen.WithUID(crossOrgLocalUID),
			models.RuleGen.WithNamespaceUID("folder-attacker"),
		).GenerateRef(),
	}
	if !sharedUIDIsRecording {
		rules = append(rules, gen.With(
			models.RuleGen.WithOrgID(crossOrgAttackerOrg),
			models.RuleGen.WithUID(crossOrgRecordingUID),
			models.RuleGen.WithNamespaceUID("folder-attacker"),
			models.RuleGen.WithMetric("recorded_metric"),
		).GenerateRef())
	}
	return rules
}

func attackerOrVictim(orgID int64) string {
	switch orgID {
	case crossOrgAttackerOrg:
		return "attacker"
	case crossOrgVictimOrg:
		return "victim"
	default:
		return "other"
	}
}

func crossOrgSequence(namespace string, recordingRefs, alertingRefs []string) alertingv0alpha1.RuleSequence {
	seq := alertingv0alpha1.RuleSequence{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crossOrgSequenceUID,
			Namespace: namespace,
		},
		Spec: alertingv0alpha1.RuleSequenceSpec{
			Trigger: alertingv0alpha1.RuleSequenceIntervalTrigger{
				Interval: "8760h",
			},
		},
	}
	for _, uid := range recordingRefs {
		seq.Spec.RecordingRules = append(seq.Spec.RecordingRules, alertingv0alpha1.RuleSequenceRuleRef{
			Name: alertingv0alpha1.RuleSequenceRuleUID(uid),
		})
	}
	for _, uid := range alertingRefs {
		seq.Spec.AlertingRules = append(seq.Spec.AlertingRules, alertingv0alpha1.RuleSequenceRuleRef{
			Name: alertingv0alpha1.RuleSequenceRuleUID(uid),
		})
	}
	return seq
}

func assertCrossOrgSchedule(t *testing.T, seq alertingv0alpha1.RuleSequence, rules []*models.AlertRule) {
	t.Helper()

	client := &namespaceSequenceClient{sequences: []alertingv0alpha1.RuleSequence{seq}}
	sequenceStore := NewK8sRuleSequenceStore(&fakeClientGenerator{client: client}, "", log.NewNopLogger())

	ruleStore := &multiOrgRulesStore{rules: rules}
	sched := setupScheduler(t, nil, nil, nil, nil, nil, nil)
	sched.ruleStore = ruleStore
	sched.ruleSequenceStore = sequenceStore
	sched.baseInterval = crossOrgBaseInterval
	sched.minRuleInterval = crossOrgBaseInterval
	sched.jitterEvaluations = JitterNever
	sched.disableGrafanaFolder = true

	ctx, cancel := context.WithCancel(context.Background())
	dispatcher, ctx := errgroup.WithContext(ctx)
	t.Cleanup(func() {
		cancel()
		_ = dispatcher.Wait()
	})

	// Tick 1 is due for a 10s rule and not for an 8760h rule.
	tick := time.Unix(int64(crossOrgBaseInterval/time.Second), 0)
	scheduled, _, _ := sched.processTick(ctx, dispatcher, tick)

	require.Equal(t, []string{""}, client.listed)

	scheduledKeys := map[models.AlertRuleKey]struct{}{}
	for _, item := range scheduled {
		scheduledKeys[item.rule.GetKey()] = struct{}{}
	}

	sequenceSeconds := int64(crossOrgSequenceInterval.Seconds())
	for _, rule := range rules {
		key := rule.GetKey()
		_, wasScheduled := scheduledKeys[key]
		loaded := sched.schedulableAlertRules.get(key)
		require.NotNil(t, loaded)

		if ruleInAttackerSequence(rule, seq) {
			require.Equal(t, sequenceSeconds, loaded.IntervalSeconds, "rule %s in org %d is a member of the sequence", rule.UID, rule.OrgID)
			require.True(t, models.IsRuleSequenceGroup(loaded.RuleGroup), "rule %s in org %d should be placed in the sequence group", rule.UID, rule.OrgID)
			require.False(t, wasScheduled, "rule %s in org %d should wait for the sequence interval", rule.UID, rule.OrgID)
			continue
		}

		require.Equal(t, int64(crossOrgBaseInterval.Seconds()), loaded.IntervalSeconds, "rule %s in org %d must keep its own interval", rule.UID, rule.OrgID)
		require.Equal(t, "original-group", loaded.RuleGroup, "rule %s in org %d must keep its own group", rule.UID, rule.OrgID)
		require.True(t, wasScheduled, "rule %s in org %d must still be evaluated on its own interval", rule.UID, rule.OrgID)
	}
}

func ruleInAttackerSequence(rule *models.AlertRule, seq alertingv0alpha1.RuleSequence) bool {
	if rule.OrgID != crossOrgAttackerOrg {
		return false
	}
	for _, ref := range seq.Spec.RecordingRules {
		if string(ref.Name) == rule.UID {
			return true
		}
	}
	for _, ref := range seq.Spec.AlertingRules {
		if string(ref.Name) == rule.UID {
			return true
		}
	}
	return false
}
