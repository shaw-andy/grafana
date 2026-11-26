package rulesequence_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/endpoints/request"

	appsdk "github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/resource"
	"github.com/grafana/grafana-app-sdk/simple"

	model "github.com/grafana/grafana/apps/alerting/rules/pkg/apis/alerting/v0alpha1"
	"github.com/grafana/grafana/apps/alerting/rules/pkg/app/alertrule"
	"github.com/grafana/grafana/apps/alerting/rules/pkg/app/config"
	"github.com/grafana/grafana/apps/alerting/rules/pkg/app/recordingrule"
	"github.com/grafana/grafana/apps/alerting/rules/pkg/app/rulesequence"
	"github.com/grafana/grafana/apps/alerting/rules/pkg/app/validation"
)

// On-prem namespaces for two organizations. Org 1 is "default"; every other org is "org-<id>".
const (
	nsVictim   = "default"
	nsAttacker = "org-2"
	folderA    = "folder-a"
	folderB    = "folder-b"

	sharedAlertUID     = "high-cpu"
	sharedRecordingUID = "shared-record"
	victimOnlyUID      = "victim-only"
	attackerOnlyUID    = "attacker-only"
)

// nsCtx is the context the kube-apiserver handlers build before admission:
// the namespace comes from the request URL.
func nsCtx(ns string) context.Context {
	return request.WithNamespace(context.Background(), ns)
}

// harness is one process-wide membership index, the same object the rules app
// installs as both the RuleSequence watcher and the admission resolver, plus
// the admission validators that read it.
type harness struct {
	idx      *rulesequence.MembershipIndex
	alert    *simple.Validator
	record   *simple.Validator
	sequence *simple.Validator
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	idx := rulesequence.NewMembershipIndex()

	// Rules that exist inside each organization. Lookup is scoped by the
	// admission request namespace, matching the legacy store's (org_id, uid) key.
	rules := map[string]map[string]string{
		nsVictim: {
			sharedAlertUID:     folderA,
			sharedRecordingUID: folderA,
			victimOnlyUID:      folderA,
		},
		nsAttacker: {
			sharedAlertUID:     folderA,
			sharedRecordingUID: folderA,
			attackerOnlyUID:    folderA,
		},
	}
	cfg := config.RuntimeConfig{
		BaseEvaluationInterval: 60 * time.Second,
		ReservedLabelKeys:      map[string]struct{}{},
		MembershipResolver:     idx,
		FolderValidator: func(_ context.Context, folderUID string) (bool, error) {
			return folderUID == folderA || folderUID == folderB, nil
		},
		ResolveRuleRef: func(ctx context.Context, uid string) (config.RuleRef, bool, error) {
			folderUID, ok := rules[request.NamespaceValue(ctx)][uid]
			if !ok {
				return config.RuleRef{}, false, nil
			}
			return config.RuleRef{UID: uid, FolderUID: folderUID}, true, nil
		},
	}

	alert, err := validation.NewBuilder[*model.AlertRule]().
		OnWrite(alertrule.ValidateWrite(cfg)).
		OnDelete(alertrule.ValidateDelete(cfg)).
		Build()
	require.NoError(t, err)
	record, err := validation.NewBuilder[*model.RecordingRule]().
		OnWrite(recordingrule.ValidateWrite(cfg)).
		OnDelete(recordingrule.ValidateDelete(cfg)).
		Build()
	require.NoError(t, err)
	sequence, err := validation.NewBuilder[*model.RuleSequence]().
		OnWrite(rulesequence.ValidateWrite(cfg)).
		Build()
	require.NoError(t, err)

	return &harness{idx: idx, alert: alert, record: record, sequence: sequence}
}

// watchAdd is the informer add/sync delivery: the event context is not the
// user's request, and the object carries its namespace.
func watchAdd(t *testing.T, idx *rulesequence.MembershipIndex, seq *model.RuleSequence) {
	t.Helper()
	require.NoError(t, idx.Add(context.Background(), seq))
}

func watchUpdate(t *testing.T, idx *rulesequence.MembershipIndex, oldSeq, newSeq *model.RuleSequence) {
	t.Helper()
	require.NoError(t, idx.Update(context.Background(), oldSeq, newSeq))
}

func watchDelete(t *testing.T, idx *rulesequence.MembershipIndex, seq *model.RuleSequence) {
	t.Helper()
	require.NoError(t, idx.Delete(context.Background(), seq))
}

func sequence(ns, name string, recordingUIDs, alertingUIDs []string) *model.RuleSequence {
	seq := model.NewRuleSequence()
	seq.Name = name
	seq.Namespace = ns
	seq.Annotations = map[string]string{model.FolderAnnotationKey: folderA}
	seq.Spec.Trigger.Interval = model.RuleSequencePromDuration("60s")
	seq.Spec.RecordingRules = make([]model.RuleSequenceRuleRef, len(recordingUIDs))
	for i, uid := range recordingUIDs {
		seq.Spec.RecordingRules[i] = model.RuleSequenceRuleRef{Name: model.RuleSequenceRuleUID(uid)}
	}
	seq.Spec.AlertingRules = make([]model.RuleSequenceRuleRef, len(alertingUIDs))
	for i, uid := range alertingUIDs {
		seq.Spec.AlertingRules[i] = model.RuleSequenceRuleRef{Name: model.RuleSequenceRuleUID(uid)}
	}
	return seq
}

func alertRule(ns, name, folderUID string) *model.AlertRule {
	r := &model.AlertRule{}
	r.SetGroupVersionKind(model.AlertRuleKind().GroupVersionKind())
	r.Name = name
	r.Namespace = ns
	r.Annotations = map[string]string{model.FolderAnnotationKey: folderUID}
	r.Labels = map[string]string{}
	r.Spec = model.AlertRuleSpec{
		Title:        "high cpu",
		Trigger:      model.AlertRuleIntervalTrigger{Interval: model.AlertRulePromDuration("60s")},
		Expressions:  model.AlertRuleExpressionMap{"A": model.AlertRuleExpression{Model: map[string]any{"expr": "1"}, Source: new(true)}},
		NoDataState:  model.DefaultNoDataState,
		ExecErrState: model.DefaultExecErrState,
	}
	return r
}

func recordingRule(ns, name, folderUID string) *model.RecordingRule {
	r := &model.RecordingRule{}
	r.SetGroupVersionKind(model.RecordingRuleKind().GroupVersionKind())
	r.Name = name
	r.Namespace = ns
	r.Annotations = map[string]string{model.FolderAnnotationKey: folderUID}
	r.Labels = map[string]string{}
	r.Spec = model.RecordingRuleSpec{
		Title:               "shared record",
		Trigger:             model.RecordingRuleIntervalTrigger{Interval: model.RecordingRulePromDuration("60s")},
		Expressions:         model.RecordingRuleExpressionMap{"A": model.RecordingRuleExpression{Model: map[string]any{"expr": "1"}, Source: new(true)}},
		Metric:              "test_metric",
		TargetDatasourceUID: "ds1",
	}
	return r
}

func membership(t *testing.T, idx *rulesequence.MembershipIndex, ns, uid string) config.RuleSequenceMembership {
	t.Helper()
	got, err := idx.Resolve(nsCtx(ns), []string{uid})
	require.NoError(t, err)
	return got[uid]
}

func (h *harness) admitSequence(t *testing.T, ns string, seq *model.RuleSequence, action resource.AdmissionAction, old *model.RuleSequence) error {
	t.Helper()
	return h.sequence.Validate(nsCtx(ns), &appsdk.AdmissionRequest{
		Action:    action,
		Object:    seq,
		OldObject: old,
	})
}

// plantAttackerSequence is the attacker's admitted create plus the informer add
// that follows a successful create. The sequence references UIDs the attacker
// can create in their own organization.
func (h *harness) plantAttackerSequence(t *testing.T, name string, recordingUIDs, alertingUIDs []string) *model.RuleSequence {
	t.Helper()
	seq := sequence(nsAttacker, name, recordingUIDs, alertingUIDs)
	require.NoError(t, h.admitSequence(t, nsAttacker, seq, resource.AdmissionActionCreate, nil))
	watchAdd(t, h.idx, seq)
	return seq
}

func TestCrossOrgMembership_ResolveStaysInsideRequestNamespace(t *testing.T) {
	h := newHarness(t)
	watchAdd(t, h.idx, sequence(nsVictim, "victim-seq", []string{victimOnlyUID}, []string{sharedAlertUID}))
	watchAdd(t, h.idx, sequence(nsAttacker, "attacker-seq", []string{attackerOnlyUID}, []string{sharedAlertUID}))

	victimShared := membership(t, h.idx, nsVictim, sharedAlertUID)
	require.True(t, victimShared.Found, "victim namespace must see its own sequence")
	require.Equal(t, "victim-seq", victimShared.SequenceUID)

	attackerShared := membership(t, h.idx, nsAttacker, sharedAlertUID)
	require.True(t, attackerShared.Found, "attacker namespace must see its own sequence")
	require.Equal(t, "attacker-seq", attackerShared.SequenceUID)

	require.False(t, membership(t, h.idx, nsVictim, attackerOnlyUID).Found, "another organization's rule UID must not be a member here")
	require.False(t, membership(t, h.idx, nsAttacker, victimOnlyUID).Found, "another organization's rule UID must not be a member here")
}

func TestCrossOrgMembership_OtherOrgSequenceDoesNotBlockAlertDelete(t *testing.T) {
	h := newHarness(t)
	h.plantAttackerSequence(t, "attacker-seq", []string{attackerOnlyUID}, []string{sharedAlertUID})

	err := h.alert.Validate(nsCtx(nsVictim), &appsdk.AdmissionRequest{
		Action:    resource.AdmissionActionDelete,
		OldObject: alertRule(nsVictim, sharedAlertUID, folderA),
	})
	require.NoError(t, err)
}

func TestCrossOrgMembership_OtherOrgSequenceDoesNotBlockRecordingDelete(t *testing.T) {
	h := newHarness(t)
	h.plantAttackerSequence(t, "attacker-seq", []string{sharedRecordingUID}, nil)

	err := h.record.Validate(nsCtx(nsVictim), &appsdk.AdmissionRequest{
		Action:    resource.AdmissionActionDelete,
		OldObject: recordingRule(nsVictim, sharedRecordingUID, folderA),
	})
	require.NoError(t, err)
}

func TestCrossOrgMembership_OtherOrgSequenceDoesNotBlockAlertFolderMove(t *testing.T) {
	h := newHarness(t)
	h.plantAttackerSequence(t, "attacker-seq", []string{attackerOnlyUID}, []string{sharedAlertUID})

	oldRule := alertRule(nsVictim, sharedAlertUID, folderA)
	moved := alertRule(nsVictim, sharedAlertUID, folderB)
	err := h.alert.Validate(nsCtx(nsVictim), &appsdk.AdmissionRequest{
		Action:    resource.AdmissionActionUpdate,
		Object:    moved,
		OldObject: oldRule,
	})
	require.NoError(t, err)
}

func TestCrossOrgMembership_OtherOrgSequenceDoesNotBlockRecordingFolderMove(t *testing.T) {
	h := newHarness(t)
	h.plantAttackerSequence(t, "attacker-seq", []string{sharedRecordingUID}, nil)

	oldRule := recordingRule(nsVictim, sharedRecordingUID, folderA)
	moved := recordingRule(nsVictim, sharedRecordingUID, folderB)
	err := h.record.Validate(nsCtx(nsVictim), &appsdk.AdmissionRequest{
		Action:    resource.AdmissionActionUpdate,
		Object:    moved,
		OldObject: oldRule,
	})
	require.NoError(t, err)
}

func TestCrossOrgMembership_OtherOrgSequenceDoesNotBlockSequenceCreate(t *testing.T) {
	h := newHarness(t)
	h.plantAttackerSequence(t, "attacker-seq", []string{attackerOnlyUID}, []string{sharedAlertUID})

	victimSeq := sequence(nsVictim, "victim-seq", []string{victimOnlyUID}, []string{sharedAlertUID})
	require.NoError(t, h.admitSequence(t, nsVictim, victimSeq, resource.AdmissionActionCreate, nil))
}

func TestCrossOrgMembership_OtherOrgSequenceDoesNotBlockSequenceUpdate(t *testing.T) {
	h := newHarness(t)
	original := sequence(nsVictim, "victim-seq", []string{victimOnlyUID}, []string{sharedAlertUID})
	require.NoError(t, h.admitSequence(t, nsVictim, original, resource.AdmissionActionCreate, nil))
	watchAdd(t, h.idx, original)

	// The other organization claims the same alert UID under a different sequence name.
	h.plantAttackerSequence(t, "attacker-seq", []string{attackerOnlyUID}, []string{sharedAlertUID})

	updated := sequence(nsVictim, "victim-seq", []string{victimOnlyUID}, []string{sharedAlertUID})
	require.NoError(t, h.admitSequence(t, nsVictim, updated, resource.AdmissionActionUpdate, original))
}

func TestCrossOrgMembership_DeletingOtherOrgSequenceKeepsVictimProtection(t *testing.T) {
	h := newHarness(t)
	victimSeq := sequence(nsVictim, "victim-seq", []string{victimOnlyUID}, []string{sharedAlertUID})
	require.NoError(t, h.admitSequence(t, nsVictim, victimSeq, resource.AdmissionActionCreate, nil))
	watchAdd(t, h.idx, victimSeq)

	// Same rule UID, different sequence name. Creating this has to be allowed in
	// the attacker's organization; deleting it must not drop the victim's membership.
	attackerSeq := h.plantAttackerSequence(t, "attacker-seq", []string{attackerOnlyUID}, []string{sharedAlertUID})
	watchDelete(t, h.idx, attackerSeq)

	err := h.alert.Validate(nsCtx(nsVictim), &appsdk.AdmissionRequest{
		Action:    resource.AdmissionActionDelete,
		OldObject: alertRule(nsVictim, sharedAlertUID, folderA),
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "victim-seq")
	require.NotContains(t, err.Error(), "attacker-seq")

	recErr := h.record.Validate(nsCtx(nsVictim), &appsdk.AdmissionRequest{
		Action:    resource.AdmissionActionDelete,
		OldObject: recordingRule(nsVictim, victimOnlyUID, folderA),
	})
	require.Error(t, recErr)
	require.ErrorContains(t, recErr, "victim-seq")
}

func TestCrossOrgMembership_SameNameDeleteDoesNotClearOtherNamespace(t *testing.T) {
	h := newHarness(t)
	// Victim already sequences the shared UID under the name the attacker will reuse.
	// Admission compares sequence name only, so the attacker's create is not rejected
	// for belonging to another sequence of the same name.
	victimSeq := sequence(nsVictim, "shared", []string{sharedRecordingUID}, []string{sharedAlertUID})
	require.NoError(t, h.admitSequence(t, nsVictim, victimSeq, resource.AdmissionActionCreate, nil))
	watchAdd(t, h.idx, victimSeq)

	attackerSeq := h.plantAttackerSequence(t, "shared", []string{sharedRecordingUID}, []string{sharedAlertUID})
	watchDelete(t, h.idx, attackerSeq)

	err := h.alert.Validate(nsCtx(nsVictim), &appsdk.AdmissionRequest{
		Action:    resource.AdmissionActionDelete,
		OldObject: alertRule(nsVictim, sharedAlertUID, folderA),
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "shared")

	recErr := h.record.Validate(nsCtx(nsVictim), &appsdk.AdmissionRequest{
		Action:    resource.AdmissionActionDelete,
		OldObject: recordingRule(nsVictim, sharedRecordingUID, folderA),
	})
	require.Error(t, recErr)
	require.ErrorContains(t, recErr, "shared")

	// The attacker's own rule must not stay indexed after their sequence is gone.
	require.False(t, membership(t, h.idx, nsAttacker, sharedAlertUID).Found)
	require.False(t, membership(t, h.idx, nsAttacker, sharedRecordingUID).Found)
}

func TestCrossOrgMembership_SameNameDeleteWithDistinctUIDsDoesNotClearOtherNamespace(t *testing.T) {
	h := newHarness(t)
	// Informer re-list order can deliver the victim object after the attacker's.
	// Delete must remove only the object that was deleted, matched by namespace and name.
	attackerSeq := sequence(nsAttacker, "shared", []string{attackerOnlyUID}, nil)
	watchAdd(t, h.idx, attackerSeq)
	victimSeq := sequence(nsVictim, "shared", []string{victimOnlyUID}, nil)
	watchAdd(t, h.idx, victimSeq)

	watchDelete(t, h.idx, attackerSeq)

	require.True(t, membership(t, h.idx, nsVictim, victimOnlyUID).Found)
	require.Equal(t, "shared", membership(t, h.idx, nsVictim, victimOnlyUID).SequenceUID)
	require.False(t, membership(t, h.idx, nsAttacker, attackerOnlyUID).Found)

	err := h.alert.Validate(nsCtx(nsVictim), &appsdk.AdmissionRequest{
		Action:    resource.AdmissionActionDelete,
		OldObject: alertRule(nsVictim, victimOnlyUID, folderA),
	})
	// victimOnlyUID is a recording ref, so the alert object with that name is a
	// different kind, but both kinds share the membership index. Deleting the
	// alert must still see the victim sequence.
	require.Error(t, err)
	require.ErrorContains(t, err, "shared")
}

func TestCrossOrgMembership_SameNameUpdateDoesNotDropOtherNamespace(t *testing.T) {
	h := newHarness(t)
	attackerBefore := sequence(nsAttacker, "shared", []string{attackerOnlyUID}, nil)
	watchAdd(t, h.idx, attackerBefore)
	victimSeq := sequence(nsVictim, "shared", []string{victimOnlyUID}, nil)
	watchAdd(t, h.idx, victimSeq)

	attackerAfter := sequence(nsAttacker, "shared", []string{attackerOnlyUID}, []string{sharedAlertUID})
	watchUpdate(t, h.idx, attackerBefore, attackerAfter)

	require.True(t, membership(t, h.idx, nsVictim, victimOnlyUID).Found)
	require.Equal(t, "shared", membership(t, h.idx, nsVictim, victimOnlyUID).SequenceUID)

	attackerOwn := membership(t, h.idx, nsAttacker, attackerOnlyUID)
	require.True(t, attackerOwn.Found)
	require.Equal(t, "shared", attackerOwn.SequenceUID)

	// The UID the attacker added on update is theirs alone.
	require.False(t, membership(t, h.idx, nsVictim, sharedAlertUID).Found)
	require.True(t, membership(t, h.idx, nsAttacker, sharedAlertUID).Found)
}

func TestSameNamespaceSequenceStillBlocksDeleteAndMove(t *testing.T) {
	h := newHarness(t)
	watchAdd(t, h.idx, sequence(nsVictim, "victim-seq", []string{victimOnlyUID}, []string{sharedAlertUID}))

	err := h.alert.Validate(nsCtx(nsVictim), &appsdk.AdmissionRequest{
		Action:    resource.AdmissionActionDelete,
		OldObject: alertRule(nsVictim, sharedAlertUID, folderA),
	})
	require.ErrorContains(t, err, "victim-seq")

	oldRule := alertRule(nsVictim, sharedAlertUID, folderA)
	moved := alertRule(nsVictim, sharedAlertUID, folderB)
	moveErr := h.alert.Validate(nsCtx(nsVictim), &appsdk.AdmissionRequest{
		Action:    resource.AdmissionActionUpdate,
		Object:    moved,
		OldObject: oldRule,
	})
	require.ErrorContains(t, moveErr, "victim-seq")

	recErr := h.record.Validate(nsCtx(nsVictim), &appsdk.AdmissionRequest{
		Action:    resource.AdmissionActionDelete,
		OldObject: recordingRule(nsVictim, victimOnlyUID, folderA),
	})
	require.ErrorContains(t, recErr, "victim-seq")
}
