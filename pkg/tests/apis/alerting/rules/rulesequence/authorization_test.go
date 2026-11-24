package rulesequence

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"

	"github.com/grafana/grafana/apps/alerting/rules/pkg/apis/alerting/v0alpha1"
	folders "github.com/grafana/grafana/apps/folder/pkg/apis/folder/v1"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/folder"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/apis/alerting/rules/common"
	"github.com/grafana/grafana/pkg/util/testutil"
)

const (
	folderA = "folder-a"
	folderB = "folder-b"
	folderC = "folder-c"

	// 10000h is a positive multiple of the default 10s base interval, so the
	// current interval check accepts it. It is long enough that a sequence
	// member is effectively never evaluated.
	unboundedInterval = "10000h"
	allowedInterval   = "1m"
)

// TestIntegrationRuleSequenceFolderAuthorization is the spec for folder-scoped
// RuleSequence authorization. It fails while a caller who can write alert rules
// in one folder can create, update, patch, or delete sequences in other folders,
// list or watch sequences outside the folders they can read, or store a sequence
// whose interval is unbounded.
func TestIntegrationRuleSequenceFolderAuthorization(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	ctx := context.Background()
	helper := common.GetTestHelperWithRuleSequences(t)

	createFolder(t, helper, folderA, "Folder A")
	createFolder(t, helper, folderB, "Folder B")
	createFolder(t, helper, folderC, "Folder C")

	// Edit on A is the folder-scoped alert.rules create/update/delete grant.
	// View on B is folders:read plus alert.rules:read. C is invisible.
	// RoleNone keeps the fixed Viewer grant (alert.rules:read on folders:uid:*)
	// out of the list/watch assertions.
	attacker := helper.CreateUser("seq-folder-editor", apis.Org1, org.RoleNone, []resourcepermissions.SetResourcePermissionCommand{
		folderScopedPermission(folderA, append(folderEditActions(), accesscontrol.ActionAlertingRuleRead, accesscontrol.ActionAlertingRuleCreate, accesscontrol.ActionAlertingRuleUpdate, accesscontrol.ActionAlertingRuleDelete)...),
		folderScopedPermission(folderB, append(folderViewActions(), accesscontrol.ActionAlertingRuleRead)...),
	})
	// The reported actor: an org Viewer with Edit on A and View on B.
	viewer := helper.CreateUser("seq-org-viewer", apis.Org1, org.RoleViewer, []resourcepermissions.SetResourcePermissionCommand{
		folderScopedPermission(folderA, append(folderEditActions(), accesscontrol.ActionAlertingRuleRead, accesscontrol.ActionAlertingRuleCreate, accesscontrol.ActionAlertingRuleUpdate, accesscontrol.ActionAlertingRuleDelete)...),
		folderScopedPermission(folderB, append(folderViewActions(), accesscontrol.ActionAlertingRuleRead)...),
	})

	adminSeq := common.NewRuleSequenceClient(t, helper.Org1.Admin)
	attackerSeq := common.NewRuleSequenceClient(t, attacker)
	viewerSeq := common.NewRuleSequenceClient(t, viewer)
	adminRules := common.NewRecordingRuleClient(t, helper.Org1.Admin)
	adminAlerts := common.NewAlertRuleClient(t, helper.Org1.Admin)

	recA := createRecordingRule(t, adminRules, "rec-a", folderA)
	recB := createRecordingRule(t, adminRules, "rec-b", folderB)
	recC := createRecordingRule(t, adminRules, "rec-c", folderC)
	alertB := createAlertRule(t, adminAlerts, "alert-b", folderB)
	// Rules that no sequence owns yet. Create attempts must target these so a
	// rejection is not the membership validator refusing a rule that is already claimed.
	recAOwn := createRecordingRule(t, adminRules, "rec-a-own", folderA)
	recASwap := createRecordingRule(t, adminRules, "rec-a-swap", folderA)
	recAInterval := createRecordingRule(t, adminRules, "rec-a-interval", folderA)
	recBAttack := createRecordingRule(t, adminRules, "rec-b-attack", folderB)
	alertBAttack := createAlertRule(t, adminAlerts, "alert-b-attack", folderB)
	recBViewer := createRecordingRule(t, adminRules, "rec-b-viewer", folderB)
	recCAttack := createRecordingRule(t, adminRules, "rec-c-attack", folderC)
	recBLock := createRecordingRule(t, adminRules, "rec-b-lock", folderB)

	attackerFolders := common.NewFolderClient(t, attacker)
	_, err := attackerFolders.Get(ctx, folderB, metav1.GetOptions{})
	require.NoError(t, err, "precondition: caller can read folder B")
	_, err = attackerFolders.Get(ctx, folderC, metav1.GetOptions{})
	require.Error(t, err, "precondition: caller cannot read folder C")

	// Sequences an admin is allowed to store. seq-a is in a folder the caller can write.
	seqA := mustCreateSequence(t, adminSeq, newSequence("seq-a", folderA, recA, allowedInterval))
	seqB := mustCreateSequence(t, adminSeq, newSequence("seq-b", folderB, recB, allowedInterval, alertB))
	seqC := mustCreateSequence(t, adminSeq, newSequence("seq-c", folderC, recC, allowedInterval))

	t.Run("caller can write a sequence in a folder they can write rules in", func(t *testing.T) {
		created, err := attackerSeq.Create(ctx, newSequence("seq-own", folderA, recAOwn, allowedInterval), metav1.CreateOptions{})
		require.NoError(t, err)
		require.Equal(t, folderA, created.Annotations[v0alpha1.FolderAnnotationKey])
		require.Equal(t, allowedInterval, string(created.Spec.Trigger.Interval))
	})

	t.Run("list hides sequences in folders the caller cannot read", func(t *testing.T) {
		list, err := attackerSeq.List(ctx, metav1.ListOptions{})
		require.NoError(t, err)
		names := sequenceNames(list)
		require.Contains(t, names, seqA.Name)
		require.Contains(t, names, seqB.Name)
		require.NotContains(t, names, seqC.Name)
	})

	t.Run("get hides a sequence in a folder the caller cannot read", func(t *testing.T) {
		_, err := attackerSeq.Get(ctx, seqA.Name, metav1.GetOptions{})
		require.NoError(t, err)
		_, err = attackerSeq.Get(ctx, seqB.Name, metav1.GetOptions{})
		require.NoError(t, err, "view on folder B includes alert.rules:read there")
		_, err = attackerSeq.Get(ctx, seqC.Name, metav1.GetOptions{})
		requireClientRejection(t, err)
	})

	t.Run("watch hides sequences in folders the caller cannot read", func(t *testing.T) {
		dyn := dynamicClient(t, attacker)
		watcher, err := dyn.Resource(v0alpha1.RuleSequenceKind().GroupVersionResource()).Namespace("default").
			Watch(ctx, metav1.ListOptions{})
		require.NoError(t, err)
		defer watcher.Stop()

		seenAllowed := false
		seenHidden := false
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		armed := false
		for {
			select {
			case ev, ok := <-watcher.ResultChan():
				if !ok {
					require.True(t, seenAllowed, "watch closed before a readable sequence was delivered")
					require.False(t, seenHidden)
					return
				}
				if ev.Type == watch.Error {
					t.Fatalf("watch error: %#v", ev.Object)
				}
				name := objectName(ev.Object)
				if name == seqA.Name || name == seqB.Name {
					seenAllowed = true
				}
				if name == seqC.Name {
					seenHidden = true
				}
				if seenHidden {
					t.Fatal("watch delivered a sequence in a folder the caller cannot read")
				}
				if seenAllowed && !armed {
					armed = true
					timer.Reset(500 * time.Millisecond)
				}
			case <-timer.C:
				if !seenAllowed {
					t.Fatal("watch did not deliver a sequence in a readable folder")
				}
				return
			}
		}
	})

	t.Run("caller cannot create a sequence in a folder they can only view", func(t *testing.T) {
		const name = "seq-create-b"
		_, err := attackerSeq.Create(ctx, newSequence(name, folderB, recBAttack, allowedInterval, alertBAttack), metav1.CreateOptions{})
		requireAuthorizationRejection(t, err)
		requireSequenceAbsent(t, adminSeq, name)
	})

	t.Run("org viewer with edit on one folder cannot create a sequence in another visible folder", func(t *testing.T) {
		const name = "seq-viewer-create-b"
		_, err := viewerSeq.Create(ctx, newSequence(name, folderB, recBViewer, allowedInterval), metav1.CreateOptions{})
		requireAuthorizationRejection(t, err)
		requireSequenceAbsent(t, adminSeq, name)
	})

	t.Run("caller cannot create a sequence in a folder they cannot see", func(t *testing.T) {
		// The folder validator already rejects this create, because the caller
		// cannot read folder C. Kept so a later change does not start allowing it.
		const name = "seq-create-c"
		_, err := attackerSeq.Create(ctx, newSequence(name, folderC, recCAttack, allowedInterval), metav1.CreateOptions{})
		requireClientRejection(t, err)
		requireSequenceAbsent(t, adminSeq, name)
	})

	t.Run("rejected create does not keep the referenced alert rule from being moved or deleted", func(t *testing.T) {
		movable := createAlertRule(t, adminAlerts, "alert-movable", folderB)
		const name = "seq-lock"
		_, err := attackerSeq.Create(ctx, newSequence(name, folderB, recBLock, unboundedInterval, movable), metav1.CreateOptions{})
		requireAuthorizationRejection(t, err)
		requireSequenceAbsent(t, adminSeq, name)

		got, err := adminAlerts.Get(ctx, movable, metav1.GetOptions{})
		require.NoError(t, err)
		moved := got.Copy().(*v0alpha1.AlertRule)
		if moved.Annotations == nil {
			moved.Annotations = map[string]string{}
		}
		moved.Annotations[v0alpha1.FolderAnnotationKey] = folderA
		_, err = adminAlerts.Update(ctx, moved, metav1.UpdateOptions{})
		require.NoError(t, err, "owner must still be able to move a rule that an unauthorized sequence tried to claim")

		err = adminAlerts.Delete(ctx, movable, metav1.DeleteOptions{})
		require.NoError(t, err, "owner must still be able to delete a rule that an unauthorized sequence tried to claim")
	})

	t.Run("authorized sequence still blocks delete and move of its rules", func(t *testing.T) {
		// seq-b was stored by an admin and references alert-b. The membership
		// index is watch-backed, so wait until admission observes it.
		require.Eventually(t, func() bool {
			err := adminAlerts.Delete(ctx, alertB, metav1.DeleteOptions{})
			return err != nil && !apierrors.IsNotFound(err)
		}, 15*time.Second, 200*time.Millisecond, "an authorized sequence must reject deletion of its alert rule")

		got, err := adminAlerts.Get(ctx, alertB, metav1.GetOptions{})
		require.NoError(t, err)
		moved := got.Copy().(*v0alpha1.AlertRule)
		moved.Annotations[v0alpha1.FolderAnnotationKey] = folderA
		_, err = adminAlerts.Update(ctx, moved, metav1.UpdateOptions{})
		require.Error(t, err, "an authorized sequence must reject moving its alert rule")
		still, err := adminAlerts.Get(ctx, alertB, metav1.GetOptions{})
		require.NoError(t, err)
		require.Equal(t, folderB, still.Annotations[v0alpha1.FolderAnnotationKey])
	})

	t.Run("caller cannot update a sequence in a folder they can only view", func(t *testing.T) {
		current, err := adminSeq.Get(ctx, seqB.Name, metav1.GetOptions{})
		require.NoError(t, err)
		updated := current.Copy().(*v0alpha1.RuleSequence)
		updated.Spec.Trigger.Interval = "2m"
		_, err = attackerSeq.Update(ctx, updated, metav1.UpdateOptions{})
		requireClientRejection(t, err)
		requireSequenceUnchanged(t, adminSeq, seqB)
	})

	t.Run("caller cannot patch a sequence in a folder they can only view", func(t *testing.T) {
		_, err := attackerSeq.Patch(ctx, seqB.Name, types.JSONPatchType,
			[]byte(`[{"op":"replace","path":"/spec/trigger/interval","value":"2m"}]`),
			metav1.PatchOptions{})
		requireClientRejection(t, err)
		requireSequenceUnchanged(t, adminSeq, seqB)
	})

	t.Run("update is authorized against the stored folder, not a folder swapped in on the request", func(t *testing.T) {
		current, err := adminSeq.Get(ctx, seqC.Name, metav1.GetOptions{})
		require.NoError(t, err)
		swapped := current.Copy().(*v0alpha1.RuleSequence)
		swapped.Annotations[v0alpha1.FolderAnnotationKey] = folderA
		swapped.Spec.RecordingRules = []v0alpha1.RuleSequenceRuleRef{{Name: v0alpha1.RuleSequenceRuleUID(recASwap)}}
		swapped.Spec.AlertingRules = nil
		swapped.Spec.Trigger.Interval = allowedInterval
		_, err = attackerSeq.Update(ctx, swapped, metav1.UpdateOptions{})
		requireClientRejection(t, err)
		requireSequenceUnchanged(t, adminSeq, seqC)
	})

	t.Run("caller cannot delete a sequence in a folder they cannot see", func(t *testing.T) {
		err := attackerSeq.Delete(ctx, seqC.Name, metav1.DeleteOptions{})
		requireClientRejection(t, err)
		requireSequenceUnchanged(t, adminSeq, seqC)
	})

	t.Run("caller cannot delete a sequence in a folder they can only view", func(t *testing.T) {
		err := attackerSeq.Delete(ctx, seqB.Name, metav1.DeleteOptions{})
		requireClientRejection(t, err)
		requireSequenceUnchanged(t, adminSeq, seqB)
	})

	t.Run("sequence interval has an upper bound", func(t *testing.T) {
		const name = "seq-unbounded"
		_, err := adminSeq.Create(ctx, newSequence(name, folderA, recAInterval, unboundedInterval), metav1.CreateOptions{})
		requireClientRejection(t, err)
		require.NotContains(t, err.Error(), "already belongs")
		requireSequenceAbsent(t, adminSeq, name)
	})

	t.Run("delete collection does not remove sequences outside folders the caller can write", func(t *testing.T) {
		recBDC := createRecordingRule(t, adminRules, "rec-b-dc", folderB)
		recCDC := createRecordingRule(t, adminRules, "rec-c-dc", folderC)
		keptB := mustCreateSequence(t, adminSeq, newSequence("seq-dc-b", folderB, recBDC, allowedInterval))
		keptC := mustCreateSequence(t, adminSeq, newSequence("seq-dc-c", folderC, recCDC, allowedInterval))
		dyn := dynamicClient(t, attacker)
		err := dyn.Resource(v0alpha1.RuleSequenceKind().GroupVersionResource()).Namespace("default").
			DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
		if err != nil {
			requireClientRejection(t, err)
		}
		requireSequenceUnchanged(t, adminSeq, keptB)
		requireSequenceUnchanged(t, adminSeq, keptC)
	})
}

func folderEditActions() []string {
	return []string{folder.ActionFoldersRead, folder.ActionFoldersWrite}
}

func folderViewActions() []string {
	return []string{folder.ActionFoldersRead}
}

func folderScopedPermission(folderUID string, actions ...string) resourcepermissions.SetResourcePermissionCommand {
	return resourcepermissions.SetResourcePermissionCommand{
		Actions:           actions,
		Resource:          "folders",
		ResourceAttribute: "uid",
		ResourceID:        folderUID,
	}
}

func createFolder(t *testing.T, helper *apis.K8sTestHelper, uid, title string) {
	t.Helper()
	client := common.NewFolderClient(t, helper.Org1.Admin)
	_, err := client.Create(context.Background(), &folders.Folder{
		ObjectMeta: metav1.ObjectMeta{Name: uid, Namespace: "default"},
		Spec:       folders.FolderSpec{Title: title},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
}

func createRecordingRule(t *testing.T, client *apis.TypedClient[v0alpha1.RecordingRule, v0alpha1.RecordingRuleList], name, folderUID string) string {
	t.Helper()
	rule := ngmodels.RuleGen.With(
		ngmodels.RuleMuts.WithUniqueTitle(),
		ngmodels.RuleMuts.WithNamespaceUID(folderUID),
		ngmodels.RuleMuts.WithGroupName("seq-group"),
		ngmodels.RuleMuts.WithAllRecordingRules(),
		ngmodels.RuleMuts.WithIntervalMatching(10*time.Second),
	).Generate()

	created, err := client.Create(context.Background(), &v0alpha1.RecordingRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Annotations: map[string]string{
				v0alpha1.FolderAnnotationKey: folderUID,
			},
		},
		Spec: v0alpha1.RecordingRuleSpec{
			Title:               rule.Title,
			Metric:              v0alpha1.RecordingRuleMetricName(rule.Record.Metric),
			TargetDatasourceUID: v0alpha1.RecordingRuleDatasourceUID(rule.Record.TargetDatasourceUID),
			Expressions: v0alpha1.RecordingRuleExpressionMap{
				"A": {
					QueryType:     new(rule.Data[0].QueryType),
					DatasourceUID: new(v0alpha1.RecordingRuleDatasourceUID(rule.Data[0].DatasourceUID)),
					Model:         rule.Data[0].Model,
					Source:        new(true),
					RelativeTimeRange: &v0alpha1.RecordingRuleRelativeTimeRange{
						From: v0alpha1.RecordingRulePromDurationWMillis("5m"),
						To:   v0alpha1.RecordingRulePromDurationWMillis("0s"),
					},
				},
			},
			Trigger: v0alpha1.RecordingRuleIntervalTrigger{
				Interval: v0alpha1.RecordingRulePromDuration(fmt.Sprintf("%ds", rule.IntervalSeconds)),
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, name, created.Name)
	return created.Name
}

func createAlertRule(t *testing.T, client *apis.TypedClient[v0alpha1.AlertRule, v0alpha1.AlertRuleList], name, folderUID string) string {
	t.Helper()
	rule := ngmodels.RuleGen.With(
		ngmodels.RuleMuts.WithUniqueTitle(),
		ngmodels.RuleMuts.WithNamespaceUID(folderUID),
		ngmodels.RuleMuts.WithGroupName("seq-group"),
		ngmodels.RuleMuts.WithIntervalMatching(10*time.Second),
	).Generate()

	created, err := client.Create(context.Background(), &v0alpha1.AlertRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Annotations: map[string]string{
				v0alpha1.FolderAnnotationKey: folderUID,
			},
		},
		Spec: v0alpha1.AlertRuleSpec{
			Title: rule.Title,
			Expressions: v0alpha1.AlertRuleExpressionMap{
				"A": {
					QueryType:     new(rule.Data[0].QueryType),
					DatasourceUID: new(v0alpha1.AlertRuleDatasourceUID(rule.Data[0].DatasourceUID)),
					Model:         rule.Data[0].Model,
					Source:        new(true),
					RelativeTimeRange: &v0alpha1.AlertRuleRelativeTimeRange{
						From: v0alpha1.AlertRulePromDurationWMillis("5m"),
						To:   v0alpha1.AlertRulePromDurationWMillis("0s"),
					},
				},
			},
			Trigger: v0alpha1.AlertRuleIntervalTrigger{
				Interval: v0alpha1.AlertRulePromDuration(fmt.Sprintf("%ds", rule.IntervalSeconds)),
			},
			NoDataState:  common.ToK8sNoDataState(rule.NoDataState),
			ExecErrState: common.ToK8sExecErrState(rule.ExecErrState),
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, name, created.Name)
	return created.Name
}

func newSequence(name, folderUID, recordingRule, interval string, alertingRules ...string) *v0alpha1.RuleSequence {
	alerting := make([]v0alpha1.RuleSequenceRuleRef, 0, len(alertingRules))
	for _, rule := range alertingRules {
		alerting = append(alerting, v0alpha1.RuleSequenceRuleRef{Name: v0alpha1.RuleSequenceRuleUID(rule)})
	}
	return &v0alpha1.RuleSequence{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Annotations: map[string]string{
				v0alpha1.FolderAnnotationKey: folderUID,
			},
		},
		Spec: v0alpha1.RuleSequenceSpec{
			Trigger: v0alpha1.RuleSequenceIntervalTrigger{
				Interval: v0alpha1.RuleSequencePromDuration(interval),
			},
			RecordingRules: []v0alpha1.RuleSequenceRuleRef{
				{Name: v0alpha1.RuleSequenceRuleUID(recordingRule)},
			},
			AlertingRules: alerting,
		},
	}
}

func mustCreateSequence(t *testing.T, client *apis.TypedClient[v0alpha1.RuleSequence, v0alpha1.RuleSequenceList], seq *v0alpha1.RuleSequence) *v0alpha1.RuleSequence {
	t.Helper()
	created, err := client.Create(context.Background(), seq, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, seq.Name, created.Name)
	require.Equal(t, seq.Annotations[v0alpha1.FolderAnnotationKey], created.Annotations[v0alpha1.FolderAnnotationKey])
	return created
}

func requireClientRejection(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var status apierrors.APIStatus
	require.ErrorAs(t, err, &status, "expected an API status error, got %v", err)
	code := int(status.Status().Code)
	require.GreaterOrEqual(t, code, 400, "expected a client rejection, got %v", err)
	require.Less(t, code, 500, "expected a client rejection, got %v", err)
}

// requireAuthorizationRejection rejects a write that failed for a reason other
// than the caller's folder scope, such as a rule already belonging to a sequence.
func requireAuthorizationRejection(t *testing.T, err error) {
	t.Helper()
	requireClientRejection(t, err)
	require.NotContains(t, err.Error(), "already belongs")
	require.NotContains(t, err.Error(), "does not exist")
	require.NotContains(t, err.Error(), "same folder")
}

func requireSequenceAbsent(t *testing.T, client *apis.TypedClient[v0alpha1.RuleSequence, v0alpha1.RuleSequenceList], name string) {
	t.Helper()
	_, err := client.Get(context.Background(), name, metav1.GetOptions{})
	require.Truef(t, apierrors.IsNotFound(err), "sequence %s must not be stored, get returned %v", name, err)
}

func requireSequenceUnchanged(t *testing.T, client *apis.TypedClient[v0alpha1.RuleSequence, v0alpha1.RuleSequenceList], original *v0alpha1.RuleSequence) {
	t.Helper()
	got, err := client.Get(context.Background(), original.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, original.Annotations[v0alpha1.FolderAnnotationKey], got.Annotations[v0alpha1.FolderAnnotationKey])
	require.Equal(t, string(original.Spec.Trigger.Interval), string(got.Spec.Trigger.Interval))
	require.Equal(t, ruleRefNames(original.Spec.RecordingRules), ruleRefNames(got.Spec.RecordingRules))
	require.Equal(t, ruleRefNames(original.Spec.AlertingRules), ruleRefNames(got.Spec.AlertingRules))
}

func ruleRefNames(refs []v0alpha1.RuleSequenceRuleRef) []string {
	names := make([]string, len(refs))
	for i, ref := range refs {
		names[i] = string(ref.Name)
	}
	return names
}

func sequenceNames(list *v0alpha1.RuleSequenceList) []string {
	names := make([]string, len(list.Items))
	for i := range list.Items {
		names[i] = list.Items[i].Name
	}
	return names
}

func dynamicClient(t *testing.T, user apis.User) dynamic.Interface {
	t.Helper()
	client, err := dynamic.NewForConfig(user.NewRestConfig())
	require.NoError(t, err)
	return client
}

func objectName(obj interface{}) string {
	switch o := obj.(type) {
	case *unstructured.Unstructured:
		return o.GetName()
	default:
		return ""
	}
}
