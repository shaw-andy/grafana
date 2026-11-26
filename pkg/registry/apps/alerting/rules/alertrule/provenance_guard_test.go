package alertrule

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	appsdk "github.com/grafana/grafana-app-sdk/app"
	sdkresource "github.com/grafana/grafana-app-sdk/resource"

	model "github.com/grafana/grafana/apps/alerting/rules/pkg/apis/alerting/v0alpha1"
	rulesManifest "github.com/grafana/grafana/apps/alerting/rules/pkg/apis/manifestdata"
	alertruleapp "github.com/grafana/grafana/apps/alerting/rules/pkg/app/alertrule"
	"github.com/grafana/grafana/apps/alerting/rules/pkg/app/config"
	recordingruleapp "github.com/grafana/grafana/apps/alerting/rules/pkg/app/recordingrule"
	appvalidation "github.com/grafana/grafana/apps/alerting/rules/pkg/app/validation"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	grafanarest "github.com/grafana/grafana/pkg/apiserver/rest"
	"github.com/grafana/grafana/pkg/expr"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/registry/apps/alerting/rules/recordingrule"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/folder/foldertest"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/provisioning"
	"github.com/grafana/grafana/pkg/services/ngalert/store"
	"github.com/grafana/grafana/pkg/services/ngalert/tests/fakes"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/quota"
	"github.com/grafana/grafana/pkg/services/user"
)

const (
	testFolderUID = "test-folder-uid"
	testOrgID     = int64(1)
	testNamespace = "default"
	siblingUID    = "sibling-unmanaged"
)

// editorPermissions matches the built-in Editor role for this API: folder-scoped
// alert-rule read and write, plus alert.provisioning.provenance:write. It does
// not include alert.provisioning:write, which only the Admin role receives.
func editorPermissions() map[string][]string {
	all := []string{folder.ScopeFoldersAll}
	return map[string][]string{
		ac.ActionAlertingRuleRead:              all,
		ac.ActionAlertingRuleCreate:            all,
		ac.ActionAlertingRuleUpdate:            all,
		ac.ActionAlertingRuleDelete:            all,
		folder.ActionFoldersRead:               all,
		ac.ActionAlertingProvisioningSetStatus: {},
	}
}

func editorUser() *user.SignedInUser {
	return &user.SignedInUser{
		OrgID:   testOrgID,
		UserUID: "editor-user",
		OrgRole: org.RoleEditor,
		Permissions: map[int64]map[string][]string{
			testOrgID: editorPermissions(),
		},
	}
}

func editorContext() context.Context {
	ctx := identity.WithRequester(context.Background(), editorUser())
	return genericapirequest.WithNamespace(ctx, testNamespace)
}

// permissionAccessControl evaluates the permission evaluator the authorizer
// builds against the caller's grants.
type permissionAccessControl struct{}

func (permissionAccessControl) Evaluate(_ context.Context, user identity.Requester, evaluator ac.Evaluator) (bool, error) {
	return evaluator.Evaluate(user.GetPermissions()), nil
}
func (permissionAccessControl) RegisterScopeAttributeResolver(string, ac.ScopeAttributeResolver) {
}
func (p permissionAccessControl) WithoutResolvers() ac.AccessControl  { return p }
func (permissionAccessControl) InvalidateResolverCache(int64, string) {}

// editorRuleAccess is the folder gate inside AlertRuleService. HasAccess uses
// the Editor grants, so org-wide provisioning read and write stay denied and
// the service takes the non-admin path. Authorize* succeeds for the folder the
// Editor can already edit.
type editorRuleAccess struct{}

func (editorRuleAccess) HasAccess(_ context.Context, user identity.Requester, evaluator ac.Evaluator) (bool, error) {
	return evaluator.Evaluate(user.GetPermissions()), nil
}
func (editorRuleAccess) AuthorizeAccessToRuleGroup(context.Context, identity.Requester, ngmodels.RulesGroup) error {
	return nil
}
func (editorRuleAccess) AuthorizeAccessInFolder(context.Context, identity.Requester, ngmodels.Namespaced) error {
	return nil
}
func (editorRuleAccess) AuthorizeRuleChanges(context.Context, identity.Requester, *store.GroupDelta) error {
	return nil
}
func (editorRuleAccess) HasAccessInFolder(context.Context, identity.Requester, ngmodels.Namespaced) (bool, error) {
	return true, nil
}

type allowQuota struct{}

func (allowQuota) CheckQuotaReached(context.Context, quota.TargetSrv, *quota.ScopeParameters) (bool, error) {
	return false, nil
}

// managerRecords keeps the manager kind and identity the SQL provenance store
// returns. The shared fake store collapses every manager to a coarse provenance
// and would hide a terraform or repo identity.
type managerRecords struct {
	mu      sync.Mutex
	records map[string]utils.ManagerProperties
}

func newManagerRecords() *managerRecords {
	return &managerRecords{records: map[string]utils.ManagerProperties{}}
}

func managerKey(org int64, id string) string {
	return fmt.Sprintf("%d/%s", org, id)
}

func (m *managerRecords) get(org int64, id string) utils.ManagerProperties {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.records[managerKey(org, id)]
}

func (m *managerRecords) set(org int64, id string, props utils.ManagerProperties) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[managerKey(org, id)] = props
}

func (m *managerRecords) del(org int64, id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, managerKey(org, id))
}

type ruleHarness struct {
	rules     *fakes.RuleStore
	managers  *managerRecords
	alerts    grafanarest.Storage
	recording grafanarest.Storage
	cfg       config.RuntimeConfig
	alertVal  admissionValidator
	recordVal admissionValidator
}

// admissionValidator is the app-sdk admission validator the apiserver runs
// before the storage write is committed.
type admissionValidator interface {
	Validate(context.Context, *appsdk.AdmissionRequest) error
}

func newHarness(t *testing.T) *ruleHarness {
	t.Helper()
	ruleStore := fakes.NewRuleStore(t)
	// Persist updates the service asks the store to save. The fake records the
	// call and returns without writing, which would hide a write that landed
	// before a later error.
	ruleStore.Hook = func(cmd any) error {
		updates, ok := cmd.([]ngmodels.UpdateRule)
		if !ok {
			return nil
		}
		for _, update := range updates {
			cp := update.New
			rules := ruleStore.Rules[cp.OrgID]
			for i, existing := range rules {
				if existing.UID == cp.UID {
					rules[i] = &cp
				}
			}
		}
		return nil
	}

	managers := newManagerRecords()
	provenance := fakes.NewFakeProvisioningStore()
	provenance.GetManagerPropertiesFunc = func(_ context.Context, o ngmodels.Provisionable, org int64) (utils.ManagerProperties, error) {
		return managers.get(org, o.ResourceID()), nil
	}
	provenance.SetManagerPropertiesFunc = func(_ context.Context, o ngmodels.Provisionable, org int64, props utils.ManagerProperties) error {
		managers.set(org, o.ResourceID(), props)
		return nil
	}
	provenance.DeleteProvenanceFunc = func(_ context.Context, o ngmodels.Provisionable, org int64) error {
		managers.del(org, o.ResourceID())
		return nil
	}
	provenance.GetAllManagerPropertiesFunc = func(_ context.Context, org int64, resourceType string) (map[string]utils.ManagerProperties, error) {
		managers.mu.Lock()
		defer managers.mu.Unlock()
		out := map[string]utils.ManagerProperties{}
		suffix := resourceType
		for key, props := range managers.records {
			prefix := fmt.Sprintf("%d/", org)
			if len(key) <= len(prefix) || key[:len(prefix)] != prefix {
				continue
			}
			id := key[len(prefix):]
			if id+suffix == id+resourceType {
				out[id] = props
			}
		}
		return out, nil
	}

	folderService := foldertest.NewFakeService()
	folderService.ExpectedFolder = &folder.Folder{UID: testFolderUID, Title: "Test Folder"}

	svc := provisioning.NewAlertRuleService(
		ruleStore, provenance, folderService, allowQuota{}, ruleStore,
		60, 10, 100, log.NewNopLogger(), nil, editorRuleAccess{}, nil,
	)
	cfg := config.RuntimeConfig{
		FolderValidator:        func(context.Context, string) (bool, error) { return true, nil },
		BaseEvaluationInterval: 10 * time.Second,
	}
	manifest := rulesManifest.LocalManifest().ManifestData
	alertValidator, err := appvalidation.NewBuilder[*model.AlertRule]().
		WithOpenAPIValidation(*manifest, schema.GroupKind{Group: model.AlertRuleKind().Group(), Kind: "AlertRule"}).
		OnWrite(alertruleapp.ValidateWrite(cfg)).
		OnDelete(alertruleapp.ValidateDelete(cfg)).
		Build()
	require.NoError(t, err)
	recordingValidator, err := appvalidation.NewBuilder[*model.RecordingRule]().
		WithOpenAPIValidation(*manifest, schema.GroupKind{Group: model.RecordingRuleKind().Group(), Kind: "RecordingRule"}).
		OnWrite(recordingruleapp.ValidateWrite(cfg)).
		OnDelete(recordingruleapp.ValidateDelete(cfg)).
		Build()
	require.NoError(t, err)

	return &ruleHarness{
		rules:     ruleStore,
		managers:  managers,
		alerts:    NewStorage(*svc, nsMapperForTest()),
		recording: recordingrule.NewStorage(*svc, nsMapperForTest()),
		cfg:       cfg,
		alertVal:  alertValidator,
		recordVal: recordingValidator,
	}
}

func (h *ruleHarness) seed(t *testing.T, rule *ngmodels.AlertRule, manager utils.ManagerProperties) {
	t.Helper()
	h.rules.PutRule(context.Background(), rule)
	if manager.Kind != utils.ManagerKindUnknown {
		h.managers.set(rule.OrgID, rule.UID, manager)
	}
}

func baseRule(uid, title string, recording bool) *ngmodels.AlertRule {
	rule := &ngmodels.AlertRule{
		ID:              1,
		OrgID:           testOrgID,
		GUID:            uid + "-guid",
		UID:             uid,
		Title:           title,
		NamespaceUID:    testFolderUID,
		RuleGroup:       "cpu",
		RuleGroupIndex:  1,
		Condition:       "A",
		Data:            []ngmodels.AlertQuery{exprQuery()},
		IntervalSeconds: 60,
		Version:         1,
		NoDataState:     ngmodels.NoData,
		ExecErrState:    ngmodels.ErrorErrState,
		Updated:         time.Now().UTC(),
	}
	if recording {
		rule.Record = &ngmodels.Record{
			Metric:              "recorded_metric",
			From:                "A",
			TargetDatasourceUID: "prometheus",
		}
	}
	return rule
}

func exprQuery() ngmodels.AlertQuery {
	return ngmodels.AlertQuery{
		RefID:         "A",
		DatasourceUID: expr.DatasourceUID,
		Model:         []byte(`{"type":"math","expression":"1","refId":"A"}`),
	}
}

func (h *ruleHarness) domainRule(t *testing.T, uid string) *ngmodels.AlertRule {
	t.Helper()
	got, err := h.rules.GetAlertRuleByUID(context.Background(), &ngmodels.GetAlertRuleByUIDQuery{OrgID: testOrgID, UID: uid})
	require.NoError(t, err)
	return got
}

var protectedManagers = []utils.ManagerProperties{
	{Kind: utils.ManagerKindClassicFP},                  //nolint:staticcheck
	{Kind: utils.ManagerKindClassicConvertedPrometheus}, //nolint:staticcheck
	{Kind: utils.ManagerKindTerraform, Identity: "workspace-1"},
	{Kind: utils.ManagerKindKubectl, Identity: "kubectl-client"},
	{Kind: utils.ManagerKindRepo, Identity: "git-sync"},
	{Kind: utils.ManagerKindClassicAPI}, //nolint:staticcheck
}

func TestKubernetesAuthorizerAllowsEditorWithoutProvisioningWrite(t *testing.T) {
	ctx := editorContext()
	acImpl := permissionAccessControl{}
	for _, verb := range []string{"get", "create", "update", "patch", "delete"} {
		t.Run("alertrules/"+verb, func(t *testing.T) {
			decision, _, err := Authorize(ctx, acImpl, authorizer.AttributesRecord{
				Verb:            verb,
				Resource:        ResourceInfo.GroupResource().Resource,
				APIGroup:        ResourceInfo.GroupResource().Group,
				ResourceRequest: true,
				Name:            "rule-uid",
			})
			require.NoError(t, err)
			require.Equal(t, authorizer.DecisionAllow, decision)
		})
		t.Run("recordingrules/"+verb, func(t *testing.T) {
			decision, _, err := recordingrule.Authorize(ctx, acImpl, authorizer.AttributesRecord{
				Verb:            verb,
				Resource:        recordingrule.ResourceInfo.GroupResource().Resource,
				APIGroup:        recordingrule.ResourceInfo.GroupResource().Group,
				ResourceRequest: true,
				Name:            "rule-uid",
			})
			require.NoError(t, err)
			require.Equal(t, authorizer.DecisionAllow, decision)
		})
	}
}

func TestUnManagedRuleUpdateStillSucceeds(t *testing.T) {
	h := newHarness(t)
	h.seed(t, baseRule("open-alert", "open alert", false), utils.ManagerProperties{})
	h.seed(t, baseRule("open-recording", "open recording", true), utils.ManagerProperties{})

	ctx := editorContext()
	h.putAlert(t, ctx, "open-alert", "open alert edited", true)
	require.Equal(t, "open alert edited", h.domainRule(t, "open-alert").Title)
	require.True(t, h.domainRule(t, "open-alert").IsPaused)
	require.Equal(t, utils.ManagerKindUnknown, h.managers.get(testOrgID, "open-alert").Kind)

	h.putRecording(t, ctx, "open-recording", "open recording edited", true)
	require.Equal(t, "open recording edited", h.domainRule(t, "open-recording").Title)
	require.True(t, h.domainRule(t, "open-recording").IsPaused)
	require.Equal(t, utils.ManagerKindUnknown, h.managers.get(testOrgID, "open-recording").Kind)
}

func TestProvisionedAlertRuleStorageRejectsEditorWrites(t *testing.T) {
	for _, manager := range protectedManagers {
		t.Run(string(manager.Kind), func(t *testing.T) {
			t.Run("put", func(t *testing.T) {
				h := newHarness(t)
				target := "file-alert"
				h.seed(t, baseRule(target, "original", false), manager)
				h.seed(t, baseRule(siblingUID, "sibling", false), utils.ManagerProperties{})

				ctx := editorContext()
				err := h.putAlert(t, ctx, target, "blunted", true)
				require.Error(t, err)
				h.requireUnchanged(t, target, "original", false, manager)
				h.requireUnchanged(t, siblingUID, "sibling", false, utils.ManagerProperties{})
			})

			t.Run("merge-patch", func(t *testing.T) {
				h := newHarness(t)
				target := "file-alert"
				h.seed(t, baseRule(target, "original", false), manager)
				h.seed(t, baseRule(siblingUID, "sibling", false), utils.ManagerProperties{})

				ctx := editorContext()
				err := h.patchAlert(t, ctx, target, []byte(`{"spec":{"paused":true,"title":"blunted"}}`))
				require.Error(t, err)
				h.requireUnchanged(t, target, "original", false, manager)
				h.requireUnchanged(t, siblingUID, "sibling", false, utils.ManagerProperties{})
			})

			t.Run("delete", func(t *testing.T) {
				h := newHarness(t)
				target := "file-alert"
				h.seed(t, baseRule(target, "original", false), manager)
				h.seed(t, baseRule(siblingUID, "sibling", false), utils.ManagerProperties{})

				ctx := editorContext()
				_, _, err := h.alerts.Delete(ctx, target, h.validateAlertDelete(t), &metav1.DeleteOptions{})
				require.Error(t, err)
				h.requireUnchanged(t, target, "original", false, manager)
				h.requireUnchanged(t, siblingUID, "sibling", false, utils.ManagerProperties{})
			})

			t.Run("create", func(t *testing.T) {
				h := newHarness(t)
				ctx := editorContext()
				obj := h.freshAlert("created-locked", "locked")
				h.stampManager(t, obj, manager)
				err := h.createAlert(t, ctx, obj)
				require.Error(t, err)
				_, getErr := h.rules.GetAlertRuleByUID(context.Background(), &ngmodels.GetAlertRuleByUIDQuery{OrgID: testOrgID, UID: "created-locked"})
				require.ErrorIs(t, getErr, ngmodels.ErrAlertRuleNotFound)
				require.Equal(t, utils.ManagerKindUnknown, h.managers.get(testOrgID, "created-locked").Kind)
			})
		})
	}

	t.Run("cannot stamp file provenance onto an unmanaged rule", func(t *testing.T) {
		h := newHarness(t)
		target := "open-alert"
		h.seed(t, baseRule(target, "original", false), utils.ManagerProperties{})
		ctx := editorContext()
		fetched := h.getAlert(t, ctx, target)
		body := roundTripAlert(t, fetched)
		body.Spec.Title = "now locked"
		h.stampManager(t, body, utils.ManagerProperties{Kind: utils.ManagerKindClassicFP}) //nolint:staticcheck
		_, _, err := h.alerts.Update(ctx, target, rest.DefaultUpdatedObjectInfo(body, h.mutateAlert(t)), func(context.Context, runtime.Object) error { return nil }, h.validateAlertUpdate(t), false, &metav1.UpdateOptions{})
		require.Error(t, err)
		h.requireUnchanged(t, target, "original", false, utils.ManagerProperties{})
	})
}

func TestProvisionedRecordingRuleStorageRejectsEditorWrites(t *testing.T) {
	for _, manager := range protectedManagers {
		t.Run(string(manager.Kind), func(t *testing.T) {
			t.Run("put", func(t *testing.T) {
				h := newHarness(t)
				target := "file-recording"
				h.seed(t, baseRule(target, "original", true), manager)
				h.seed(t, baseRule(siblingUID, "sibling", true), utils.ManagerProperties{})

				err := h.putRecording(t, editorContext(), target, "blunted", true)
				require.Error(t, err)
				h.requireUnchanged(t, target, "original", false, manager)
				h.requireUnchanged(t, siblingUID, "sibling", false, utils.ManagerProperties{})
			})

			t.Run("merge-patch", func(t *testing.T) {
				h := newHarness(t)
				target := "file-recording"
				h.seed(t, baseRule(target, "original", true), manager)
				h.seed(t, baseRule(siblingUID, "sibling", true), utils.ManagerProperties{})

				err := h.patchRecording(t, editorContext(), target, []byte(`{"spec":{"paused":true,"title":"blunted"}}`))
				require.Error(t, err)
				h.requireUnchanged(t, target, "original", false, manager)
				h.requireUnchanged(t, siblingUID, "sibling", false, utils.ManagerProperties{})
			})

			t.Run("delete", func(t *testing.T) {
				h := newHarness(t)
				target := "file-recording"
				h.seed(t, baseRule(target, "original", true), manager)
				h.seed(t, baseRule(siblingUID, "sibling", true), utils.ManagerProperties{})

				_, _, err := h.recording.Delete(editorContext(), target, h.validateRecordingDelete(t), &metav1.DeleteOptions{})
				require.Error(t, err)
				h.requireUnchanged(t, target, "original", false, manager)
				h.requireUnchanged(t, siblingUID, "sibling", false, utils.ManagerProperties{})
			})

			t.Run("create", func(t *testing.T) {
				h := newHarness(t)
				obj := h.freshRecording("created-locked", "locked")
				h.stampRecordingManager(t, obj, manager)
				err := h.createRecording(t, editorContext(), obj)
				require.Error(t, err)
				_, getErr := h.rules.GetAlertRuleByUID(context.Background(), &ngmodels.GetAlertRuleByUIDQuery{OrgID: testOrgID, UID: "created-locked"})
				require.ErrorIs(t, getErr, ngmodels.ErrAlertRuleNotFound)
				require.Equal(t, utils.ManagerKindUnknown, h.managers.get(testOrgID, "created-locked").Kind)
			})
		})
	}

	t.Run("cannot stamp file provenance onto an unmanaged rule", func(t *testing.T) {
		h := newHarness(t)
		target := "open-recording"
		h.seed(t, baseRule(target, "original", true), utils.ManagerProperties{})
		fetched := h.getRecording(t, editorContext(), target)
		body := roundTripRecording(t, fetched)
		body.Spec.Title = "now locked"
		h.stampRecordingManager(t, body, utils.ManagerProperties{Kind: utils.ManagerKindClassicFP}) //nolint:staticcheck
		_, _, err := h.recording.Update(editorContext(), target, rest.DefaultUpdatedObjectInfo(body, h.mutateRecording(t)), func(context.Context, runtime.Object) error { return nil }, h.validateRecordingUpdate(t), false, &metav1.UpdateOptions{})
		require.Error(t, err)
		h.requireUnchanged(t, target, "original", false, utils.ManagerProperties{})
	})
}

func (h *ruleHarness) requireUnchanged(t *testing.T, uid, title string, paused bool, manager utils.ManagerProperties) {
	t.Helper()
	got := h.domainRule(t, uid)
	require.Equal(t, title, got.Title)
	require.Equal(t, paused, got.IsPaused)
	require.Equal(t, manager, h.managers.get(testOrgID, uid))
}

func (h *ruleHarness) getAlert(t *testing.T, ctx context.Context, name string) *model.AlertRule {
	t.Helper()
	obj, err := h.alerts.Get(ctx, name, &metav1.GetOptions{})
	require.NoError(t, err)
	rule, ok := obj.(*model.AlertRule)
	require.True(t, ok)
	return rule
}

func (h *ruleHarness) getRecording(t *testing.T, ctx context.Context, name string) *model.RecordingRule {
	t.Helper()
	obj, err := h.recording.Get(ctx, name, &metav1.GetOptions{})
	require.NoError(t, err)
	rule, ok := obj.(*model.RecordingRule)
	require.True(t, ok)
	return rule
}

func (h *ruleHarness) putAlert(t *testing.T, ctx context.Context, name, title string, paused bool) error {
	t.Helper()
	fetched := h.getAlert(t, ctx, name)
	body := roundTripAlert(t, fetched)
	body.Spec.Title = title
	body.Spec.Paused = &paused
	if err := h.alertVal.Validate(ctx, &appsdk.AdmissionRequest{
		Action:    sdkresource.AdmissionActionUpdate,
		Object:    body,
		OldObject: fetched,
	}); err != nil {
		return err
	}
	_, _, err := h.alerts.Update(ctx, name, rest.DefaultUpdatedObjectInfo(body, h.mutateAlert(t)), func(context.Context, runtime.Object) error { return nil }, h.validateAlertUpdate(t), false, &metav1.UpdateOptions{})
	return err
}

func (h *ruleHarness) putRecording(t *testing.T, ctx context.Context, name, title string, paused bool) error {
	t.Helper()
	fetched := h.getRecording(t, ctx, name)
	body := roundTripRecording(t, fetched)
	body.Spec.Title = title
	body.Spec.Paused = &paused
	if err := h.recordVal.Validate(ctx, &appsdk.AdmissionRequest{
		Action:    sdkresource.AdmissionActionUpdate,
		Object:    body,
		OldObject: fetched,
	}); err != nil {
		return err
	}
	_, _, err := h.recording.Update(ctx, name, rest.DefaultUpdatedObjectInfo(body, h.mutateRecording(t)), func(context.Context, runtime.Object) error { return nil }, h.validateRecordingUpdate(t), false, &metav1.UpdateOptions{})
	return err
}

func (h *ruleHarness) patchAlert(t *testing.T, ctx context.Context, name string, patch []byte) error {
	t.Helper()
	_, _, err := h.alerts.Update(ctx, name, rest.DefaultUpdatedObjectInfo(nil, h.mergeThenMutateAlert(t, patch)), func(context.Context, runtime.Object) error { return nil }, h.validateAlertUpdate(t), false, &metav1.UpdateOptions{})
	return err
}

func (h *ruleHarness) patchRecording(t *testing.T, ctx context.Context, name string, patch []byte) error {
	t.Helper()
	_, _, err := h.recording.Update(ctx, name, rest.DefaultUpdatedObjectInfo(nil, h.mergeThenMutateRecording(t, patch)), func(context.Context, runtime.Object) error { return nil }, h.validateRecordingUpdate(t), false, &metav1.UpdateOptions{})
	return err
}

func (h *ruleHarness) createAlert(t *testing.T, ctx context.Context, obj *model.AlertRule) error {
	t.Helper()
	mutated := h.mustMutateAlert(t, ctx, obj, nil).(*model.AlertRule)
	if err := h.alertVal.Validate(ctx, &appsdk.AdmissionRequest{
		Action: sdkresource.AdmissionActionCreate,
		Object: mutated,
	}); err != nil {
		return err
	}
	_, err := h.alerts.Create(ctx, mutated, h.validateAlertCreate(t), &metav1.CreateOptions{})
	return err
}

func (h *ruleHarness) createRecording(t *testing.T, ctx context.Context, obj *model.RecordingRule) error {
	t.Helper()
	mutated := h.mustMutateRecording(t, ctx, obj, nil).(*model.RecordingRule)
	if err := h.recordVal.Validate(ctx, &appsdk.AdmissionRequest{
		Action: sdkresource.AdmissionActionCreate,
		Object: mutated,
	}); err != nil {
		return err
	}
	_, err := h.recording.Create(ctx, mutated, func(context.Context, runtime.Object) error {
		return h.recordVal.Validate(ctx, &appsdk.AdmissionRequest{Action: sdkresource.AdmissionActionCreate, Object: mutated})
	}, &metav1.CreateOptions{})
	return err
}

func (h *ruleHarness) freshAlert(name, title string) *model.AlertRule {
	return &model.AlertRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Annotations: map[string]string{
				model.FolderAnnotationKey: testFolderUID,
			},
		},
		Spec: model.AlertRuleSpec{
			Title:        title,
			Trigger:      model.AlertRuleIntervalTrigger{Interval: "1m"},
			NoDataState:  model.AlertRuleNoDataStateNoData,
			ExecErrState: model.AlertRuleExecErrStateError,
			Expressions: model.AlertRuleExpressionMap{
				"A": model.AlertRuleExpression{
					Model:  map[string]any{"type": "math", "expression": "1", "refId": "A"},
					Source: new(true),
				},
			},
		},
	}
}

func (h *ruleHarness) freshRecording(name, title string) *model.RecordingRule {
	return &model.RecordingRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Annotations: map[string]string{
				model.FolderAnnotationKey: testFolderUID,
			},
		},
		Spec: model.RecordingRuleSpec{
			Title:               title,
			Metric:              "recorded_metric",
			TargetDatasourceUID: "prometheus",
			Trigger:             model.RecordingRuleIntervalTrigger{Interval: "1m"},
			Expressions: model.RecordingRuleExpressionMap{
				"A": model.RecordingRuleExpression{
					Model:  map[string]any{"type": "math", "expression": "1", "refId": "A"},
					Source: new(true),
				},
			},
		},
	}
}

func (h *ruleHarness) stampManager(t *testing.T, rule *model.AlertRule, manager utils.ManagerProperties) {
	t.Helper()
	meta, err := utils.MetaAccessor(rule)
	require.NoError(t, err)
	meta.SetManagerProperties(manager)
	require.NoError(t, rule.SetProvenanceStatus(string(ngmodels.ManagerPropertiesToProvenance(manager))))
}

func (h *ruleHarness) stampRecordingManager(t *testing.T, rule *model.RecordingRule, manager utils.ManagerProperties) {
	t.Helper()
	meta, err := utils.MetaAccessor(rule)
	require.NoError(t, err)
	meta.SetManagerProperties(manager)
	require.NoError(t, rule.SetProvenanceStatus(string(ngmodels.ManagerPropertiesToProvenance(manager))))
}

func (h *ruleHarness) validateAlertUpdate(t *testing.T) rest.ValidateObjectUpdateFunc {
	t.Helper()
	return func(ctx context.Context, obj, old runtime.Object) error {
		return h.alertVal.Validate(ctx, &appsdk.AdmissionRequest{
			Action:    sdkresource.AdmissionActionUpdate,
			Object:    asSDK(obj),
			OldObject: asSDK(old),
		})
	}
}

func (h *ruleHarness) validateAlertCreate(t *testing.T) rest.ValidateObjectFunc {
	t.Helper()
	return func(ctx context.Context, obj runtime.Object) error {
		return h.alertVal.Validate(ctx, &appsdk.AdmissionRequest{
			Action: sdkresource.AdmissionActionCreate,
			Object: asSDK(obj),
		})
	}
}

func (h *ruleHarness) validateAlertDelete(t *testing.T) rest.ValidateObjectFunc {
	t.Helper()
	return func(ctx context.Context, obj runtime.Object) error {
		return h.alertVal.Validate(ctx, &appsdk.AdmissionRequest{
			Action:    sdkresource.AdmissionActionDelete,
			OldObject: asSDK(obj),
		})
	}
}

func (h *ruleHarness) validateRecordingUpdate(t *testing.T) rest.ValidateObjectUpdateFunc {
	t.Helper()
	return func(ctx context.Context, obj, old runtime.Object) error {
		return h.recordVal.Validate(ctx, &appsdk.AdmissionRequest{
			Action:    sdkresource.AdmissionActionUpdate,
			Object:    asSDK(obj),
			OldObject: asSDK(old),
		})
	}
}

func (h *ruleHarness) validateRecordingDelete(t *testing.T) rest.ValidateObjectFunc {
	t.Helper()
	return func(ctx context.Context, obj runtime.Object) error {
		return h.recordVal.Validate(ctx, &appsdk.AdmissionRequest{
			Action:    sdkresource.AdmissionActionDelete,
			OldObject: asSDK(obj),
		})
	}
}

func (h *ruleHarness) mutateAlert(t *testing.T) rest.TransformFunc {
	t.Helper()
	mutator := alertruleapp.NewMutator(h.cfg)
	return func(ctx context.Context, obj, old runtime.Object) (runtime.Object, error) {
		return applyMutator(t, ctx, mutator, obj, old)
	}
}

func (h *ruleHarness) mutateRecording(t *testing.T) rest.TransformFunc {
	t.Helper()
	mutator := recordingruleapp.NewMutator(h.cfg)
	return func(ctx context.Context, obj, old runtime.Object) (runtime.Object, error) {
		return applyMutator(t, ctx, mutator, obj, old)
	}
}

func (h *ruleHarness) mergeThenMutateAlert(t *testing.T, patch []byte) rest.TransformFunc {
	t.Helper()
	mutate := h.mutateAlert(t)
	return func(ctx context.Context, _, old runtime.Object) (runtime.Object, error) {
		merged, err := mergePatchObject(old, patch, &model.AlertRule{})
		if err != nil {
			return nil, err
		}
		// The merged object must still carry the provenance the GET echoed.
		// A patch that drops it is not the attack under test.
		alert := merged.(*model.AlertRule)
		if alert.GetProvenanceStatus() == "" && !hasManager(alert) {
			t.Fatalf("merge patch dropped provenance from the stored object")
		}
		return mutate(ctx, merged, old)
	}
}

func (h *ruleHarness) mergeThenMutateRecording(t *testing.T, patch []byte) rest.TransformFunc {
	t.Helper()
	mutate := h.mutateRecording(t)
	return func(ctx context.Context, _, old runtime.Object) (runtime.Object, error) {
		merged, err := mergePatchObject(old, patch, &model.RecordingRule{})
		if err != nil {
			return nil, err
		}
		rec := merged.(*model.RecordingRule)
		if rec.GetProvenanceStatus() == "" && !hasRecordingManager(rec) {
			t.Fatalf("merge patch dropped provenance from the stored object")
		}
		return mutate(ctx, merged, old)
	}
}

func (h *ruleHarness) mustMutateAlert(t *testing.T, ctx context.Context, obj, old runtime.Object) runtime.Object {
	t.Helper()
	out, err := h.mutateAlert(t)(ctx, obj, old)
	require.NoError(t, err)
	return out
}

func (h *ruleHarness) mustMutateRecording(t *testing.T, ctx context.Context, obj, old runtime.Object) runtime.Object {
	t.Helper()
	out, err := h.mutateRecording(t)(ctx, obj, old)
	require.NoError(t, err)
	return out
}

func hasManager(rule *model.AlertRule) bool {
	meta, err := utils.MetaAccessor(rule)
	if err != nil {
		return false
	}
	_, ok := meta.GetManagerProperties()
	return ok
}

func hasRecordingManager(rule *model.RecordingRule) bool {
	meta, err := utils.MetaAccessor(rule)
	if err != nil {
		return false
	}
	_, ok := meta.GetManagerProperties()
	return ok
}

// mergePatchObject applies an RFC 7386 merge patch the same way the Kubernetes
// apiserver's JSON merge-patch handler does: encode the current object, merge
// the patch, decode into a new object.
func mergePatchObject(current runtime.Object, patch []byte, into runtime.Object) (runtime.Object, error) {
	raw, err := json.Marshal(current)
	if err != nil {
		return nil, err
	}
	patched, err := jsonpatch.MergePatch(raw, patch)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(patched, into); err != nil {
		return nil, err
	}
	return into, nil
}

func roundTripAlert(t *testing.T, in *model.AlertRule) *model.AlertRule {
	t.Helper()
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	out := &model.AlertRule{}
	require.NoError(t, json.Unmarshal(raw, out))
	return out
}

func roundTripRecording(t *testing.T, in *model.RecordingRule) *model.RecordingRule {
	t.Helper()
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	out := &model.RecordingRule{}
	require.NoError(t, json.Unmarshal(raw, out))
	return out
}

type mutatingAdmission interface {
	Mutate(context.Context, *appsdk.AdmissionRequest) (*appsdk.MutatingResponse, error)
}

func applyMutator(t *testing.T, ctx context.Context, mutator mutatingAdmission, obj, old runtime.Object) (runtime.Object, error) {
	t.Helper()
	action := sdkresource.AdmissionActionUpdate
	if old == nil {
		action = sdkresource.AdmissionActionCreate
	}
	resp, err := mutator.Mutate(ctx, &appsdk.AdmissionRequest{
		Action:    action,
		Object:    asSDK(obj),
		OldObject: asSDK(old),
	})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.UpdatedObject == nil {
		return obj, nil
	}
	return resp.UpdatedObject, nil
}

func asSDK(obj runtime.Object) sdkresource.Object {
	if obj == nil {
		return nil
	}
	return obj.(sdkresource.Object)
}
