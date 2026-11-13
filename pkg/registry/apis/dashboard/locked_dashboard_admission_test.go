package dashboard

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apiserver/pkg/admission"

	authtypes "github.com/grafana/authlib/types"

	dashv1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/services/dashboards"
	dashsvc "github.com/grafana/grafana/pkg/services/dashboards/service"
)

// Dashboard update admission is the request gate in front of unified storage.
// It currently checks title, tags, folder, and refresh interval, and never the
// stored manager's allows-edits flag. These tests require the same rejection the
// legacy /api/dashboards/db route already returns.

func TestDashboardUpdateAdmissionRejectsLockedManagers(t *testing.T) {
	kinds := []struct {
		name     string
		kind     utils.ManagerKind
		identity string
	}{
		{name: "classic file provisioning", kind: utils.ManagerKindClassicFP, identity: "dash-files"}, //nolint:staticcheck
		{name: "classic file provisioning without identity", kind: utils.ManagerKindClassicFP},        //nolint:staticcheck
		{name: "plugin", kind: utils.ManagerKindPlugin, identity: "plugin-1"},
		{name: "classic api provisioning", kind: utils.ManagerKindClassicAPI, identity: "api"},                           //nolint:staticcheck
		{name: "classic converted prometheus", kind: utils.ManagerKindClassicConvertedPrometheus, identity: "converted"}, //nolint:staticcheck
		{name: "terraform", kind: utils.ManagerKindTerraform, identity: "grafana-terraform-provider"},
		{name: "kubectl", kind: utils.ManagerKindKubectl, identity: "kubectl-context"},
	}

	humans := []struct {
		name string
		user *identity.StaticRequester
	}{
		{name: "editor", user: admissionUser("editor-uid", identity.RoleEditor, false)},
		{name: "org admin", user: admissionUser("org-admin-uid", identity.RoleAdmin, false)},
		{name: "grafana admin", user: admissionUser("grafana-admin-uid", identity.RoleAdmin, true)},
	}

	for _, kind := range kinds {
		t.Run(kind.name, func(t *testing.T) {
			for _, who := range humans {
				t.Run(who.name+" spec update", func(t *testing.T) {
					oldObj := admissionDashboard(kind.kind, kind.identity, false, "original_query")
					newObj := admissionDashboard(kind.kind, kind.identity, false, "rewritten_query")
					err := validateDashboardUpdate(who.user, newObj, oldObj)
					require.ErrorContains(t, err, dashboards.ErrDashboardCannotSaveProvisionedDashboard.Error())
				})

				t.Run(who.name+" request sets allows-edits", func(t *testing.T) {
					oldObj := admissionDashboard(kind.kind, kind.identity, false, "original_query")
					newObj := admissionDashboard(kind.kind, kind.identity, true, "rewritten_query")
					err := validateDashboardUpdate(who.user, newObj, oldObj)
					require.ErrorContains(t, err, dashboards.ErrDashboardCannotSaveProvisionedDashboard.Error())
				})

				t.Run(who.name+" removes the manager", func(t *testing.T) {
					oldObj := admissionDashboard(kind.kind, kind.identity, false, "original_query")
					newObj := admissionDashboard(kind.kind, kind.identity, false, "rewritten_query")
					meta, err := utils.MetaAccessor(newObj)
					require.NoError(t, err)
					meta.SetManagerProperties(utils.ManagerProperties{})
					err = validateDashboardUpdate(who.user, newObj, oldObj)
					require.ErrorContains(t, err, dashboards.ErrDashboardCannotSaveProvisionedDashboard.Error())
				})
			}
		})
	}

	t.Run("service identity can update a locked file-provisioned dashboard", func(t *testing.T) {
		ctx, user := identity.WithServiceIdentity(context.Background(), 1)
		oldObj := admissionDashboard(utils.ManagerKindClassicFP, "dash-files", false, "original_query")    //nolint:staticcheck
		newObj := admissionDashboard(utils.ManagerKindClassicFP, "dash-files", false, "provisioned_query") //nolint:staticcheck
		err := validateDashboardUpdateAs(ctx, user.(*identity.StaticRequester), newObj, oldObj)
		require.NoError(t, err)
	})

	t.Run("editor can update when the stored dashboard allows edits", func(t *testing.T) {
		user := admissionUser("editor-uid", identity.RoleEditor, false)
		oldObj := admissionDashboard(utils.ManagerKindClassicFP, "dash-files", true, "original_query") //nolint:staticcheck
		newObj := admissionDashboard(utils.ManagerKindClassicFP, "dash-files", true, "allowed_query")  //nolint:staticcheck
		err := validateDashboardUpdate(user, newObj, oldObj)
		require.NoError(t, err)
	})
}

func TestDashboardDeleteAdmissionRejectsLockedNonClassicManagers(t *testing.T) {
	kinds := []struct {
		name     string
		kind     utils.ManagerKind
		identity string
	}{
		{name: "plugin", kind: utils.ManagerKindPlugin, identity: "plugin-1"},
		{name: "classic api provisioning", kind: utils.ManagerKindClassicAPI, identity: "api"},                           //nolint:staticcheck
		{name: "classic converted prometheus", kind: utils.ManagerKindClassicConvertedPrometheus, identity: "converted"}, //nolint:staticcheck
		{name: "terraform", kind: utils.ManagerKindTerraform, identity: "grafana-terraform-provider"},
		{name: "kubectl", kind: utils.ManagerKindKubectl, identity: "kubectl-context"},
	}
	for _, kind := range kinds {
		t.Run(kind.name, func(t *testing.T) {
			stored := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "dashboard.grafana.app/v1",
				"kind":       "Dashboard",
				"metadata": map[string]any{
					"name":      "locked-dash",
					"namespace": "stacks-123",
				},
			}}
			meta, err := utils.MetaAccessor(stored)
			require.NoError(t, err)
			meta.SetManagerProperties(utils.ManagerProperties{Kind: kind.kind, Identity: kind.identity, AllowsEdits: false})

			builder := &DashboardsAPIBuilder{
				dashboardK8sClient: &mockK8sHandler{getResponse: stored},
			}
			user := admissionUser("editor-uid", identity.RoleEditor, false)
			err = builder.Validate(identity.WithRequester(context.Background(), user), admission.NewAttributesRecord(
				&dashv1.Dashboard{ObjectMeta: metav1.ObjectMeta{Name: "locked-dash", Namespace: "stacks-123"}},
				nil,
				dashv1.DashboardResourceInfo.GroupVersionKind(),
				"stacks-123",
				"locked-dash",
				dashv1.DashboardResourceInfo.GroupVersionResource(),
				"",
				admission.Delete,
				&metav1.DeleteOptions{},
				false,
				user,
			), nil)
			require.Error(t, err)
			require.True(t, builder.dashboardK8sClient.(*mockK8sHandler).getCalled)
		})
	}

	t.Run("editor can delete when allows-edits is true", func(t *testing.T) {
		stored := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "dashboard.grafana.app/v1",
			"kind":       "Dashboard",
			"metadata": map[string]any{
				"name":      "open-dash",
				"namespace": "stacks-123",
			},
		}}
		meta, err := utils.MetaAccessor(stored)
		require.NoError(t, err)
		meta.SetManagerProperties(utils.ManagerProperties{
			Kind:        utils.ManagerKindTerraform,
			Identity:    "grafana-terraform-provider",
			AllowsEdits: true,
		})
		builder := &DashboardsAPIBuilder{dashboardK8sClient: &mockK8sHandler{getResponse: stored}}
		user := admissionUser("editor-uid", identity.RoleEditor, false)
		err = builder.Validate(identity.WithRequester(context.Background(), user), admission.NewAttributesRecord(
			&dashv1.Dashboard{ObjectMeta: metav1.ObjectMeta{Name: "open-dash", Namespace: "stacks-123"}},
			nil,
			dashv1.DashboardResourceInfo.GroupVersionKind(),
			"stacks-123",
			"open-dash",
			dashv1.DashboardResourceInfo.GroupVersionResource(),
			"",
			admission.Delete,
			&metav1.DeleteOptions{},
			false,
			user,
		), nil)
		require.NoError(t, err)
	})
}

func admissionUser(uid string, role identity.RoleType, grafanaAdmin bool) *identity.StaticRequester {
	return &identity.StaticRequester{
		Type:           authtypes.TypeUser,
		UserUID:        uid,
		UserID:         42,
		OrgID:          1,
		OrgRole:        role,
		IsGrafanaAdmin: grafanaAdmin,
		Namespace:      "stacks-123",
	}
}

func admissionDashboard(kind utils.ManagerKind, managerID string, allowsEdits bool, expr string) *dashv1.Dashboard {
	obj := &dashv1.Dashboard{
		TypeMeta: metav1.TypeMeta{APIVersion: dashv1.DashboardResourceInfo.GroupVersion().String(), Kind: "Dashboard"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "locked-dash",
			Namespace: "stacks-123",
		},
		Spec: common.Unstructured{Object: map[string]any{
			"title": "Locked",
			"panels": []any{
				map[string]any{
					"targets": []any{map[string]any{"expr": expr}},
				},
			},
		}},
	}
	meta, err := utils.MetaAccessor(obj)
	if err != nil {
		panic(err)
	}
	meta.SetManagerProperties(utils.ManagerProperties{
		Kind:        kind,
		Identity:    managerID,
		AllowsEdits: allowsEdits,
	})
	return obj
}

func validateDashboardUpdate(user *identity.StaticRequester, newObj, oldObj *dashv1.Dashboard) error {
	return validateDashboardUpdateAs(identity.WithRequester(context.Background(), user), user, newObj, oldObj)
}

func validateDashboardUpdateAs(ctx context.Context, user *identity.StaticRequester, newObj, oldObj *dashv1.Dashboard) error {
	builder := &DashboardsAPIBuilder{dashboardService: &dashsvc.DashboardServiceImpl{}}
	return builder.Validate(ctx, admission.NewAttributesRecord(
		newObj,
		oldObj,
		dashv1.DashboardResourceInfo.GroupVersionKind(),
		"stacks-123",
		newObj.Name,
		dashv1.DashboardResourceInfo.GroupVersionResource(),
		"",
		admission.Update,
		&metav1.UpdateOptions{},
		false,
		user,
	), nil)
}
