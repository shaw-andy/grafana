package dashboard

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/admission"

	dashboardV0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	dashboardV1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	dashboardV2 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2"
	dashboardV2alpha1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2alpha1"
	dashboardV2beta1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2beta1"
	"github.com/grafana/grafana/apps/dashboard/pkg/migration"
	"github.com/grafana/grafana/apps/dashboard/pkg/migration/schemaversion"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/util"
)

func (b *DashboardsAPIBuilder) Mutate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) (err error) {
	op := a.GetOperation()

	// Mutate removes any internal ID set in the spec & adds it as a label
	if op != admission.Create && op != admission.Update {
		return nil
	}

	switch a.GetResource().Resource {
	case dashboardV0.DASHBOARD_RESOURCE:
		return b.mutateDashboard(ctx, a)
	// Reachability invariant: variable storage is always registered, but
	// FlagGrafanaDashboardGlobalVariables is gated per request in GetAuthorizer.
	// When the feature is disabled the authorizer denies the request (403)
	// before admission runs, so this case only fires when global variables
	// are enabled.
	case dashboardV2beta1.VariableResourceInfo.GroupVersionResource().Resource:
		return mutateVariable(a)

	// Reachability invariant: this case only fires when the apiserver routes a
	// request to the v2beta1 Notebook storage, which is registered in
	// UpdateAPIGroupInfo behind FlagDashboardNotebooks (see register.go).
	// Notebooks need no mutation today; layout validation happens in Validate.
	case dashboardV2beta1.NotebookResourceInfo.GroupVersionResource().Resource:
		return nil

	case dashboardV0.LIBRARY_PANEL_RESOURCE:
		return nil // nothing needed
	case dashboardV0.SNAPSHOT_RESOURCE:
		return nil
	}

	return fmt.Errorf("unexpected resource: %+v", a.GetResource())
}

func (b *DashboardsAPIBuilder) mutateDashboard(ctx context.Context, a admission.Attributes) (err error) {
	var internalID int64
	obj := a.GetObject()
	meta, err := utils.MetaAccessor(obj)
	if err != nil {
		return err
	}

	var migrationErr error
	var resourceInfo utils.ResourceInfo
	switch v := obj.(type) {
	case *dashboardV0.Dashboard:
		delete(v.Spec.Object, "uid")
		delete(v.Spec.Object, "version")
		if id, ok := v.Spec.Object["id"].(float64); ok {
			delete(v.Spec.Object, "id")
			internalID = int64(id)
		}
		// Strip BOMs from all string values in the dashboard spec
		v.Spec.Object = util.StripBOMFromInterface(v.Spec.Object).(map[string]any)
		resourceInfo = dashboardV0.DashboardResourceInfo

	case *dashboardV1.Dashboard:
		delete(v.Spec.Object, "uid")
		delete(v.Spec.Object, "version")
		if id, ok := v.Spec.Object["id"].(float64); ok {
			delete(v.Spec.Object, "id")
			internalID = int64(id)
		}
		// Strip BOMs from all string values in the dashboard spec
		v.Spec.Object = util.StripBOMFromInterface(v.Spec.Object).(map[string]any)
		resourceInfo = dashboardV1.DashboardResourceInfo
		migrationErr = migration.Migrate(ctx, v.Spec.Object, schemaversion.LATEST_VERSION)
		if migrationErr != nil {
			v.Status.Conversion = &dashboardV1.DashboardConversionStatus{
				Failed: true,
				Error:  new(migrationErr.Error()),
			}
		}

	case *dashboardV2alpha1.Dashboard:
		// Temporary fix: The generator fails to properly initialize this property, so we'll do it here
		// until the generator is fixed.
		if v.Spec.Layout.GridLayoutKind == nil && v.Spec.Layout.RowsLayoutKind == nil && v.Spec.Layout.AutoGridLayoutKind == nil && v.Spec.Layout.TabsLayoutKind == nil {
			v.Spec.Layout.GridLayoutKind = &dashboardV2alpha1.DashboardGridLayoutKind{
				Kind: "GridLayout",
				Spec: dashboardV2alpha1.DashboardGridLayoutSpec{},
			}
		}
		// Strip BOMs from all string fields recursively
		util.StripBOMFromStruct(&v.Spec)
		resourceInfo = dashboardV2alpha1.DashboardResourceInfo

	case *dashboardV2beta1.Dashboard:
		// Temporary fix: The generator fails to properly initialize this property, so we'll do it here
		// until the generator is fixed.
		if v.Spec.Layout.GridLayoutKind == nil && v.Spec.Layout.RowsLayoutKind == nil && v.Spec.Layout.AutoGridLayoutKind == nil && v.Spec.Layout.TabsLayoutKind == nil {
			v.Spec.Layout.GridLayoutKind = &dashboardV2beta1.DashboardGridLayoutKind{
				Kind: "GridLayout",
				Spec: dashboardV2beta1.DashboardGridLayoutSpec{},
			}
		}
		// Strip BOMs from all string fields recursively
		util.StripBOMFromStruct(&v.Spec)
		resourceInfo = dashboardV2beta1.DashboardResourceInfo

	case *dashboardV2.Dashboard:
		if v.Spec.Layout.GridLayoutKind == nil && v.Spec.Layout.RowsLayoutKind == nil && v.Spec.Layout.AutoGridLayoutKind == nil && v.Spec.Layout.TabsLayoutKind == nil {
			v.Spec.Layout.GridLayoutKind = &dashboardV2.DashboardGridLayoutKind{
				Kind: "GridLayout",
				Spec: dashboardV2.DashboardGridLayoutSpec{},
			}
		}
		// Strip BOMs from all string fields recursively
		util.StripBOMFromStruct(&v.Spec)
		resourceInfo = dashboardV2.DashboardResourceInfo

	default:
		return fmt.Errorf("mutation error: expected to dashboard, got %T", obj)
	}

	if internalID != 0 {
		meta.SetDeprecatedInternalID(internalID) // nolint:staticcheck
	}

	// Library panel uids are interpolated into request paths by viewers' browsers,
	// so they are enforced independently of the field validation mode.
	if errs := validateLibraryPanelUIDs(obj); len(errs) > 0 {
		return apierrors.NewInvalid(resourceInfo.GroupVersionKind().GroupKind(), meta.GetName(), errs)
	}

	return b.validateDashboardIfStrict(ctx, a, migrationErr, resourceInfo)
}

func validateLibraryPanelUIDs(obj runtime.Object) field.ErrorList {
	specPath := field.NewPath("spec")
	switch v := obj.(type) {
	case *dashboardV0.Dashboard:
		return validateUnstructuredLibraryPanelUIDs(v.Spec.Object, specPath)
	case *dashboardV1.Dashboard:
		return validateUnstructuredLibraryPanelUIDs(v.Spec.Object, specPath)
	case *dashboardV2alpha1.Dashboard:
		var errs field.ErrorList
		for key, element := range v.Spec.Elements {
			if element.LibraryPanelKind != nil {
				errs = append(errs, validateLibraryPanelUID(element.LibraryPanelKind.Spec.LibraryPanel.Uid,
					specPath.Child("elements").Key(key).Child("spec", "libraryPanel", "uid"))...)
			}
		}
		return errs
	case *dashboardV2beta1.Dashboard:
		var errs field.ErrorList
		for key, element := range v.Spec.Elements {
			if element.LibraryPanelKind != nil {
				errs = append(errs, validateLibraryPanelUID(element.LibraryPanelKind.Spec.LibraryPanel.Uid,
					specPath.Child("elements").Key(key).Child("spec", "libraryPanel", "uid"))...)
			}
		}
		return errs
	case *dashboardV2.Dashboard:
		var errs field.ErrorList
		for key, element := range v.Spec.Elements {
			if element.LibraryPanelKind != nil {
				errs = append(errs, validateLibraryPanelUID(element.LibraryPanelKind.Spec.LibraryPanel.Uid,
					specPath.Child("elements").Key(key).Child("spec", "libraryPanel", "uid"))...)
			}
		}
		return errs
	}
	return nil
}

// validateUnstructuredLibraryPanelUIDs checks panels at any nesting depth, including
// collapsed rows and pre-schema-16 "rows", because the frontend migrates all of them
// into library panels.
func validateUnstructuredLibraryPanelUIDs(spec map[string]any, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	for _, key := range []string{"panels", "rows"} {
		items, ok := spec[key].([]any)
		if !ok {
			continue
		}
		for i, item := range items {
			panel, ok := item.(map[string]any)
			if !ok {
				continue
			}
			panelPath := path.Child(key).Index(i)
			if libraryPanel, ok := panel["libraryPanel"].(map[string]any); ok {
				if raw, exists := libraryPanel["uid"]; exists && raw != nil {
					uid, isString := raw.(string)
					if !isString {
						errs = append(errs, field.Invalid(panelPath.Child("libraryPanel", "uid"), raw, "library panel uid must be a string"))
					} else {
						errs = append(errs, validateLibraryPanelUID(uid, panelPath.Child("libraryPanel", "uid"))...)
					}
				}
			}
			errs = append(errs, validateUnstructuredLibraryPanelUIDs(panel, panelPath)...)
		}
	}
	return errs
}

func validateLibraryPanelUID(uid string, path *field.Path) field.ErrorList {
	if !util.IsValidShortUID(uid) {
		return field.ErrorList{field.Invalid(path, uid, "library panel uid may only contain letters, digits, '-' and '_'")}
	}
	return nil
}

// validateDashboardIfStrict validates the dashboard spec if field validation mode is strict.
func (b *DashboardsAPIBuilder) validateDashboardIfStrict(ctx context.Context, a admission.Attributes, migrationErr error, resourceInfo utils.ResourceInfo) error {
	obj := a.GetObject()
	meta, err := utils.MetaAccessor(obj)
	if err != nil {
		return err
	}

	fieldValidationMode := getFieldValidationMode(a)

	var validationErrorList field.ErrorList
	var validationProcessingError error
	if migrationErr == nil {
		// Migration check passed, validate the spec now - this will respect the field validation mode!
		validationErrorList, validationProcessingError = b.ValidateDashboardSpec(ctx, obj, fieldValidationMode)
	}

	// Only fail if the field validation mode is strict
	if fieldValidationMode == metav1.FieldValidationStrict {
		if migrationErr != nil {
			return apierrors.NewInvalid(resourceInfo.GroupVersionKind().GroupKind(), meta.GetName(), field.ErrorList{
				field.Invalid(field.NewPath("spec"), meta.GetName(), migrationErr.Error())})
		}
		if validationProcessingError != nil {
			return validationProcessingError
		}
		if len(validationErrorList) > 0 {
			return apierrors.NewInvalid(resourceInfo.GroupVersionKind().GroupKind(), meta.GetName(), validationErrorList)
		}
	}

	return nil
}

func mutateVariable(a admission.Attributes) error {
	variable, ok := a.GetObject().(*dashboardV2beta1.Variable)
	if !ok {
		return fmt.Errorf("mutation error: expected variable, got %T", a.GetObject())
	}

	meta, err := utils.MetaAccessor(variable)
	if err != nil {
		return err
	}

	labels := variable.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}

	if folderUID := meta.GetFolder(); folderUID != "" {
		labels[variableFolderLabelKey] = folderUID
	} else {
		delete(labels, variableFolderLabelKey)
	}
	variable.SetLabels(labels)

	if a.GetOperation() == admission.Create && variable.GetName() == "" {
		variable.SetName(deriveVariableMetadataName(getVariableName(variable.Spec), meta.GetFolder()))
	}

	return nil
}

func getFieldValidationMode(a admission.Attributes) string {
	var validation string
	switch opts := a.GetOperationOptions().(type) {
	case *metav1.CreateOptions:
		validation = opts.FieldValidation
	case *metav1.UpdateOptions:
		validation = opts.FieldValidation
	default:
		validation = metav1.FieldValidationStrict
	}

	if validation == "" {
		validation = metav1.FieldValidationStrict
	}

	return validation
}
