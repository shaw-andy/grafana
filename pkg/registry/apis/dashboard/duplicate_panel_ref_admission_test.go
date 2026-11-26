package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"

	dashv2 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2"
	dashv2alpha1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2alpha1"
	dashv2beta1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2beta1"
)

// TestDuplicatePanelReferencesRejectedByAdmission is the create/update spec.
// Dashboard admission must reject a v2 dashboard whose layout references one
// element more than once. The apiserver passes the client's fieldValidation
// through unchanged, and an empty value is not Strict, so the rejection has to
// happen for Ignore, Warn, Strict, and the empty default.
func TestDuplicatePanelReferencesRejectedByAdmission(t *testing.T) {
	modes := []string{"", metav1.FieldValidationIgnore, metav1.FieldValidationWarn, metav1.FieldValidationStrict}
	ops := []admission.Operation{admission.Create, admission.Update}
	layouts := []string{"grid", "autogrid", "rows", "rows-collapsed", "rows-hidden", "tabs", "rows-autogrid", "tabs-rows-grid", "library"}

	versions := []struct {
		name       string
		apiVersion string
		gvk        schema.GroupVersionKind
		gvr        schema.GroupVersionResource
		decode     func([]byte) (runtime.Object, error)
	}{
		{
			name:       "v2alpha1",
			apiVersion: dashv2alpha1.APIVERSION,
			gvk:        dashv2alpha1.DashboardResourceInfo.GroupVersionKind(),
			gvr:        dashv2alpha1.DashboardResourceInfo.GroupVersionResource(),
			decode: func(raw []byte) (runtime.Object, error) {
				return decodeAdmissionDashboard[*dashv2alpha1.Dashboard](raw)
			},
		},
		{
			name:       "v2beta1",
			apiVersion: dashv2beta1.APIVERSION,
			gvk:        dashv2beta1.DashboardResourceInfo.GroupVersionKind(),
			gvr:        dashv2beta1.DashboardResourceInfo.GroupVersionResource(),
			decode: func(raw []byte) (runtime.Object, error) {
				return decodeAdmissionDashboard[*dashv2beta1.Dashboard](raw)
			},
		},
		{
			name:       "v2",
			apiVersion: dashv2.APIVERSION,
			gvk:        dashv2.DashboardResourceInfo.GroupVersionKind(),
			gvr:        dashv2.DashboardResourceInfo.GroupVersionResource(),
			decode: func(raw []byte) (runtime.Object, error) {
				return decodeAdmissionDashboard[*dashv2.Dashboard](raw)
			},
		},
	}

	for _, ver := range versions {
		for _, layout := range layouts {
			raw := admissionPanelRefDashboard(ver.apiVersion, layout, admissionRepeated("panel-1", 2), "x")
			for _, op := range ops {
				for _, mode := range modes {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", ver.name, layout, op, modeName(mode)), func(t *testing.T) {
						obj, err := ver.decode(raw)
						require.NoError(t, err)
						old, err := ver.decode(raw)
						require.NoError(t, err)
						err = admitDashboard(t, obj, old, ver.gvk, ver.gvr, op, mode)
						require.Error(t, err)
					})
				}
			}
		}
	}
}

// TestUniqueElementReferencesAdmitted keeps a dashboard that references each
// element once admissible under strict validation, for every version.
func TestUniqueElementReferencesAdmitted(t *testing.T) {
	versions := []struct {
		name       string
		apiVersion string
		gvk        schema.GroupVersionKind
		gvr        schema.GroupVersionResource
		decode     func([]byte) (runtime.Object, error)
	}{
		{
			name:       "v2alpha1",
			apiVersion: dashv2alpha1.APIVERSION,
			gvk:        dashv2alpha1.DashboardResourceInfo.GroupVersionKind(),
			gvr:        dashv2alpha1.DashboardResourceInfo.GroupVersionResource(),
			decode: func(raw []byte) (runtime.Object, error) {
				return decodeAdmissionDashboard[*dashv2alpha1.Dashboard](raw)
			},
		},
		{
			name:       "v2beta1",
			apiVersion: dashv2beta1.APIVERSION,
			gvk:        dashv2beta1.DashboardResourceInfo.GroupVersionKind(),
			gvr:        dashv2beta1.DashboardResourceInfo.GroupVersionResource(),
			decode: func(raw []byte) (runtime.Object, error) {
				return decodeAdmissionDashboard[*dashv2beta1.Dashboard](raw)
			},
		},
		{
			name:       "v2",
			apiVersion: dashv2.APIVERSION,
			gvk:        dashv2.DashboardResourceInfo.GroupVersionKind(),
			gvr:        dashv2.DashboardResourceInfo.GroupVersionResource(),
			decode: func(raw []byte) (runtime.Object, error) {
				return decodeAdmissionDashboard[*dashv2.Dashboard](raw)
			},
		},
	}

	for _, ver := range versions {
		t.Run(ver.name, func(t *testing.T) {
			raw := admissionPanelRefDashboard(ver.apiVersion, "grid", []string{"panel-1", "panel-2"}, "x")
			obj, err := ver.decode(raw)
			require.NoError(t, err)
			err = admitDashboard(t, obj, nil, ver.gvk, ver.gvr, admission.Create, metav1.FieldValidationStrict)
			require.NoError(t, err)
		})
	}
}

func admitDashboard(t *testing.T, obj, old runtime.Object, gvk schema.GroupVersionKind, gvr schema.GroupVersionResource, op admission.Operation, fieldValidation string) error {
	t.Helper()
	var options runtime.Object
	switch op {
	case admission.Create:
		options = &metav1.CreateOptions{FieldValidation: fieldValidation}
	case admission.Update:
		options = &metav1.UpdateOptions{FieldValidation: fieldValidation}
	}
	if op != admission.Update {
		old = nil
	}
	b := &DashboardsAPIBuilder{}
	return b.Mutate(context.Background(), admission.NewAttributesRecord(
		obj,
		old,
		gvk,
		"default",
		"panel-ref-bounds",
		gvr,
		"",
		op,
		options,
		false,
		nil,
	), nil)
}

func modeName(mode string) string {
	if mode == "" {
		return "empty"
	}
	return mode
}

func decodeAdmissionDashboard[T any](raw []byte) (T, error) {
	var obj T
	err := json.Unmarshal(raw, &obj)
	return obj, err
}

func admissionRepeated(name string, n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = name
	}
	return names
}

func admissionPanelRefDashboard(apiVersion, layout string, names []string, payload string) []byte {
	library := layout == "library"
	body := fmt.Sprintf(`{
		"kind":"Dashboard",
		"apiVersion":%q,
		"metadata":{"name":"panel-ref-bounds","namespace":"default"},
		"spec":{
			"title":"panel-ref-bounds",
			"cursorSync":"Off",
			"annotations":[],
			"links":[],
			"tags":[],
			"variables":[],
			"preload":false,
			"timeSettings":{"from":"now-6h","to":"now","autoRefresh":"","hideTimepicker":false,"fiscalYearStartMonth":0},
			"elements":%s,
			"layout":%s
		}
	}`, apiVersion, admissionElementsJSON(names, payload, library), admissionLayoutJSON(layout, names))
	return []byte(body)
}

func admissionElementsJSON(names []string, payload string, library bool) string {
	seen := map[string]struct{}{}
	var b strings.Builder
	b.WriteByte('{')
	first := true
	for _, name := range names {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		if !first {
			b.WriteByte(',')
		}
		first = false
		if library {
			fmt.Fprintf(&b, `%q:{"kind":"LibraryPanel","spec":{"id":1,"title":"lib","libraryPanel":{"name":"lib","uid":%q}}}`, name, payload)
		} else {
			fmt.Fprintf(&b, `%q:{"kind":"Panel","spec":{"id":1,"title":"panel","description":"","links":[],"data":{"kind":"QueryGroup","spec":{"queries":[{"kind":"PanelQuery","spec":{"query":{"kind":"grafana-testdata-datasource","spec":{"refId":"A"}},"refId":"A","hidden":false}}],"transformations":[],"queryOptions":{}}},"vizConfig":{"kind":"text","spec":{"pluginVersion":"1.0.0","options":{"blob":%q},"fieldConfig":{"defaults":{},"overrides":[]}}}}}`, name, payload)
		}
	}
	b.WriteByte('}')
	return b.String()
}

func admissionLayoutJSON(layout string, names []string) string {
	grid := `{"kind":"GridLayout","spec":{"items":[` + admissionGridItems(names) + `]}}`
	auto := `{"kind":"AutoGridLayout","spec":{"maxColumnCount":3,"columnWidthMode":"standard","rowHeightMode":"standard","items":[` + admissionAutoItems(names) + `]}}`
	row := func(inner string, collapse, hide *bool) string {
		extra := ""
		if collapse != nil {
			extra += fmt.Sprintf(`,"collapse":%t`, *collapse)
		}
		if hide != nil {
			extra += fmt.Sprintf(`,"hideHeader":%t`, *hide)
		}
		return `{"kind":"RowsLayout","spec":{"rows":[{"kind":"RowsLayoutRow","spec":{"title":"row"` + extra + `,"layout":` + inner + `}}]}}`
	}
	tab := func(inner string) string {
		return `{"kind":"TabsLayout","spec":{"tabs":[{"kind":"TabsLayoutTab","spec":{"title":"tab","layout":` + inner + `}}]}}`
	}
	yes := true
	switch layout {
	case "grid":
		return grid
	case "autogrid", "library":
		return auto
	case "rows":
		return row(grid, nil, nil)
	case "rows-collapsed":
		return row(grid, &yes, nil)
	case "rows-hidden":
		return row(grid, nil, &yes)
	case "tabs":
		return tab(grid)
	case "rows-autogrid":
		return row(auto, nil, nil)
	case "tabs-rows-grid":
		return tab(row(grid, nil, nil))
	default:
		panic("unknown layout " + layout)
	}
}

func admissionGridItems(names []string) string {
	var b strings.Builder
	for i, name := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"kind":"GridLayoutItem","spec":{"x":0,"y":%d,"width":12,"height":8,"element":{"kind":"ElementReference","name":%q}}}`, i, name)
	}
	return b.String()
}

func admissionAutoItems(names []string) string {
	var b strings.Builder
	for i, name := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"kind":"AutoGridLayoutItem","spec":{"element":{"kind":"ElementReference","name":%q}}}`, name)
	}
	return b.String()
}
