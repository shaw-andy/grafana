package conversion

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"

	dashv0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	dashv1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	dashv2 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2"
	dashv2alpha1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2alpha1"
	dashv2beta1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2beta1"
)

// duplicatePanelRefLayouts are the v2 layout shapes whose converters emit one
// v1 panel per item (grid, rows, collapsed rows, hidden-header rows, tabs,
// auto grid, and the nested combinations of those).
var duplicatePanelRefLayouts = []string{
	"grid",
	"autogrid",
	"rows",
	"rows-collapsed",
	"rows-hidden",
	"tabs",
	"rows-autogrid",
	"tabs-rows-grid",
	"library",
}

const (
	duplicatePanelRefCount   = 20
	duplicatePanelPayloadLen = 4096
	// One emitted copy of the payload plus dashboard chrome. Twenty copies are ~80KB of payload alone.
	duplicatePanelMaxOutputBytes = 48 * 1024
)

// TestDuplicatePanelReferencesDoNotExpandOnConversion is the read-path spec.
// A stored v2 dashboard may be served as v1 or v0alpha1. Conversion must fail
// when a layout item repeats an element name, and the object it leaves behind
// must not already contain one serialised copy of that element per reference.
// The registered scheme is the function the apiserver runs for those reads.
func TestDuplicatePanelReferencesDoNotExpandOnConversion(t *testing.T) {
	scheme := setupTestConversionScheme(t)
	payload := strings.Repeat("P", duplicatePanelPayloadLen)

	versions := []struct {
		name       string
		apiVersion string
		decode     func([]byte) (runtime.Object, error)
	}{
		{
			name:       "v2alpha1",
			apiVersion: dashv2alpha1.APIVERSION,
			decode: func(raw []byte) (runtime.Object, error) {
				return decodeDashboard[*dashv2alpha1.Dashboard](raw)
			},
		},
		{
			name:       "v2beta1",
			apiVersion: dashv2beta1.APIVERSION,
			decode: func(raw []byte) (runtime.Object, error) {
				return decodeDashboard[*dashv2beta1.Dashboard](raw)
			},
		},
		{
			name:       "v2",
			apiVersion: dashv2.APIVERSION,
			decode: func(raw []byte) (runtime.Object, error) {
				return decodeDashboard[*dashv2.Dashboard](raw)
			},
		},
	}

	targets := []struct {
		name string
		new  func() runtime.Object
	}{
		{name: "v1", new: func() runtime.Object { return &dashv1.Dashboard{} }},
		{name: "v0alpha1", new: func() runtime.Object { return &dashv0.Dashboard{} }},
	}

	for _, ver := range versions {
		for _, layout := range duplicatePanelRefLayouts {
			raw := panelRefDashboard(ver.apiVersion, layout, repeatedNames("panel-1", duplicatePanelRefCount), payload)
			in, err := ver.decode(raw)
			require.NoError(t, err, "decode %s %s", ver.name, layout)

			for _, target := range targets {
				t.Run(ver.name+"/"+layout+"/to_"+target.name, func(t *testing.T) {
					out := target.new()
					err := scheme.Convert(in.DeepCopyObject(), out, nil)
					assertConvertedDashboardBounded(t, err, out, payload)
				})
			}
		}
	}
}

// TestConvertDashboardV2alpha1ToV1RejectsDuplicateElementRefs covers the function
// the version chain calls directly, including layouts that only that function walks.
func TestConvertDashboardV2alpha1ToV1RejectsDuplicateElementRefs(t *testing.T) {
	payload := strings.Repeat("P", duplicatePanelPayloadLen)
	for _, layout := range duplicatePanelRefLayouts {
		t.Run(layout, func(t *testing.T) {
			raw := panelRefDashboard(dashv2alpha1.APIVERSION, layout, repeatedNames("panel-1", duplicatePanelRefCount), payload)
			in, err := decodeDashboard[*dashv2alpha1.Dashboard](raw)
			require.NoError(t, err)

			out := &dashv1.Dashboard{}
			err = ConvertDashboard_V2alpha1_to_V1(in, out, nil)
			assertConvertedDashboardBounded(t, err, out, payload)
		})
	}
}

// TestUniqueElementReferencesStillConvert keeps a dashboard that references each
// element once on the successful conversion path.
func TestUniqueElementReferencesStillConvert(t *testing.T) {
	scheme := setupTestConversionScheme(t)
	payload := strings.Repeat("P", 32)
	raw := panelRefDashboard(dashv2alpha1.APIVERSION, "grid", []string{"panel-1", "panel-2"}, payload)
	// Second element carries no payload so a single copy of the marker is expected.
	in, err := decodeDashboard[*dashv2alpha1.Dashboard](raw)
	require.NoError(t, err)
	in.Spec.Elements["panel-2"].PanelKind.Spec.VizConfig.Spec.Options = map[string]interface{}{}

	for _, target := range []runtime.Object{&dashv1.Dashboard{}, &dashv0.Dashboard{}} {
		out := target.DeepCopyObject()
		err := scheme.Convert(in.DeepCopyObject(), out, nil)
		require.NoError(t, err)
		encoded, mErr := json.Marshal(out)
		require.NoError(t, mErr)
		require.Equal(t, 1, strings.Count(string(encoded), payload))
	}
}

// TestDuplicatePanelReferencesRejectedBySchemaValidation is the write-path spec
// for the CUE validators used by dashboard admission.
func TestDuplicatePanelReferencesRejectedBySchemaValidation(t *testing.T) {
	payload := "x"
	for _, layout := range duplicatePanelRefLayouts {
		t.Run("reject/"+layout, func(t *testing.T) {
			names := repeatedNames("panel-1", 2)
			require.NotEmpty(t, dashv2alpha1.ValidateDashboardSpec(mustDashboard[*dashv2alpha1.Dashboard](t, dashv2alpha1.APIVERSION, layout, names, payload)))
			require.NotEmpty(t, dashv2beta1.ValidateDashboardSpec(mustDashboard[*dashv2beta1.Dashboard](t, dashv2beta1.APIVERSION, layout, names, payload)))
			require.NotEmpty(t, dashv2.ValidateDashboardSpec(mustDashboard[*dashv2.Dashboard](t, dashv2.APIVERSION, layout, names, payload)))
		})
	}

	for _, layout := range duplicatePanelRefLayouts {
		t.Run("accept/"+layout, func(t *testing.T) {
			names := []string{"panel-1"}
			if layout != "library" {
				names = []string{"panel-1", "panel-2"}
			}
			require.Empty(t, dashv2alpha1.ValidateDashboardSpec(mustDashboard[*dashv2alpha1.Dashboard](t, dashv2alpha1.APIVERSION, layout, names, payload)))
			require.Empty(t, dashv2beta1.ValidateDashboardSpec(mustDashboard[*dashv2beta1.Dashboard](t, dashv2beta1.APIVERSION, layout, names, payload)))
			require.Empty(t, dashv2.ValidateDashboardSpec(mustDashboard[*dashv2.Dashboard](t, dashv2.APIVERSION, layout, names, payload)))
		})
	}
}

func assertConvertedDashboardBounded(t *testing.T, convErr error, out runtime.Object, payload string) {
	t.Helper()
	encoded, err := json.Marshal(out)
	require.NoError(t, err)
	copies := strings.Count(string(encoded), payload)
	require.Errorf(t, convErr, "conversion succeeded and repeated the panel payload %d times (%d bytes)", copies, len(encoded))
	require.LessOrEqualf(t, copies, 1, "conversion wrote %d copies of the panel payload (%d bytes) before returning %v", copies, len(encoded), convErr)
	require.Lessf(t, len(encoded), duplicatePanelMaxOutputBytes, "conversion left %d bytes encoded after error %v", len(encoded), convErr)
}

func mustDashboard[T any](t *testing.T, apiVersion, layout string, names []string, payload string) T {
	t.Helper()
	obj, err := decodeDashboard[T](panelRefDashboard(apiVersion, layout, names, payload))
	require.NoError(t, err)
	return obj
}

func decodeDashboard[T any](raw []byte) (T, error) {
	var obj T
	err := json.Unmarshal(raw, &obj)
	return obj, err
}

func repeatedNames(name string, n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = name
	}
	return names
}

func panelRefDashboard(apiVersion, layout string, names []string, payload string) []byte {
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
	}`, apiVersion, elementsJSON(names, payload, library), layoutJSON(layout, names))
	return []byte(body)
}

func elementsJSON(names []string, payload string, library bool) string {
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

func layoutJSON(layout string, names []string) string {
	grid := `{"kind":"GridLayout","spec":{"items":[` + gridItems(names) + `]}}`
	auto := `{"kind":"AutoGridLayout","spec":{"maxColumnCount":3,"columnWidthMode":"standard","rowHeightMode":"standard","items":[` + autoItems(names) + `]}}`
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

func gridItems(names []string) string {
	var b strings.Builder
	for i, name := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"kind":"GridLayoutItem","spec":{"x":0,"y":%d,"width":12,"height":8,"element":{"kind":"ElementReference","name":%q}}}`, i, name)
	}
	return b.String()
}

func autoItems(names []string) string {
	var b strings.Builder
	for i, name := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"kind":"AutoGridLayoutItem","spec":{"element":{"kind":"ElementReference","name":%q}}}`, name)
	}
	return b.String()
}
