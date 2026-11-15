package dashboard

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"

	dashv0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	dashv1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
)

func TestDashboardAdmissionRejectsLibraryPanelUIDTraversal(t *testing.T) {
	// Legacy POST /api/dashboards/db stores a v0 dashboard with FieldValidationIgnore.
	// A uid that is not a short uid must be rejected there, including when it is nested
	// in a collapsed row, and the rejection must still happen when field validation is ignored.
	cases := []struct {
		name string
		uid  string
	}{
		{name: "parent directory logout", uid: "../../logout"},
		{name: "parent directory switch org", uid: "../../profile/switch-org/2"},
		{name: "percent encoded parent directory", uid: "%2e%2e/%2e%2e/logout"},
		{name: "slash", uid: "foo/bar"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			obj := legacyDashboardWithLibraryPanelUID(tt.uid, tt.uid)
			err := admitDashboard(t, obj, metav1.FieldValidationIgnore)
			require.Error(t, err)
		})
	}
}

func TestDashboardAdmissionKeepsValidLibraryPanelUID(t *testing.T) {
	const uid = "panel_ok"
	obj := legacyDashboardWithLibraryPanelUID(uid, uid)

	require.NoError(t, admitDashboard(t, obj, metav1.FieldValidationIgnore))

	panels := obj.Spec.Object["panels"].([]interface{})
	require.Equal(t, uid, libraryPanelUID(t, panels[0]))

	row := panels[1].(map[string]interface{})
	nested := row["panels"].([]interface{})
	require.Equal(t, uid, libraryPanelUID(t, nested[0]))
}

func admitDashboard(t *testing.T, obj runtime.Object, fieldValidation string) error {
	t.Helper()
	builder := &DashboardsAPIBuilder{}
	return builder.Mutate(context.Background(), admission.NewAttributesRecord(
		obj,
		nil,
		dashv1.DashboardResourceInfo.GroupVersionKind(),
		"default",
		"dashuid",
		dashv1.DashboardResourceInfo.GroupVersionResource(),
		"",
		admission.Create,
		&metav1.CreateOptions{FieldValidation: fieldValidation},
		false,
		nil,
	), nil)
}

func legacyDashboardWithLibraryPanelUID(topLevelUID, rowUID string) *dashv0.Dashboard {
	return &dashv0.Dashboard{
		Spec: common.Unstructured{Object: map[string]interface{}{
			"title":         "Planted",
			"uid":           "dashuid",
			"schemaVersion": float64(42),
			"panels": []interface{}{
				map[string]interface{}{
					"id":    float64(1),
					"type":  "timeseries",
					"title": "Planted",
					"gridPos": map[string]interface{}{
						"h": float64(8), "w": float64(12), "x": float64(0), "y": float64(0),
					},
					"libraryPanel": map[string]interface{}{
						"name": "Planted",
						"uid":  topLevelUID,
					},
				},
				map[string]interface{}{
					"id":        float64(2),
					"type":      "row",
					"title":     "Row",
					"collapsed": true,
					"gridPos": map[string]interface{}{
						"h": float64(1), "w": float64(24), "x": float64(0), "y": float64(8),
					},
					"panels": []interface{}{
						map[string]interface{}{
							"id":    float64(3),
							"type":  "timeseries",
							"title": "Nested",
							"gridPos": map[string]interface{}{
								"h": float64(8), "w": float64(12), "x": float64(0), "y": float64(9),
							},
							"libraryPanel": map[string]interface{}{
								"name": "Nested",
								"uid":  rowUID,
							},
						},
					},
				},
			},
		}},
	}
}

func libraryPanelUID(t *testing.T, panel interface{}) string {
	t.Helper()
	asMap, ok := panel.(map[string]interface{})
	require.True(t, ok)
	libraryPanel, ok := asMap["libraryPanel"].(map[string]interface{})
	require.True(t, ok)
	uid, ok := libraryPanel["uid"].(string)
	require.True(t, ok)
	return uid
}
