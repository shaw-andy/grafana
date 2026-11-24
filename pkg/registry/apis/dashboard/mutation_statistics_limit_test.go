package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"

	dashv1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	"github.com/grafana/grafana/apps/dashboard/pkg/migration"
	"github.com/grafana/grafana/apps/dashboard/pkg/migration/testutil"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
)

func TestMutateRejectsOversizedCloudWatchStatisticsOnCreateAndUpdate(t *testing.T) {
	migration.Initialize(testutil.NewDataSourceProvider(testutil.StandardTestConfig), testutil.NewLibraryElementProvider(), migration.DefaultCacheTTL)

	// v1beta1.Dashboard is a type alias of v1.Dashboard, so the same admission
	// case handles both API versions.
	tests := []struct {
		name      string
		operation admission.Operation
		options   runtime.Object
	}{
		{
			name:      "create",
			operation: admission.Create,
			options:   &metav1.CreateOptions{},
		},
		{
			name:      "update",
			operation: admission.Update,
			options:   &metav1.UpdateOptions{FieldValidation: metav1.FieldValidationWarn},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := oversizedCloudWatchSpec()
			obj := &dashv1.Dashboard{Spec: common.Unstructured{Object: spec}}
			builder := &DashboardsAPIBuilder{}

			started := time.Now()
			err := builder.Mutate(context.Background(), admission.NewAttributesRecord(
				obj,
				nil,
				dashv1.DashboardResourceInfo.GroupVersionKind(),
				"default",
				"cpu",
				dashv1.DashboardResourceInfo.GroupVersionResource(),
				"",
				tt.operation,
				tt.options,
				false,
				nil,
			), nil)
			elapsed := time.Since(started)

			require.Less(t, elapsed, 500*time.Millisecond)
			targets := spec["panels"].([]interface{})[0].(map[string]interface{})["targets"].([]interface{})
			require.Len(t, targets, 1)
			if tt.operation == admission.Create {
				require.Error(t, err)
			}
		})
	}
}

func oversizedCloudWatchSpec() map[string]interface{} {
	stats := make([]interface{}, 8192)
	for i := range stats {
		stats[i] = "Average"
	}
	return map[string]interface{}{
		"title":         "cloudwatch",
		"schemaVersion": float64(33),
		"panels": []interface{}{
			map[string]interface{}{
				"id":   1,
				"type": "timeseries",
				"targets": []interface{}{
					map[string]interface{}{
						"refId":      "A",
						"dimensions": map[string]interface{}{"InstanceId": "i-123"},
						"namespace":  "AWS/EC2",
						"region":     "us-east-1",
						"metricName": "CPUUtilization",
						"statistics": stats,
					},
				},
			},
		},
	}
}
