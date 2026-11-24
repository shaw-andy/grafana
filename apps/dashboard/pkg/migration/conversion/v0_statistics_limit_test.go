package conversion

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	dashv0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	dashv1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	"github.com/grafana/grafana/apps/dashboard/pkg/migration"
	"github.com/grafana/grafana/apps/dashboard/pkg/migration/testutil"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
)

func TestConvertDashboardV0ToV1RejectsOversizedCloudWatchStatistics(t *testing.T) {
	migration.Initialize(testutil.NewDataSourceProvider(testutil.StandardTestConfig), testutil.NewLibraryElementProvider(), migration.DefaultCacheTTL)

	// v0 saves skip schema migration. A later v1 or v2 read converts through
	// ConvertDashboard_V0_to_V1, which migrates to the latest schema and therefore
	// runs V34. v0 to v2alpha1 and v0 to v2beta1 call this function first.
	spec := cloudWatchSpec(8192)
	in := &dashv0.Dashboard{
		ObjectMeta: metav1.ObjectMeta{Name: "cpu", Namespace: "default"},
		Spec:       common.Unstructured{Object: spec},
	}
	out := &dashv1.Dashboard{}

	started := time.Now()
	err := ConvertDashboard_V0_to_V1(in, out, nil)
	elapsed := time.Since(started)

	require.Less(t, elapsed, 500*time.Millisecond)
	require.Error(t, err)
	targets := spec["panels"].([]interface{})[0].(map[string]interface{})["targets"].([]interface{})
	require.Len(t, targets, 1)
}

func cloudWatchSpec(statistics int) map[string]interface{} {
	stats := make([]interface{}, statistics)
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
