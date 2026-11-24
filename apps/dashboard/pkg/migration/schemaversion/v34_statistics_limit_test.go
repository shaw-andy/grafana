package schemaversion_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/apps/dashboard/pkg/migration"
	"github.com/grafana/grafana/apps/dashboard/pkg/migration/schemaversion"
	"github.com/grafana/grafana/apps/dashboard/pkg/migration/testutil"
)

// maxCloudWatchStatisticsPerQuery is the most statistics one CloudWatch query may
// expand into. V34 splits each entry into its own target and, while choosing a
// refId, rescans every target created so far. That rescan is quadratic in the
// length of statistics, and the array is otherwise unbounded.
const maxCloudWatchStatisticsPerQuery = 64

// oversizedStatisticsCount is large enough that the quadratic refId scan takes
// longer than oversizedStatisticsWorkBudget on this code. A length check returns
// before that scan.
const oversizedStatisticsCount = 8192

// oversizedStatisticsWorkBudget is long enough for a length check and short
// enough that the quadratic refId scan cannot finish first.
const oversizedStatisticsWorkBudget = 500 * time.Millisecond

func TestV34AllowsStatisticsAtCap(t *testing.T) {
	dash := cloudWatchDashboard(maxCloudWatchStatisticsPerQuery, false)
	require.NoError(t, schemaversion.V34(context.Background(), dash))

	targets := panelTargets(t, dash, false)
	require.Len(t, targets, maxCloudWatchStatisticsPerQuery)
	requireUniqueRefIDs(t, targets)
}

func TestV34RejectsOneStatisticPastCapWithoutExpanding(t *testing.T) {
	dash := cloudWatchDashboard(maxCloudWatchStatisticsPerQuery+1, false)
	err := schemaversion.V34(context.Background(), dash)
	require.Error(t, err)
	require.Len(t, panelTargets(t, dash, false), 1)
}

func TestV34RejectsOversizedStatisticsBeforeQuadraticRefIDScan(t *testing.T) {
	dash := cloudWatchDashboard(oversizedStatisticsCount, false)
	started := time.Now()
	err := schemaversion.V34(context.Background(), dash)
	elapsed := time.Since(started)

	require.Less(t, elapsed, oversizedStatisticsWorkBudget)
	require.Error(t, err)
	require.Len(t, panelTargets(t, dash, false), 1)
}

func TestV34RejectsOversizedStatisticsInNestedPanel(t *testing.T) {
	dash := cloudWatchDashboard(oversizedStatisticsCount, true)
	started := time.Now()
	err := schemaversion.V34(context.Background(), dash)
	elapsed := time.Since(started)

	require.Less(t, elapsed, oversizedStatisticsWorkBudget)
	require.Error(t, err)
	require.Len(t, panelTargets(t, dash, true), 1)
}

func TestMigrateRejectsOversizedCloudWatchStatistics(t *testing.T) {
	migration.Initialize(testutil.NewDataSourceProvider(testutil.StandardTestConfig), testutil.NewLibraryElementProvider(), migration.DefaultCacheTTL)

	// JSON objects decode schemaVersion as float64. 33 is the last schema
	// before V34, so Migrate's next step is the CloudWatch statistics split.
	dash := cloudWatchDashboard(oversizedStatisticsCount, false)
	dash["schemaVersion"] = float64(33)

	started := time.Now()
	err := migration.Migrate(context.Background(), dash, schemaversion.LATEST_VERSION)
	elapsed := time.Since(started)

	require.Less(t, elapsed, oversizedStatisticsWorkBudget)
	require.Error(t, err)
	require.Len(t, panelTargets(t, dash, false), 1)
}

func TestMigrateStillSplitsASmallCloudWatchStatisticsArray(t *testing.T) {
	migration.Initialize(testutil.NewDataSourceProvider(testutil.StandardTestConfig), testutil.NewLibraryElementProvider(), migration.DefaultCacheTTL)

	dash := cloudWatchDashboard(3, false)
	dash["schemaVersion"] = float64(33)
	require.NoError(t, migration.Migrate(context.Background(), dash, schemaversion.LATEST_VERSION))
	require.GreaterOrEqual(t, len(panelTargets(t, dash, false)), 3)
}

func cloudWatchDashboard(statistics int, nested bool) map[string]interface{} {
	stats := make([]interface{}, statistics)
	for i := range stats {
		stats[i] = fmt.Sprintf("s%d", i)
	}
	target := map[string]interface{}{
		"refId":      "A",
		"dimensions": map[string]interface{}{"InstanceId": "i-123"},
		"namespace":  "AWS/EC2",
		"region":     "us-east-1",
		"metricName": "CPUUtilization",
		"statistics": stats,
	}
	panel := map[string]interface{}{
		"id":      1,
		"type":    "timeseries",
		"targets": []interface{}{target},
	}
	if nested {
		panel = map[string]interface{}{
			"id":     2,
			"type":   "row",
			"panels": []interface{}{panel},
		}
	}
	return map[string]interface{}{
		"title":         "cloudwatch",
		"schemaVersion": 33,
		"panels":        []interface{}{panel},
	}
}

func panelTargets(t *testing.T, dash map[string]interface{}, nested bool) []interface{} {
	t.Helper()
	panels, ok := dash["panels"].([]interface{})
	require.True(t, ok)
	require.NotEmpty(t, panels)
	panel, ok := panels[0].(map[string]interface{})
	require.True(t, ok)
	if nested {
		children, ok := panel["panels"].([]interface{})
		require.True(t, ok)
		require.NotEmpty(t, children)
		panel, ok = children[0].(map[string]interface{})
		require.True(t, ok)
	}
	targets, ok := panel["targets"].([]interface{})
	require.True(t, ok)
	return targets
}

func requireUniqueRefIDs(t *testing.T, targets []interface{}) {
	t.Helper()
	seen := map[string]struct{}{}
	for _, target := range targets {
		query, ok := target.(map[string]interface{})
		require.True(t, ok)
		refID, ok := query["refId"].(string)
		require.True(t, ok)
		require.NotEmpty(t, refID)
		_, dup := seen[refID]
		require.False(t, dup, "duplicate refId %s", refID)
		seen[refID] = struct{}{}
	}
}
