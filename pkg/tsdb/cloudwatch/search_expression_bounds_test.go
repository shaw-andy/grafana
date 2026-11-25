package cloudwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/features"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/mocks"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
)

// maxSearchBuildAlloc is the allocation budget for refusing an oversized
// CloudWatch search query. A quadratic join of a few thousand values copies
// tens of megabytes; rejecting during validation stays well under this.
const maxSearchBuildAlloc = 8 << 20

func TestCloudWatchSearchExpressionBounds(t *testing.T) {
	origNewCWClient := NewCWClient
	t.Cleanup(func() {
		NewCWClient = origNewCWClient
	})

	// A builder query the UI can already send: three dimension values become one
	// SEARCH expression, and that expression is what would be sent to AWS.
	t.Run("small multi value search still reaches GetMetricData", func(t *testing.T) {
		client := &mocks.MetricsAPI{}
		NewCWClient = func(aws.Config) models.CWClient { return client }
		client.On("GetMetricData", mock.Anything, mock.Anything, mock.Anything).
			Return(&cloudwatch.GetMetricDataOutput{}, nil).Once()

		_, err := runDimensionQuery(t, false, "", map[string][]string{
			"LoadBalancer": {"lb1", "lb2", "lb3"},
		})
		require.NoError(t, err)
		require.Len(t, client.Calls, 1)
		input := client.Calls[0].Arguments.Get(1).(*cloudwatch.GetMetricDataInput)
		require.NotNil(t, input.MetricDataQueries[0].Expression)
		require.Contains(t, *input.MetricDataQueries[0].Expression, `"lb1" OR "lb2" OR "lb3"`)
	})

	// Attack path: matchExact false, builder search, one dimension, thousands of values.
	// join() appends to a growing string once per value.
	t.Run("matchExact false rejects thousands of dimension values before joining", func(t *testing.T) {
		assertRejectedBeforeAWS(t, false, "", map[string][]string{
			"InstanceId": uniqueValues(2500),
		})
	})

	// IsInferredSearchExpression is also true when matchExact is true and a
	// dimension has more than one value, and buildSearchExpression joins those
	// values on that path too.
	t.Run("matchExact true rejects thousands of dimension values before joining", func(t *testing.T) {
		assertRejectedBeforeAWS(t, true, "", map[string][]string{
			"InstanceId": uniqueValues(2500),
		})
	})

	// appendSearch copies the whole search term once per dimension key.
	t.Run("matchExact false rejects thousands of single value dimensions before appending", func(t *testing.T) {
		assertRejectedBeforeAWS(t, false, "", manyDimensions(2500, []string{"v"}))
	})

	// Wildcard values are omitted from the value join and joined again by name.
	t.Run("matchExact false rejects thousands of wildcard dimensions before joining names", func(t *testing.T) {
		assertRejectedBeforeAWS(t, false, "", manyDimensions(2500, []string{"*"}))
	})

	// MatchExact schema join, plus the label += loop when new label parsing is on.
	t.Run("matchExact true rejects thousands of multi value dimensions before schema and label joins", func(t *testing.T) {
		assertRejectedBeforeAWS(t, true, "", manyDimensions(2000, []string{"a", "b"}))
	})

	// accountId "all" forces an inferred search even when every dimension has one value.
	t.Run("account all rejects thousands of dimensions before the schema join", func(t *testing.T) {
		assertRejectedBeforeAWS(t, true, "all", manyDimensions(2500, []string{"v"}))
	})
}

func assertRejectedBeforeAWS(t *testing.T, matchExact bool, accountID string, dimensions map[string][]string) {
	t.Helper()

	client := &countingMetricsAPI{}
	NewCWClient = func(aws.Config) models.CWClient { return client }

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	_, err := runDimensionQuery(t, matchExact, accountID, dimensions)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)

	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("err=%v alloc=%d elapsed=%s awsCalls=%d", err, alloc, elapsed, client.calls)

	require.Error(t, err, "oversized dimension input must be rejected")
	require.Zero(t, client.calls, "rejection must happen before any CloudWatch API call")
	require.Less(t, alloc, uint64(maxSearchBuildAlloc), "rejection must happen before the quadratic string copies, allocated %d in %s", alloc, elapsed)
}

func runDimensionQuery(t *testing.T, matchExact bool, accountID string, dimensions map[string][]string) (*backend.QueryDataResponse, error) {
	t.Helper()
	ds := newTestDatasource()
	body := dimensionQueryJSON(t, matchExact, accountID, dimensions)
	now := time.Now()
	return ds.QueryData(contextWithFeaturesEnabled(
		features.FlagCloudWatchNewLabelParsing,
		features.FlagCloudWatchCrossAccountQuerying,
	), &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{
			DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{},
		},
		Queries: []backend.DataQuery{{
			RefID: "A",
			TimeRange: backend.TimeRange{
				From: now.Add(-time.Hour),
				To:   now,
			},
			JSON: body,
		}},
	})
}

func dimensionQueryJSON(t *testing.T, matchExact bool, accountID string, dimensions map[string][]string) json.RawMessage {
	t.Helper()
	payload := map[string]any{
		"type":             "timeSeriesQuery",
		"namespace":        "AWS/EC2",
		"metricName":       "CPUUtilization",
		"region":           "us-east-1",
		"statistic":        "Average",
		"period":           "300",
		"matchExact":       matchExact,
		"metricQueryType":  0,
		"metricEditorMode": 0,
		"dimensions":       dimensions,
	}
	if accountID != "" {
		payload["accountId"] = accountID
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	return raw
}

func uniqueValues(n int) []string {
	values := make([]string, n)
	for i := range values {
		values[i] = fmt.Sprintf("v%05d", i)
	}
	return values
}

func manyDimensions(n int, values []string) map[string][]string {
	dimensions := make(map[string][]string, n)
	copied := append([]string(nil), values...)
	for i := 0; i < n; i++ {
		dimensions[fmt.Sprintf("k%04d", i)] = copied
	}
	return dimensions
}

// countingMetricsAPI records CloudWatch calls. The methods that build the
// search expression return before any of these on a rejected query.
type countingMetricsAPI struct {
	mocks.MetricsAPI
	calls int
}

func (c *countingMetricsAPI) GetMetricData(context.Context, *cloudwatch.GetMetricDataInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	c.calls++
	return &cloudwatch.GetMetricDataOutput{}, nil
}

func (c *countingMetricsAPI) ListMetrics(context.Context, *cloudwatch.ListMetricsInput, ...func(*cloudwatch.Options)) (*cloudwatch.ListMetricsOutput, error) {
	c.calls++
	return &cloudwatch.ListMetricsOutput{}, nil
}
