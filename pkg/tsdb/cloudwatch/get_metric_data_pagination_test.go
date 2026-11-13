package cloudwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"github.com/grafana/grafana-aws-sdk/pkg/awsds"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/config"

	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsso"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/features"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"

	"github.com/stretchr/testify/require"
)

// pagingGetMetricDataClient records each GetMetricData call as it happens.
// executeRequest mutates one GetMetricDataInput in place, so the end time has to
// be copied during the call. Pages advance only when the request carries the
// token returned by the previous page, which is how GetMetricData pagination works.
type pagingGetMetricDataClient struct {
	models.CWClient

	maxPages   int
	calls      int
	lastToken  string
	endTimes   []time.Time
	startTimes []time.Time
	values     []float64
}

func (c *pagingGetMetricDataClient) GetMetricData(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	if input.EndTime == nil || input.StartTime == nil {
		return nil, fmt.Errorf("GetMetricData input is missing a time bound")
	}
	if c.calls > 0 && (input.NextToken == nil || *input.NextToken != c.lastToken) {
		return nil, fmt.Errorf("page %d was requested without the token from the previous page", c.calls+1)
	}

	c.calls++
	c.endTimes = append(c.endTimes, input.EndTime.UTC())
	c.startTimes = append(c.startTimes, input.StartTime.UTC())
	value := float64(c.calls)
	c.values = append(c.values, value)

	out := &cloudwatch.GetMetricDataOutput{
		MetricDataResults: []cloudwatchtypes.MetricDataResult{{
			StatusCode: cloudwatchtypes.StatusCodeComplete,
			Id:         aws.String("a"),
			Label:      aws.String("NetworkOut"),
			Values:     []float64{value},
			Timestamps: []time.Time{time.Unix(int64(c.calls), 0).UTC()},
		}},
	}
	if c.calls < c.maxPages {
		c.lastToken = fmt.Sprintf("token-%d", c.calls)
		out.NextToken = aws.String(c.lastToken)
	}
	return out, nil
}

func TestExecuteRequest_roundsEndTimeOnceAcrossPages(t *testing.T) {
	start := time.Date(2024, 5, 1, 0, 45, 4, 0, time.UTC)

	t.Run("feature enabled and end time is not on a minute boundary", func(t *testing.T) {
		end := time.Date(2024, 5, 1, 1, 45, 4, 0, time.UTC)
		client := runPagedExecuteRequest(t, end, start, 3, 50, true)
		require.Equal(t, 3, client.calls)
		requireSameInstant(t, end.Truncate(time.Minute).Add(time.Minute), client.endTimes)
		requireSameInstant(t, start, client.startTimes)
	})

	t.Run("feature enabled and end time is already on a minute boundary", func(t *testing.T) {
		end := time.Date(2024, 5, 1, 1, 45, 0, 0, time.UTC)
		client := runPagedExecuteRequest(t, end, start, 3, 50, true)
		require.Equal(t, 3, client.calls)
		requireSameInstant(t, end.Truncate(time.Minute).Add(time.Minute), client.endTimes)
		requireSameInstant(t, start, client.startTimes)
	})

	t.Run("feature disabled leaves the requested end time on every page", func(t *testing.T) {
		end := time.Date(2024, 5, 1, 1, 45, 4, 0, time.UTC)
		client := runPagedExecuteRequest(t, end, start, 3, 50, false)
		require.Equal(t, 3, client.calls)
		requireSameInstant(t, end, client.endTimes)
		requireSameInstant(t, start, client.startTimes)
	})
}

func TestExecuteRequest_stopsAtListMetricsPageLimit(t *testing.T) {
	start := time.Date(2024, 5, 1, 0, 45, 4, 0, time.UTC)
	end := time.Date(2024, 5, 1, 1, 45, 4, 0, time.UTC)

	t.Run("keeps the pages already fetched and does not request a page past the limit", func(t *testing.T) {
		const pageLimit = 3
		const pagesAvailable = 8
		client, pages := runPagedExecuteRequestResult(t, end, start, pagesAvailable, pageLimit, true)
		require.Equal(t, pageLimit, client.calls)
		require.Equal(t, []float64{1, 2, 3}, client.values)
		require.Len(t, pages, pageLimit)
		for i, page := range pages {
			require.Equal(t, []float64{float64(i + 1)}, page.MetricDataResults[0].Values)
		}
		requireSameInstant(t, end.Truncate(time.Minute).Add(time.Minute), client.endTimes)
	})

	t.Run("the page limit applies when end time rounding is disabled", func(t *testing.T) {
		const pageLimit = 3
		client, pages := runPagedExecuteRequestResult(t, end, start, 8, pageLimit, false)
		require.Equal(t, pageLimit, client.calls)
		require.Len(t, pages, pageLimit)
		requireSameInstant(t, end, client.endTimes)
	})

	t.Run("returns every page when the result ends before the limit", func(t *testing.T) {
		const pageLimit = 5
		client, pages := runPagedExecuteRequestResult(t, end, start, 2, pageLimit, true)
		require.Equal(t, 2, client.calls)
		require.Len(t, pages, 2)
		require.Equal(t, []float64{1, 2}, client.values)
		requireSameInstant(t, end.Truncate(time.Minute).Add(time.Minute), client.endTimes)
	})

	t.Run("a datasource with no configured page limit uses the default of 500", func(t *testing.T) {
		ctx, pageLimit := cloudWatchQueryContext(t, "")
		require.Equal(t, 500, pageLimit)
		loaded := loadCloudWatchSettings(t, ctx)
		require.Equal(t, 500, loaded.GrafanaSettings.ListMetricsPageLimit)

		client := &pagingGetMetricDataClient{maxPages: pageLimit + 1}
		ds := &DataSource{Settings: loaded}
		pages, err := ds.executeRequest(ctx, client, &cloudwatch.GetMetricDataInput{
			StartTime: aws.Time(start),
			EndTime:   aws.Time(end),
		})
		require.NoError(t, err)
		require.Equal(t, pageLimit, client.calls)
		require.Len(t, pages, pageLimit)
		require.Equal(t, float64(1), pages[0].MetricDataResults[0].Values[0])
		require.Equal(t, float64(pageLimit), pages[pageLimit-1].MetricDataResults[0].Values[0])
		requireSameInstant(t, end.Truncate(time.Minute).Add(time.Minute), client.endTimes)
	})
}

func TestQueryData_GetMetricData_pageLimitAndEndTime(t *testing.T) {
	start := time.Date(2024, 5, 1, 0, 45, 4, 0, time.UTC)
	end := time.Date(2024, 5, 1, 1, 45, 4, 0, time.UTC)
	ctx, pageLimit := cloudWatchQueryContext(t, "3")
	require.Equal(t, 3, pageLimit)
	require.Equal(t, featuremgmt.FlagCloudWatchRoundUpEndTime, features.FlagCloudWatchRoundUpEndTime)
	require.True(t, features.IsEnabled(ctx, features.FlagCloudWatchRoundUpEndTime))

	// timeSeriesQuery and an omitted type are the two QueryData branches that run a
	// metric query. Alert and expression requests for a metric query use those same
	// branches; only log queries take a different path.
	cases := []struct {
		name      string
		queryType string
		headers   map[string]string
	}{
		{name: "time series query", queryType: timeSeriesQuery},
		{name: "omitted query type", queryType: ""},
		{name: "alert metric query", queryType: timeSeriesQuery, headers: map[string]string{headerFromAlert: "true"}},
		{name: "expression metric query", queryType: timeSeriesQuery, headers: map[string]string{headerFromExpression: "true"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const pagesAvailable = 8
			client := &pagingGetMetricDataClient{maxPages: pagesAvailable}
			ds := datasourceWithSettings(t, ctx, client)

			resp, err := ds.QueryData(ctx, &backend.QueryDataRequest{
				PluginContext: backend.PluginContext{DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{}},
				Headers:       tc.headers,
				Queries: []backend.DataQuery{{
					RefID:     "A",
					TimeRange: backend.TimeRange{From: start, To: end},
					JSON:      metricQueryJSON(t, tc.queryType),
				}},
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NoError(t, resp.Responses["A"].Error)
			require.Equal(t, pageLimit, client.calls)
			require.Equal(t, []float64{1, 2, 3}, client.values)
			requireSameInstant(t, end.Truncate(time.Minute).Add(time.Minute), client.endTimes)
			requireSameInstant(t, start, client.startTimes)
			require.Equal(t, pageLimit, responsePointCount(t, resp.Responses["A"]))
		})
	}
}

func runPagedExecuteRequest(t *testing.T, end, start time.Time, pagesAvailable, pageLimit int, roundUp bool) *pagingGetMetricDataClient {
	t.Helper()
	client, _ := runPagedExecuteRequestResult(t, end, start, pagesAvailable, pageLimit, roundUp)
	return client
}

func runPagedExecuteRequestResult(t *testing.T, end, start time.Time, pagesAvailable, pageLimit int, roundUp bool) (*pagingGetMetricDataClient, []*cloudwatch.GetMetricDataOutput) {
	t.Helper()
	ctx := context.Background()
	if roundUp {
		ctx = contextWithFeaturesEnabled(features.FlagCloudWatchRoundUpEndTime)
	}
	client := &pagingGetMetricDataClient{maxPages: pagesAvailable}
	ds := &DataSource{Settings: models.CloudWatchSettings{
		GrafanaSettings: awsds.AuthSettings{ListMetricsPageLimit: pageLimit},
	}}
	pages, err := ds.executeRequest(ctx, client, &cloudwatch.GetMetricDataInput{
		StartTime: aws.Time(start),
		EndTime:   aws.Time(end),
	})
	require.NoError(t, err)
	return client, pages
}

func cloudWatchQueryContext(t *testing.T, pageLimit string) (context.Context, int) {
	t.Helper()
	cfg := setting.NewCfg()
	_, err := cfg.Raw.Section("aws").NewKey("forward_settings_to_plugins", "cloudwatch")
	require.NoError(t, err)
	if pageLimit != "" {
		_, err = cfg.Raw.Section("aws").NewKey("list_metrics_page_limit", pageLimit)
		require.NoError(t, err)
	}

	featureManager, err := featuremgmt.ProvideManagerService(cfg)
	require.NoError(t, err)
	require.True(t, featureManager.IsEnabledGlobally(featuremgmt.FlagCloudWatchRoundUpEndTime))

	instanceCfg, err := pluginconfig.ProvidePluginInstanceConfig(cfg, setting.ProvideProvider(cfg), featureManager)
	require.NoError(t, err)
	requestConfig := pluginconfig.NewRequestConfigProvider(instanceCfg, noopSSOSettings{}).PluginRequestConfig(context.Background(), "cloudwatch", nil)
	ctx := config.WithGrafanaConfig(context.Background(), config.NewGrafanaCfg(requestConfig))
	require.True(t, features.IsEnabled(ctx, features.FlagCloudWatchRoundUpEndTime))

	authSettings, _ := awsds.ReadAuthSettingsFromContext(ctx)
	require.NotNil(t, authSettings)
	return ctx, authSettings.ListMetricsPageLimit
}

func loadCloudWatchSettings(t *testing.T, ctx context.Context) models.CloudWatchSettings {
	t.Helper()
	loaded, err := models.LoadCloudWatchSettings(ctx, backend.DataSourceInstanceSettings{
		JSONData: []byte(`{"region":"us-east-2"}`),
	})
	require.NoError(t, err)
	return loaded
}

func datasourceWithSettings(t *testing.T, ctx context.Context, client *pagingGetMetricDataClient) *DataSource {
	t.Helper()
	loaded := loadCloudWatchSettings(t, ctx)
	ds := newTestDatasource(func(ds *DataSource) {
		ds.Settings = loaded
	})
	origNewCWClient := NewCWClient
	t.Cleanup(func() {
		NewCWClient = origNewCWClient
	})
	NewCWClient = func(aws.Config) models.CWClient {
		return client
	}
	return ds
}

func metricQueryJSON(t *testing.T, queryType string) json.RawMessage {
	t.Helper()
	payload := map[string]any{
		"subtype":    "metrics",
		"namespace":  "AWS/EC2",
		"metricName": "NetworkOut",
		"expression": "",
		"dimensions": map[string]any{
			"InstanceId": "i-00645d91ed77d87ac",
		},
		"region":     "us-east-2",
		"id":         "a",
		"statistics": []string{"Maximum"},
		"period":     "300",
		"hide":       false,
		"matchExact": true,
		"refId":      "A",
	}
	if queryType != "" {
		payload["type"] = queryType
	}
	encoded, err := json.Marshal(payload)
	require.NoError(t, err)
	return encoded
}

func responsePointCount(t *testing.T, response backend.DataResponse) int {
	t.Helper()
	total := 0
	for _, frame := range response.Frames {
		total += frame.Rows()
	}
	return total
}

func requireSameInstant(t *testing.T, want time.Time, got []time.Time) {
	t.Helper()
	require.NotEmpty(t, got)
	for i, actual := range got {
		require.Truef(t, want.Equal(actual), "call %d end or start time = %s, want %s on every page", i+1, actual.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}

type noopSSOSettings struct{}

func (noopSSOSettings) GetForProvider(context.Context, string) (*pluginsso.Settings, error) {
	return &pluginsso.Settings{}, nil
}
