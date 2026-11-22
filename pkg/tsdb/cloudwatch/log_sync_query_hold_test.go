package cloudwatch

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-aws-sdk/pkg/awsds"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/config"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
)

// runningLogsClient stands in for CloudWatch Logs. GetQueryResults reports Running
// while the request context is active, which is the status syncQuery treats as
// "not finished". A cancelled context returns the context error, matching a call
// that observes the context passed into CWLogsClient.GetQueryResults.
type runningLogsClient struct {
	fakeCWLogsClient

	mu     sync.Mutex
	starts []*cloudwatchlogs.StartQueryInput
	gets   int
	stops  []*cloudwatchlogs.StopQueryInput
}

func (c *runningLogsClient) StartQuery(_ context.Context, input *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	c.mu.Lock()
	c.starts = append(c.starts, input)
	c.mu.Unlock()
	return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String("logs-query-id")}, nil
}

func (c *runningLogsClient) GetQueryResults(ctx context.Context, input *cloudwatchlogs.GetQueryResultsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	c.mu.Lock()
	c.gets++
	c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if input == nil || input.QueryId == nil || *input.QueryId != "logs-query-id" {
		return nil, context.Canceled
	}
	return &cloudwatchlogs.GetQueryResultsOutput{Status: "Running"}, nil
}

func (c *runningLogsClient) StopQuery(_ context.Context, input *cloudwatchlogs.StopQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error) {
	c.mu.Lock()
	c.stops = append(c.stops, input)
	c.mu.Unlock()
	return &cloudwatchlogs.StopQueryOutput{Success: true}, nil
}

func (c *runningLogsClient) counts() (starts, gets, stops int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.starts), c.gets, len(c.stops)
}

func (c *runningLogsClient) startedQuery() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.starts) == 0 || c.starts[0].QueryString == nil {
		return ""
	}
	return *c.starts[0].QueryString
}

// queryJSONAsPostedQuery is the transformation parseMetricRequest applies to a
// query object on the default /api/ds/query path: simplejson.MarshalJSON of the
// posted query, with no type field added.
func queryJSONAsPostedQuery(t *testing.T, raw string) json.RawMessage {
	t.Helper()
	parsed, err := simplejson.NewJson([]byte(raw))
	require.NoError(t, err)
	encoded, err := parsed.MarshalJSON()
	require.NoError(t, err)
	return encoded
}

func TestOmittedTypeLogsQueryDoesNotSyncPoll(t *testing.T) {
	settingCtx := config.WithGrafanaConfig(context.Background(), config.NewGrafanaCfg(map[string]string{
		awsds.AllowedAuthProvidersEnvVarKeyName: "default,keys,credentials",
		awsds.AssumeRoleEnabledEnvVarKeyName:    "false",
		awsds.SessionDurationEnvVarKeyName:      "10m",
	}))
	loaded, err := models.LoadCloudWatchSettings(settingCtx, backend.DataSourceInstanceSettings{
		JSONData: []byte(`{"authType":"default","defaultRegion":"us-east-1"}`),
	})
	require.NoError(t, err)
	require.Equal(t, 30*time.Minute, loaded.LogsTimeout.Duration)

	// These are the shapes a caller of POST /api/ds/query can put in queries[]
	// without FromAlert or X-Grafana-From-Expr. None names an alert, expression,
	// or public-dashboard signal. type is missing, empty, or JSON null.
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "missing type and logsMode",
			raw: `{
				"refId": "A",
				"datasource": {"type": "cloudwatch", "uid": "cw"},
				"queryMode": "Logs",
				"region": "us-east-1",
				"expression": "fields @timestamp, @message | filter @message like /ERROR/",
				"logGroups": [{"arn": "arn:aws:logs:us-east-1:123456789012:log-group:app", "name": "app"}]
			}`,
		},
		{
			name: "empty type and empty logsMode",
			raw: `{
				"refId": "A",
				"datasource": {"type": "cloudwatch", "uid": "cw"},
				"queryMode": "Logs",
				"logsMode": "",
				"type": "",
				"region": "us-east-1",
				"expression": "fields @timestamp, @message | filter @message like /ERROR/"
			}`,
		},
		{
			name: "null type and null logsMode",
			raw: `{
				"refId": "A",
				"datasource": {"type": "cloudwatch", "uid": "cw"},
				"queryMode": "Logs",
				"logsMode": null,
				"type": null,
				"region": "us-east-1",
				"expression": "fields @timestamp, @message | stats count() by bin(5m)"
			}`,
		},
		{
			name: "logsMode Insights with type omitted",
			raw: `{
				"refId": "A",
				"datasource": {"type": "cloudwatch", "uid": "cw"},
				"queryMode": "Logs",
				"logsMode": "Insights",
				"region": "us-east-1",
				"expression": "fields @timestamp, @message"
			}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			posted := queryJSONAsPostedQuery(t, tc.raw)
			var probe DataQueryJson
			require.NoError(t, json.Unmarshal(posted, &probe))
			require.Empty(t, probe.Type)
			require.Equal(t, "Logs", string(probe.QueryMode))

			assertOmittedTypeDoesNotHold(t, []backend.DataQuery{{
				RefID:     "A",
				TimeRange: backend.TimeRange{From: time.Unix(0, 0), To: time.Unix(60, 0)},
				JSON:      posted,
			}}, loaded.LogsTimeout.Duration)
		})
	}

	t.Run("first omitted-type logs query selects the path for every query in the request", func(t *testing.T) {
		first := queryJSONAsPostedQuery(t, `{
			"refId": "A",
			"queryMode": "Logs",
			"region": "us-east-1",
			"expression": "fields @message"
		}`)
		second := queryJSONAsPostedQuery(t, `{
			"refId": "B",
			"queryMode": "Logs",
			"region": "us-east-1",
			"expression": "fields @timestamp"
		}`)
		assertOmittedTypeDoesNotHold(t, []backend.DataQuery{
			{RefID: "A", TimeRange: backend.TimeRange{From: time.Unix(0, 0), To: time.Unix(60, 0)}, JSON: first},
			{RefID: "B", TimeRange: backend.TimeRange{From: time.Unix(0, 0), To: time.Unix(60, 0)}, JSON: second},
		}, loaded.LogsTimeout.Duration)
	})
}

// assertOmittedTypeDoesNotHold fails while QueryData treats a logs query with no
// type as a synchronous public-dashboard query. That path starts a CloudWatch
// Logs Insights query and then polls GetQueryResults once a second until the
// datasource logs timeout, which defaults to 30 minutes. The request context
// stays active, which is the client holding the HTTP connection open.
func assertOmittedTypeDoesNotHold(t *testing.T, queries []backend.DataQuery, logsTimeout time.Duration) {
	t.Helper()

	client := &runningLogsClient{}
	orig := NewCWLogsClient
	NewCWLogsClient = func(awsConfig aws.Config) models.CWLogsClient { return client }
	t.Cleanup(func() { NewCWLogsClient = orig })

	ds := newTestDatasource(func(ds *DataSource) {
		ds.Settings.Region = "us-east-1"
		ds.Settings.LogsTimeout = models.Duration{Duration: logsTimeout}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type outcome struct {
		resp *backend.QueryDataResponse
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		resp, err := ds.QueryData(ctx, &backend.QueryDataRequest{
			PluginContext: backend.PluginContext{DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{}},
			Queries:       queries,
		})
		done <- outcome{resp: resp, err: err}
	}()

	const returnLimit = 400 * time.Millisecond
	select {
	case result := <-done:
		starts, gets, _ := client.counts()
		require.Zero(t, starts, "StartQuery ran for an omitted-type logs query (%s)", client.startedQuery())
		require.Zero(t, gets, "GetQueryResults was polled for an omitted-type logs query")
		if result.err != nil {
			require.NotContains(t, result.err.Error(), "exceeded logs timeout")
		}
	case <-time.After(returnLimit):
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("QueryData was still polling after the request context was cancelled")
		}
		starts, gets, stops := client.counts()
		t.Fatalf("omitted type held QueryData in the logs poll (starts=%d gets=%d stops=%d query=%q); the request context was still active for %s and logsTimeout is %s",
			starts, gets, stops, client.startedQuery(), returnLimit, logsTimeout)
	}
}

func TestSyncLogQueryStopsCloudWatchQueryWhenRequestContextEnds(t *testing.T) {
	client := &runningLogsClient{}
	orig := NewCWLogsClient
	NewCWLogsClient = func(awsConfig aws.Config) models.CWLogsClient { return client }
	t.Cleanup(func() { NewCWLogsClient = orig })

	ds := newTestDatasource(func(ds *DataSource) {
		ds.Settings.Region = "us-east-1"
		ds.Settings.LogsTimeout = models.Duration{Duration: 30 * time.Minute}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = ds.QueryData(ctx, &backend.QueryDataRequest{
			Headers:       map[string]string{headerFromAlert: "true"},
			PluginContext: backend.PluginContext{DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{}},
			Queries: []backend.DataQuery{{
				RefID:     "A",
				TimeRange: backend.TimeRange{From: time.Unix(0, 0), To: time.Unix(60, 0)},
				JSON: json.RawMessage(`{
					"refId": "A",
					"queryMode": "Logs",
					"region": "us-east-1",
					"expression": "fields @timestamp, @message"
				}`),
			}},
		})
	}()

	time.Sleep(50 * time.Millisecond)
	cancelledAt := time.Now()
	cancel()

	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("sync logs poll kept running for more than 300ms after the request context ended")
	}
	require.Less(t, time.Since(cancelledAt), 300*time.Millisecond)

	client.mu.Lock()
	defer client.mu.Unlock()
	require.NotEmpty(t, client.starts, "alert sync path should start the CloudWatch query before polling")
	require.NotEmpty(t, client.stops, "the CloudWatch query must be stopped when the request context ends")
	require.NotNil(t, client.stops[0].QueryId)
	require.Equal(t, "logs-query-id", *client.stops[0].QueryId)
}
