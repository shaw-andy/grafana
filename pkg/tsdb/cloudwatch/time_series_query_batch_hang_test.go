package cloudwatch

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/features"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
)

// CloudWatch GetMetricData returns one MetricDataResult per MetricDataQuery in the request.
// The sample responses in the API reference include every requested id, and queries that
// return data include a Label. parseResponse emits one result per labeled id, so a query
// copied into several batches is sent once per batch.
// https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricData.html

func TestQueryData_SharedMetricCopiedIntoMathBatchesDoesNotHang(t *testing.T) {
	client := &batchResultClient{}
	ds := datasourceWithMetricClient(t, client)

	ctx, cancel := context.WithCancel(contextWithFeaturesEnabled(features.FlagCloudWatchBatchQueries))
	t.Cleanup(cancel)

	resp := requireQueryDataReturns(t, ctx, cancel, ds, sharedMetricBatchRequest(), allSharedMetricRefIDs)
	require.Equal(t, int32(5), client.calls.Load(), "cloudWatchBatchQueries must still run one GetMetricData call per batch")
	for _, refID := range allSharedMetricRefIDs {
		require.NoError(t, resp.Responses[refID].Error)
		require.NotEmpty(t, resp.Responses[refID].Frames)
	}
}

func TestQueryData_FailedSQLBatchesDoNotHangOnErrorSend(t *testing.T) {
	client := &batchResultClient{sqlErr: errors.New("Error in expression 's1': Invalid syntax")}
	ds := datasourceWithMetricClient(t, client)

	ctx, cancel := context.WithCancel(contextWithFeaturesEnabled(features.FlagCloudWatchBatchQueries))
	t.Cleanup(cancel)

	resp := requireQueryDataReturns(t, ctx, cancel, ds, sharedMetricBatchRequest(), []string{"A", "E1", "E2", "E3"})
	require.Equal(t, int32(5), client.calls.Load())
	for _, refID := range []string{"A", "E1", "E2", "E3"} {
		require.NoError(t, resp.Responses[refID].Error)
		require.NotEmpty(t, resp.Responses[refID].Frames)
	}
}

func TestQueryData_PanicRecoverSendRespectsCancellation(t *testing.T) {
	release := make(chan struct{})
	var closeRelease sync.Once
	releaseOnce := func() { closeRelease.Do(func() { close(release) }) }
	t.Cleanup(releaseOnce)

	client := &batchResultClient{
		holdID:         "e3",
		extraUnknownID: true,
		started:        make(chan struct{}, 1),
		release:        release,
	}
	ds := datasourceWithMetricClient(t, client)

	ctx, cancel := context.WithCancel(contextWithFeaturesEnabled(features.FlagCloudWatchBatchQueries))
	t.Cleanup(cancel)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = ds.QueryData(ctx, sharedMetricBatchRequest())
	}()

	select {
	case <-client.started:
	case <-done:
		t.Fatal("QueryData returned before the batch that panics was invoked")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the batch that panics to be invoked")
	}

	require.Eventually(t, func() bool { return client.finished.Load() == 4 }, 5*time.Second, 5*time.Millisecond)
	// The other four batches have returned from GetMetricData. Their six labeled results
	// fill a channel buffered to the six incoming queries, and Wait is stuck on this batch.
	time.Sleep(100 * time.Millisecond)
	cancel()
	releaseOnce()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("QueryData was still blocked after the request context was cancelled")
	}
}

func TestQueryData_SharedMetricWithoutBatchingStillReturns(t *testing.T) {
	client := &batchResultClient{}
	ds := datasourceWithMetricClient(t, client)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	resp := requireQueryDataReturns(t, ctx, cancel, ds, sharedMetricBatchRequest(), allSharedMetricRefIDs)
	require.Equal(t, int32(1), client.calls.Load())
	for _, refID := range allSharedMetricRefIDs {
		require.NoError(t, resp.Responses[refID].Error)
		require.NotEmpty(t, resp.Responses[refID].Frames)
	}
}

var allSharedMetricRefIDs = []string{"S1", "S2", "A", "E1", "E2", "E3"}

func requireQueryDataReturns(t *testing.T, ctx context.Context, cancel context.CancelFunc, ds *DataSource, req *backend.QueryDataRequest, wantRefIDs []string) *backend.QueryDataResponse {
	t.Helper()

	type outcome struct {
		resp *backend.QueryDataResponse
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		resp, err := ds.QueryData(ctx, req)
		done <- outcome{resp: resp, err: err}
	}()

	select {
	case got := <-done:
		require.NoError(t, got.err)
		for _, refID := range wantRefIDs {
			_, ok := got.resp.Responses[refID]
			require.Truef(t, ok, "missing response for refId %s", refID)
		}
		return got.resp
	case <-time.After(2 * time.Second):
		cancel()
		select {
		case <-done:
			t.Fatal("QueryData stayed blocked until the request context was cancelled")
		case <-time.After(2 * time.Second):
			t.Fatal("QueryData was still blocked after the request context was cancelled")
		}
	}
	return nil
}

func datasourceWithMetricClient(t *testing.T, client models.CWClient) *DataSource {
	t.Helper()
	orig := NewCWClient
	t.Cleanup(func() { NewCWClient = orig })
	NewCWClient = func(aws.Config) models.CWClient { return client }
	return newTestDatasource()
}

func sharedMetricBatchRequest() *backend.QueryDataRequest {
	now := time.Now()
	tr := backend.TimeRange{From: now.Add(-2 * time.Hour), To: now.Add(-time.Hour)}
	bodies := []struct {
		refID string
		json  string
	}{
		{refID: "A", json: `{
			"refId":"A","type":"timeSeriesQuery","region":"us-east-1",
			"namespace":"AWS/EC2","metricName":"CPUUtilization",
			"dimensions":{"InstanceId":"i-0123456789abcdef0"},
			"statistic":"Average","period":"300","id":"a",
			"metricQueryType":0,"metricEditorMode":0
		}`},
		{refID: "S1", json: `{
			"refId":"S1","type":"timeSeriesQuery","region":"us-east-1",
			"namespace":"AWS/EC2","metricName":"CPUUtilization",
			"statistic":"Average","period":"300","id":"s1",
			"metricQueryType":1,"metricEditorMode":1,
			"sqlExpression":"SELECT AVG(CPUUtilization) FROM SCHEMA(\"AWS/EC2\", InstanceId)"
		}`},
		{refID: "S2", json: `{
			"refId":"S2","type":"timeSeriesQuery","region":"us-east-1",
			"namespace":"AWS/EC2","metricName":"CPUUtilization",
			"statistic":"Average","period":"300","id":"s2",
			"metricQueryType":1,"metricEditorMode":1,
			"sqlExpression":"SELECT MAX(CPUUtilization) FROM SCHEMA(\"AWS/EC2\", InstanceId)"
		}`},
		{refID: "E1", json: `{
			"refId":"E1","type":"timeSeriesQuery","region":"us-east-1",
			"statistic":"Average","period":"300","id":"e1",
			"expression":"a*2","metricQueryType":0,"metricEditorMode":1
		}`},
		{refID: "E2", json: `{
			"refId":"E2","type":"timeSeriesQuery","region":"us-east-1",
			"statistic":"Average","period":"300","id":"e2",
			"expression":"a*3","metricQueryType":0,"metricEditorMode":1
		}`},
		{refID: "E3", json: `{
			"refId":"E3","type":"timeSeriesQuery","region":"us-east-1",
			"statistic":"Average","period":"300","id":"e3",
			"expression":"a*4","metricQueryType":0,"metricEditorMode":1
		}`},
	}

	queries := make([]backend.DataQuery, 0, len(bodies))
	for _, body := range bodies {
		queries = append(queries, backend.DataQuery{
			RefID:     body.refID,
			TimeRange: tr,
			JSON:      []byte(body.json),
		})
	}
	return &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{
			DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{},
		},
		Queries: queries,
	}
}

// batchResultClient stands in for the CloudWatch GetMetricData API. A successful call
// returns one labeled MetricDataResult for each MetricDataQuery id in that call.
type batchResultClient struct {
	models.CWClient

	sqlErr         error
	holdID         string
	extraUnknownID bool
	started        chan struct{}
	release        <-chan struct{}

	calls    atomic.Int32
	finished atomic.Int32
}

func (c *batchResultClient) GetMetricData(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	c.calls.Add(1)
	if c.holdID != "" && metricDataInputHasID(input, c.holdID) {
		select {
		case c.started <- struct{}{}:
		default:
		}
		<-c.release
	}

	if c.sqlErr != nil && isMetricsInsightsBatch(input) {
		c.finished.Add(1)
		return &cloudwatch.GetMetricDataOutput{}, c.sqlErr
	}

	out := &cloudwatch.GetMetricDataOutput{
		MetricDataResults: make([]cloudwatchtypes.MetricDataResult, 0, len(input.MetricDataQueries)+1),
	}
	for _, query := range input.MetricDataQueries {
		id := aws.ToString(query.Id)
		out.MetricDataResults = append(out.MetricDataResults, labeledMetricResult(id))
	}
	if c.extraUnknownID && c.holdID != "" && metricDataInputHasID(input, c.holdID) {
		out.MetricDataResults = append(out.MetricDataResults, labeledMetricResult("notInBatch"))
	}
	c.finished.Add(1)
	return out, nil
}

func labeledMetricResult(id string) cloudwatchtypes.MetricDataResult {
	return cloudwatchtypes.MetricDataResult{
		Id:         aws.String(id),
		Label:      aws.String(id),
		StatusCode: cloudwatchtypes.StatusCodeComplete,
		Timestamps: []time.Time{time.Unix(1_700_000_000, 0).UTC()},
		Values:     []float64{1},
	}
}

func isMetricsInsightsBatch(input *cloudwatch.GetMetricDataInput) bool {
	if input == nil || len(input.MetricDataQueries) != 1 {
		return false
	}
	return strings.Contains(aws.ToString(input.MetricDataQueries[0].Expression), "SELECT")
}

func metricDataInputHasID(input *cloudwatch.GetMetricDataInput, id string) bool {
	if input == nil {
		return false
	}
	for _, query := range input.MetricDataQueries {
		if aws.ToString(query.Id) == id {
			return true
		}
	}
	return false
}
