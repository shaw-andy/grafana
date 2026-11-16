package cloudwatch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/grafana/grafana-aws-sdk/pkg/awsauth"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
	"github.com/stretchr/testify/require"
)

// These tests pin the metrics error path that compiles a query refId and metric id
// with regexp.MustCompile. They fail while that compile can panic, and they pass
// once a failed metrics call returns a normal datasource error for every identifier
// the caller can send.

func TestTimeSeriesQuery_InvalidRefIDDoesNotPanicWhenClientSetupFails(t *testing.T) {
	for _, refID := range []string{"(", ")", "**"} {
		t.Run(refID, func(t *testing.T) {
			ds := datasourceWithoutDefaultRegion()
			require.NotPanics(t, func() {
				resp, err := ds.QueryData(context.Background(), metricsQueryRequest(metricsQuery(refID, "", "")))
				requireDatasourceMetricError(t, resp, err)
			})
		})
	}
}

func TestTimeSeriesQuery_InvalidMetricIDDoesNotPanicWhenClientSetupFails(t *testing.T) {
	for _, id := range []string{"(", "[", "**"} {
		t.Run(id, func(t *testing.T) {
			ds := datasourceWithoutDefaultRegion()
			require.NotPanics(t, func() {
				resp, err := ds.QueryData(context.Background(), metricsQueryRequest(metricsQuery("A", id, "")))
				requireDatasourceMetricError(t, resp, err)
			})
		})
	}
}

func TestTimeSeriesQuery_InvalidRefIDDoesNotPanicWhenGetMetricDataFails(t *testing.T) {
	srv, requests := metricDataRejectServer(t)
	ds := datasourceWithEndpoint(t, srv.URL)

	require.NotPanics(t, func() {
		resp, err := ds.QueryData(context.Background(), metricsQueryRequest(metricsQuery("(", "", "us-east-1")))
		requireDatasourceMetricError(t, resp, err)
	})
	require.NotEmpty(t, *requests, "GetMetricData never reached the CloudWatch client")
}

func TestTimeSeriesQuery_InvalidMetricIDDoesNotPanicWhenGetMetricDataFails(t *testing.T) {
	srv, requests := metricDataRejectServer(t)
	ds := datasourceWithEndpoint(t, srv.URL)

	require.NotPanics(t, func() {
		resp, err := ds.QueryData(context.Background(), metricsQueryRequest(metricsQuery("A", "(", "us-east-1")))
		requireDatasourceMetricError(t, resp, err)
	})
	require.NotEmpty(t, *requests, "GetMetricData never reached the CloudWatch client")
	body := strings.Join(*requests, "\n")
	require.Truef(t, strings.Contains(body, "(") || strings.Contains(body, "%28"),
		"caller-supplied metric id was not sent to GetMetricData: %s", body)
}

func TestTimeSeriesQuery_ValidIdentifiersStillSelectTheFailingQuery(t *testing.T) {
	t.Run("error names the refId", func(t *testing.T) {
		resp := queryWithMetricClientError(t, "A", "queryA", "Error in expression 'A': Invalid syntax")
		require.Error(t, resp.Responses["A"].Error)
		require.ErrorContains(t, resp.Responses["A"].Error, "metric request error")
	})

	t.Run("error names the metric id", func(t *testing.T) {
		resp := queryWithMetricClientError(t, "A", "queryA", "Error in expression 'queryA': Invalid syntax")
		require.Error(t, resp.Responses["A"].Error)
		require.ErrorContains(t, resp.Responses["A"].Error, "metric request error")
	})
}

func datasourceWithoutDefaultRegion() *DataSource {
	return newTestDatasource(func(ds *DataSource) {
		ds.Settings.Region = ""
	})
}

func datasourceWithEndpoint(t *testing.T, endpoint string) *DataSource {
	t.Helper()
	return newTestDatasource(func(ds *DataSource) {
		ds.Settings.Region = "us-east-1"
		ds.AWSConfigProvider = staticEndpointConfig(endpoint)
	})
}

func staticEndpointConfig(endpoint string) awsauth.ConfigProvider {
	return endpointConfigProvider{cfg: aws.Config{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(endpoint),
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     "test-access-key",
				SecretAccessKey: "test-secret-key",
				Source:          "TimeSeriesQueryInvalidRegexpTest",
			}, nil
		}),
		Retryer:    func() aws.Retryer { return aws.NopRetryer{} },
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	}}
}

type endpointConfigProvider struct {
	cfg aws.Config
}

func (p endpointConfigProvider) GetConfig(context.Context, awsauth.Settings) (aws.Config, error) {
	return p.cfg, nil
}

func metricDataRejectServer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		requests = append(requests, string(body))
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidParameterValue</Code><Message>rejected</Message></Error></ErrorResponse>`)
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

func queryWithMetricClientError(t *testing.T, refID, id, clientErr string) *backend.QueryDataResponse {
	t.Helper()
	ds := newTestDatasource()
	origNewCWClient := NewCWClient
	t.Cleanup(func() {
		NewCWClient = origNewCWClient
	})
	NewCWClient = func(aws.Config) models.CWClient {
		return &recordingMetricsClient{err: awsError(clientErr)}
	}

	var resp *backend.QueryDataResponse
	require.NotPanics(t, func() {
		var err error
		resp, err = ds.QueryData(context.Background(), metricsQueryRequest(metricsQuery(refID, id, "us-east-1")))
		require.NoError(t, err)
		require.NotNil(t, resp)
	})
	return resp
}

type recordingMetricsClient struct {
	models.CWClient
	err error
}

func (c *recordingMetricsClient) GetMetricData(context.Context, *cloudwatch.GetMetricDataInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	return &cloudwatch.GetMetricDataOutput{}, c.err
}

type awsError string

func (e awsError) Error() string { return string(e) }

func metricsQueryRequest(queries ...backend.DataQuery) *backend.QueryDataRequest {
	return &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{
			DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{},
		},
		Queries: queries,
	}
}

func metricsQuery(refID, id, region string) backend.DataQuery {
	payload := map[string]any{
		"type":       "timeSeriesQuery",
		"namespace":  "AWS/EC2",
		"metricName": "CPUUtilization",
		"region":     region,
		"statistic":  "Average",
		"period":     "300",
	}
	if id != "" {
		payload["id"] = id
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	now := time.Now()
	return backend.DataQuery{
		RefID: refID,
		TimeRange: backend.TimeRange{
			From: now.Add(-time.Hour),
			To:   now,
		},
		JSON: raw,
	}
}

func requireDatasourceMetricError(t *testing.T, resp *backend.QueryDataResponse, err error) {
	t.Helper()
	require.NoError(t, err)
	require.NotNil(t, resp)
	var messages []string
	for refID, result := range resp.Responses {
		if result.Error != nil {
			messages = append(messages, refID+": "+result.Error.Error())
		}
	}
	require.NotEmpty(t, messages, "expected a datasource error on the query response, got %#v", resp.Responses)
	require.Contains(t, strings.Join(messages, "\n"), "metric request error")
}
