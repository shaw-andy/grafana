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
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
)

// These tests describe the behavior required when CloudWatch Logs returns a
// ResultField whose name or value is null. They go through QueryData and the
// AWS SDK deserializer (cloudwatchlogs v1.73.0): a JSON null or an omitted
// member becomes a nil *string. While the converter dereferences those
// pointers, the tests abort the process. Once a nil name or value is an empty
// cell, including while an earlier row is rescanned after a column changes
// type, the tests pass.

func TestGetQueryResultsNullLogFields(t *testing.T) {
	const (
		ts1 = "2020-03-02 15:04:05.000"
		ts2 = "2020-03-02 15:04:06.000"
	)

	t.Run("null value in a multi-column row is an empty cell", func(t *testing.T) {
		frame := queryGetQueryResults(t, `{
			"status": "Complete",
			"results": [[
				{"field": "@timestamp", "value": "`+ts1+`"},
				{"field": "line", "value": null},
				{"field": "@ptr", "value": "ptr-1"},
				{"field": "status", "value": "ok"}
			]]
		}`)
		require.Equal(t, []string{"@timestamp", "line", "status"}, fieldNames(frame))
		require.Equal(t, "ok", stringValue(t, frame, "status", 0))
		require.Nil(t, frame.Fields[fieldIndex(frame, "line")].At(0))
		requireTime(t, frame, "@timestamp", 0, ts1)
	})

	t.Run("omitted value in a multi-column row is an empty cell", func(t *testing.T) {
		frame := queryGetQueryResults(t, `{
			"status": "Complete",
			"results": [[
				{"field": "@timestamp", "value": "`+ts1+`"},
				{"field": "line"},
				{"field": "status", "value": "ok"}
			]]
		}`)
		require.Equal(t, "ok", stringValue(t, frame, "status", 0))
		require.Nil(t, frame.Fields[fieldIndex(frame, "line")].At(0))
		requireTime(t, frame, "@timestamp", 0, ts1)
	})

	t.Run("null field name is skipped and the other columns are kept", func(t *testing.T) {
		frame := queryGetQueryResults(t, `{
			"status": "Complete",
			"results": [[
				{"field": "@timestamp", "value": "`+ts1+`"},
				{"field": null, "value": "orphan"},
				{"field": "status", "value": "ok"}
			]]
		}`)
		require.Equal(t, []string{"@timestamp", "status"}, fieldNames(frame))
		require.Equal(t, "ok", stringValue(t, frame, "status", 0))
		require.NotContains(t, fieldValues(frame, 0), "orphan")
	})

	t.Run("null timestamp value in a multi-column row is an empty time cell", func(t *testing.T) {
		frame := queryGetQueryResults(t, `{
			"status": "Complete",
			"results": [[
				{"field": "@timestamp", "value": null},
				{"field": "line", "value": "hello"},
				{"field": "@ptr", "value": "ptr-1"}
			]]
		}`)
		require.Equal(t, []string{"@timestamp", "line"}, fieldNames(frame))
		require.Equal(t, "hello", stringValue(t, frame, "line", 0))
		require.Nil(t, frame.Fields[fieldIndex(frame, "@timestamp")].At(0))
		require.Equal(t, data.FieldTypeNullableTime, frame.Fields[fieldIndex(frame, "@timestamp")].Type())
	})

	t.Run("null value of an established numeric column is an empty cell", func(t *testing.T) {
		frame := queryGetQueryResults(t, `{
			"status": "Complete",
			"results": [
				[
					{"field": "@timestamp", "value": "`+ts1+`"},
					{"field": "count", "value": "10"},
					{"field": "keep", "value": "first"}
				],
				[
					{"field": "@timestamp", "value": "`+ts2+`"},
					{"field": "count", "value": null},
					{"field": "keep", "value": "second"}
				]
			]
		}`)
		require.Equal(t, 2, frame.Rows())
		require.Equal(t, "first", stringValue(t, frame, "keep", 0))
		require.Equal(t, "second", stringValue(t, frame, "keep", 1))
		count := frame.Fields[fieldIndex(frame, "count")]
		require.Equal(t, data.FieldTypeNullableFloat64, count.Type())
		require.Equal(t, 10.0, *count.At(0).(*float64))
		require.Nil(t, count.At(1))
	})

	t.Run("nil field name is skipped while a column is rescanned after a type change", func(t *testing.T) {
		frame := queryGetQueryResults(t, `{
			"status": "Complete",
			"results": [
				[
					{"field": "@timestamp", "value": "`+ts1+`"},
					{"field": "count", "value": "10"},
					{"field": "keep", "value": "first"}
				],
				[
					{"field": "@timestamp", "value": "`+ts2+`"},
					{"field": "count", "value": "not-a-number"},
					{"field": null, "value": "orphan"},
					{"field": "keep", "value": "second"}
				]
			]
		}`)
		require.Equal(t, 2, frame.Rows())
		count := frame.Fields[fieldIndex(frame, "count")]
		require.Equal(t, data.FieldTypeNullableString, count.Type())
		require.Equal(t, "10", *count.At(0).(*string))
		require.Equal(t, "not-a-number", *count.At(1).(*string))
		require.Equal(t, "second", stringValue(t, frame, "keep", 1))
		require.NotContains(t, fieldValues(frame, 1), "orphan")
	})
}

func TestSyncLogQueryNullValueIsEmptyCell(t *testing.T) {
	const ts1 = "2020-03-02 15:04:05.000"
	frame := querySyncLogResults(t, `{
		"status": "Complete",
		"results": [[
			{"field": "@timestamp", "value": "`+ts1+`"},
			{"field": "line", "value": null},
			{"field": "@ptr", "value": "ptr-1"},
			{"field": "status", "value": "ok"}
		]]
	}`)
	require.Equal(t, []string{"@timestamp", "line", "status"}, fieldNames(frame))
	require.Equal(t, "ok", stringValue(t, frame, "status", 0))
	require.Nil(t, frame.Fields[fieldIndex(frame, "line")].At(0))
	requireTime(t, frame, "@timestamp", 0, ts1)
}

func queryGetQueryResults(t *testing.T, resultsBody string) *data.Frame {
	t.Helper()
	useLogsClient(t, resultsBody)
	ds := newTestDatasource()
	resp, err := ds.QueryData(context.Background(), &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{
			DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{},
		},
		Queries: []backend.DataQuery{{
			RefID: "A",
			JSON: json.RawMessage(`{
				"type": "logAction",
				"subtype": "GetQueryResults",
				"queryId": "query-1",
				"region": "us-east-1"
			}`),
		}},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	result := resp.Responses["A"]
	require.NoError(t, result.Error)
	require.Len(t, result.Frames, 1)
	return result.Frames[0]
}

func querySyncLogResults(t *testing.T, resultsBody string) *data.Frame {
	t.Helper()
	useLogsClient(t, resultsBody)
	ds := newTestDatasource()
	resp, err := ds.QueryData(context.Background(), &backend.QueryDataRequest{
		Headers: map[string]string{headerFromAlert: "true"},
		PluginContext: backend.PluginContext{
			DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{},
		},
		Queries: []backend.DataQuery{{
			RefID:     "A",
			TimeRange: backend.TimeRange{From: time.Unix(0, 0), To: time.Unix(60, 0)},
			JSON: json.RawMessage(`{
				"queryMode": "Logs",
				"region": "us-east-1",
				"logGroups": [{"arn": "arn:aws:logs:us-east-1:000000000000:log-group:app", "name": "app"}],
				"expression": "fields @timestamp, line, status"
			}`),
		}},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	result := resp.Responses["A"]
	require.NoError(t, result.Error)
	require.NotEmpty(t, result.Frames)
	return result.Frames[0]
}

func useLogsClient(t *testing.T, resultsBody string) {
	t.Helper()
	orig := NewCWLogsClient
	t.Cleanup(func() { NewCWLogsClient = orig })
	client := newCloudWatchLogsResultsClient(t, resultsBody)
	NewCWLogsClient = func(aws.Config) models.CWLogsClient {
		return client
	}
}

// newCloudWatchLogsResultsClient serves the AWS JSON 1.1 body the Logs API
// returns and lets the SDK shipped with Grafana decode it.
func newCloudWatchLogsResultsClient(t *testing.T, resultsBody string) *cloudwatchlogs.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		var body string
		switch {
		case strings.HasSuffix(target, ".StartQuery"):
			body = `{"queryId":"query-1"}`
		case strings.HasSuffix(target, ".GetQueryResults"):
			body = resultsBody
		default:
			http.Error(w, "unexpected target "+target, http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	return cloudwatchlogs.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("placeholder-access-key", "placeholder-secret-key", ""),
	}, func(o *cloudwatchlogs.Options) {
		o.BaseEndpoint = aws.String(srv.URL)
	})
}

func fieldNames(frame *data.Frame) []string {
	names := make([]string, len(frame.Fields))
	for i, field := range frame.Fields {
		names[i] = field.Name
	}
	return names
}

func fieldIndex(frame *data.Frame, name string) int {
	for i, field := range frame.Fields {
		if field.Name == name {
			return i
		}
	}
	return -1
}

func stringValue(t *testing.T, frame *data.Frame, name string, row int) string {
	t.Helper()
	idx := fieldIndex(frame, name)
	require.GreaterOrEqual(t, idx, 0, "missing field %s", name)
	value, ok := frame.Fields[idx].At(row).(*string)
	require.True(t, ok, "field %s is %T", name, frame.Fields[idx].At(row))
	require.NotNil(t, value)
	return *value
}

func requireTime(t *testing.T, frame *data.Frame, name string, row int, want string) {
	t.Helper()
	idx := fieldIndex(frame, name)
	require.GreaterOrEqual(t, idx, 0)
	got, ok := frame.Fields[idx].At(row).(*time.Time)
	require.True(t, ok)
	require.NotNil(t, got)
	parsed, err := time.Parse(cloudWatchTSFormat, want)
	require.NoError(t, err)
	require.True(t, parsed.Equal(*got), "got %s", got)
}

func fieldValues(frame *data.Frame, row int) []string {
	var values []string
	for _, field := range frame.Fields {
		if value, ok := field.At(row).(*string); ok && value != nil {
			values = append(values, *value)
		}
	}
	return values
}
