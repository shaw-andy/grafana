package cloudwatch

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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

const nullLogFieldQueryID = "query-null-fields"

// nullMessageResults is a GetQueryResults body the AWS JSON 1.1 deserializer accepts.
// value is JSON null on a multi-column row, which leaves ResultField.Value nil.
const nullMessageResults = `{
  "status": "Complete",
  "results": [[
    {"field": "@timestamp", "value": "2020-03-20 10:37:23.000"},
    {"field": "@message", "value": null},
    {"field": "@ptr", "value": "ptr-1"}
  ]]
}`

// omittedValueResults omits value entirely. The deserializer also leaves ResultField.Value nil.
const omittedValueResults = `{
  "status": "Complete",
  "results": [[
    {"field": "@timestamp", "value": "2020-03-20 10:37:23.000"},
    {"field": "@message"},
    {"field": "level", "value": "info"}
  ]]
}`

// nullFieldNameResults has a ResultField whose name is JSON null.
const nullFieldNameResults = `{
  "status": "Complete",
  "results": [[
    {"field": "@timestamp", "value": "2020-03-20 10:37:23.000"},
    {"field": null, "value": "orphan"},
    {"field": "@message", "value": "hello"}
  ]]
}`

// numericThenNullResults establishes a numeric column, then returns a null cell in that column.
const numericThenNullResults = `{
  "status": "Complete",
  "results": [
    [
      {"field": "@timestamp", "value": "2020-03-20 10:37:23.000"},
      {"field": "n", "value": "1"}
    ],
    [
      {"field": "@timestamp", "value": "2020-03-20 10:40:43.000"},
      {"field": "n", "value": null}
    ]
  ]
}`

// mixedTypeNullNameResults forces a numeric column to be rescanned as strings
// while a later cell in the same row has a null field name.
const mixedTypeNullNameResults = `{
  "status": "Complete",
  "results": [
    [
      {"field": "mix", "value": "1"},
      {"field": "note", "value": "a"}
    ],
    [
      {"field": "mix", "value": "not-a-number"},
      {"field": null, "value": "later"}
    ]
  ]
}`

func TestGetQueryResultsNullValueIsEmptyCell(t *testing.T) {
	resp := queryGetQueryResults(t, nullMessageResults, nullLogFieldQueryID)
	frame := requireLogFrame(t, resp, "A")

	ts := requireField(t, frame, "@timestamp")
	require.Equal(t, data.FieldTypeNullableTime, ts.Type())
	require.NotNil(t, ts.At(0))

	msg := requireField(t, frame, "@message")
	require.Equal(t, data.FieldTypeNullableString, msg.Type())
	require.True(t, fieldValueNil(msg, 0))
	require.Nil(t, fieldByName(frame, "@ptr"))
}

func TestGetQueryResultsOmittedValueIsEmptyCell(t *testing.T) {
	resp := queryGetQueryResults(t, omittedValueResults, nullLogFieldQueryID)
	frame := requireLogFrame(t, resp, "A")

	msg := requireField(t, frame, "@message")
	require.True(t, fieldValueNil(msg, 0))
	level := requireField(t, frame, "level")
	require.Equal(t, "info", derefString(t, level.At(0)))
}

func TestGetQueryResultsNullFieldNameIsSkipped(t *testing.T) {
	resp := queryGetQueryResults(t, nullFieldNameResults, nullLogFieldQueryID)
	frame := requireLogFrame(t, resp, "A")

	require.NotNil(t, requireField(t, frame, "@timestamp").At(0))
	msg := requireField(t, frame, "@message")
	require.Equal(t, "hello", derefString(t, msg.At(0)))
	require.Len(t, frame.Fields, 2)
}

func TestGetQueryResultsNullNumericCellIsEmpty(t *testing.T) {
	resp := queryGetQueryResults(t, numericThenNullResults, nullLogFieldQueryID)
	frame := requireLogFrame(t, resp, "A")

	n := requireField(t, frame, "n")
	require.Equal(t, data.FieldTypeNullableFloat64, n.Type())
	require.Equal(t, 1.0, derefFloat(t, n.At(0)))
	require.True(t, fieldValueNil(n, 1))
}

func TestGetQueryResultsTypeChangeSkipsNullFieldName(t *testing.T) {
	resp := queryGetQueryResults(t, mixedTypeNullNameResults, nullLogFieldQueryID)
	frame := requireLogFrame(t, resp, "A")

	mix := requireField(t, frame, "mix")
	require.Equal(t, data.FieldTypeNullableString, mix.Type())
	require.Equal(t, "1", derefString(t, mix.At(0)))
	require.Equal(t, "not-a-number", derefString(t, mix.At(1)))

	note := requireField(t, frame, "note")
	require.Equal(t, "a", derefString(t, note.At(0)))
	require.True(t, fieldValueNil(note, 1))
	require.Len(t, frame.Fields, 2)
}

func TestSyncLogQueryNullValueIsEmptyCell(t *testing.T) {
	var sawQueryID string
	srv := startLogsAPI(t, nullMessageResults, &sawQueryID)
	ds := newTestDatasource()
	useRealLogsClient(t, srv)

	resp, err := ds.QueryData(context.Background(), &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{}},
		Queries: []backend.DataQuery{
			{
				RefID:     "A",
				TimeRange: backend.TimeRange{From: time.Unix(0, 0), To: time.Unix(60, 0)},
				JSON: []byte(`{
					"queryMode": "Logs",
					"region": "us-east-1",
					"expression": "fields @timestamp, @message"
				}`),
			},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, sawQueryID)

	frame := requireLogFrame(t, resp, "A")
	msg := requireField(t, frame, "@message")
	require.True(t, fieldValueNil(msg, 0))
}

func TestGetQueryResultsNullLogFieldDoesNotStopTheProcess(t *testing.T) {
	if os.Getenv("CW_NULL_FIELD_SUBPROCESS") == "1" {
		resp := queryGetQueryResults(t, nullMessageResults, nullLogFieldQueryID)
		frame := requireLogFrame(t, resp, "A")
		require.True(t, fieldValueNil(requireField(t, frame, "@message"), 0))
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestGetQueryResultsNullLogFieldDoesNotStopTheProcess$")
	cmd.Env = append(os.Environ(), "CW_NULL_FIELD_SUBPROCESS=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "GetQueryResults with a null log field stopped the process:\n%s", out)
}

func queryGetQueryResults(t *testing.T, resultsJSON, queryID string) *backend.QueryDataResponse {
	t.Helper()
	var sawQueryID string
	srv := startLogsAPI(t, resultsJSON, &sawQueryID)
	ds := newTestDatasource()
	useRealLogsClient(t, srv)

	resp, err := ds.QueryData(context.Background(), &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{}},
		Queries: []backend.DataQuery{
			{
				RefID: "A",
				JSON: []byte(`{
					"type": "logAction",
					"subtype": "GetQueryResults",
					"queryId": "` + queryID + `",
					"region": "us-east-1"
				}`),
			},
		},
	})
	require.NoError(t, err)
	require.Equal(t, queryID, sawQueryID)
	return resp
}

func startLogsAPI(t *testing.T, resultsJSON string, sawQueryID *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		target := r.Header.Get("X-Amz-Target")
		switch {
		case strings.HasSuffix(target, ".GetQueryResults"):
			*sawQueryID = queryIDFromBody(string(body))
			_, _ = w.Write([]byte(resultsJSON))
		case strings.HasSuffix(target, ".StartQuery"):
			_, _ = w.Write([]byte(`{"queryId":"started-query"}`))
		default:
			http.Error(w, "unexpected target "+target, http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func useRealLogsClient(t *testing.T, srv *httptest.Server) {
	t.Helper()
	orig := NewCWLogsClient
	t.Cleanup(func() { NewCWLogsClient = orig })
	NewCWLogsClient = func(cfg aws.Config) models.CWLogsClient {
		cfg.Region = "us-east-1"
		cfg.Credentials = credentials.NewStaticCredentialsProvider("placeholder", "placeholder", "")
		return cloudwatchlogs.NewFromConfig(cfg, func(o *cloudwatchlogs.Options) {
			o.BaseEndpoint = aws.String(srv.URL)
			o.RetryMaxAttempts = 1
		})
	}
}

func queryIDFromBody(body string) string {
	const key = `"queryId":"`
	i := strings.Index(body, key)
	if i < 0 {
		return ""
	}
	rest := body[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func requireLogFrame(t *testing.T, resp *backend.QueryDataResponse, refID string) *data.Frame {
	t.Helper()
	require.NotNil(t, resp)
	dr, ok := resp.Responses[refID]
	require.True(t, ok)
	require.NoError(t, dr.Error)
	require.NotEmpty(t, dr.Frames)
	return dr.Frames[0]
}

func requireField(t *testing.T, frame *data.Frame, name string) *data.Field {
	t.Helper()
	field := fieldByName(frame, name)
	require.NotNil(t, field, "missing field %s", name)
	return field
}

func fieldByName(frame *data.Frame, name string) *data.Field {
	for _, field := range frame.Fields {
		if field.Name == name {
			return field
		}
	}
	return nil
}

func fieldValueNil(field *data.Field, i int) bool {
	v := field.At(i)
	if v == nil {
		return true
	}
	switch p := v.(type) {
	case *string:
		return p == nil
	case *float64:
		return p == nil
	case *time.Time:
		return p == nil
	default:
		return false
	}
}

func derefString(t *testing.T, v any) string {
	t.Helper()
	s, ok := v.(*string)
	require.True(t, ok)
	require.NotNil(t, s)
	return *s
}

func derefFloat(t *testing.T, v any) float64 {
	t.Helper()
	n, ok := v.(*float64)
	require.True(t, ok)
	require.NotNil(t, n)
	return *n
}
