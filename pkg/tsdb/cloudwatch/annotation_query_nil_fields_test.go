package cloudwatch

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/grafana/grafana-aws-sdk/pkg/awsauth"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"
)

// These tests are the spec for optional CloudWatch annotation fields.
// They call QueryData, which is the handler behind POST /api/ds/query, and let the
// CloudWatch client shipped with Grafana decode a query-protocol response that omits
// the optional members. The query must succeed and still return annotations for the
// alarm and history item whose fields are present.
func TestAnnotationQuery_OptionalCloudWatchFields(t *testing.T) {
	from := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2024, 6, 2, 0, 0, 0, 0, time.UTC)

	const keptSummary = "kept history item"

	t.Run("complete alarm and history", func(t *testing.T) {
		alarms := metricAlarmsXML(alarmMember("kept-alarm", map[string]string{
			"Namespace":  "AWS/EC2",
			"MetricName": "CPUUtilization",
			"Period":     "60",
			"Statistic":  "Average",
		}, ""))
		history := alarmHistoryXML(
			historyMember("kept-alarm", "2024-06-01T00:00:00Z", "StateUpdate", keptSummary),
		)
		resp := runAnnotationQuery(t, alarms, history, annotationQueryJSON(true), from, to)
		require.Equal(t, []string{keptSummary}, frameStrings(t, resp, "text"))
	})

	t.Run("prefix matching keeps a later alarm when Namespace is omitted", func(t *testing.T) {
		alarms := metricAlarmsXML(
			alarmMember("math-alarm", map[string]string{
				"MetricName": "CPUUtilization",
				"Period":     "60",
				"Statistic":  "Average",
			}, metricMathFragment()),
			alarmMember("kept-alarm", map[string]string{
				"Namespace":  "AWS/EC2",
				"MetricName": "CPUUtilization",
				"Period":     "60",
				"Statistic":  "Average",
			}, ""),
		)
		history := alarmHistoryXML(historyMember("kept-alarm", "2024-06-01T00:00:00Z", "StateUpdate", keptSummary))
		resp := runAnnotationQuery(t, alarms, history, annotationQueryJSON(true), from, to)
		require.Contains(t, frameStrings(t, resp, "text"), keptSummary)
	})

	t.Run("prefix matching keeps a later alarm when MetricName is omitted", func(t *testing.T) {
		alarms := metricAlarmsXML(
			alarmMember("math-alarm", map[string]string{
				"Namespace": "AWS/EC2",
				"Period":    "60",
				"Statistic": "Average",
			}, metricMathFragment()),
			alarmMember("kept-alarm", map[string]string{
				"Namespace":  "AWS/EC2",
				"MetricName": "CPUUtilization",
				"Period":     "60",
				"Statistic":  "Average",
			}, ""),
		)
		history := alarmHistoryXML(historyMember("kept-alarm", "2024-06-01T00:00:00Z", "StateUpdate", keptSummary))
		resp := runAnnotationQuery(t, alarms, history, annotationQueryJSON(true), from, to)
		require.Contains(t, frameStrings(t, resp, "text"), keptSummary)
	})

	t.Run("prefix matching keeps a later alarm when Period is omitted", func(t *testing.T) {
		alarms := metricAlarmsXML(
			alarmMember("math-alarm", map[string]string{
				"Namespace":  "AWS/EC2",
				"MetricName": "CPUUtilization",
				"Statistic":  "Average",
			}, metricMathFragment()),
			alarmMember("kept-alarm", map[string]string{
				"Namespace":  "AWS/EC2",
				"MetricName": "CPUUtilization",
				"Period":     "60",
				"Statistic":  "Average",
			}, ""),
		)
		history := alarmHistoryXML(historyMember("kept-alarm", "2024-06-01T00:00:00Z", "StateUpdate", keptSummary))
		resp := runAnnotationQuery(t, alarms, history, annotationQueryJSON(true), from, to)
		require.Contains(t, frameStrings(t, resp, "text"), keptSummary)
	})

	t.Run("prefix matching keeps a later alarm when Dimension Name is omitted", func(t *testing.T) {
		alarms := metricAlarmsXML(
			alarmMember("math-alarm", map[string]string{
				"Namespace":  "AWS/EC2",
				"MetricName": "CPUUtilization",
				"Period":     "60",
				"Statistic":  "Average",
			}, `<Dimensions><member><Value>i-abc</Value></member></Dimensions>`),
			alarmMember("kept-alarm", map[string]string{
				"Namespace":  "AWS/EC2",
				"MetricName": "CPUUtilization",
				"Period":     "60",
				"Statistic":  "Average",
			}, `<Dimensions><member><Name>InstanceId</Name><Value>i-abc</Value></member></Dimensions>`),
		)
		history := alarmHistoryXML(historyMember("kept-alarm", "2024-06-01T00:00:00Z", "StateUpdate", keptSummary))
		query := `{
			"type": "annotationQuery",
			"region": "us-east-1",
			"namespace": "AWS/EC2",
			"metricName": "CPUUtilization",
			"statistic": "Average",
			"period": "60",
			"prefixMatching": true,
			"actionPrefix": "arn:aws:sns:us-east-1:000000000000:notify-",
			"alarmNamePrefix": "kept-",
			"dimensions": {"InstanceId": ["i-abc"]}
		}`
		resp := runAnnotationQuery(t, alarms, history, query, from, to)
		require.Contains(t, frameStrings(t, resp, "text"), keptSummary)
	})

	for _, mode := range []struct {
		name   string
		prefix bool
	}{
		{name: "prefix matching", prefix: true},
		{name: "alarm for metric", prefix: false},
	} {
		t.Run(mode.name+" keeps a later history item when Timestamp is omitted", func(t *testing.T) {
			resp := runHistoryGap(t, mode.prefix, historyMember("kept-alarm", "", "StateUpdate", "missing timestamp"), from, to)
			require.Contains(t, frameStrings(t, resp, "text"), keptSummary)
		})
		t.Run(mode.name+" keeps a later history item when AlarmName is omitted", func(t *testing.T) {
			resp := runHistoryGap(t, mode.prefix, historyMember("", "2024-06-01T00:00:00Z", "StateUpdate", "missing alarm name"), from, to)
			require.Contains(t, frameStrings(t, resp, "text"), keptSummary)
		})
		t.Run(mode.name+" keeps a later history item when HistorySummary is omitted", func(t *testing.T) {
			resp := runHistoryGap(t, mode.prefix, historyMember("partial-alarm", "2024-06-01T00:00:00Z", "StateUpdate", ""), from, to)
			require.Contains(t, frameStrings(t, resp, "text"), keptSummary)
		})
	}
}

func runHistoryGap(t *testing.T, prefix bool, partialItem string, from, to time.Time) *backend.QueryDataResponse {
	t.Helper()
	alarms := metricAlarmsXML(alarmMember("kept-alarm", map[string]string{
		"Namespace":  "AWS/EC2",
		"MetricName": "CPUUtilization",
		"Period":     "60",
		"Statistic":  "Average",
	}, ""))
	history := alarmHistoryXML(
		partialItem,
		historyMember("kept-alarm", "2024-06-01T01:00:00Z", "StateUpdate", "kept history item"),
	)
	return runAnnotationQuery(t, alarms, history, annotationQueryJSON(prefix), from, to)
}

func annotationQueryJSON(prefix bool) string {
	if prefix {
		return `{
			"type": "annotationQuery",
			"region": "us-east-1",
			"namespace": "AWS/EC2",
			"metricName": "CPUUtilization",
			"statistic": "Average",
			"period": "60",
			"prefixMatching": true,
			"actionPrefix": "arn:aws:sns:us-east-1:000000000000:notify-",
			"alarmNamePrefix": "kept-"
		}`
	}
	return `{
		"type": "annotationQuery",
		"region": "us-east-1",
		"namespace": "AWS/EC2",
		"metricName": "CPUUtilization",
		"statistic": "Average",
		"period": "60"
	}`
}

func runAnnotationQuery(t *testing.T, alarmsXML, historyXML, queryJSON string, from, to time.Time) *backend.QueryDataResponse {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		switch action := values.Get("Action"); action {
		case "DescribeAlarms", "DescribeAlarmsForMetric":
			_, _ = io.WriteString(w, wrapAlarmsResponse(action, alarmsXML))
		case "DescribeAlarmHistory":
			_, _ = io.WriteString(w, historyXML)
		default:
			http.Error(w, "unexpected action "+action, http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	ds := newTestDatasource(func(ds *DataSource) {
		ds.AWSConfigProvider = endpointConfigProvider{cfg: aws.Config{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(srv.URL),
			Credentials:  credentials.NewStaticCredentialsProvider("test-access-key", "test-secret-key", ""),
			HTTPClient:   srv.Client(),
		}}
	})

	var resp *backend.QueryDataResponse
	var err error
	require.NotPanics(t, func() {
		resp, err = ds.QueryData(context.Background(), &backend.QueryDataRequest{
			PluginContext: backend.PluginContext{
				DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{},
			},
			Queries: []backend.DataQuery{{
				RefID: "A",
				TimeRange: backend.TimeRange{
					From: from,
					To:   to,
				},
				JSON: []byte(queryJSON),
			}},
		})
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	dr := resp.Responses["A"]
	require.NoError(t, dr.Error)
	require.NotEmpty(t, dr.Frames)
	return resp
}

func frameStrings(t *testing.T, resp *backend.QueryDataResponse, fieldName string) []string {
	t.Helper()
	frame := resp.Responses["A"].Frames[0]
	field, idx := frame.FieldByName(fieldName)
	require.GreaterOrEqual(t, idx, 0)
	out := make([]string, field.Len())
	for i := 0; i < field.Len(); i++ {
		out[i] = field.At(i).(string)
	}
	return out
}

type endpointConfigProvider struct {
	cfg aws.Config
}

func (p endpointConfigProvider) GetConfig(context.Context, awsauth.Settings) (aws.Config, error) {
	return p.cfg, nil
}

func metricAlarmsXML(members ...string) string {
	body := ""
	for _, member := range members {
		body += member
	}
	return body
}

func wrapAlarmsResponse(action, members string) string {
	result := "DescribeAlarmsResult"
	response := "DescribeAlarmsResponse"
	if action == "DescribeAlarmsForMetric" {
		result = "DescribeAlarmsForMetricResult"
		response = "DescribeAlarmsForMetricResponse"
	}
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<` + response + ` xmlns="http://monitoring.amazonaws.com/doc/2010-08-01/">` +
		`<` + result + `><MetricAlarms>` + members + `</MetricAlarms></` + result + `>` +
		`<ResponseMetadata><RequestId>req-alarms</RequestId></ResponseMetadata>` +
		`</` + response + `>`
}

func alarmMember(name string, fields map[string]string, extra string) string {
	body := "<member><AlarmName>" + name + "</AlarmName>"
	// Stable order so a nil field is the only difference between cases.
	for _, key := range []string{"Namespace", "MetricName", "Period", "Statistic"} {
		if value, ok := fields[key]; ok {
			body += "<" + key + ">" + value + "</" + key + ">"
		}
	}
	body += extra + "</member>"
	return body
}

func metricMathFragment() string {
	return `<Metrics><member><Id>e1</Id><Expression>m1+m2</Expression><ReturnData>true</ReturnData></member></Metrics>`
}

func alarmHistoryXML(members ...string) string {
	body := ""
	for _, member := range members {
		body += member
	}
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<DescribeAlarmHistoryResponse xmlns="http://monitoring.amazonaws.com/doc/2010-08-01/">` +
		`<DescribeAlarmHistoryResult><AlarmHistoryItems>` + body + `</AlarmHistoryItems></DescribeAlarmHistoryResult>` +
		`<ResponseMetadata><RequestId>req-history</RequestId></ResponseMetadata>` +
		`</DescribeAlarmHistoryResponse>`
}

func historyMember(alarmName, timestamp, itemType, summary string) string {
	body := "<member>"
	if alarmName != "" {
		body += "<AlarmName>" + alarmName + "</AlarmName>"
	}
	if itemType != "" {
		body += "<HistoryItemType>" + itemType + "</HistoryItemType>"
	}
	if summary != "" {
		body += "<HistorySummary>" + summary + "</HistorySummary>"
	}
	if timestamp != "" {
		body += "<Timestamp>" + timestamp + "</Timestamp>"
	}
	body += "</member>"
	return body
}
