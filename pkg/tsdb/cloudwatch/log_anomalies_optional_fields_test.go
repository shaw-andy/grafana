package cloudwatch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
	"github.com/stretchr/testify/require"
)

// TestQueryDataLogAnomaliesOptionalFields runs a logs anomalies query through
// DataSource.QueryData and the AWS SDK ListAnomalies client. The fixture is a
// ListAnomalies JSON body the SDK deserializer accepts. Priority and suppressed
// are optional on that shape, and description and anomalyDetectorArn are
// pointers the converter reads the same way. Each case expects a frame with an
// empty string or false for a missing value, and the original value when the
// field is present.
func TestQueryDataLogAnomaliesOptionalFields(t *testing.T) {
	const (
		presentPriority    = "HIGH"
		presentDescription = "detected spike"
		presentARN         = "arn:aws:logs:us-east-1:123456789012:anomaly-detector:detector"
		presentPattern     = "ERROR *"
	)

	cases := []struct {
		name            string
		drop            []string
		null            []string
		wantPriority    string
		wantSuppressed  bool
		wantDescription string
		wantARN         string
	}{
		{
			name:            "omitted priority",
			drop:            []string{"priority"},
			wantPriority:    "",
			wantSuppressed:  true,
			wantDescription: presentDescription,
			wantARN:         presentARN,
		},
		{
			name:            "omitted suppressed",
			drop:            []string{"suppressed"},
			wantPriority:    presentPriority,
			wantSuppressed:  false,
			wantDescription: presentDescription,
			wantARN:         presentARN,
		},
		{
			name:            "null priority and suppressed",
			null:            []string{"priority", "suppressed"},
			wantPriority:    "",
			wantSuppressed:  false,
			wantDescription: presentDescription,
			wantARN:         presentARN,
		},
		{
			name:            "omitted description and anomaly detector arn",
			drop:            []string{"description", "anomalyDetectorArn"},
			wantPriority:    presentPriority,
			wantSuppressed:  true,
			wantDescription: "",
			wantARN:         "",
		},
		{
			name:            "omitted priority suppressed description and anomaly detector arn",
			drop:            []string{"priority", "suppressed", "description", "anomalyDetectorArn"},
			wantPriority:    "",
			wantSuppressed:  false,
			wantDescription: "",
			wantARN:         "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			partial := anomalyDocument(presentPriority, true, presentDescription, presentARN, presentPattern)
			for _, key := range tc.drop {
				delete(partial, key)
			}
			for _, key := range tc.null {
				partial[key] = nil
			}
			complete := anomalyDocument(presentPriority, true, presentDescription, presentARN, presentPattern)
			body := listAnomaliesBody(t, partial, complete)

			seen := installListAnomaliesServer(t, body)
			resp, err := queryLogAnomalies(t, map[string]string{headerFromAlert: "true"}, "A", "B")
			require.NoError(t, err)
			require.NotEmpty(t, seen.targets)
			for _, target := range seen.targets {
				require.Equal(t, "Logs_20140328.ListAnomalies", target)
			}

			for _, refID := range []string{"A", "B"} {
				frame := responseFrame(t, resp, refID)
				require.Equal(t, "Log anomalies", frame.Name)
				require.Equal(t, 2, frame.Fields[0].Len())

				// Row 0 is the anomaly with the optional fields removed. Row 1 is a
				// complete anomaly in the same response, so a fix cannot blank every row.
				require.Equal(t, tc.wantDescription, frame.Fields[1].At(0))
				require.Equal(t, presentDescription, frame.Fields[1].At(1))
				require.Equal(t, tc.wantPriority, frame.Fields[2].At(0))
				require.Equal(t, presentPriority, frame.Fields[2].At(1))
				require.Equal(t, presentPattern, frame.Fields[3].At(0))
				require.Equal(t, presentPattern, frame.Fields[3].At(1))
				require.Equal(t, tc.wantSuppressed, frame.Fields[7].At(0))
				require.Equal(t, true, frame.Fields[7].At(1))
				require.Equal(t, tc.wantARN, frame.Fields[9].At(0))
				require.Equal(t, presentARN, frame.Fields[9].At(1))
			}
		})
	}
}

func queryLogAnomalies(t *testing.T, headers map[string]string, refIDs ...string) (*backend.QueryDataResponse, error) {
	t.Helper()
	queries := make([]backend.DataQuery, 0, len(refIDs))
	for _, refID := range refIDs {
		queries = append(queries, backend.DataQuery{
			RefID:     refID,
			TimeRange: backend.TimeRange{From: time.Unix(0, 0), To: time.Unix(1, 0)},
			JSON: json.RawMessage(`{
				"queryMode": "Logs",
				"logsMode": "Anomalies",
				"type": "logAction",
				"suppressionState": "all",
				"region": "us-east-1"
			}`),
		})
	}
	ds := newTestDatasource()
	return ds.QueryData(context.Background(), &backend.QueryDataRequest{
		Headers:       headers,
		PluginContext: backend.PluginContext{DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{}},
		Queries:       queries,
	})
}

type listAnomaliesCalls struct {
	targets []string
}

func installListAnomaliesServer(t *testing.T, body []byte) *listAnomaliesCalls {
	t.Helper()
	seen := &listAnomaliesCalls{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.targets = append(seen.targets, r.Header.Get("X-Amz-Target"))
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	orig := NewCWLogsClient
	t.Cleanup(func() { NewCWLogsClient = orig })
	NewCWLogsClient = func(aws.Config) models.CWLogsClient {
		return cloudwatchlogs.New(cloudwatchlogs.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(srv.URL),
			Credentials:  credentials.NewStaticCredentialsProvider("placeholder", "placeholder", ""),
		})
	}
	return seen
}

func anomalyDocument(priority string, suppressed bool, description, arn, pattern string) map[string]any {
	return map[string]any{
		"active":             true,
		"anomalyDetectorArn": arn,
		"anomalyId":          "anomaly-1",
		"description":        description,
		"firstSeen":          int64(1622505600000),
		"histogram":          map[string]int64{"1622505600000": 5},
		"lastSeen":           int64(1622592000000),
		"logGroupArnList":    []string{"arn:aws:logs:us-east-1:123456789012:log-group:app"},
		"patternString":      pattern,
		"priority":           priority,
		"state":              "Active",
		"suppressed":         suppressed,
	}
}

func listAnomaliesBody(t *testing.T, anomalies ...map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"anomalies": anomalies})
	require.NoError(t, err)
	return body
}

func responseFrame(t *testing.T, resp *backend.QueryDataResponse, refID string) *data.Frame {
	t.Helper()
	require.NotNil(t, resp)
	result, ok := resp.Responses[refID]
	require.True(t, ok, "missing response for %s", refID)
	require.NoError(t, result.Error)
	require.Len(t, result.Frames, 1)
	return result.Frames[0]
}
