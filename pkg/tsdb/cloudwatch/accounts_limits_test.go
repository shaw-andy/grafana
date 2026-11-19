package cloudwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/oam"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/features"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
)

func TestAccountsResourceDoesNotRepeatDiscovery(t *testing.T) {
	var sinks atomic.Int32
	client := newOAMClientFromTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ListSinks":
			sinks.Add(1)
			writeAccountsJSON(t, w, map[string]any{
				"Items": []map[string]string{{
					"Name": "monitoring",
					"Arn":  "arn:aws:oam:us-east-1:111111111111:sink/monitoring",
				}},
			})
		case "/ListAttachedLinks":
			writeAccountsJSON(t, w, map[string]any{
				"Items": []map[string]string{{
					"Label":   "linked",
					"LinkArn": "arn:aws:oam:us-east-1:222222222222:link/linked",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	})

	orig := NewOAMAPI
	NewOAMAPI = func(aws.Config) models.OAMAPIProvider { return client }
	t.Cleanup(func() { NewOAMAPI = orig })

	ds := newTestDatasource()
	handler := http.HandlerFunc(ds.resourceRequestMiddleware(ds.AccountsHandler))
	for range 2 {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/accounts?region=us-east-1", nil)
		handler.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	}
	require.Equal(t, int32(1), sinks.Load(), "repeating the accounts resource must not walk ListSinks again")
}

func TestLogsQueryAccountDiscoveryCapsChangingNextToken(t *testing.T) {
	const pageLimit = 20
	const offered = 40
	var links atomic.Int32
	client := newOAMClientFromTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ListSinks":
			writeAccountsJSON(t, w, map[string]any{
				"Items": []map[string]string{{
					"Name": "monitoring",
					"Arn":  "arn:aws:oam:us-east-1:111111111111:sink/monitoring",
				}},
			})
		case "/ListAttachedLinks":
			n := links.Add(1)
			payload := map[string]any{
				"Items": []map[string]string{{
					"Label":   "linked",
					"LinkArn": "arn:aws:oam:us-east-1:222222222222:link/linked",
				}},
			}
			if n <= offered {
				payload["NextToken"] = fmt.Sprintf("link-page-%d", n)
			}
			writeAccountsJSON(t, w, payload)
		default:
			http.NotFound(w, r)
		}
	})

	origOAM := NewOAMAPI
	origLogs := NewCWLogsClient
	NewOAMAPI = func(aws.Config) models.OAMAPIProvider { return client }
	NewCWLogsClient = func(aws.Config) models.CWLogsClient { return stubStartQueryClient{} }
	t.Cleanup(func() {
		NewOAMAPI = origOAM
		NewCWLogsClient = origLogs
	})

	ds := newTestDatasource()
	_, err := ds.QueryData(contextWithFeaturesEnabled(features.FlagCloudWatchCrossAccountQuerying), &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{}},
		Queries: []backend.DataQuery{{
			RefID:     "A",
			TimeRange: backend.TimeRange{From: time.Unix(0, 0), To: time.Unix(1, 0)},
			JSON: json.RawMessage(`{
				"type": "logAction",
				"subtype": "StartQuery",
				"queryString": "fields @message",
				"logGroups": [{"arn": "arn:aws:logs:us-east-1:111111111111:log-group:app"}],
				"region": "us-east-1"
			}`),
		}},
	})
	require.NoError(t, err)
	require.LessOrEqual(t, links.Load(), int32(pageLimit))
}

type stubStartQueryClient struct {
	models.CWLogsClient
}

func (stubStartQueryClient) StartQuery(context.Context, *cloudwatchlogs.StartQueryInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String("query-1")}, nil
}

func newOAMClientFromTestServer(t *testing.T, handler http.HandlerFunc) models.OAMAPIProvider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return oam.NewFromConfig(aws.Config{
		Region:       "us-east-1",
		Credentials:  aws.AnonymousCredentials{},
		BaseEndpoint: aws.String(srv.URL),
		HTTPClient:   srv.Client(),
		Retryer:      func() aws.Retryer { return aws.NopRetryer{} },
	})
}

func writeAccountsJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(payload))
}
