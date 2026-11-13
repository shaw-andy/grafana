package cloudwatch

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/features"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
	"github.com/stretchr/testify/require"
)

func TestLogsSQLLiteralsEscapeInsertedQuotes(t *testing.T) {
	origNewCWLogsClient := NewCWLogsClient
	t.Cleanup(func() {
		NewCWLogsClient = origNewCWLogsClient
	})

	var cli fakeCWLogsClient
	NewCWLogsClient = func(cfg aws.Config) models.CWLogsClient {
		return &cli
	}

	const fieldsClause = "fields @timestamp,ltrim(@log) as " + logIdentifierInternal + ",ltrim(@logStream) as " + logStreamIdentifierInternal

	t.Run("sql log group macro keeps a quote inside one literal", func(t *testing.T) {
		cli = fakeCWLogsClient{}
		ds := newTestDatasource()
		queryJSON, err := json.Marshal(map[string]any{
			"type":          "logAction",
			"subtype":       "StartQuery",
			"queryLanguage": "SQL",
			"queryString":   "SELECT * FROM $__logGroups",
			"logGroups": []map[string]string{{
				"arn":  "arn:aws:logs:us-east-1:123456789012:log-group:allowed",
				"name": "allowed', 'other",
			}},
		})
		require.NoError(t, err)

		_, err = ds.QueryData(context.Background(), startQueryRequest(queryJSON))
		require.NoError(t, err)
		require.Len(t, cli.calls.startQuery, 1)
		require.Equal(t, "SELECT * FROM logGroups(logGroupIdentifier: ['allowed'', ''other'])", *cli.calls.startQuery[0].QueryString)
	})

	t.Run("sql source macro keeps a quote inside one literal", func(t *testing.T) {
		cli = fakeCWLogsClient{}
		ds := newTestDatasource()
		queryJSON, err := json.Marshal(map[string]any{
			"type":          "logAction",
			"subtype":       "StartQuery",
			"queryLanguage": "SQL",
			"queryString":   "SELECT * FROM $__source",
			"logGroups": []map[string]string{{
				"arn":  "arn:aws:logs:us-east-1:123456789012:log-group:allowed",
				"name": "allowed', 'other",
			}},
		})
		require.NoError(t, err)

		_, err = ds.QueryData(context.Background(), startQueryRequest(queryJSON))
		require.NoError(t, err)
		require.Len(t, cli.calls.startQuery, 1)
		require.Equal(t, "SELECT * FROM logGroups(logGroupIdentifier: ['allowed'', ''other'])", *cli.calls.startQuery[0].QueryString)
	})

	t.Run("monitoring account sql macro escapes the arn after trimming the trailing wildcard", func(t *testing.T) {
		cli = fakeCWLogsClient{}
		ds := newTestDatasource(func(ds *DataSource) {
			ds.monitoringAccountCache.Store("us-east-1", true)
		})
		queryJSON, err := json.Marshal(map[string]any{
			"type":          "logAction",
			"subtype":       "StartQuery",
			"queryLanguage": "SQL",
			"region":        "us-east-1",
			"queryString":   "SELECT * FROM $__logGroups",
			"logGroups": []map[string]string{{
				"arn":  "arn:aws:logs:us-east-1:123456789012:log-group:allowed:*', 'arn:aws:logs:us-east-1:123456789012:log-group:other:*",
				"name": "allowed",
			}},
		})
		require.NoError(t, err)

		_, err = ds.QueryData(contextWithFeaturesEnabled(features.FlagCloudWatchCrossAccountQuerying), startQueryRequest(queryJSON))
		require.NoError(t, err)
		require.Len(t, cli.calls.startQuery, 1)
		require.Equal(t,
			"SELECT * FROM logGroups(logGroupIdentifier: ['arn:aws:logs:us-east-1:123456789012:log-group:allowed:*'', ''arn:aws:logs:us-east-1:123456789012:log-group:other:'])",
			*cli.calls.startQuery[0].QueryString,
		)
	})

	t.Run("cwli source clause escapes prefix and account identifier quotes", func(t *testing.T) {
		cli = fakeCWLogsClient{}
		ds := newTestDatasource(func(ds *DataSource) {
			ds.monitoringAccountCache.Store("us-east-1", true)
		})
		queryJSON, err := json.Marshal(map[string]any{
			"type":               "logAction",
			"subtype":            "StartQuery",
			"queryLanguage":      "CWLI",
			"region":             "us-east-1",
			"queryString":        "fields @message",
			"logsQueryScope":     "namePrefix",
			"logGroupPrefixes":   []string{"/aws', '/secret"},
			"selectedAccountIds": []string{"123456789012', '999999999999"},
		})
		require.NoError(t, err)

		_, err = ds.QueryData(contextWithFeaturesEnabled(features.FlagCloudWatchCrossAccountQuerying), startQueryRequest(queryJSON))
		require.NoError(t, err)
		require.Len(t, cli.calls.startQuery, 1)
		require.Equal(t,
			"SOURCE logGroups(namePrefix: ['/aws'', ''/secret'], accountIdentifier: ['123456789012'', ''999999999999']) | "+fieldsClause+"|fields @message",
			*cli.calls.startQuery[0].QueryString,
		)
	})

	t.Run("sync log query escapes quotes inserted into the sql log group macro", func(t *testing.T) {
		cli = fakeCWLogsClient{}
		cli.queryResults.Status = cloudwatchlogstypes.QueryStatusComplete
		ds := newTestDatasource()
		queryJSON, err := json.Marshal(map[string]any{
			"queryMode":     "Logs",
			"queryLanguage": "SQL",
			"expression":    "SELECT * FROM $__logGroups",
			"logGroups": []map[string]string{{
				"arn":  "arn:aws:logs:us-east-1:123456789012:log-group:allowed",
				"name": "allowed', 'other",
			}},
		})
		require.NoError(t, err)

		_, err = ds.QueryData(context.Background(), startQueryRequest(queryJSON))
		require.NoError(t, err)
		require.Len(t, cli.calls.startQuery, 1)
		require.Equal(t, "SELECT * FROM logGroups(logGroupIdentifier: ['allowed'', ''other'])", *cli.calls.startQuery[0].QueryString)
	})
}

func startQueryRequest(queryJSON []byte) *backend.QueryDataRequest {
	return &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{}},
		Queries: []backend.DataQuery{{
			RefID:     "A",
			TimeRange: backend.TimeRange{From: time.Unix(0, 0), To: time.Unix(1, 0)},
			JSON:      queryJSON,
		}},
	}
}
