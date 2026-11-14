package cloudwatch

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/features"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
)

const injectedLogGroup = "injected-log-group"

// pplSourceBreakout closes the backtick Grafana wraps around a log group, ends the
// generated source list, and appends another source command. The saved query text
// itself does not contain a source command.
func pplSourceBreakout() string {
	return "selected`], source=[lg:`" + injectedLogGroup + "`] | fields `@message` -- "
}

func TestPPLLogGroupSourceInjection(t *testing.T) {
	savedQuery := "fields `@timestamp` | where source = 'application'"
	require.False(t, containsPPLSourceCommand(savedQuery))

	t.Run("refuses a log group name that closes the PPL identifier and appends a source command", func(t *testing.T) {
		resp, err, cli := runLogAction(t, pplLogsQuery(savedQuery, logGroup(pplSourceBreakout(), "arn:aws:logs:us-east-1:123456789012:log-group:selected")))
		requireSourceNotStarted(t, resp, err, cli)
	})

	t.Run("refuses the breakout when it is the second selected log group", func(t *testing.T) {
		query := pplLogsQuery(savedQuery,
			logGroup("/aws/lambda/selected", "arn:aws:logs:us-east-1:123456789012:log-group:selected"),
			logGroup(pplSourceBreakout(), "arn:aws:logs:us-east-1:123456789012:log-group:other"),
		)
		resp, err, cli := runLogAction(t, query)
		requireSourceNotStarted(t, resp, err, cli)
	})

	t.Run("refuses the breakout when a monitoring account copies the log group ARN into the source clause", func(t *testing.T) {
		query := pplLogsQuery(savedQuery, logGroup("/aws/lambda/selected", pplSourceBreakout()))
		query["region"] = "us-east-1"
		resp, err, cli := runLogActionMonitoring(t, query)
		requireSourceNotStarted(t, resp, err, cli)
	})

	t.Run("refuses a log group name containing a backtick, pipe, or bracket", func(t *testing.T) {
		for _, name := range []string{"app`extra", "app|extra", "app[extra", "app]extra"} {
			t.Run(name, func(t *testing.T) {
				resp, err, cli := runLogAction(t, pplLogsQuery(savedQuery, logGroup(name, "arn:aws:logs:us-east-1:123456789012:log-group:selected")))
				requireSourceNotStarted(t, resp, err, cli)
			})
		}
	})

	t.Run("still queries a plain log group name with the selected data source", func(t *testing.T) {
		resp, err, cli := runLogAction(t, pplLogsQuery(savedQuery, logGroup("/aws/lambda/selected", "arn:aws:logs:us-east-1:123456789012:log-group:selected")))
		require.NoError(t, err)
		require.NoError(t, resp.Responses["A"].Error)
		require.Len(t, cli.calls.startQuery, 1)
		require.Equal(t, cloudwatchlogstypes.QueryLanguagePpl, cli.calls.startQuery[0].QueryLanguage)
		require.Nil(t, cli.calls.startQuery[0].LogGroupNames)
		require.Nil(t, cli.calls.startQuery[0].LogGroupIdentifiers)
		require.Equal(t, "source=[ds:`amazon_vpc.flow`, lg:`/aws/lambda/selected`] | "+savedQuery, aws.ToString(cli.calls.startQuery[0].QueryString))
	})

	t.Run("alert evaluation refuses the breakout after copying expression into the query string", func(t *testing.T) {
		query := pplLogsQuery(savedQuery, logGroup(pplSourceBreakout(), "arn:aws:logs:us-east-1:123456789012:log-group:selected"))
		delete(query, "queryString")
		delete(query, "subtype")
		query["type"] = "saved"
		query["queryMode"] = "Logs"
		query["expression"] = savedQuery
		resp, err, cli := runSyncLogQuery(t, query, map[string]string{headerFromAlert: "true"})
		requireSourceNotStarted(t, resp, err, cli)
	})

	t.Run("expression queries refuse the breakout after copying expression into the query string", func(t *testing.T) {
		query := pplLogsQuery(savedQuery, logGroup(pplSourceBreakout(), "arn:aws:logs:us-east-1:123456789012:log-group:selected"))
		delete(query, "queryString")
		delete(query, "subtype")
		query["type"] = "saved"
		query["queryMode"] = "Logs"
		query["expression"] = savedQuery
		resp, err, cli := runSyncLogQuery(t, query, map[string]string{"http_" + headerFromExpression: "true"})
		requireSourceNotStarted(t, resp, err, cli)
	})

	t.Run("public dashboard queries refuse the breakout", func(t *testing.T) {
		query := pplLogsQuery(savedQuery, logGroup(pplSourceBreakout(), "arn:aws:logs:us-east-1:123456789012:log-group:selected"))
		delete(query, "queryString")
		delete(query, "type")
		delete(query, "subtype")
		query["queryMode"] = "Logs"
		query["expression"] = savedQuery
		resp, err, cli := runSyncLogQuery(t, query, nil)
		requireSourceNotStarted(t, resp, err, cli)
	})
}

func TestLogSelectionLiteralInjection(t *testing.T) {
	t.Run("SQL log group macro refuses a name that breaks out of the quoted identifier", func(t *testing.T) {
		query := map[string]any{
			"type":          "logAction",
			"subtype":       "StartQuery",
			"queryLanguage": "SQL",
			"queryString":   "SELECT * FROM `$__logGroups`",
			"logGroups":     []any{logGroup("x') FROM `"+injectedLogGroup+"` -- ", "arn:aws:logs:us-east-1:123456789012:log-group:selected")},
		}
		resp, err, cli := runLogAction(t, query)
		requireSourceNotStarted(t, resp, err, cli)
	})

	t.Run("SQL source macro refuses a name that breaks out of the quoted identifier", func(t *testing.T) {
		query := map[string]any{
			"type":           "logAction",
			"subtype":        "StartQuery",
			"queryLanguage":  "SQL",
			"queryString":    "SELECT * FROM `$__source`",
			"logGroups":      []any{logGroup("x') FROM `"+injectedLogGroup+"` -- ", "arn:aws:logs:us-east-1:123456789012:log-group:selected")},
			"logDataSources": []any{map[string]any{"name": "amazon_vpc", "type": "flow"}},
		}
		resp, err, cli := runLogAction(t, query)
		requireSourceNotStarted(t, resp, err, cli)
	})

	t.Run("SQL log group macro refuses the breakout carried by a monitoring-account ARN", func(t *testing.T) {
		query := map[string]any{
			"type":          "logAction",
			"subtype":       "StartQuery",
			"queryLanguage": "SQL",
			"region":        "us-east-1",
			"queryString":   "SELECT * FROM `$__logGroups`",
			"logGroups":     []any{logGroup("/aws/lambda/selected", "x') FROM `"+injectedLogGroup+"` -- ")},
		}
		resp, err, cli := runLogActionMonitoring(t, query)
		requireSourceNotStarted(t, resp, err, cli)
	})

	t.Run("CWLI name prefix refuses a value that closes the quote and appends SOURCE", func(t *testing.T) {
		query := map[string]any{
			"type":             "logAction",
			"subtype":          "StartQuery",
			"queryLanguage":    "CWLI",
			"queryString":      "fields @message",
			"logsQueryScope":   "namePrefix",
			"logGroupPrefixes": []any{"abc']) | SOURCE logGroups(logGroupIdentifier: ['" + injectedLogGroup + "']) | fields @message -- "},
		}
		require.False(t, containsSourceCommand("fields @message"))
		resp, err, cli := runLogAction(t, query)
		requireSourceNotStarted(t, resp, err, cli)
	})

	t.Run("CWLI account identifier refuses a value that closes the quote and appends SOURCE", func(t *testing.T) {
		query := map[string]any{
			"type":               "logAction",
			"subtype":            "StartQuery",
			"queryLanguage":      "CWLI",
			"queryString":        "fields @message",
			"region":             "us-east-1",
			"logsQueryScope":     "allLogGroups",
			"selectedAccountIds": []any{"123']) | SOURCE logGroups(logGroupIdentifier: ['" + injectedLogGroup + "']) | fields @message -- "},
		}
		resp, err, cli := runLogActionMonitoring(t, query)
		requireSourceNotStarted(t, resp, err, cli)
	})
}

func pplLogsQuery(queryString string, groups ...any) map[string]any {
	return map[string]any{
		"type":           "logAction",
		"subtype":        "StartQuery",
		"queryLanguage":  "PPL",
		"queryString":    queryString,
		"logGroups":      groups,
		"logDataSources": []any{map[string]any{"name": "amazon_vpc", "type": "flow"}},
	}
}

func logGroup(name, arn string) map[string]any {
	return map[string]any{"name": name, "arn": arn}
}

func runLogAction(t *testing.T, query map[string]any) (*backend.QueryDataResponse, error, *fakeCWLogsClient) {
	t.Helper()
	return runQuery(t, context.Background(), query, nil, false)
}

func runLogActionMonitoring(t *testing.T, query map[string]any) (*backend.QueryDataResponse, error, *fakeCWLogsClient) {
	t.Helper()
	return runQuery(t, contextWithFeaturesEnabled(features.FlagCloudWatchCrossAccountQuerying), query, nil, true)
}

func runSyncLogQuery(t *testing.T, query map[string]any, headers map[string]string) (*backend.QueryDataResponse, error, *fakeCWLogsClient) {
	t.Helper()
	return runQuery(t, context.Background(), query, headers, false)
}

func runQuery(t *testing.T, ctx context.Context, query map[string]any, headers map[string]string, monitoring bool) (*backend.QueryDataResponse, error, *fakeCWLogsClient) {
	t.Helper()
	orig := NewCWLogsClient
	t.Cleanup(func() {
		NewCWLogsClient = orig
	})

	cli := &fakeCWLogsClient{queryResults: cloudwatchlogs.GetQueryResultsOutput{Status: cloudwatchlogstypes.QueryStatusComplete}}
	NewCWLogsClient = func(aws.Config) models.CWLogsClient {
		return cli
	}
	ds := newTestDatasource()
	ds.Settings.LogsTimeout = models.Duration{Duration: time.Minute}
	if monitoring {
		ds.monitoringAccountCache.Store("us-east-1", true)
	}

	raw, err := json.Marshal(query)
	require.NoError(t, err)
	resp, err := ds.QueryData(ctx, &backend.QueryDataRequest{
		Headers:       headers,
		PluginContext: backend.PluginContext{DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{}},
		Queries: []backend.DataQuery{{
			RefID:     "A",
			TimeRange: backend.TimeRange{From: time.Unix(0, 0), To: time.Unix(1, 0)},
			JSON:      raw,
		}},
	})
	return resp, err, cli
}

func requireSourceNotStarted(t *testing.T, resp *backend.QueryDataResponse, err error, cli *fakeCWLogsClient) {
	t.Helper()
	if len(cli.calls.startQuery) > 0 {
		t.Fatalf("StartQuery was invoked before the log selection was refused: %s", aws.ToString(cli.calls.startQuery[0].QueryString))
	}
	if err != nil {
		return
	}
	require.NotNil(t, resp)
	require.Error(t, resp.Responses["A"].Error)
}
