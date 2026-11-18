package cloudwatch

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
)

// Unknown and omitted CloudWatch logAction subtypes must come back as a query
// error. They must not panic, including on the per-query goroutine, and they
// must not call CloudWatch. A valid log action in the same request must still
// succeed.
func TestQueryData_logActionUnknownSubtype_returnsQueryError(t *testing.T) {
	origNewCWLogsClient := NewCWLogsClient
	t.Cleanup(func() {
		NewCWLogsClient = origNewCWLogsClient
	})

	cli := &fakeCWLogsClient{}
	NewCWLogsClient = func(cfg aws.Config) models.CWLogsClient {
		return cli
	}

	cases := []struct {
		name  string
		query string
	}{
		{
			name:  "omitted subtype",
			query: `{"type":"logAction","region":"us-east-1"}`,
		},
		{
			name:  "unknown subtype",
			query: `{"type":"logAction","subtype":"NotALogAction","region":"us-east-1"}`,
		},
		{
			name:  "wrong case",
			query: `{"type":"logAction","subtype":"startquery","region":"us-east-1"}`,
		},
		{
			name:  "unknown subtype with stats groups",
			query: `{"type":"logAction","subtype":"Nope","statsGroups":["bin(1m)"],"region":"us-east-1"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			*cli = fakeCWLogsClient{}
			ds := newTestDatasource()

			resp, err := ds.QueryData(context.Background(), logActionRequest("A", tc.query))
			require.NoError(t, err)
			require.NotNil(t, resp)

			got, ok := resp.Responses["A"]
			require.True(t, ok)
			require.Error(t, got.Error)
			require.Empty(t, got.Frames)
			require.Empty(t, cli.calls.startQuery)
			require.Empty(t, cli.calls.getEvents)
		})
	}
}

func TestQueryData_logActionUnknownSubtype_doesNotFailSiblingQuery(t *testing.T) {
	origNewCWLogsClient := NewCWLogsClient
	t.Cleanup(func() {
		NewCWLogsClient = origNewCWLogsClient
	})

	cli := &fakeCWLogsClient{}
	NewCWLogsClient = func(cfg aws.Config) models.CWLogsClient {
		return cli
	}

	ds := newTestDatasource()
	req := &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{
			DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{},
		},
		Queries: []backend.DataQuery{
			{
				RefID:     "good",
				TimeRange: backend.TimeRange{From: time.Unix(0, 0), To: time.Unix(1, 0)},
				JSON: json.RawMessage(`{
					"type":"logAction",
					"subtype":"GetLogEvents",
					"region":"us-east-1",
					"logGroupName":"group",
					"logStreamName":"stream"
				}`),
			},
			{
				RefID:     "bad",
				TimeRange: backend.TimeRange{From: time.Unix(0, 0), To: time.Unix(1, 0)},
				JSON:      json.RawMessage(`{"type":"logAction","subtype":"NotALogAction","region":"us-east-1"}`),
			},
		},
	}

	resp, err := ds.QueryData(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	good, ok := resp.Responses["good"]
	require.True(t, ok)
	require.NoError(t, good.Error)
	require.NotEmpty(t, good.Frames)

	bad, ok := resp.Responses["bad"]
	require.True(t, ok)
	require.Error(t, bad.Error)
	require.Empty(t, bad.Frames)

	require.Len(t, cli.calls.getEvents, 1)
	require.Empty(t, cli.calls.startQuery)
}

func TestServiceQueryData_logActionUnknownSubtype_returnsQueryError(t *testing.T) {
	origNewCWLogsClient := NewCWLogsClient
	t.Cleanup(func() {
		NewCWLogsClient = origNewCWLogsClient
	})

	cli := &fakeCWLogsClient{}
	NewCWLogsClient = func(cfg aws.Config) models.CWLogsClient {
		return cli
	}

	// ProvideService uses NewDatasource, which loads a real AWS config.
	svc := ProvideService()

	resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{
			PluginID: "cloudwatch",
			DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{
				UID:      "cw-uid",
				JSONData: json.RawMessage(`{"region":"us-east-1","authType":"default"}`),
			},
		},
		Queries: []backend.DataQuery{
			{
				RefID:     "A",
				TimeRange: backend.TimeRange{From: time.Unix(0, 0), To: time.Unix(1, 0)},
				JSON:      json.RawMessage(`{"type":"logAction","subtype":"NotALogAction","region":"us-east-1"}`),
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	got, ok := resp.Responses["A"]
	require.True(t, ok)
	require.Error(t, got.Error)
	require.Empty(t, cli.calls.startQuery)
	require.Empty(t, cli.calls.getEvents)
}

func logActionRequest(refID, query string) *backend.QueryDataRequest {
	return &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{
			DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{},
		},
		Queries: []backend.DataQuery{
			{
				RefID:     refID,
				TimeRange: backend.TimeRange{From: time.Unix(0, 0), To: time.Unix(1, 0)},
				JSON:      json.RawMessage(query),
			},
		},
	}
}
