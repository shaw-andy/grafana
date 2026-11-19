package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models/resources"
)

// logGroupPageLimit is the most DescribeLogGroups requests one GetLogGroups
// call may make when ListAllLogGroups is set and every page carries a next token.
const logGroupPageLimit = 20

const offeredLogGroupPages = 40

func TestGetLogGroupsListAllStopsOnEmptyNextToken(t *testing.T) {
	var calls atomic.Int32
	client := newLogsClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Logs_20140328.DescribeLogGroups", r.Header.Get("X-Amz-Target"))
		n := calls.Add(1)
		next := ""
		include := n <= offeredLogGroupPages
		writeLogGroupsPage(t, w, include, next, n)
	})

	groups, _, err := NewLogGroupsService(client, false).GetLogGroups(context.Background(), resources.LogGroupsRequest{
		ListAllLogGroups: true,
		Limit:            50,
	})
	require.NoError(t, err)
	require.NotEmpty(t, groups)
	require.Equal(t, int32(1), calls.Load(), "empty nextToken must end a list-all log group walk")
}

func TestGetLogGroupsListAllCapsChangingNextToken(t *testing.T) {
	var calls atomic.Int32
	client := newLogsClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Logs_20140328.DescribeLogGroups", r.Header.Get("X-Amz-Target"))
		n := calls.Add(1)
		if n > offeredLogGroupPages {
			writeLogGroupsPage(t, w, false, "", n)
			return
		}
		writeLogGroupsPage(t, w, true, fmt.Sprintf("groups-%d", n), n)
	})

	_, _, err := NewLogGroupsService(client, false).GetLogGroups(context.Background(), resources.LogGroupsRequest{
		ListAllLogGroups: true,
		Limit:            50,
	})
	if err != nil {
		require.LessOrEqual(t, calls.Load(), int32(logGroupPageLimit))
		return
	}
	require.LessOrEqual(t, calls.Load(), int32(logGroupPageLimit))
}

func writeLogGroupsPage(t *testing.T, w http.ResponseWriter, includeNext bool, next string, n int32) {
	t.Helper()
	payload := map[string]any{
		"logGroups": []map[string]string{{
			"arn":          fmt.Sprintf("arn:aws:logs:us-east-1:111111111111:log-group:group-%d", n),
			"logGroupName": fmt.Sprintf("group-%d", n),
		}},
	}
	if includeNext {
		payload["nextToken"] = next
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	require.NoError(t, json.NewEncoder(w).Encode(payload))
}

func newLogsClient(t *testing.T, handler http.HandlerFunc) models.CloudWatchLogsAPIProvider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return cloudwatchlogs.NewFromConfig(aws.Config{
		Region:       "us-east-1",
		Credentials:  aws.AnonymousCredentials{},
		BaseEndpoint: aws.String(srv.URL),
		HTTPClient:   srv.Client(),
		Retryer:      func() aws.Retryer { return aws.NopRetryer{} },
	})
}
