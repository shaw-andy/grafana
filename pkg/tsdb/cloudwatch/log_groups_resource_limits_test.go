package cloudwatch

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
)

func TestLogGroupsResourceListAllCapsChangingNextToken(t *testing.T) {
	const pageLimit = 20
	const offered = 40
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Logs_20140328.DescribeLogGroups", r.Header.Get("X-Amz-Target"))
		n := calls.Add(1)
		token := ""
		if n <= offered {
			token = fmt.Sprintf(`,"nextToken":"groups-%d"`, n)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, err := fmt.Fprintf(w, `{"logGroups":[{"arn":"arn:aws:logs:us-east-1:111111111111:log-group:group-%d","logGroupName":"group-%d"}]%s}`, n, n, token)
		require.NoError(t, err)
	}))
	t.Cleanup(srv.Close)

	client := cloudwatchlogs.NewFromConfig(aws.Config{
		Region:       "us-east-1",
		Credentials:  aws.AnonymousCredentials{},
		BaseEndpoint: aws.String(srv.URL),
		HTTPClient:   srv.Client(),
		Retryer:      func() aws.Retryer { return aws.NopRetryer{} },
	})
	orig := NewLogsAPI
	NewLogsAPI = func(aws.Config) models.CloudWatchLogsAPIProvider { return client }
	t.Cleanup(func() { NewLogsAPI = orig })

	ds := newTestDatasource()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/log-groups?region=us-east-1&listAllLogGroups=true", nil)
	http.HandlerFunc(ds.resourceRequestWithHeadersMiddleware(ds.LogGroupsHandler)).ServeHTTP(rr, req)

	require.Greater(t, calls.Load(), int32(1))
	require.LessOrEqual(t, calls.Load(), int32(pageLimit))
}
