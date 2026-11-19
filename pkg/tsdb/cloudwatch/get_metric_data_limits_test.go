package cloudwatch

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/stretchr/testify/require"
)

// metricDataPageLimit is the most GetMetricData requests one executeRequest
// call may make when every page carries a non-empty next token.
const metricDataPageLimit = 20

const offeredMetricDataPages = 40

func TestGetMetricDataCapsChangingNextToken(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		token := ""
		if n <= offeredMetricDataPages {
			token = fmt.Sprintf("<NextToken>metric-page-%d</NextToken>", n)
		}
		w.Header().Set("Content-Type", "text/xml")
		_, err := fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<GetMetricDataResponse xmlns="http://monitoring.amazonaws.com/doc/2010-08-01/">
  <GetMetricDataResult>
    <MetricDataResults></MetricDataResults>
    %s
  </GetMetricDataResult>
  <ResponseMetadata><RequestId>req</RequestId></ResponseMetadata>
</GetMetricDataResponse>`, token)
		require.NoError(t, err)
	}))
	t.Cleanup(srv.Close)

	client := cloudwatch.NewFromConfig(aws.Config{
		Region:       "us-east-1",
		Credentials:  aws.AnonymousCredentials{},
		BaseEndpoint: aws.String(srv.URL),
		HTTPClient:   srv.Client(),
		Retryer:      func() aws.Retryer { return aws.NopRetryer{} },
	})

	end := time.Unix(1_700_000_000, 0).UTC()
	_, err := (&DataSource{}).executeRequest(context.Background(), client, &cloudwatch.GetMetricDataInput{
		StartTime: aws.Time(end.Add(-time.Minute)),
		EndTime:   &end,
		MetricDataQueries: []cloudwatchtypes.MetricDataQuery{{
			Id: aws.String("q1"),
		}},
	})
	require.Greater(t, calls.Load(), int32(1), "GetMetricData stand-in was not followed: %v", err)
	require.LessOrEqual(t, calls.Load(), int32(metricDataPageLimit))
}
