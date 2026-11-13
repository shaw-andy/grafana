package cloudwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/features"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models/resources"
)

// resourcePagingLogsAPI stands in for DescribeLogGroups. Each call returns the
// single page selected by the request token. A further token is returned until
// pageCount pages have been served. Callers copy NextToken before the service
// overwrites the input it reuses for the next page.
type resourcePagingLogsAPI struct {
	pageCount int
	calls     []recordedResourceDescribe
}

type recordedResourceDescribe struct {
	limit     int32
	nextToken string
	accounts  []string
	linked    bool
}

func (a *resourcePagingLogsAPI) DescribeLogGroups(_ context.Context, input *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	token := ""
	if input.NextToken != nil {
		token = *input.NextToken
	}
	page := 1
	if token != "" {
		var n int
		if _, err := fmt.Sscanf(token, "token-%d", &n); err == nil && n >= 1 {
			page = n + 1
		}
	}

	recorded := recordedResourceDescribe{accounts: append([]string(nil), input.AccountIdentifiers...)}
	if input.Limit != nil {
		recorded.limit = *input.Limit
	}
	recorded.nextToken = token
	if input.IncludeLinkedAccounts != nil {
		recorded.linked = *input.IncludeLinkedAccounts
	}
	a.calls = append(a.calls, recorded)

	name := fmt.Sprintf("group-%d", page)
	out := &cloudwatchlogs.DescribeLogGroupsOutput{
		LogGroups: []cloudwatchlogstypes.LogGroup{{
			Arn:          aws.String("arn:aws:logs:us-east-1:111111111111:log-group:" + name),
			LogGroupName: aws.String(name),
		}},
	}
	if page < a.pageCount {
		out.NextToken = aws.String(fmt.Sprintf("token-%d", page))
	}
	return out, nil
}

func (a *resourcePagingLogsAPI) GetLogGroupFields(context.Context, *cloudwatchlogs.GetLogGroupFieldsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogGroupFieldsOutput, error) {
	return nil, fmt.Errorf("unexpected GetLogGroupFields")
}

func (a *resourcePagingLogsAPI) ListAggregateLogGroupSummaries(context.Context, *cloudwatchlogs.ListAggregateLogGroupSummariesInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.ListAggregateLogGroupSummariesOutput, error) {
	return nil, fmt.Errorf("unexpected ListAggregateLogGroupSummaries")
}

func TestLogGroupsResourceListAllLogGroupsReturnsOnePage(t *testing.T) {
	const pageCount = 8

	origNewLogsAPI := NewLogsAPI
	t.Cleanup(func() {
		NewLogsAPI = origNewLogsAPI
	})

	tests := []struct {
		name         string
		query        string
		crossAccount bool
		wantName     string
		wantToken    string
		wantLimit    int32
		wantAccounts []string
		wantLinked   bool
	}{
		{
			name:      "query flag",
			query:     "region=us-east-1&listAllLogGroups=true",
			wantName:  "group-1",
			wantToken: "token-1",
			wantLimit: 50,
		},
		{
			name:      "limit does not cap pages",
			query:     "region=us-east-1&limit=1&listAllLogGroups=true",
			wantName:  "group-1",
			wantToken: "token-1",
			wantLimit: 1,
		},
		{
			name:      "resume token",
			query:     "region=us-east-1&listAllLogGroups=true&nextToken=token-2",
			wantName:  "group-3",
			wantToken: "token-3",
			wantLimit: 50,
		},
		{
			name:         "cross account",
			query:        "region=us-east-1&accountId=123456789012&listAllLogGroups=true",
			crossAccount: true,
			wantName:     "group-1",
			wantToken:    "token-1",
			wantLimit:    50,
			wantAccounts: []string{"123456789012"},
			wantLinked:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &resourcePagingLogsAPI{pageCount: pageCount}
			NewLogsAPI = func(aws.Config) models.CloudWatchLogsAPIProvider {
				return api
			}

			ctx := context.Background()
			if tt.crossAccount {
				ctx = contextWithFeaturesEnabled(features.FlagCloudWatchCrossAccountQuerying)
			}

			sender := &mockedCallResourceResponseSenderForOauth{}
			ds := newTestDatasource()
			req := &backend.CallResourceRequest{
				Method: http.MethodGet,
				Path:   "/log-groups",
				URL:    "/log-groups?" + tt.query,
			}

			err := ds.CallResource(ctx, req, sender)
			require.NoError(t, err)
			require.NotNil(t, sender.Response)
			require.Equal(t, http.StatusOK, sender.Response.Status)
			require.Len(t, api.calls, 1, "GET log-groups must not follow every DescribeLogGroups page")
			assert.Equal(t, tt.wantLimit, api.calls[0].limit)
			assert.Equal(t, tt.wantAccounts, api.calls[0].accounts)
			assert.Equal(t, tt.wantLinked, api.calls[0].linked)

			var body []resources.ResourceResponse[resources.LogGroup]
			require.NoError(t, json.Unmarshal(sender.Response.Body, &body))
			require.Len(t, body, 1)
			assert.Equal(t, tt.wantName, body[0].Value.Name)
			assert.Equal(t, "111111111111", aws.ToString(body[0].AccountId))

			link := http.Header(sender.Response.Headers).Get("Link")
			assert.Contains(t, link, "nextToken="+tt.wantToken)
			assert.Contains(t, link, `rel="next"`)
			assert.NotContains(t, link, "nextToken=token-8")
		})
	}
}
