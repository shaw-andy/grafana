package services

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models/resources"
)

// pagingDescribeLogGroupsAPI returns one log group per DescribeLogGroups call and
// a next token until pageCount pages have been served. GetLogGroups reuses the
// same input pointer across pages, so each call records a copy of the token and
// limit it actually received.
type pagingDescribeLogGroupsAPI struct {
	pageCount int
	calls     []recordedDescribeLogGroups
}

type recordedDescribeLogGroups struct {
	limit      int32
	nextToken  string
	accounts   []string
	linked     bool
	namePrefix string
}

func pageAfterToken(nextToken string) int {
	if nextToken == "" {
		return 1
	}
	var n int
	if _, err := fmt.Sscanf(nextToken, "token-%d", &n); err != nil || n < 1 {
		return 1
	}
	return n + 1
}

func (a *pagingDescribeLogGroupsAPI) DescribeLogGroups(_ context.Context, input *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	token := ""
	if input.NextToken != nil {
		token = *input.NextToken
	}
	page := pageAfterToken(token)
	recorded := recordedDescribeLogGroups{
		accounts: append([]string(nil), input.AccountIdentifiers...),
	}
	if input.Limit != nil {
		recorded.limit = *input.Limit
	}
	if input.NextToken != nil {
		recorded.nextToken = *input.NextToken
	}
	if input.IncludeLinkedAccounts != nil {
		recorded.linked = *input.IncludeLinkedAccounts
	}
	if input.LogGroupNamePrefix != nil {
		recorded.namePrefix = *input.LogGroupNamePrefix
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

func (a *pagingDescribeLogGroupsAPI) GetLogGroupFields(context.Context, *cloudwatchlogs.GetLogGroupFieldsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogGroupFieldsOutput, error) {
	return nil, fmt.Errorf("unexpected GetLogGroupFields")
}

func (a *pagingDescribeLogGroupsAPI) ListAggregateLogGroupSummaries(context.Context, *cloudwatchlogs.ListAggregateLogGroupSummariesInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.ListAggregateLogGroupSummariesOutput, error) {
	return nil, fmt.Errorf("unexpected ListAggregateLogGroupSummaries")
}

func TestGetLogGroupsListAllLogGroupsReturnsOnePage(t *testing.T) {
	const pageCount = 8

	tests := []struct {
		name          string
		crossAccount  bool
		request       resources.LogGroupsRequest
		wantName      string
		wantNextToken string
		wantLimit     int32
		wantAccounts  []string
		wantLinked    bool
		wantPrefix    string
	}{
		{
			name:         "flag drains no further pages",
			crossAccount: false,
			request: resources.LogGroupsRequest{
				Limit:            50,
				ListAllLogGroups: true,
			},
			wantName:      "group-1",
			wantNextToken: "token-1",
			wantLimit:     50,
		},
		{
			name:         "per-page limit is not a cap on pages",
			crossAccount: false,
			request: resources.LogGroupsRequest{
				Limit:              1,
				LogGroupNamePrefix: new("app"),
				ListAllLogGroups:   true,
			},
			wantName:      "group-1",
			wantNextToken: "token-1",
			wantLimit:     1,
			wantPrefix:    "app",
		},
		{
			name:         "resume token still returns only that page",
			crossAccount: false,
			request: resources.LogGroupsRequest{
				Limit:            50,
				ListAllLogGroups: true,
				NextToken:        new("token-2"),
			},
			wantName:      "group-3",
			wantNextToken: "token-3",
			wantLimit:     50,
		},
		{
			name:         "cross-account account id",
			crossAccount: true,
			request: resources.LogGroupsRequest{
				ResourceRequest:  resources.ResourceRequest{AccountId: new("123456789012")},
				Limit:            50,
				ListAllLogGroups: true,
			},
			wantName:      "group-1",
			wantNextToken: "token-1",
			wantLimit:     50,
			wantAccounts:  []string{"123456789012"},
			wantLinked:    true,
		},
		{
			name:         "cross-account all accounts",
			crossAccount: true,
			request: resources.LogGroupsRequest{
				ResourceRequest:  resources.ResourceRequest{AccountId: new("all")},
				Limit:            50,
				ListAllLogGroups: true,
			},
			wantName:      "group-1",
			wantNextToken: "token-1",
			wantLimit:     50,
			wantLinked:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &pagingDescribeLogGroupsAPI{pageCount: pageCount}
			service := NewLogGroupsService(api, tt.crossAccount)

			results, nextToken, err := service.GetLogGroups(context.Background(), tt.request)

			require.NoError(t, err)
			require.Len(t, api.calls, 1, "one resource call must follow one DescribeLogGroups page, not all %d", pageCount)
			assert.Equal(t, tt.wantLimit, api.calls[0].limit)
			assert.Equal(t, tt.wantAccounts, api.calls[0].accounts)
			assert.Equal(t, tt.wantLinked, api.calls[0].linked)
			assert.Equal(t, tt.wantPrefix, api.calls[0].namePrefix)
			if tt.request.NextToken != nil {
				assert.Equal(t, *tt.request.NextToken, api.calls[0].nextToken)
			} else {
				assert.Empty(t, api.calls[0].nextToken)
			}

			require.Len(t, results, 1)
			assert.Equal(t, tt.wantName, results[0].Value.Name)
			require.NotNil(t, nextToken)
			assert.Equal(t, tt.wantNextToken, *nextToken)
		})
	}
}
