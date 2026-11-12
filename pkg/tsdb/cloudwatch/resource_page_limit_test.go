package cloudwatch

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/oam"
	oamtypes "github.com/aws/aws-sdk-go-v2/service/oam/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	rgtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
)

// These tests are the expected bound for CloudWatch resource routes that follow
// an AWS paginator. list_metrics_page_limit stops ListMetrics. The same limit
// has to stop these routes, and one response must not hold every page.
// An empty EC2 filter set or an empty resource-ARN tag set is rejected for
// anyone who is not an organization administrator, and that rejection happens
// before any AWS page is requested.

const (
	resourcePageLimit = 2
	resourcePageCount = 5
	// conf/defaults.ini ships list_metrics_page_limit at this value.
	shippedListMetricsPageLimit = 500
)

func TestUnboundedCloudWatchResourcePages(t *testing.T) {
	t.Run("ec2 instance attribute", func(t *testing.T) {
		t.Run("viewer with a real filter gets one page window and a continuation", func(t *testing.T) {
			client := &pagingEC2{pages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, client, nil, nil, nil)
			resp := callResource(t, ds, roleUser(identity.RoleViewer), ec2AttributePath(`{"tag:Environment":["production"]}`, nil))
			requirePageWindow(t, resp, len(client.calls), resourcePageLimit, "i-0000", "i-0004")
			requireEC2Filters(t, client.calls, "tag:Environment", "production")
			token := requireContinuation(t, resp, strconv.Itoa(resourcePageLimit))
			follow := callResource(t, ds, roleUser(identity.RoleViewer), ec2AttributePath(`{"tag:Environment":["production"]}`, url.Values{"nextToken": {token}}))
			requireFollowUpWindow(t, follow, client.calls, resourcePageLimit, token, "i-")
		})

		t.Run("viewer empty filter is rejected before describe instances", func(t *testing.T) {
			client := &pagingEC2{pages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, client, nil, nil, nil)
			resp := callResource(t, ds, roleUser(identity.RoleViewer), ec2AttributePath(`{}`, nil))
			requireRejectedBeforeCall(t, resp, len(client.calls), "i-0000")
		})

		t.Run("viewer filter values that are not arrays are an empty filter set", func(t *testing.T) {
			client := &pagingEC2{pages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, client, nil, nil, nil)
			resp := callResource(t, ds, roleUser(identity.RoleViewer), ec2AttributePath(`{"tag:Name":"web"}`, nil))
			requireRejectedBeforeCall(t, resp, len(client.calls), "i-0000")
		})

		t.Run("editor empty filter is rejected before describe instances", func(t *testing.T) {
			client := &pagingEC2{pages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, client, nil, nil, nil)
			resp := callResource(t, ds, roleUser(identity.RoleEditor), ec2AttributePath(`{}`, nil))
			requireRejectedBeforeCall(t, resp, len(client.calls), "i-0000")
		})

		t.Run("missing user empty filter is rejected before describe instances", func(t *testing.T) {
			client := &pagingEC2{pages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, client, nil, nil, nil)
			resp := callResource(t, ds, nil, ec2AttributePath(`{}`, nil))
			requireRejectedBeforeCall(t, resp, len(client.calls), "i-0000")
		})

		t.Run("admin empty filter is unfiltered but still one page window", func(t *testing.T) {
			client := &pagingEC2{pages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, client, nil, nil, nil)
			resp := callResource(t, ds, roleUser(identity.RoleAdmin), ec2AttributePath(`{}`, nil))
			requirePageWindow(t, resp, len(client.calls), resourcePageLimit, "i-0000", "i-0004")
			require.Empty(t, client.calls[0].filters)
			token := requireContinuation(t, resp, strconv.Itoa(resourcePageLimit))
			follow := callResource(t, ds, roleUser(identity.RoleAdmin), ec2AttributePath(`{}`, url.Values{"nextToken": {token}}))
			requireFollowUpWindow(t, follow, client.calls, resourcePageLimit, token, "i-")
			require.Empty(t, client.calls[resourcePageLimit].filters)
		})

		t.Run("admin allowance does not stick on the shared datasource for a later viewer", func(t *testing.T) {
			client := &pagingEC2{pages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, client, nil, nil, nil)
			adminResp := callResource(t, ds, roleUser(identity.RoleAdmin), ec2AttributePath(`{}`, nil))
			requirePageWindow(t, adminResp, len(client.calls), resourcePageLimit, "i-0000", "i-0004")
			before := len(client.calls)
			viewerResp := callResource(t, ds, roleUser(identity.RoleViewer), ec2AttributePath(`{}`, nil))
			requireRejectedBeforeCall(t, viewerResp, len(client.calls)-before, "i-0000")
		})

		t.Run("stops at the shipped list metrics page limit", func(t *testing.T) {
			const pages = shippedListMetricsPageLimit + 1
			client := &pagingEC2{pages: pages}
			ds := datasourceWithPageLimit(t, shippedListMetricsPageLimit, client, nil, nil, nil)
			resp := callResource(t, ds, roleUser(identity.RoleViewer), ec2AttributePath(`{"tag:Environment":["production"]}`, nil))
			beyond := fmt.Sprintf("i-%04d", shippedListMetricsPageLimit)
			requirePageWindow(t, resp, len(client.calls), shippedListMetricsPageLimit, "i-0000", beyond)
			requireContinuation(t, resp, strconv.Itoa(shippedListMetricsPageLimit))
		})

		t.Run("last page does not invent a continuation", func(t *testing.T) {
			client := &pagingEC2{pages: 1}
			ds := datasourceWithPageLimit(t, resourcePageLimit, client, nil, nil, nil)
			resp := callResource(t, ds, roleUser(identity.RoleViewer), ec2AttributePath(`{"tag:Environment":["production"]}`, nil))
			body := requireOK(t, resp)
			require.Equal(t, 1, len(client.calls))
			require.Contains(t, body, "i-0000")
			requireNoContinuation(t, resp)
		})

		t.Run("invalid filters do not call describe instances", func(t *testing.T) {
			client := &pagingEC2{pages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, client, nil, nil, nil)
			resp := callResource(t, ds, roleUser(identity.RoleViewer), "/ec2-instance-attribute?region=us-east-1&attributeName=InstanceId&filters=")
			require.Zero(t, len(client.calls))
			require.NotEqual(t, http.StatusOK, resp.Status)
		})
	})

	t.Run("ebs volume ids use the same describe instances paginator", func(t *testing.T) {
		client := &pagingEC2{pages: resourcePageCount}
		ds := datasourceWithPageLimit(t, resourcePageLimit, client, nil, nil, nil)
		resp := callResource(t, ds, roleUser(identity.RoleViewer), "/ebs-volume-ids?region=us-east-1&instanceId=i-0000")
		requirePageWindow(t, resp, len(client.calls), resourcePageLimit, "vol-0000", "vol-0004")
		require.Equal(t, []string{"i-0000"}, client.calls[0].instanceIDs)
		token := requireContinuation(t, resp, strconv.Itoa(resourcePageLimit))
		follow := callResource(t, ds, roleUser(identity.RoleViewer), "/ebs-volume-ids?region=us-east-1&instanceId=i-0000&nextToken="+url.QueryEscape(token))
		requireFollowUpWindow(t, follow, client.calls, resourcePageLimit, token, "vol-")
	})

	t.Run("resource arns", func(t *testing.T) {
		t.Run("viewer with tags gets one page window and a continuation", func(t *testing.T) {
			client := &pagingResources{pages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, nil, client, nil, nil)
			resp := callResource(t, ds, roleUser(identity.RoleViewer), resourceARNPath(`{"Environment":["production"]}`, nil))
			requirePageWindow(t, resp, len(client.calls), resourcePageLimit, "instance/i-0000", "instance/i-0004")
			require.Equal(t, "Environment", client.calls[0].tagKey)
			token := requireContinuation(t, resp, strconv.Itoa(resourcePageLimit))
			follow := callResource(t, ds, roleUser(identity.RoleViewer), resourceARNPath(`{"Environment":["production"]}`, url.Values{"nextToken": {token}}))
			requireFollowUpWindow(t, follow, client.calls, resourcePageLimit, token, "instance/i-")
		})

		t.Run("viewer empty tags are rejected before get resources", func(t *testing.T) {
			client := &pagingResources{pages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, nil, client, nil, nil)
			resp := callResource(t, ds, roleUser(identity.RoleViewer), resourceARNPath(`{}`, nil))
			requireRejectedBeforeCall(t, resp, len(client.calls), "instance/i-0000")
		})

		t.Run("viewer tag values that are not arrays are an empty filter set", func(t *testing.T) {
			client := &pagingResources{pages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, nil, client, nil, nil)
			resp := callResource(t, ds, roleUser(identity.RoleViewer), resourceARNPath(`{"Environment":"production"}`, nil))
			requireRejectedBeforeCall(t, resp, len(client.calls), "instance/i-0000")
		})

		t.Run("admin empty tags are unfiltered but still one page window", func(t *testing.T) {
			client := &pagingResources{pages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, nil, client, nil, nil)
			resp := callResource(t, ds, roleUser(identity.RoleAdmin), resourceARNPath(`{}`, nil))
			requirePageWindow(t, resp, len(client.calls), resourcePageLimit, "instance/i-0000", "instance/i-0004")
			require.Empty(t, client.calls[0].tagKey)
			token := requireContinuation(t, resp, strconv.Itoa(resourcePageLimit))
			follow := callResource(t, ds, roleUser(identity.RoleAdmin), resourceARNPath(`{}`, url.Values{"nextToken": {token}}))
			requireFollowUpWindow(t, follow, client.calls, resourcePageLimit, token, "instance/i-")
		})

		t.Run("admin allowance does not stick for a later viewer", func(t *testing.T) {
			client := &pagingResources{pages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, nil, client, nil, nil)
			adminResp := callResource(t, ds, roleUser(identity.RoleAdmin), resourceARNPath(`{}`, nil))
			requirePageWindow(t, adminResp, len(client.calls), resourcePageLimit, "instance/i-0000", "instance/i-0004")
			before := len(client.calls)
			viewerResp := callResource(t, ds, roleUser(identity.RoleViewer), resourceARNPath(`{}`, nil))
			requireRejectedBeforeCall(t, viewerResp, len(client.calls)-before, "instance/i-0000")
		})
	})

	t.Run("log data sources", func(t *testing.T) {
		client := &pagingLogs{summaryPages: resourcePageCount}
		ds := datasourceWithPageLimit(t, resourcePageLimit, nil, nil, client, nil)
		resp := callResource(t, ds, roleUser(identity.RoleViewer), "/data-sources?region=us-east-1")
		requirePageWindow(t, resp, len(client.summaryCalls), resourcePageLimit, "name-0000", "name-0004")
		token := requireContinuation(t, resp, strconv.Itoa(resourcePageLimit))
		follow := callResource(t, ds, roleUser(identity.RoleViewer), "/data-sources?region=us-east-1&nextToken="+url.QueryEscape(token))
		requireFollowUpWindow(t, follow, client.summaryCalls, resourcePageLimit, token, "name-")
	})

	t.Run("log groups listed in full", func(t *testing.T) {
		t.Run("one page is returned when listAllLogGroups is not set", func(t *testing.T) {
			client := &pagingLogs{groupPages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, nil, nil, client, nil)
			resp := callResource(t, ds, roleUser(identity.RoleViewer), "/log-groups?region=us-east-1")
			requirePageWindow(t, resp, len(client.groupCalls), 1, "group-0000", "group-0001")
			requireContinuation(t, resp, "1")
		})

		t.Run("listAllLogGroups stops at the page limit and continues from the token", func(t *testing.T) {
			client := &pagingLogs{groupPages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, nil, nil, client, nil)
			resp := callResource(t, ds, roleUser(identity.RoleViewer), "/log-groups?region=us-east-1&listAllLogGroups=true")
			requirePageWindow(t, resp, len(client.groupCalls), resourcePageLimit, "group-0000", "group-0004")
			token := requireContinuation(t, resp, strconv.Itoa(resourcePageLimit))
			follow := callResource(t, ds, roleUser(identity.RoleViewer), "/log-groups?region=us-east-1&listAllLogGroups=true&nextToken="+url.QueryEscape(token))
			requireFollowUpWindow(t, follow, client.groupCalls, resourcePageLimit, token, "group-")
		})
	})

	t.Run("monitoring account sinks and links", func(t *testing.T) {
		t.Run("list sinks stops at the page limit", func(t *testing.T) {
			client := &pagingOAM{sinkPages: resourcePageCount, linkPages: 1}
			ds := datasourceWithPageLimit(t, resourcePageLimit, nil, nil, nil, client)
			resp := callResource(t, ds, roleUser(identity.RoleViewer), "/accounts?region=us-east-1")
			requirePageWindow(t, resp, len(client.sinkCalls), resourcePageLimit, "sink-0000", "sink-0004")
			require.LessOrEqual(t, len(client.linkCalls), resourcePageLimit)
			require.NotContains(t, string(resp.Body), "link-0004")
		})

		t.Run("list attached links stops at the page limit", func(t *testing.T) {
			client := &pagingOAM{sinkPages: 1, linkPages: resourcePageCount}
			ds := datasourceWithPageLimit(t, resourcePageLimit, nil, nil, nil, client)
			resp := callResource(t, ds, roleUser(identity.RoleViewer), "/accounts?region=us-east-1")
			require.Equal(t, 1, len(client.sinkCalls))
			requirePageWindow(t, resp, len(client.linkCalls), resourcePageLimit, "link-0000", "link-0004")
		})
	})
}

func datasourceWithPageLimit(t *testing.T, limit int, ec2Client *pagingEC2, resources *pagingResources, logs *pagingLogs, oamClient *pagingOAM) *DataSource {
	t.Helper()
	if ec2Client != nil {
		orig := NewEC2API
		NewEC2API = func(aws.Config) models.EC2APIProvider { return ec2Client }
		t.Cleanup(func() { NewEC2API = orig })
	}
	if resources != nil {
		orig := NewRGTAClient
		NewRGTAClient = func(aws.Config) resourcegroupstaggingapi.GetResourcesAPIClient { return resources }
		t.Cleanup(func() { NewRGTAClient = orig })
	}
	if logs != nil {
		orig := NewLogsAPI
		NewLogsAPI = func(aws.Config) models.CloudWatchLogsAPIProvider { return logs }
		t.Cleanup(func() { NewLogsAPI = orig })
	}
	if oamClient != nil {
		orig := NewOAMAPI
		NewOAMAPI = func(aws.Config) models.OAMAPIProvider { return oamClient }
		t.Cleanup(func() { NewOAMAPI = orig })
	}
	return newTestDatasource(func(ds *DataSource) {
		ds.Settings.GrafanaSettings.ListMetricsPageLimit = limit
	})
}

func roleUser(role identity.RoleType) *backend.User {
	return &backend.User{Login: "caller", Role: string(role)}
}

func callResource(t *testing.T, ds *DataSource, user *backend.User, path string) *backend.CallResourceResponse {
	t.Helper()
	sender := &mockedCallResourceResponseSenderForOauth{}
	err := ds.CallResource(contextWithFeaturesEnabled(), &backend.CallResourceRequest{
		Method: http.MethodGet,
		Path:   path,
		PluginContext: backend.PluginContext{
			PluginID:                   "cloudwatch",
			User:                       user,
			DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{UID: "cw"},
		},
	}, sender)
	require.NoError(t, err)
	require.NotNil(t, sender.Response)
	return sender.Response
}

func ec2AttributePath(filters string, extra url.Values) string {
	q := url.Values{}
	q.Set("region", "us-east-1")
	q.Set("attributeName", "InstanceId")
	q.Set("filters", filters)
	for key, values := range extra {
		for _, value := range values {
			q.Set(key, value)
		}
	}
	return "/ec2-instance-attribute?" + q.Encode()
}

func resourceARNPath(tags string, extra url.Values) string {
	q := url.Values{}
	q.Set("region", "us-east-1")
	q.Set("resourceType", "ec2:instance")
	q.Set("tags", tags)
	for key, values := range extra {
		for _, value := range values {
			q.Set(key, value)
		}
	}
	return "/resource-arns?" + q.Encode()
}

func requireOK(t *testing.T, resp *backend.CallResourceResponse) string {
	t.Helper()
	require.Equal(t, http.StatusOK, resp.Status, "body: %s", truncateBody(resp.Body))
	return string(resp.Body)
}

func requirePageWindow(t *testing.T, resp *backend.CallResourceResponse, calls int, limit int, firstID string, beyondID string) string {
	t.Helper()
	require.Equal(t, limit, calls, "AWS pages fetched = %d, page limit = %d; the handler kept requesting pages", calls, limit)
	body := requireOK(t, resp)
	require.Contains(t, body, firstID)
	if strings.Contains(body, beyondID) {
		t.Fatalf("response contains %s from a page past the limit (body length %d)", beyondID, len(body))
	}
	return body
}

func requireRejectedBeforeCall(t *testing.T, resp *backend.CallResourceResponse, calls int, leaked string) {
	t.Helper()
	require.Zero(t, calls, "AWS was called %d times before the empty filter set was rejected", calls)
	require.Contains(t, []int{http.StatusBadRequest, http.StatusForbidden}, resp.Status, "status=%d body=%s", resp.Status, truncateBody(resp.Body))
	require.NotContains(t, string(resp.Body), leaked)
}

func requireContinuation(t *testing.T, resp *backend.CallResourceResponse, want string) string {
	t.Helper()
	token := linkNextToken(resp.Headers)
	require.NotEmpty(t, token, "partial result must include a Link header of the form <?nextToken=...>; rel=\"next\", matching LogGroupsHandler; the token is the NextToken from the last AWS page that was fetched")
	require.Equal(t, want, token, "continuation token must be the AWS pagination token of the first page that was not fetched")
	return token
}

func requireNoContinuation(t *testing.T, resp *backend.CallResourceResponse) {
	t.Helper()
	require.Empty(t, linkNextToken(resp.Headers))
}

func requireFollowUpWindow[C pageCall](t *testing.T, resp *backend.CallResourceResponse, calls []C, limit int, token string, idPrefix string) {
	t.Helper()
	require.GreaterOrEqual(t, len(calls), limit+1)
	window := calls[limit:]
	require.Equal(t, limit, len(window), "follow-up fetched %d AWS pages, page limit = %d", len(window), limit)
	require.Equal(t, token, window[0].pageToken(), "follow-up must start at the continuation token, not the first page")
	body := requireOK(t, resp)
	idx, err := strconv.Atoi(token)
	require.NoError(t, err)
	require.Contains(t, body, fmt.Sprintf("%s%04d", idPrefix, idx))
	if idx > 0 {
		require.NotContains(t, body, fmt.Sprintf("%s%04d", idPrefix, idx-1))
	}
	beyond := idx + limit
	require.NotContains(t, body, fmt.Sprintf("%s%04d", idPrefix, beyond))
}

func requireEC2Filters(t *testing.T, calls []ec2PageCall, name string, value string) {
	t.Helper()
	require.NotEmpty(t, calls)
	for _, call := range calls[:resourcePageLimit] {
		require.NotEmpty(t, call.filters)
		require.Equal(t, name, aws.ToString(call.filters[0].Name))
		require.Equal(t, []string{value}, call.filters[0].Values)
	}
}

func linkNextToken(headers map[string][]string) string {
	for key, values := range headers {
		if !strings.EqualFold(key, "Link") {
			continue
		}
		for _, link := range values {
			if !strings.Contains(link, `rel="next"`) {
				continue
			}
			start := strings.Index(link, "<?")
			end := strings.Index(link, ">")
			if start < 0 || end <= start+2 {
				continue
			}
			query, err := url.ParseQuery(link[start+2 : end])
			if err != nil {
				continue
			}
			if token := query.Get("nextToken"); token != "" {
				return token
			}
		}
	}
	return ""
}

func truncateBody(body []byte) string {
	if len(body) > 300 {
		return string(body[:300]) + "..."
	}
	return string(body)
}

type pageCall interface {
	pageToken() string
}

type ec2PageCall struct {
	token       string
	filters     []ec2types.Filter
	instanceIDs []string
}

func (c ec2PageCall) pageToken() string { return c.token }

type pagingEC2 struct {
	pages int
	calls []ec2PageCall
}

func (c *pagingEC2) DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	return &ec2.DescribeRegionsOutput{}, nil
}

func (c *pagingEC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	idx, err := pageIndex(in.NextToken)
	if err != nil {
		return nil, err
	}
	filters := make([]ec2types.Filter, len(in.Filters))
	for i, filter := range in.Filters {
		filters[i] = ec2types.Filter{
			Name:   filter.Name,
			Values: append([]string(nil), filter.Values...),
		}
	}
	c.calls = append(c.calls, ec2PageCall{
		token:       aws.ToString(in.NextToken),
		filters:     filters,
		instanceIDs: append([]string(nil), in.InstanceIds...),
	})
	id := fmt.Sprintf("i-%04d", idx)
	vol := fmt.Sprintf("vol-%04d", idx)
	out := &ec2.DescribeInstancesOutput{
		Reservations: []ec2types.Reservation{{
			Instances: []ec2types.Instance{{
				InstanceId: aws.String(id),
				BlockDeviceMappings: []ec2types.InstanceBlockDeviceMapping{{
					Ebs: &ec2types.EbsInstanceBlockDevice{VolumeId: aws.String(vol)},
				}},
			}},
		}},
	}
	out.NextToken = nextPageToken(idx, c.pages)
	return out, nil
}

type resourcePageCall struct {
	token  string
	tagKey string
}

func (c resourcePageCall) pageToken() string { return c.token }

type pagingResources struct {
	pages int
	calls []resourcePageCall
}

func (c *pagingResources) GetResources(_ context.Context, in *resourcegroupstaggingapi.GetResourcesInput, _ ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error) {
	idx, err := pageIndex(in.PaginationToken)
	if err != nil {
		return nil, err
	}
	tagKey := ""
	if len(in.TagFilters) > 0 {
		tagKey = aws.ToString(in.TagFilters[0].Key)
	}
	c.calls = append(c.calls, resourcePageCall{token: aws.ToString(in.PaginationToken), tagKey: tagKey})
	arn := fmt.Sprintf("arn:aws:ec2:us-east-1:123456789012:instance/i-%04d", idx)
	out := &resourcegroupstaggingapi.GetResourcesOutput{
		ResourceTagMappingList: []rgtypes.ResourceTagMapping{{
			ResourceARN: aws.String(arn),
		}},
	}
	out.PaginationToken = nextPageToken(idx, c.pages)
	return out, nil
}

type logPageCall struct {
	token string
}

func (c logPageCall) pageToken() string { return c.token }

type pagingLogs struct {
	summaryPages int
	groupPages   int
	summaryCalls []logPageCall
	groupCalls   []logPageCall
}

func (c *pagingLogs) DescribeLogGroups(_ context.Context, in *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	idx, err := pageIndex(in.NextToken)
	if err != nil {
		return nil, err
	}
	c.groupCalls = append(c.groupCalls, logPageCall{token: aws.ToString(in.NextToken)})
	name := fmt.Sprintf("group-%04d", idx)
	out := &cloudwatchlogs.DescribeLogGroupsOutput{
		LogGroups: []cloudwatchlogstypes.LogGroup{{
			LogGroupName: aws.String(name),
			Arn:          aws.String("arn:aws:logs:us-east-1:123456789012:log-group:" + name),
		}},
	}
	out.NextToken = nextPageToken(idx, c.groupPages)
	return out, nil
}

func (c *pagingLogs) GetLogGroupFields(context.Context, *cloudwatchlogs.GetLogGroupFieldsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogGroupFieldsOutput, error) {
	return &cloudwatchlogs.GetLogGroupFieldsOutput{}, nil
}

func (c *pagingLogs) ListAggregateLogGroupSummaries(_ context.Context, in *cloudwatchlogs.ListAggregateLogGroupSummariesInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.ListAggregateLogGroupSummariesOutput, error) {
	idx, err := pageIndex(in.NextToken)
	if err != nil {
		return nil, err
	}
	c.summaryCalls = append(c.summaryCalls, logPageCall{token: aws.ToString(in.NextToken)})
	name := fmt.Sprintf("name-%04d", idx)
	out := &cloudwatchlogs.ListAggregateLogGroupSummariesOutput{
		AggregateLogGroupSummaries: []cloudwatchlogstypes.AggregateLogGroupSummary{{
			GroupingIdentifiers: []cloudwatchlogstypes.GroupingIdentifier{
				{Key: aws.String("datasource.name"), Value: aws.String(name)},
				{Key: aws.String("datasource.type"), Value: aws.String("flow")},
			},
		}},
	}
	out.NextToken = nextPageToken(idx, c.summaryPages)
	return out, nil
}

type oamPageCall struct {
	token string
}

func (c oamPageCall) pageToken() string { return c.token }

type pagingOAM struct {
	sinkPages int
	linkPages int
	sinkCalls []oamPageCall
	linkCalls []oamPageCall
}

func (c *pagingOAM) ListSinks(_ context.Context, in *oam.ListSinksInput, _ ...func(*oam.Options)) (*oam.ListSinksOutput, error) {
	idx, err := pageIndex(in.NextToken)
	if err != nil {
		return nil, err
	}
	c.sinkCalls = append(c.sinkCalls, oamPageCall{token: aws.ToString(in.NextToken)})
	name := fmt.Sprintf("sink-%04d", idx)
	out := &oam.ListSinksOutput{
		Items: []oamtypes.ListSinksItem{{
			Arn:  aws.String(fmt.Sprintf("arn:aws:oam:us-east-1:123456789012:sink/%s", name)),
			Name: aws.String(name),
		}},
	}
	out.NextToken = nextPageToken(idx, c.sinkPages)
	return out, nil
}

func (c *pagingOAM) ListAttachedLinks(_ context.Context, in *oam.ListAttachedLinksInput, _ ...func(*oam.Options)) (*oam.ListAttachedLinksOutput, error) {
	idx, err := pageIndex(in.NextToken)
	if err != nil {
		return nil, err
	}
	c.linkCalls = append(c.linkCalls, oamPageCall{token: aws.ToString(in.NextToken)})
	name := fmt.Sprintf("link-%04d", idx)
	out := &oam.ListAttachedLinksOutput{
		Items: []oamtypes.ListAttachedLinksItem{{
			Label:   aws.String(name),
			LinkArn: aws.String(fmt.Sprintf("arn:aws:oam:us-east-1:123456789012:link/%s", name)),
		}},
	}
	out.NextToken = nextPageToken(idx, c.linkPages)
	return out, nil
}

func pageIndex(token *string) (int, error) {
	if token == nil || *token == "" {
		return 0, nil
	}
	return strconv.Atoi(*token)
}

func nextPageToken(idx int, pages int) *string {
	if idx+1 < pages {
		return aws.String(strconv.Itoa(idx + 1))
	}
	return nil
}
