package cloudwatch

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/features"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/utils"
)

const defaultGetMetricDataPageLimit = 500

func (ds *DataSource) executeRequest(ctx context.Context, client models.CWClient,
	metricDataInput *cloudwatch.GetMetricDataInput) ([]*cloudwatch.GetMetricDataOutput, error) {
	mdo := make([]*cloudwatch.GetMetricDataOutput, 0)

	// GetMetricData EndTime is exclusive, so we round up to the next minute to get the last data point.
	// Every page of a paginated request must use the same time range as the first page.
	if metricDataInput.EndTime != nil && features.IsEnabled(ctx, features.FlagCloudWatchRoundUpEndTime) {
		metricDataInput.EndTime = aws.Time(metricDataInput.EndTime.Truncate(time.Minute).Add(time.Minute))
	}

	pageLimit := ds.Settings.GrafanaSettings.ListMetricsPageLimit
	if pageLimit <= 0 {
		pageLimit = defaultGetMetricDataPageLimit
	}

	nextToken := ""
	for pages := 0; pages < pageLimit; pages++ {
		if nextToken != "" {
			metricDataInput.NextToken = aws.String(nextToken)
		}

		resp, err := client.GetMetricData(ctx, metricDataInput)
		if err != nil {
			return mdo, backend.DownstreamError(err)
		}

		mdo = append(mdo, resp)
		utils.QueriesTotalCounter.WithLabelValues(utils.GetMetricDataLabel).Add(float64(len(metricDataInput.MetricDataQueries)))
		if resp.NextToken == nil || *resp.NextToken == "" {
			return mdo, nil
		}
		nextToken = *resp.NextToken
	}

	if ds.logger != nil {
		ds.logger.FromContext(ctx).Warn("GetMetricData page limit reached, returning partial results", "pageLimit", pageLimit)
	}
	return mdo, nil
}
