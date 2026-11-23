package cloudwatch

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/models/resources"
	"github.com/grafana/grafana/pkg/tsdb/cloudwatch/services"
)

// These requests follow the resource call the datasource HTTP route builds:
// CallResourceRequest.Path is the resource name and URL carries the query
// string, including dimensionFilters. Non-string values must be rejected with
// 400 before any metrics lookup.
func TestDimensionFilterResourceRejectsNonStringValues(t *testing.T) {
	cases := []struct {
		name   string
		filter string
	}{
		{name: "number in array", filter: `{"InstanceId":[1]}`},
		{name: "null in array", filter: `{"InstanceId":[null]}`},
		{name: "object in array", filter: `{"InstanceId":[{}]}`},
		{name: "bool in array", filter: `{"InstanceId":[true]}`},
		{name: "string then number in array", filter: `{"InstanceId":["i-abc",1]}`},
		{name: "number value", filter: `{"InstanceId":1}`},
		{name: "bool value", filter: `{"InstanceId":false}`},
		{name: "object value", filter: `{"InstanceId":{"id":"i-abc"}}`},
	}
	routes := []string{"dimension-keys", "dimension-values"}

	for _, route := range routes {
		for _, tc := range cases {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				spy := installListMetricsSpy(t)
				status, body, err := callDimensionResource(t, route, tc.filter)
				require.NoError(t, err)
				require.Equal(t, http.StatusBadRequest, status, "body: %s", body)
				require.False(t, spy.called, "metrics lookup ran before the filter was refused")
			})
		}
	}
}

func TestDimensionFilterResourceKeepsStringAndNullValues(t *testing.T) {
	cases := []struct {
		name   string
		filter string
	}{
		{name: "string", filter: `{"InstanceId":"i-abc"}`},
		{name: "string array", filter: `{"InstanceId":["i-abc","i-def"]}`},
		{name: "null", filter: `{"InstanceId":null}`},
	}
	routes := []string{"dimension-keys", "dimension-values"}

	for _, route := range routes {
		for _, tc := range cases {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				installListMetricsSpy(t)
				status, body, err := callDimensionResource(t, route, tc.filter)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, status, "body: %s", body)
			})
		}
	}
}

type listMetricsSpy struct {
	called bool
}

func (s *listMetricsSpy) GetDimensionKeysByDimensionFilter(context.Context, resources.DimensionKeysRequest) ([]resources.ResourceResponse[string], error) {
	s.called = true
	return []resources.ResourceResponse[string]{}, nil
}

func (s *listMetricsSpy) GetDimensionValuesByDimensionFilter(context.Context, resources.DimensionValuesRequest) ([]resources.ResourceResponse[string], error) {
	s.called = true
	return []resources.ResourceResponse[string]{}, nil
}

func (s *listMetricsSpy) GetMetricsByNamespace(context.Context, resources.MetricsRequest) ([]resources.ResourceResponse[resources.Metric], error) {
	s.called = true
	return nil, nil
}

func installListMetricsSpy(t *testing.T) *listMetricsSpy {
	t.Helper()
	orig := services.NewListMetricsService
	spy := &listMetricsSpy{}
	services.NewListMetricsService = func(models.MetricsClientProvider) models.ListMetricsProvider {
		return spy
	}
	t.Cleanup(func() {
		services.NewListMetricsService = orig
	})
	return spy
}

func callDimensionResource(t *testing.T, route, filter string) (int, string, error) {
	t.Helper()
	query := url.Values{}
	query.Set("region", "us-east-1")
	query.Set("namespace", "AWS/EC2")
	if route == "dimension-values" {
		query.Set("dimensionKey", "InstanceId")
	}
	if filter != "" {
		query.Set("dimensionFilters", filter)
	}

	sender := &resourceResponseRecorder{}
	err := newTestDatasource().CallResource(context.Background(), &backend.CallResourceRequest{
		Path:   route,
		Method: http.MethodGet,
		URL:    route + "?" + query.Encode(),
	}, sender)
	return sender.status, sender.body, err
}

type resourceResponseRecorder struct {
	status int
	body   string
}

func (s *resourceResponseRecorder) Send(resp *backend.CallResourceResponse) error {
	if resp == nil {
		return nil
	}
	if s.status == 0 {
		s.status = resp.Status
	}
	s.body += string(resp.Body)
	return nil
}
