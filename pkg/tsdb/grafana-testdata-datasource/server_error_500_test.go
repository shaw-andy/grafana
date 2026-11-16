package testdatasource

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/plugins/backendplugin"
	"github.com/grafana/grafana/pkg/plugins/backendplugin/coreplugin"
	pluglog "github.com/grafana/grafana/pkg/plugins/log"
)

// These tests follow the query a signed-in caller posts to /api/ds/query.
// parseMetricRequest copies queryType onto DataQuery.QueryType and the rest of
// the object into DataQuery.JSON. The core plugin then calls Service.QueryData.
// An empty or omitted stringInput must come back as a plugin or downstream
// error on that query. It must not panic.

func TestServerError500EmptyStringInputReturnsPluginOrDownstreamError(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "omitted stringInput",
			body: `{"refId":"A","scenarioId":"server_error_500"}`,
		},
		{
			name: "empty stringInput",
			body: `{"refId":"A","scenarioId":"server_error_500","stringInput":""}`,
		},
		{
			name: "null stringInput",
			body: `{"refId":"A","scenarioId":"server_error_500","stringInput":null}`,
		},
		{
			name: "queryType routes to the scenario when scenarioId is omitted",
			body: `{"refId":"A","queryType":"server_error_500"}`,
		},
		{
			name: "server panic error type",
			body: `{"refId":"A","scenarioId":"server_error_500","stringInput":"","errorType":"server_panic"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := queryThroughCorePlugin(t, queryAsAPIParsesIt(t, tc.body))
			require.NoError(t, err)
			requirePluginOrDownstreamError(t, resp, "A")
		})
	}
}

func TestServerError500EmptyStringInputDoesNotDropSiblingQueries(t *testing.T) {
	resp, err := queryThroughCorePlugin(t,
		queryAsAPIParsesIt(t, `{"refId":"A","scenarioId":"server_error_500","stringInput":"1,2,3"}`),
		queryAsAPIParsesIt(t, `{"refId":"B","scenarioId":"server_error_500","stringInput":""}`),
	)
	require.NoError(t, err)
	requireSuccessfulFrames(t, resp, "A")
	requirePluginOrDownstreamError(t, resp, "B")
}

func TestServerError500NonEmptyStringInputStillReturnsFrames(t *testing.T) {
	resp, err := queryThroughCorePlugin(t,
		queryAsAPIParsesIt(t, `{"refId":"A","scenarioId":"server_error_500","stringInput":"1,20,90,30,5,0"}`),
	)
	require.NoError(t, err)
	requireSuccessfulFrames(t, resp, "A")
}

func TestServerError500ChunkedEmptyStringInputReturnsError(t *testing.T) {
	plugin := newCorePlugin(t, ProvideService())
	writer := &captureChunkWriter{}

	err := plugin.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{
		PluginContext: backend.PluginContext{PluginID: "grafana-testdata-datasource"},
		Queries: []backend.DataQuery{
			queryAsAPIParsesIt(t, `{"refId":"A","scenarioId":"server_error_500"}`),
		},
	}, writer)
	require.NoError(t, err)

	got, ok := writer.errs["A"]
	require.True(t, ok, "chunked query wrote no error for ref A: %+v", writer.errs)
	require.Error(t, got)
	require.NotContains(t, got.Error(), "Test Data Panic")
}

// queryAsAPIParsesIt builds the DataQuery /api/ds/query produces for one object
// in MetricRequest.Queries when X-Query-V2 is not set. See parseMetricRequest.
func queryAsAPIParsesIt(t *testing.T, raw string) backend.DataQuery {
	t.Helper()

	parsed, err := simplejson.NewJson([]byte(raw))
	require.NoError(t, err)
	modelJSON, err := parsed.MarshalJSON()
	require.NoError(t, err)

	return backend.DataQuery{
		TimeRange: backend.TimeRange{
			From: time.Now().Add(-time.Hour).UTC(),
			To:   time.Now().UTC(),
		},
		RefID:         parsed.Get("refId").MustString("A"),
		MaxDataPoints: parsed.Get("maxDataPoints").MustInt64(100),
		Interval:      time.Duration(parsed.Get("intervalMs").MustInt64(1000)) * time.Millisecond,
		QueryType:     parsed.Get("queryType").MustString(""),
		JSON:          modelJSON,
	}
}

func queryThroughCorePlugin(t *testing.T, queries ...backend.DataQuery) (resp *backend.QueryDataResponse, err error) {
	t.Helper()

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("testdata query panicked (%v); an empty stringInput must return a plugin or downstream error", recovered)
		}
	}()

	plugin := newCorePlugin(t, ProvideService())
	return plugin.QueryData(context.Background(), &backend.QueryDataRequest{
		PluginContext: backend.PluginContext{PluginID: "grafana-testdata-datasource"},
		Queries:       queries,
	})
}

func newCorePlugin(t *testing.T, svc *Service) backendplugin.Plugin {
	t.Helper()

	factory := coreplugin.New(backend.ServeOpts{
		QueryDataHandler:        svc,
		QueryChunkedDataHandler: svc,
	})
	plugin, err := factory("grafana-testdata-datasource", pluglog.New("test.testdata"), nil, nil)
	require.NoError(t, err)
	return plugin
}

func requirePluginOrDownstreamError(t *testing.T, resp *backend.QueryDataResponse, refID string) {
	t.Helper()

	require.NotNil(t, resp)
	dr, ok := resp.Responses[refID]
	require.Truef(t, ok, "ref %s missing from response", refID)
	require.Error(t, dr.Error)
	require.NotContains(t, dr.Error.Error(), "Test Data Panic")
	switch dr.ErrorSource {
	case backend.ErrorSourcePlugin, backend.ErrorSourceDownstream:
	default:
		t.Fatalf("ref %s error source = %q, want plugin or downstream", refID, dr.ErrorSource)
	}
}

func requireSuccessfulFrames(t *testing.T, resp *backend.QueryDataResponse, refID string) {
	t.Helper()

	require.NotNil(t, resp)
	dr, ok := resp.Responses[refID]
	require.Truef(t, ok, "ref %s missing from response", refID)
	require.NoError(t, dr.Error)
	require.NotEmpty(t, dr.Frames)
}

type captureChunkWriter struct {
	errs map[string]error
}

func (c *captureChunkWriter) WriteFrame(context.Context, string, string, *data.Frame) error {
	return nil
}

func (c *captureChunkWriter) WriteError(_ context.Context, refID string, _ backend.Status, err error) error {
	if c.errs == nil {
		c.errs = map[string]error{}
	}
	c.errs[refID] = err
	return nil
}
