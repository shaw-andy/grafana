package loganalytics

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/kinds/dataquery"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/types"
)

// azureResponseRowCap is the row guard the logs format already applies.
// Every result format must stay within it: the logs view is not the only
// caller, and the default format for a Log Analytics query is time series.
const azureResponseRowCap = 30000

// decodedAzureBodyCap is the maximum decoded response body these tests allow.
// Azure Monitor already caps metrics batch bodies at 32 MiB; Log Analytics
// query, correlation, and metadata bodies have to stop at the same size
// before they are unmarshalled.
const decodedAzureBodyCap = 32 * 1024 * 1024

func TestLogAnalyticsQueryCapsRowsForEveryResultFormat(t *testing.T) {
	body := primaryResultBody(t, azureResponseRowCap+1)
	formats := []struct {
		name   string
		format *string
	}{
		{name: "omitted result format", format: nil},
		{name: "time_series", format: formatPtr(dataquery.ResultFormatTimeSeries)},
		{name: "table", format: formatPtr(dataquery.ResultFormatTable)},
		{name: "trace", format: formatPtr(dataquery.ResultFormatTrace)},
		{name: "logs", format: formatPtr(dataquery.ResultFormatLogs)},
	}

	for _, tc := range formats {
		t.Run(tc.name, func(t *testing.T) {
			result := queryLogAnalytics(t, body, logAnalyticsQuery(t, tc.format))
			requireFrameRowsAtMost(t, result, azureResponseRowCap)
		})
	}
}

func TestTracesQueryCapsRowsForEveryResultFormat(t *testing.T) {
	body := primaryResultBody(t, azureResponseRowCap+1)
	formats := []struct {
		name   string
		format *string
	}{
		{name: "omitted result format", format: nil},
		{name: "table", format: formatPtr(dataquery.ResultFormatTable)},
		{name: "trace", format: formatPtr(dataquery.ResultFormatTrace)},
	}

	for _, tc := range formats {
		t.Run(tc.name, func(t *testing.T) {
			result := queryLogAnalytics(t, body, tracesQuery(t, tc.format, ""))
			requireFrameRowsAtMost(t, result, azureResponseRowCap)
		})
	}
}

func TestLogAnalyticsQueryRejectsOversizedDecodedBody(t *testing.T) {
	t.Run("plain response", func(t *testing.T) {
		payload := oversizedPrimaryResult(t, decodedAzureBodyCap+64*1024)
		counted := &countingReadCloser{r: bytes.NewReader(payload)}
		ds := &AzureLogAnalyticsDatasource{}
		_, err := ds.unmarshalResponse(&http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       counted,
		})
		require.Error(t, err)
		require.LessOrEqual(t, counted.n, int64(decodedAzureBodyCap+1))
	})

	t.Run("non-2xx response", func(t *testing.T) {
		payload := bytes.Repeat([]byte("x"), decodedAzureBodyCap+64*1024)
		counted := &countingReadCloser{r: bytes.NewReader(payload)}
		ds := &AzureLogAnalyticsDatasource{}
		_, err := ds.unmarshalResponse(&http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "502 Bad Gateway",
			Header:     make(http.Header),
			Body:       counted,
		})
		require.Error(t, err)
		require.LessOrEqual(t, counted.n, int64(decodedAzureBodyCap+1))
	})

	t.Run("gzip response decoded by the http client", func(t *testing.T) {
		payload := oversizedPrimaryResult(t, decodedAzureBodyCap+64*1024)
		var compressed bytes.Buffer
		gz := gzip.NewWriter(&compressed)
		_, err := gz.Write(payload)
		require.NoError(t, err)
		require.NoError(t, gz.Close())
		require.Less(t, compressed.Len(), decodedAzureBodyCap, "fixture must be small compressed and large decoded")

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(compressed.Bytes())
		}))
		t.Cleanup(srv.Close)

		result, err := (&AzureLogAnalyticsDatasource{}).ExecuteTimeSeriesQuery(
			context.Background(),
			[]backend.DataQuery{logAnalyticsQuery(t, nil)},
			portalDSInfo(),
			srv.Client(),
			srv.URL,
			false,
		)
		require.NoError(t, err)
		resp, ok := result.Responses["A"]
		require.True(t, ok)
		require.Error(t, resp.Error)
		require.Empty(t, resp.Frames)
	})

	t.Run("small gzip response still succeeds", func(t *testing.T) {
		payload := primaryResultBody(t, 1)
		var compressed bytes.Buffer
		gz := gzip.NewWriter(&compressed)
		_, err := gz.Write(payload)
		require.NoError(t, err)
		require.NoError(t, gz.Close())

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(compressed.Bytes())
		}))
		t.Cleanup(srv.Close)

		result, err := (&AzureLogAnalyticsDatasource{}).ExecuteTimeSeriesQuery(
			context.Background(),
			[]backend.DataQuery{logAnalyticsQuery(t, nil)},
			portalDSInfo(),
			srv.Client(),
			srv.URL,
			false,
		)
		require.NoError(t, err)
		resp := result.Responses["A"]
		require.NoError(t, resp.Error)
		require.NotEmpty(t, resp.Frames)
		require.Equal(t, 1, resp.Frames[0].Rows())
	})
}

func TestCorrelationResponseRejectsOversizedBody(t *testing.T) {
	var padding bytes.Buffer
	padding.WriteString(`{"id":"id","name":"name","type":"microsoft.insights/transactions","properties":{"resources":["/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Insights/components/app"]},"padding":"`)
	padding.WriteString(strings.Repeat("a", decodedAzureBodyCap+64*1024))
	padding.WriteString(`"}`)
	counted := &countingReadCloser{r: bytes.NewReader(padding.Bytes())}

	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.String(), "transactions") {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       counted,
				Request:    r,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(primaryResultBody(t, 1))),
			Request:    r,
		}, nil
	})}

	dsInfo := portalDSInfo()
	dsInfo.Services = map[string]types.DatasourceService{
		"Azure Monitor": {URL: "http://azure.example", HTTPClient: client},
	}
	result, err := (&AzureLogAnalyticsDatasource{}).ExecuteTimeSeriesQuery(
		context.Background(),
		[]backend.DataQuery{tracesQuery(t, formatPtr(dataquery.ResultFormatTable), "op-huge")},
		dsInfo,
		client,
		"http://azure.example",
		false,
	)
	require.NoError(t, err)
	resp, ok := result.Responses["A"]
	require.True(t, ok)
	require.Error(t, resp.Error)
	require.LessOrEqual(t, counted.n, int64(decodedAzureBodyCap+1))
}

func TestMetadataResponseRejectsOversizedDecodedBody(t *testing.T) {
	t.Run("plain response", func(t *testing.T) {
		payload := oversizedMetadata(t, decodedAzureBodyCap+64*1024)
		counted := &countingReadCloser{r: bytes.NewReader(payload)}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://azure.example/metadata", nil)
		req.RequestURI = ""
		client := &http.Client{Transport: fixedBodyTransport(counted, "")}
		_, err := (&AzureLogAnalyticsDatasource{}).ResourceRequest(rec, req, client)
		requireOversizedMetadataRefused(t, err, rec, counted.n)
	})

	t.Run("gzip response", func(t *testing.T) {
		payload := oversizedMetadata(t, decodedAzureBodyCap+64*1024)
		var compressed bytes.Buffer
		gz := gzip.NewWriter(&compressed)
		_, err := gz.Write(payload)
		require.NoError(t, err)
		require.NoError(t, gz.Close())
		require.Less(t, compressed.Len(), decodedAzureBodyCap)

		counted := &countingReadCloser{r: bytes.NewReader(compressed.Bytes())}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://azure.example/metadata", nil)
		req.RequestURI = ""
		client := &http.Client{Transport: fixedBodyTransport(counted, "gzip")}
		_, err = (&AzureLogAnalyticsDatasource{}).ResourceRequest(rec, req, client)
		require.LessOrEqual(t, rec.Body.Len(), decodedAzureBodyCap)
		if err == nil && !bytes.Contains(rec.Body.Bytes(), []byte(`"error"`)) {
			t.Fatalf("gzip metadata response of %d decoded bytes was accepted", len(payload))
		}
	})
}

func requireOversizedMetadataRefused(t *testing.T, err error, rec *httptest.ResponseRecorder, bytesRead int64) {
	t.Helper()
	if err == nil && rec.Body.Len() > decodedAzureBodyCap {
		t.Fatalf("metadata response of %d bytes was accepted after reading %d bytes", rec.Body.Len(), bytesRead)
	}
	require.LessOrEqual(t, bytesRead, int64(decodedAzureBodyCap+1))
	require.LessOrEqual(t, rec.Body.Len(), decodedAzureBodyCap)
}

func requireFrameRowsAtMost(t *testing.T, result *backend.QueryDataResponse, limit int) {
	t.Helper()
	resp, ok := result.Responses["A"]
	require.True(t, ok)
	if resp.Error != nil {
		require.Empty(t, resp.Frames)
		return
	}
	require.NotEmpty(t, resp.Frames)
	require.LessOrEqual(t, resp.Frames[0].Rows(), limit)
}

func queryLogAnalytics(t *testing.T, body []byte, query backend.DataQuery) *backend.QueryDataResponse {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	result, err := (&AzureLogAnalyticsDatasource{}).ExecuteTimeSeriesQuery(
		context.Background(),
		[]backend.DataQuery{query},
		portalDSInfo(),
		srv.Client(),
		srv.URL,
		false,
	)
	require.NoError(t, err)
	return result
}

func portalDSInfo() types.DatasourceInfo {
	return types.DatasourceInfo{
		Routes: map[string]types.AzRoute{
			types.RouteAzurePortal: {URL: "https://portal.azure.com"},
		},
	}
}

func logAnalyticsQuery(t *testing.T, resultFormat *string) backend.DataQuery {
	t.Helper()
	target := map[string]any{
		"query":    "Table",
		"resource": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws",
	}
	if resultFormat != nil {
		target["resultFormat"] = string(*resultFormat)
	}
	raw := mustJSON(t, map[string]any{
		"queryType":         "Azure Log Analytics",
		"azureLogAnalytics": target,
	})
	return backend.DataQuery{
		RefID:     "A",
		QueryType: string(dataquery.AzureQueryTypeLogAnalytics),
		JSON:      raw,
		TimeRange: backend.TimeRange{From: time.Unix(0, 0).UTC(), To: time.Unix(60, 0).UTC()},
	}
}

func tracesQuery(t *testing.T, resultFormat *string, operationID string) backend.DataQuery {
	t.Helper()
	target := map[string]any{
		"resources": []string{"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Insights/components/app"},
	}
	if resultFormat != nil {
		target["resultFormat"] = string(*resultFormat)
	}
	if operationID != "" {
		target["operationId"] = operationID
	}
	raw := mustJSON(t, map[string]any{
		"queryType":   "Azure Traces",
		"azureTraces": target,
	})
	return backend.DataQuery{
		RefID:     "A",
		QueryType: string(dataquery.AzureQueryTypeAzureTraces),
		JSON:      raw,
		TimeRange: backend.TimeRange{From: time.Unix(0, 0).UTC(), To: time.Unix(60, 0).UTC()},
	}
}

func primaryResultBody(t *testing.T, rows int) []byte {
	t.Helper()
	tableRows := make([][]any, rows)
	for i := range tableRows {
		tableRows[i] = []any{i}
	}
	return mustJSON(t, map[string]any{
		"tables": []any{
			map[string]any{
				"name": "PrimaryResult",
				"columns": []any{
					map[string]any{"name": "value", "type": "int"},
				},
				"rows": tableRows,
			},
		},
	})
}

func oversizedPrimaryResult(t *testing.T, padding int) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{
		"tables": []any{
			map[string]any{
				"name": "PrimaryResult",
				"columns": []any{
					map[string]any{"name": "value", "type": "string"},
				},
				"rows": []any{[]any{strings.Repeat("a", padding)}},
			},
		},
	})
}

func oversizedMetadata(t *testing.T, padding int) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{
		"tables": []any{
			map[string]any{
				"name":        "Table",
				"description": strings.Repeat("a", padding),
				"hasData":     true,
			},
		},
	})
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return raw
}

func formatPtr(format dataquery.ResultFormat) *string {
	value := string(format)
	return &value
}

type countingReadCloser struct {
	r io.Reader
	n int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReadCloser) Close() error { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fixedBodyTransport(body io.ReadCloser, encoding string) roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("Content-Type", "application/json")
		if encoding != "" {
			header.Set("Content-Encoding", encoding)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     header,
			Body:       body,
			Request:    r,
		}, nil
	}
}
