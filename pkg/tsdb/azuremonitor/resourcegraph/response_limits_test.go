package resourcegraph

import (
	"bytes"
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
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/kinds/dataquery"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/types"
)

// Resource Graph reuses the Log Analytics frame converter. Its default result
// format is table, so the logs-only row guard does not apply. The decoded
// body cap matches the 32 MiB cap the metrics batch client already uses.
const azureResponseRowCap = 30000
const decodedAzureBodyCap = 32 * 1024 * 1024

func TestResourceGraphQueryCapsRowsForEveryResultFormat(t *testing.T) {
	body := resourceGraphBody(t, azureResponseRowCap+1)
	formats := []struct {
		name   string
		format *string
	}{
		{name: "omitted result format", format: nil},
		{name: "table", format: strPtr("table")},
		{name: "time_series", format: strPtr("time_series")},
	}

	for _, tc := range formats {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(body)
			}))
			t.Cleanup(srv.Close)

			result, err := (&AzureResourceGraphDatasource{Logger: log.NewNullLogger()}).ExecuteTimeSeriesQuery(
				context.Background(),
				[]backend.DataQuery{resourceGraphQuery(t, tc.format)},
				types.DatasourceInfo{Routes: map[string]types.AzRoute{
					types.RouteAzurePortal: {URL: "https://portal.azure.com"},
				}},
				srv.Client(),
				srv.URL,
				false,
			)
			require.NoError(t, err)
			resp, ok := result.Responses["A"]
			require.True(t, ok)
			if resp.Error != nil {
				require.Empty(t, resp.Frames)
				return
			}
			require.NotEmpty(t, resp.Frames)
			require.LessOrEqual(t, resp.Frames[0].Rows(), azureResponseRowCap)
		})
	}
}

func TestResourceGraphRejectsOversizedDecodedBody(t *testing.T) {
	t.Run("plain response", func(t *testing.T) {
		payload := oversizedResourceGraphBody(t, decodedAzureBodyCap+64*1024)
		counted := &countingReadCloser{r: bytes.NewReader(payload)}
		ds := &AzureResourceGraphDatasource{Logger: log.NewNullLogger()}
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
		ds := &AzureResourceGraphDatasource{Logger: log.NewNullLogger()}
		_, err := ds.unmarshalResponse(&http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "502 Bad Gateway",
			Header:     make(http.Header),
			Body:       counted,
		})
		require.Error(t, err)
		require.LessOrEqual(t, counted.n, int64(decodedAzureBodyCap+1))
	})
}

func resourceGraphQuery(t *testing.T, resultFormat *string) backend.DataQuery {
	t.Helper()
	target := map[string]any{"query": "resources"}
	if resultFormat != nil {
		target["resultFormat"] = *resultFormat
	}
	raw, err := json.Marshal(map[string]any{
		"queryType":          string(dataquery.AzureQueryTypeAzureResourceGraph),
		"azureResourceGraph": target,
	})
	require.NoError(t, err)
	return backend.DataQuery{
		RefID:     "A",
		QueryType: string(dataquery.AzureQueryTypeAzureResourceGraph),
		JSON:      raw,
		TimeRange: backend.TimeRange{From: time.Unix(0, 0).UTC(), To: time.Unix(60, 0).UTC()},
	}
}

func resourceGraphBody(t *testing.T, rows int) []byte {
	t.Helper()
	tableRows := make([][]any, rows)
	for i := range tableRows {
		tableRows[i] = []any{i}
	}
	raw, err := json.Marshal(map[string]any{
		"data": map[string]any{
			"columns": []any{map[string]any{"name": "value", "type": "int"}},
			"rows":    tableRows,
		},
	})
	require.NoError(t, err)
	return raw
}

func oversizedResourceGraphBody(t *testing.T, padding int) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"data": map[string]any{
			"columns": []any{map[string]any{"name": "value", "type": "string"}},
			"rows":    []any{[]any{strings.Repeat("a", padding)}},
		},
	})
	require.NoError(t, err)
	return raw
}

func strPtr(v string) *string { return &v }

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
