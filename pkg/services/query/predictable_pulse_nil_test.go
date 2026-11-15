package query

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/user"
	testdatasource "github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource"
	"github.com/grafana/grafana/pkg/web"
)

// The body is the one a signed-in caller posts to /api/ds/query. Binding and
// parseMetricRequest must forward it unchanged into the TestData plugin, and
// that plugin must reject a predictable_pulse query that omits pulseWave
// instead of panicking.
func TestPredictablePulseDSQueryBodyIsRejected(t *testing.T) {
	cases := []struct {
		name             string
		supportLocalTime bool
		queryJSON        string
		wantSuccess      bool
	}{
		{
			name:      "omitted pulseWave",
			queryJSON: `{"scenarioId":"predictable_pulse","refId":"A","datasource":{"type":"grafana-testdata-datasource","uid":"testdata"}}`,
		},
		{
			name:             "omitted pulseWave with per-query time range",
			supportLocalTime: true,
			queryJSON:        `{"scenarioId":"predictable_pulse","refId":"A","datasource":{"type":"grafana-testdata-datasource","uid":"testdata"},"timeRange":{"from":"now-5m","to":"now"}}`,
		},
		{
			name:      "null pulseWave",
			queryJSON: `{"scenarioId":"predictable_pulse","refId":"A","pulseWave":null,"datasource":{"type":"grafana-testdata-datasource","uid":"testdata"}}`,
		},
		{
			name:      "queryType predictable_pulse and omitted pulseWave",
			queryJSON: `{"queryType":"predictable_pulse","refId":"A","datasource":{"type":"grafana-testdata-datasource","uid":"testdata"}}`,
		},
		{
			name:        "complete pulseWave",
			wantSuccess: true,
			queryJSON:   `{"scenarioId":"predictable_pulse","refId":"A","datasource":{"type":"grafana-testdata-datasource","uid":"testdata"},"pulseWave":{"timeStep":60,"onCount":1,"offCount":1,"onValue":2,"offValue":1}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"from":"now-5m","to":"now","queries":[` + tc.queryJSON + `]}`
			req := httptest.NewRequest(http.MethodPost, "/api/ds/query", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			var metricReq dtos.MetricRequest
			require.NoError(t, web.Bind(req, &metricReq))

			parsed, err := predictablePulseQueryService().parseMetricRequest(
				context.Background(),
				&user.SignedInUser{OrgID: 1, OrgRole: identity.RoleViewer},
				true,
				metricReq,
				tc.supportLocalTime,
			)
			require.NoError(t, err)
			flat := parsed.getFlattenedQueries()
			require.Len(t, flat, 1)

			plugin := testdatasource.ProvideService()
			resp, err := plugin.QueryData(context.Background(), &backend.QueryDataRequest{
				Queries: []backend.DataQuery{flat[0].query},
			})
			if tc.wantSuccess {
				require.NoError(t, err)
				require.NotNil(t, resp)
				dr, ok := resp.Responses["A"]
				require.True(t, ok)
				require.NoError(t, dr.Error)
				require.NotEmpty(t, dr.Frames)
				return
			}
			if err != nil {
				require.Error(t, err)
				return
			}
			require.NotNil(t, resp)
			dr, ok := resp.Responses["A"]
			require.True(t, ok, "missing pulseWave must be reported on the query response")
			require.Error(t, dr.Error)
			require.Empty(t, dr.Frames)
		})
	}
}

func predictablePulseQueryService() *ServiceImpl {
	return &ServiceImpl{
		log: log.New("test"),
		dataSourceCache: &fakeDataSourceCache{cache: []*datasources.DataSource{{
			UID:   "testdata",
			Type:  datasources.DS_TESTDATA,
			OrgID: 1,
		}}},
	}
}
