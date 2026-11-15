package testdatasource

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
)

// Label text on a TestData query is caller-supplied. A piece with no '=' must
// be skipped or the query must fail with an error. These tests fail while
// parseLabelsString slices that piece at index -1 and panics.
func TestQueryLabelPiecesWithoutEqualsDoNotPanic(t *testing.T) {
	svc := ProvideService()

	// keep is present only when the query returns frames. An error, or a
	// response with no frames, is a refusal and is accepted.
	cases := []struct {
		name      string
		queryType string
		json      string
		keep      map[string]string
		absent    []string
		// hidden is set when the scenario parses labels only to build a frame
		// it does not return, so a successful response has no label map to read.
		hidden bool
	}{
		{
			name: "random walk fallback scenario id",
			json: `{"scenarioId":"random_walk","seriesCount":1,"labels":"{noequals}"}`,
			absent: []string{
				"noequals",
			},
		},
		{
			name:      "random walk explicit query type",
			queryType: "random_walk",
			json:      `{"scenarioId":"random_walk","seriesCount":1,"labels":"{job=foo,noequals}"}`,
			keep:      map[string]string{"job": "foo"},
			absent:    []string{"noequals"},
		},
		{
			name:   "random walk trailing empty piece",
			json:   `{"scenarioId":"random_walk","seriesCount":2,"labels":"{a=b,}"}`,
			keep:   map[string]string{"a": "b"},
			absent: []string{""},
		},
		{
			name:   "random walk unbraced piece",
			json:   `{"scenarioId":"random_walk","seriesCount":1,"labels":"job=foo, noequals"}`,
			keep:   map[string]string{"job": "foo"},
			absent: []string{"noequals"},
		},
		{
			name:   "predictable pulse",
			json:   `{"scenarioId":"predictable_pulse","labels":"{job=foo,noequals}","pulseWave":{"timeStep":1,"onCount":1,"offCount":1,"onValue":1,"offValue":0}}`,
			keep:   map[string]string{"job": "foo"},
			absent: []string{"noequals"},
		},
		{
			name:   "predictable csv wave",
			json:   `{"scenarioId":"predictable_csv_wave","csvWave":[{"timeStep":1,"valuesCSV":"1,2,3","labels":"{job=foo,noequals}","name":"wave"}]}`,
			keep:   map[string]string{"job": "foo"},
			absent: []string{"noequals"},
		},
		{
			name:   "csv content column name",
			json:   `{"scenarioId":"csv_content","csvContent":"time,\"value{job=foo,noequals}\"\n1,2\n"}`,
			keep:   map[string]string{"job": "foo"},
			absent: []string{"noequals"},
		},
		{
			name:   "csv content column without equals",
			json:   `{"scenarioId":"csv_content","csvContent":"value{noequals}\n1\n"}`,
			absent: []string{"noequals"},
		},
		{
			name:   "errors and notices",
			json:   `{"scenarioId":"errors_and_notices","labels":"{job=foo,noequals}"}`,
			keep:   map[string]string{"job": "foo"},
			absent: []string{"noequals"},
		},
		{
			name:   "random walk with error",
			json:   `{"scenarioId":"random_walk_with_error","labels":"{job=foo,noequals}"}`,
			keep:   map[string]string{"job": "foo"},
			absent: []string{"noequals"},
		},
		{
			name:   "slow query",
			json:   `{"scenarioId":"slow_query","labels":"{job=foo,noequals}"}`,
			keep:   map[string]string{"job": "foo"},
			absent: []string{"noequals"},
		},
		{
			name:   "flaky query",
			json:   `{"scenarioId":"flaky_query","labels":"{job=foo,noequals}"}`,
			keep:   map[string]string{"job": "foo"},
			absent: []string{"noequals"},
		},
		{
			name:   "exemplars reference walk",
			json:   `{"scenarioId":"exemplars","labels":"{job=foo,noequals}"}`,
			absent: []string{"noequals"},
			hidden: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("query panicked: %v", recovered)
				}
			}()

			resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{
				Queries: []backend.DataQuery{labelQuery(tc.queryType, tc.json)},
			})
			requireLabelPiecesRefusedOrKept(t, err, resp, tc.keep, tc.absent, tc.hidden)
		})
	}
}

func labelQuery(queryType, body string) backend.DataQuery {
	from := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	return backend.DataQuery{
		RefID: "A",
		TimeRange: backend.TimeRange{
			From: from,
			To:   from.Add(5 * time.Minute),
		},
		Interval:      time.Second,
		MaxDataPoints: 10,
		QueryType:     queryType,
		JSON:          []byte(body),
	}
}

// requireLabelPiecesRefusedOrKept passes when the query is refused, or when
// every returned frame keeps well-formed pairs and drops pieces with no '='.
func requireLabelPiecesRefusedOrKept(t *testing.T, err error, resp *backend.QueryDataResponse, keep map[string]string, absent []string, hidden bool) {
	t.Helper()
	if err != nil {
		return
	}
	require.NotNil(t, resp)

	dr, ok := resp.Responses["A"]
	if !ok || len(dr.Frames) == 0 {
		return
	}

	sawLabels := false
	for _, frame := range dr.Frames {
		if frame == nil {
			continue
		}
		for _, field := range frame.Fields {
			if len(field.Labels) == 0 {
				continue
			}
			sawLabels = true
			if !hidden {
				for key, value := range keep {
					require.Equal(t, value, field.Labels[key], "label %q", key)
				}
			}
			for _, key := range absent {
				_, present := field.Labels[key]
				require.Falsef(t, present, "label piece %q has no equals sign", key)
			}
		}
	}

	if sawLabels || hidden {
		return
	}
	for key, value := range keep {
		t.Fatalf("query returned frames without label %q=%q; keep well-formed pairs or return an error", key, value)
	}
}
