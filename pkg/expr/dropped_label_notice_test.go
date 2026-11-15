package expr

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/datasources"
)

// Same-origin GETs that change the caller's session when the browser requests
// them with the session cookie. See pkg/api/api.go route registration.
const (
	sessionRotatePath = "/user/auth-tokens/rotate"
	orgSwitchPath     = "/profile/switch-org/2"
)

func TestDroppedSeriesLabelIsNotActiveMarkupInResultNotice(t *testing.T) {
	payloads := []string{
		"![x](" + sessionRotatePath + ")",
		"![x](" + orgSwitchPath + ")",
		`<img src="` + sessionRotatePath + `">`,
		`<img src="` + orgSwitchPath + `">`,
		`<video src="` + sessionRotatePath + `"></video>`,
		`<audio src="` + orgSwitchPath + `"></audio>`,
		`<div style="background-image: url(` + sessionRotatePath + `)"></div>`,
	}
	// Every binary operator is evaluated by walkBinary, which records unmatched
	// labels and addDropNotices copies them into the result notice.
	expressions := []string{
		"$A || $B",
		"$A && $B",
		"$A == $B",
		"$A != $B",
		"$A > $B",
		"$A >= $B",
		"$A < $B",
		"$A <= $B",
		"$A + $B",
		"$A - $B",
		"$A * $B",
		"$A / $B",
		"$A % $B",
		"$A ** $B",
	}

	for _, payload := range payloads {
		for _, expression := range expressions {
			t.Run(expression+" series "+payload, func(t *testing.T) {
				notice := executeMathNotice(t, expression, wideSeriesResponses(payload))
				assertNoticeDoesNotCarryActiveMarkup(t, notice, payload)
			})
			t.Run(expression+" numbers "+payload, func(t *testing.T) {
				notice := executeMathNotice(t, expression, numberTableResponses(payload))
				assertNoticeDoesNotCarryActiveMarkup(t, notice, payload)
			})
		}
	}
}

func executeMathNotice(t *testing.T, expression string, responses map[string]backend.DataResponse) string {
	t.Helper()

	ds := &datasources.DataSource{OrgID: 1, UID: "test", Type: "test"}
	queries := []Query{
		{
			RefID:      "A",
			DataSource: ds,
			JSON:       json.RawMessage(`{ "datasource": { "uid": "test" }, "refId": "A" }`),
			TimeRange:  AbsoluteTimeRange{From: time.Unix(0, 0), To: time.Unix(10, 0)},
		},
		{
			RefID:      "B",
			DataSource: ds,
			JSON:       json.RawMessage(`{ "datasource": { "uid": "test" }, "refId": "B" }`),
			TimeRange:  AbsoluteTimeRange{From: time.Unix(0, 0), To: time.Unix(10, 0)},
		},
		{
			RefID:      "C",
			DataSource: dataSourceModel(),
			JSON:       json.RawMessage(`{ "datasource": { "uid": "__expr__", "type": "__expr__"}, "type": "math", "expression": "` + expression + `" }`),
		},
	}

	svc, req := newMockQueryService(responses, queries)
	pipeline, err := svc.BuildPipeline(t.Context(), req)
	require.NoError(t, err)

	res, err := svc.ExecutePipeline(t.Context(), time.Unix(10, 0), pipeline)
	require.NoError(t, err)

	response, ok := res.Responses["C"]
	require.True(t, ok, "math expression did not return a result")
	require.NoError(t, response.Error)

	var notices []string
	for _, frame := range response.Frames {
		if frame.Meta == nil {
			continue
		}
		for _, notice := range frame.Meta.Notices {
			notices = append(notices, notice.Text)
		}
	}
	require.NotEmpty(t, notices, "math expression did not record a drop notice, so the label never reached the result the inspector renders")
	return strings.Join(notices, "\n")
}

func assertNoticeDoesNotCarryActiveMarkup(t *testing.T, notice, payload string) {
	t.Helper()
	// The inspector renders this text with the shared markdown renderer, which
	// keeps images. The label has to be neutralized before it is written here.
	if strings.Contains(notice, payload) ||
		strings.Contains(notice, "![") ||
		strings.Contains(notice, "](") ||
		strings.Contains(notice, "<img") ||
		strings.Contains(notice, "<image") ||
		strings.Contains(notice, "src=") {
		t.Fatalf("dropped label is still active markup in the query-result notice:\n%s", notice)
	}
}

func wideSeriesResponses(payload string) map[string]backend.DataResponse {
	return map[string]backend.DataResponse{
		"A": {Frames: data.Frames{
			labeledSeriesFrame(data.Labels{"job": "api"}, 1),
			labeledSeriesFrame(data.Labels{"job": payload}, 2),
		}},
		"B": {Frames: data.Frames{
			labeledSeriesFrame(data.Labels{"job": "api"}, 3),
		}},
	}
}

func numberTableResponses(payload string) map[string]backend.DataResponse {
	return map[string]backend.DataResponse{
		"A": {Frames: data.Frames{
			data.NewFrame("numbers",
				data.NewField("job", nil, []string{"api", payload}),
				data.NewField("value", nil, []float64{1, 2}),
			),
		}},
		"B": {Frames: data.Frames{
			data.NewFrame("numbers",
				data.NewField("job", nil, []string{"api"}),
				data.NewField("value", nil, []float64{3}),
			),
		}},
	}
}

func labeledSeriesFrame(labels data.Labels, value float64) *data.Frame {
	return data.NewFrame("series",
		data.NewField("time", nil, []time.Time{time.Unix(1, 0)}),
		data.NewField("value", labels, []*float64{floatPtr(value)}),
	)
}

func floatPtr(v float64) *float64 {
	return &v
}
