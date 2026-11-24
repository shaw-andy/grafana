package search

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/resource"
	"github.com/stretchr/testify/require"

	model "github.com/grafana/grafana/apps/alerting/rules/pkg/apis/alerting/v0alpha1"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
)

// searchDecodeSamples is how many times a search is timed. The fastest sample
// is compared, so one stalled run cannot hide the quadratic scan.
const searchDecodeSamples = 3

// TestSearchRulesLabelDecodeScales runs the federated search handler on rows
// encoded the way the legacy backend encodes them: ruleColumnValues flattens
// labels with LabelTerms, ruleCells writes the cells, and SearchRules reads
// them back through parseHits. A unified index hit reaches the same parseHits
// path, because both backends store the labels column as those terms.
//
// Each hit is a paused rule. Pausing skips evaluation, and this path still
// rebuilds the labels. One alert rule and one recording rule are returned
// together, which is what a federated /searchRules response carries. An empty
// body lists every rule. A title filter is the other request that still
// returns the hit. Both go through parseHits.
//
// Doubling the labels on the page must cost less than 3x. The full scan costs
// about 4x. The decoded map has to be the labels that were stored.
func TestSearchRulesLabelDecodeScales(t *testing.T) {
	const smallN = 2048
	const largeN = 4096

	t.Run("empty body", func(t *testing.T) {
		assertSearchDecodeScales(t, nil, smallN, largeN)
	})

	t.Run("title filter", func(t *testing.T) {
		body, err := json.Marshal(model.CreateSearchRulesRequestBody{
			Where: &model.CreateSearchRulesRequestSearchWhereNode{
				Text: &model.CreateSearchRulesRequestSearchTextLeaf{Value: "cpu"},
			},
		})
		require.NoError(t, err)
		assertSearchDecodeScales(t, body, smallN, largeN)
	})
}

// TestSearchRulesLabelDecodeAfterCancel covers a request whose context is
// already done, which is where an apiserver timeout leaves the handler.
// parseHits does not consult the context. The call must finish within the
// budget a linear decode of one large hit needs, or return context.Canceled
// without doing that scan. A completed response must still carry the labels.
func TestSearchRulesLabelDecodeAfterCancel(t *testing.T) {
	const n = 8192
	labels := labelsWithEmptyValues(n)
	alert := pausedRule(testAlertRule(), labels)
	h := NewHandler(&fakeIndex{resp: legacyRows(t, alert)}, &fakeIndex{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	rec := httptest.NewRecorder()
	err := h.SearchRules(ctx, rec, &app.CustomRouteRequest{
		ResourceIdentifier: resource.FullIdentifier{Namespace: "default"},
	})
	elapsed := time.Since(start)
	t.Logf("canceled search returned in %s (err=%v)", elapsed, err)

	if err != nil {
		require.ErrorIs(t, err, context.Canceled)
		require.Less(t, elapsed, 80*time.Millisecond,
			"canceled search spent %s before returning", elapsed)
		return
	}
	require.Equal(t, http.StatusOK, rec.Code)
	hits := decodeSearchHits(t, rec.Body.Bytes())
	require.Len(t, hits, 1)
	require.Equal(t, labels, hits[0].Fields.Labels)
	require.Less(t, elapsed, 80*time.Millisecond,
		"canceled search spent %s rebuilding labels", elapsed)
}

func assertSearchDecodeScales(t *testing.T, raw []byte, smallN, largeN int) {
	t.Helper()
	smallTime := fastestSearchDecode(t, raw, smallN)
	largeTime := fastestSearchDecode(t, raw, largeN)
	t.Logf("search decode: %d labels %s, %d labels %s", smallN, smallTime, largeN, largeTime)
	require.Less(t, largeTime, smallTime*3,
		"searching %d labels took %s and %d took %s; doubling the labels on the page must not quadruple the cost",
		largeN, largeTime, smallN, smallTime)
	require.Less(t, largeTime, 120*time.Millisecond,
		"searching %d labels took %s", largeN, largeTime)
}

func fastestSearchDecode(t *testing.T, raw []byte, n int) time.Duration {
	t.Helper()
	labels := labelsWithEmptyValues(n)
	alert := pausedRule(testAlertRule(), labels)
	recording := pausedRule(testRecordingRule(), labels)
	h := NewHandler(&fakeIndex{resp: legacyRows(t, alert, recording)}, &fakeIndex{})

	best := time.Duration(0)
	for i := 0; i < searchDecodeSamples; i++ {
		elapsed, hits := searchOnce(t, h, raw)
		require.Len(t, hits, 2)
		require.Equal(t, labels, hitsByName(t, hits)[alert.UID].Fields.Labels)
		require.Equal(t, labels, hitsByName(t, hits)[recording.UID].Fields.Labels)
		require.NotNil(t, hitsByName(t, hits)[alert.UID].Fields.Paused)
		require.True(t, *hitsByName(t, hits)[alert.UID].Fields.Paused)
		require.True(t, *hitsByName(t, hits)[recording.UID].Fields.Paused)
		if best == 0 || elapsed < best {
			best = elapsed
		}
	}
	return best
}

func searchOnce(t *testing.T, h *Handler, raw []byte) (time.Duration, []model.CreateSearchRulesSearchResultHit) {
	t.Helper()
	var body io.ReadCloser
	if raw != nil {
		body = io.NopCloser(strings.NewReader(string(raw)))
	}
	start := time.Now()
	rec := httptest.NewRecorder()
	err := h.SearchRules(context.Background(), rec, &app.CustomRouteRequest{
		ResourceIdentifier: resource.FullIdentifier{Namespace: "default"},
		Body:               body,
	})
	elapsed := time.Since(start)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)
	return elapsed, decodeSearchHits(t, rec.Body.Bytes())
}

func pausedRule(rule *ngmodels.AlertRule, labels map[string]string) *ngmodels.AlertRule {
	rule.IsPaused = true
	rule.Labels = labels
	return rule
}

func hitsByName(t *testing.T, hits []model.CreateSearchRulesSearchResultHit) map[string]model.CreateSearchRulesSearchResultHit {
	t.Helper()
	byName := make(map[string]model.CreateSearchRulesSearchResultHit, len(hits))
	for _, hit := range hits {
		byName[hit.Resource.Name] = hit
	}
	return byName
}

func decodeSearchHits(t *testing.T, raw []byte) []model.CreateSearchRulesSearchResultHit {
	t.Helper()
	var out model.CreateSearchRulesResponse
	require.NoError(t, json.Unmarshal(raw, &out))
	return out.Items
}

func labelsWithEmptyValues(n int) map[string]string {
	labels := make(map[string]string, n)
	for i := 0; i < n; i++ {
		// Fixed width so every key=value term is one byte longer than its key,
		// which is the shape that makes the longest-first scan miss every time.
		labels[fmt.Sprintf("k%06d", i)] = ""
	}
	return labels
}
