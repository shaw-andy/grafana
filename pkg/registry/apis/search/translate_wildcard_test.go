package search

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	searchv0 "github.com/grafana/grafana/pkg/apis/search/v0alpha1"
)

func TestTranslateSearchQueryBoundsWildcardText(t *testing.T) {
	cases := []string{
		strings.Repeat("*", 4000),
		strings.Repeat("?", 100),
		"cpu*usage?",
	}
	for _, text := range cases {
		t.Run(text[:min(12, len(text))], func(t *testing.T) {
			q := searchQuery(&searchv0.WhereNode{Text: &searchv0.TextPredicate{Value: text}})
			req, errs := TranslateSearchQuery(q, dashboardsGVR, "default", testProvider())
			if len(errs) > 0 {
				return
			}
			require.NotNil(t, req)
			require.Truef(t, boundedSearchPattern(req.Query), "text %q became query %q", text, req.Query)
		})
	}
}

func TestTranslateSearchQueryKeepsOrdinaryText(t *testing.T) {
	q := &searchv0.SearchQuery{
		TypeMeta: metav1.TypeMeta{APIVersion: searchv0.APIVERSION, Kind: searchv0.KindSearchQuery},
		Where:    &searchv0.WhereNode{Text: &searchv0.TextPredicate{Value: "cpu"}},
	}
	req, errs := TranslateSearchQuery(q, dashboardsGVR, "default", testProvider())
	require.Empty(t, errs)
	require.Equal(t, "cpu", req.Query)
	require.True(t, boundedSearchPattern(req.Query))
}
