package search_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// A Bleve wildcard treats every '*' and '?' as a metacharacter. A backslash
// does not escape them: the wildcard-to-regexp replacement rewrites '\' and
// the metacharacters separately, so '\*' is still '.*'.
//
// These tests run that query through the scorch index Grafana builds. They
// pass once an over-wide pattern is rejected or rewritten before Bleve
// compiles it, and they fail while the index compiles the pattern.

const wildcardQueryBudget = 400 * time.Millisecond

func TestWildcardQueryManyAsterisksIsBounded(t *testing.T) {
	index := newTitleIndex(t, map[string]string{"dash": "abcd"})

	// Same shape legacy dashboard search sends: a star on each side of the
	// caller's text. A few thousand stars is enough to make scorch spend
	// about a second compiling the automaton for one field, and the title
	// query compiles it twice (title and title_phrase).
	pattern := "*" + strings.Repeat("*", 4000) + "*"
	requireBoundedWildcard(t, index, pattern)
}

func TestWildcardQueryBackslashEscapedAsterisksAreBounded(t *testing.T) {
	index := newTitleIndex(t, map[string]string{"dash": "abcd"})

	// User search prefixes a backslash to each star and then wraps the text
	// with another star. The backslash does not stop Bleve compiling one
	// '.*' per star.
	pattern := "*" + strings.Repeat(`\*`, 200) + "*"
	requireBoundedWildcard(t, index, pattern)
}

func TestWildcardQueryQuestionMarksAreNotSingleCharWildcards(t *testing.T) {
	index := newTitleIndex(t, map[string]string{"dash": "abcd"})

	// The star selects the wildcard query. Each question mark is then one
	// character, so this matches "abcd". Deleting the question marks leaves
	// "*ac", which does not.
	res, err := index.Search(context.Background(), nil, newTestQuery("*a?c?"), nil, nil)
	if err != nil || (res != nil && res.Error != nil) {
		return
	}
	require.NotNil(t, res)
	require.Equal(t, int64(0), res.TotalHits, "question marks were executed as single-character wildcards and matched %q", "abcd")
}

func TestWildcardQueryOrdinaryContainsStillMatches(t *testing.T) {
	index := newTitleIndex(t, map[string]string{"dash": "abcd"})

	res, err := index.Search(context.Background(), nil, newTestQuery("*abc*"), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Nil(t, res.Error)
	require.Equal(t, int64(1), res.TotalHits)
	require.Equal(t, "dash", res.Results.Rows[0].Key.Name)
}

func newTitleIndex(t *testing.T, docs map[string]string) resource.ResourceIndex {
	t.Helper()
	key := resource.NamespacedResource{
		Namespace: "default",
		Group:     "dashboard.grafana.app",
		Resource:  "dashboards",
	}
	index := newTestDashboardsIndex(t, threshold, int64(len(docs)), noop)
	indexDocumentsWithTitles(t, index, key, docs)
	return index
}

func requireBoundedWildcard(t *testing.T, index resource.ResourceIndex, pattern string) {
	t.Helper()

	// One ordinary contains query first, so the timed call is not paying for
	// opening the index.
	warmup, err := index.Search(context.Background(), nil, newTestQuery("*abc*"), nil, nil)
	require.NoError(t, err)
	require.Nil(t, warmup.Error)

	start := time.Now()
	res, err := index.Search(context.Background(), nil, newTestQuery(pattern), nil, nil)
	elapsed := time.Since(start)
	if err != nil || (res != nil && res.Error != nil) {
		return
	}
	require.Lessf(t, elapsed, wildcardQueryBudget, "wildcard %q ran for %s and matched %d documents", pattern, elapsed, totalHits(res))
}

func totalHits(res *resourcepb.ResourceSearchResponse) int64 {
	if res == nil {
		return 0
	}
	return res.TotalHits
}
