package searchencoding

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// labelMapSamples is how many times a size is decoded. The fastest sample is
// the one compared, so a single stalled run cannot hide a quadratic scan or
// fail a linear one.
const labelMapSamples = 5

// TestLabelMapDecodeScalesWithLabelCount locks the cost of rebuilding a label
// map from the terms LabelTerms writes.
//
// LabelMap walks every term and, for each one, scans the whole term list for a
// candidate that starts with that term plus "=". Terms are ordered longest
// first, so the key=value terms (the ones that match nothing) run first and
// each does a full scan. Doubling the label count therefore about quadruples
// the work. A few thousand labels already takes tens of milliseconds; a few
// hundred thousand, which a rule is allowed to store, takes minutes on one core.
//
// The bound is the contract for a fix: decoding must stay under 60ms at 4096
// labels and must grow by less than 3x when the label count doubles. A full
// scan fails both. A linear or n log n decode of the same terms, which still
// has to return every label unchanged, passes both.
func TestLabelMapDecodeScalesWithLabelCount(t *testing.T) {
	const smallN = 2048
	const largeN = 4096

	small := labelsWithEmptyValues(smallN)
	large := labelsWithEmptyValues(largeN)

	// Warm the allocator so the first measured call is not paying for new maps.
	_ = LabelMap(LabelTerms(labelsWithEmptyValues(256)))

	smallTime := fastestLabelMapDecode(t, small)
	largeTime := fastestLabelMapDecode(t, large)
	t.Logf("label map decode: %d labels %s, %d labels %s", smallN, smallTime, largeN, largeTime)

	require.Less(t, largeTime, 60*time.Millisecond,
		"decoding %d labels took %s; LabelMap scans every term for every other term", largeN, largeTime)
	require.Less(t, largeTime, smallTime*3,
		"decoding %d labels took %s and %d took %s; doubling the input must not quadruple the cost",
		largeN, largeTime, smallN, smallTime)
}

func fastestLabelMapDecode(t *testing.T, labels map[string]string) time.Duration {
	t.Helper()
	terms := LabelTerms(labels)
	best := time.Duration(0)
	for i := 0; i < labelMapSamples; i++ {
		start := time.Now()
		got := LabelMap(terms)
		elapsed := time.Since(start)
		require.Equal(t, labels, got)
		if best == 0 || elapsed < best {
			best = elapsed
		}
	}
	return best
}

func labelsWithEmptyValues(n int) map[string]string {
	labels := make(map[string]string, n)
	for i := 0; i < n; i++ {
		labels[fmt.Sprintf("k%06d", i)] = ""
	}
	return labels
}
