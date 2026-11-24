// Package searchencoding defines how a rule's map-shaped fields are
// represented in the search index and on a search hit.
package searchencoding

import (
	"encoding/json"
	"sort"
	"strings"
)

// LabelTerms flattens a rule's labels into the indexed representation: a bare
// "key" term so an existence matcher can hit, plus a "key=value" term so an
// equality matcher can filter using it.
func LabelTerms[T ~string](labels map[string]T) []string {
	if len(labels) == 0 {
		return nil
	}
	out := make([]string, 0, len(labels)*2)
	for k, v := range labels {
		out = append(out, k, k+"="+string(v))
	}
	return out
}

// LabelMap rebuilds the label map from the flattened terms produced by
// LabelTerms.
//
// Splitting each term on its first "=" would be wrong when a label key itself
// contains "=", because the bare existence term for key "a=b" is then
// indistinguishable from the equality term for key "a" with value "b". Nothing
// validates rule label names — sanitizeLabelName in the external Alertmanager
// sender exists precisely because names that are not valid Prometheus label
// names reach storage — so that input is reachable.
//
// LabelTerms always emits both forms for every label, so a term is a key
// exactly when some other term extends it by "=". Candidates are tried longest
// first and each term is consumed once, which resolves the case where one key
// is a "k=v"-shaped prefix of another: given {"a": "x", "a=b": "y"} the term
// "a=b" is claimed as a key by "a=b=y" before "a" can mistake it for its own
// value, leaving "a=x" for "a".
//
// Ties in length are broken lexicographically so the result never depends on
// the order bleve happens to return the terms in.
//
// A rule's label count is not bounded, so the candidates for a key are found
// with a binary search over the lexicographically sorted terms (every term
// extending a prefix sits in one contiguous run) and a segment tree that
// returns the shortest unused term in that run. Comparing each key against
// every term instead makes decoding one hit quadratic in its label count.
func LabelMap(terms []string) map[string]string {
	if len(terms) == 0 {
		return nil
	}

	lex := make([]int, len(terms))
	for i := range lex {
		lex[i] = i
	}
	sort.Slice(lex, func(a, b int) bool { return terms[lex[a]] < terms[lex[b]] })
	sorted := make([]string, len(lex))
	pos := make([]int, len(terms))
	for p, ti := range lex {
		sorted[p] = terms[ti]
		pos[ti] = p
	}
	avail := newShortestTree(sorted)

	order := make([]int, len(terms))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool { return before(terms[order[a]], terms[order[b]]) })

	out := make(map[string]string, len(terms)/2)
	for _, ki := range order {
		if !avail.has(pos[ki]) {
			continue
		}
		prefix := terms[ki] + "="
		lo := sort.SearchStrings(sorted, prefix)
		hi := lo + sort.Search(len(sorted)-lo, func(i int) bool { return !strings.HasPrefix(sorted[lo+i], prefix) })
		// Shortest extension first: it is the value of this key rather than of
		// a longer key that also starts with it.
		best := avail.shortest(lo, hi)
		if best == -1 {
			continue
		}
		avail.remove(pos[ki])
		avail.remove(best)
		out[terms[ki]] = sorted[best][len(prefix):]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// shortestTree is a segment tree over lexicographically sorted terms that
// answers "shortest present term in [lo, hi)", ties going to the
// lexicographically smaller (lower position) term.
type shortestTree struct {
	terms []string
	size  int
	node  []int // position of the best present term in the subtree, or -1
}

func newShortestTree(sorted []string) *shortestTree {
	size := 1
	for size < len(sorted) {
		size <<= 1
	}
	t := &shortestTree{terms: sorted, size: size, node: make([]int, 2*size)}
	for i := range t.node {
		t.node[i] = -1
	}
	for p := range sorted {
		t.node[size+p] = p
	}
	for i := size - 1; i > 0; i-- {
		t.node[i] = t.pick(t.node[2*i], t.node[2*i+1])
	}
	return t
}

func (t *shortestTree) pick(a, b int) int {
	if a == -1 {
		return b
	}
	if b == -1 {
		return a
	}
	if len(t.terms[b]) < len(t.terms[a]) || (len(t.terms[b]) == len(t.terms[a]) && b < a) {
		return b
	}
	return a
}

func (t *shortestTree) has(p int) bool {
	return t.node[t.size+p] != -1
}

func (t *shortestTree) remove(p int) {
	i := t.size + p
	t.node[i] = -1
	for i >>= 1; i > 0; i >>= 1 {
		t.node[i] = t.pick(t.node[2*i], t.node[2*i+1])
	}
}

func (t *shortestTree) shortest(lo, hi int) int {
	best := -1
	for l, r := lo+t.size, hi+t.size; l < r; l, r = l>>1, r>>1 {
		if l&1 == 1 {
			best = t.pick(best, t.node[l])
			l++
		}
		if r&1 == 1 {
			r--
			best = t.pick(best, t.node[r])
		}
	}
	return best
}

// before orders terms longest first, then lexicographically.
func before(a, b string) bool {
	if len(a) != len(b) {
		return len(a) > len(b)
	}
	return a < b
}

// AnnotationsJSON encodes rule annotations as a JSON object string for display,
// or "" when there are none. Annotations are display-only, so unlike labels
// they are stored whole rather than flattened into matchable terms.
func AnnotationsJSON[T ~string](annotations map[string]T) string {
	if len(annotations) == 0 {
		return ""
	}
	m := make(map[string]string, len(annotations))
	for k, v := range annotations {
		m[k] = string(v)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}
