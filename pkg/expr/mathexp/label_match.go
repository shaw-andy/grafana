package mathexp

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"sort"

	"github.com/grafana/grafana-plugin-sdk-go/data"

	"github.com/grafana/grafana/pkg/expr/mathexp/parse"
)

const (
	// labelMatchWorkPerLabel and labelMatchBaseWork bound the work spent
	// matching labels to a multiple of the input size. Values match when one
	// label set is a subset of the other; that is found with hash lookups,
	// but which label name sets relate to each other is still checked pairwise.
	labelMatchWorkPerLabel = 32
	labelMatchBaseWork     = 1 << 16

	// ctxCheckInterval is how many units of work run between context checks.
	ctxCheckInterval = 1024
)

var errLabelMatchTooExpensive = errors.New("label matching work limit exceeded")

// labelMatch records which values of a binary operation are combined. Two
// values are combined when the labels of one contain the labels of the other.
type labelMatch struct {
	a, b Values
	// buckets[i] holds the indices of the B values combined with A value i.
	// Each slice is ascending and the slices for one i are disjoint.
	buckets [][][]int
	// pairs is the total number of combined pairs.
	pairs int64
	// single is set when only A[0] and B[0] are combined, without labels:
	// one side starts with NoData and a side has one value, or each side has
	// one value and their labels do not match.
	single bool
}

type labelGroup struct {
	keys    []string
	members []int
	// byValues maps the label values of a member, in key order, to the members
	// holding those values.
	byValues map[string][]int
}

type labelGroups struct {
	labels    []data.Labels
	groups    []*labelGroup
	byKeys    map[string]*labelGroup
	byLen     map[int][]*labelGroup
	groupOf   []*labelGroup
	valuesKey []string
}

type workBudget struct {
	ctx       context.Context
	spent     int64
	limit     int64
	nextCheck int64
}

func (w *workBudget) spend(n int) error {
	w.spent += int64(n)
	if w.spent > w.limit {
		return errLabelMatchTooExpensive
	}
	if w.spent >= w.nextCheck {
		w.nextCheck = w.spent + ctxCheckInterval
		return w.ctx.Err()
	}
	return nil
}

func appendLenPrefixed(buf []byte, s string) []byte {
	buf = binary.AppendUvarint(buf, uint64(len(s)))
	return append(buf, s...)
}

func valuesKey(buf []byte, labels data.Labels, keys []string) ([]byte, string) {
	buf = buf[:0]
	for _, k := range keys {
		buf = appendLenPrefixed(buf, labels[k])
	}
	return buf, string(buf)
}

func groupLabels(values Values, w *workBudget) (*labelGroups, error) {
	g := &labelGroups{
		labels:    make([]data.Labels, len(values)),
		byKeys:    map[string]*labelGroup{},
		byLen:     map[int][]*labelGroup{},
		groupOf:   make([]*labelGroup, len(values)),
		valuesKey: make([]string, len(values)),
	}
	var buf []byte
	keys := []string{}
	for i, v := range values {
		labels := v.GetLabels()
		if err := w.spend(len(labels) + 1); err != nil {
			return nil, err
		}
		g.labels[i] = labels

		keys = keys[:0]
		for k := range labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf = keysID(buf, keys)
		group, ok := g.byKeys[string(buf)]
		if !ok {
			group = &labelGroup{keys: slices.Clone(keys), byValues: map[string][]int{}}
			g.byKeys[string(buf)] = group
			g.byLen[len(keys)] = append(g.byLen[len(keys)], group)
			g.groups = append(g.groups, group)
		}
		var key string
		buf, key = valuesKey(buf, labels, group.keys)
		group.members = append(group.members, i)
		group.byValues[key] = append(group.byValues[key], i)
		g.groupOf[i] = group
		g.valuesKey[i] = key
	}
	return g, nil
}

// containsKeys reports whether sorted keys sup contains every key of sorted keys sub.
func containsKeys(sup, sub []string) bool {
	i := 0
	for _, k := range sub {
		for i < len(sup) && sup[i] < k {
			i++
		}
		if i == len(sup) || sup[i] != k {
			return false
		}
		i++
	}
	return true
}

// matchLabels finds the pairs union() combines without comparing every A value
// with every B value. The work is bounded by the input size; when the label
// name sets would need more, it returns errLabelMatchTooExpensive.
func matchLabels(ctx context.Context, aResults, bResults Results) (*labelMatch, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	m := &labelMatch{a: aResults.Values, b: bResults.Values}
	aLen, bLen := len(m.a), len(m.b)
	if aLen == 0 || bLen == 0 {
		return m, nil
	}
	if aLen == 1 || bLen == 1 {
		if m.a[0].Type() == parse.TypeNoData || m.b[0].Type() == parse.TypeNoData {
			m.single = true
			m.pairs = 1
			return m, nil
		}
	}

	inputSize := 0
	for _, v := range m.a {
		inputSize += len(v.GetLabels()) + 1
	}
	for _, v := range m.b {
		inputSize += len(v.GetLabels()) + 1
	}
	w := &workBudget{
		ctx:   ctx,
		limit: int64(inputSize)*labelMatchWorkPerLabel + labelMatchBaseWork,
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ag, err := groupLabels(m.a, w)
	if err != nil {
		return nil, err
	}
	bg, err := groupLabels(m.b, w)
	if err != nil {
		return nil, err
	}
	m.buckets = make([][][]int, aLen)

	for _, j := range ag.groups {
		if err := m.matchGroup(j, ag, bg, w); err != nil {
			return nil, err
		}
	}

	if m.pairs == 0 && aLen == 1 && bLen == 1 {
		m.single = true
		m.pairs = 1
		m.buckets = nil
	}
	return m, nil
}

// matchGroup adds the B values matched with each member of the A group j.
func (m *labelMatch) matchGroup(j *labelGroup, ag, bg *labelGroups, w *workBudget) error {
	addBucket := func(ia int, bucket []int) {
		if len(bucket) == 0 {
			return
		}
		m.buckets[ia] = append(m.buckets[ia], bucket)
		m.pairs += int64(len(bucket))
	}

	// Label sets with the same number of names match only when they are equal.
	if k, ok := bg.byKeys[string(keysID(nil, j.keys))]; ok {
		for _, ia := range j.members {
			if err := w.spend(1); err != nil {
				return err
			}
			addBucket(ia, k.byValues[ag.valuesKey[ia]])
		}
	}

	var buf []byte
	for n, ks := range bg.byLen {
		if n == len(j.keys) {
			continue
		}
		for _, k := range ks {
			if err := w.spend(len(j.keys) + len(k.keys) + 1); err != nil {
				return err
			}
			switch {
			case n < len(j.keys) && containsKeys(j.keys, k.keys):
				for _, ia := range j.members {
					if err := w.spend(len(k.keys) + 1); err != nil {
						return err
					}
					var key string
					buf, key = valuesKey(buf, ag.labels[ia], k.keys)
					addBucket(ia, k.byValues[key])
				}
			case n > len(j.keys) && containsKeys(k.keys, j.keys):
				projected := map[string][]int{}
				for _, ib := range k.members {
					if err := w.spend(len(j.keys) + 1); err != nil {
						return err
					}
					var key string
					buf, key = valuesKey(buf, bg.labels[ib], j.keys)
					projected[key] = append(projected[key], ib)
				}
				for _, ia := range j.members {
					if err := w.spend(1); err != nil {
						return err
					}
					addBucket(ia, projected[ag.valuesKey[ia]])
				}
			}
		}
	}
	return nil
}

func keysID(buf []byte, keys []string) []byte {
	buf = buf[:0]
	for _, k := range keys {
		buf = appendLenPrefixed(buf, k)
	}
	return buf
}

// each calls fn for every combined pair in the order union() emits them: by A
// index, then by B index. It stops when fn returns false or ctx is canceled.
func (m *labelMatch) each(ctx context.Context, fn func(ia, ib int) bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if m.single {
		fn(0, 0)
		return nil
	}
	visited := 0
	var merged []int
	for ia, buckets := range m.buckets {
		bs := []int(nil)
		switch len(buckets) {
		case 0:
			continue
		case 1:
			bs = buckets[0]
		default:
			merged = merged[:0]
			for _, b := range buckets {
				merged = append(merged, b...)
			}
			slices.Sort(merged)
			bs = merged
		}
		for _, ib := range bs {
			if visited%ctxCheckInterval == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			visited++
			if !fn(ia, ib) {
				return nil
			}
		}
	}
	return nil
}

// unionLabels returns the labels union() assigns to a combined pair: the larger
// of the two label sets, which contains the other.
func unionLabels(a, b data.Labels) data.Labels {
	if len(a) > 0 && len(a) >= len(b) {
		return a
	}
	return b
}
