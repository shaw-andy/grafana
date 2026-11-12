//go:build !arm

package sql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	mysql "github.com/dolthub/go-mysql-server/sql"
	"github.com/dolthub/go-mysql-server/sql/analyzer"
	"github.com/dolthub/go-mysql-server/sql/expression"
	"github.com/dolthub/go-mysql-server/sql/expression/function/aggregation"
	"github.com/dolthub/go-mysql-server/sql/plan"
	"github.com/dolthub/go-mysql-server/sql/transform"
	"github.com/dolthub/go-mysql-server/sql/types"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/shopspring/decimal"
)

// The limits grow with the input so a query can still transform every input
// value a few times; only the amount a query can create from nothing is fixed.
const (
	inputValueBytesFactor = 4
	inputCellsFactor      = 10
)

type limitKind int

const (
	valueBytesLimit limitKind = iota
	processedCellsLimit
)

type limitExceededError struct {
	kind  limitKind
	limit int64
}

func (e *limitExceededError) Error() string {
	if e.kind == valueBytesLimit {
		return fmt.Sprintf("sql expression would build more than %d bytes of string and JSON values", e.limit)
	}
	return fmt.Sprintf("sql expression would process more than %d cells", e.limit)
}

// queryLimits is the budget of a single query. It is charged while the engine
// evaluates, and every string or JSON value is checked against it before it is
// built, because refusing a row after the engine returned it is too late: the
// memory has already been allocated.
type queryLimits struct {
	maxValueBytes int64
	valueBytes    int64
	maxCells      int64
	cells         int64
}

// newQueryLimits returns the limits for a query over frames. A limit of 0 or
// less disables that limit.
func newQueryLimits(maxValueBytes, maxCells int64, frames []*data.Frame) *queryLimits {
	l := &queryLimits{}
	inputBytes, inputCells := frameSizes(frames)
	if maxValueBytes > 0 {
		l.maxValueBytes = satAdd(maxValueBytes, satMul(inputBytes, inputValueBytesFactor))
	}
	if maxCells > 0 {
		l.maxCells = satAdd(maxCells, satMul(inputCells, inputCellsFactor))
	}
	return l
}

func (l *queryLimits) remainingBytes() int64 {
	if l.maxValueBytes <= 0 {
		return math.MaxInt64
	}
	return l.maxValueBytes - l.valueBytes
}

// reserve refuses a value of n bytes before it is built.
func (l *queryLimits) reserve(n int64) error {
	if n > l.remainingBytes() {
		return &limitExceededError{kind: valueBytesLimit, limit: l.maxValueBytes}
	}
	return nil
}

func (l *queryLimits) chargeBytes(n int64) error {
	if err := l.reserve(n); err != nil {
		return err
	}
	l.valueBytes += n
	return nil
}

// chargeValue charges the size of a value that was just built or retained.
func (l *queryLimits) chargeValue(ctx context.Context, v interface{}) error {
	if l.maxValueBytes <= 0 {
		return nil
	}
	return l.chargeBytes(valueSize(ctx, v, l.remainingBytes()))
}

func (l *queryLimits) chargeCells(n int) error {
	if l.maxCells <= 0 {
		return nil
	}
	if n < 1 {
		n = 1
	}
	l.cells += int64(n)
	if l.cells > l.maxCells {
		return &limitExceededError{kind: processedCellsLimit, limit: l.maxCells}
	}
	return nil
}

func frameSizes(frames []*data.Frame) (bytes, cells int64) {
	for _, f := range frames {
		if f == nil {
			continue
		}
		for _, field := range f.Fields {
			n := field.Len()
			cells += int64(n)
			for i := 0; i < n; i++ {
				switch v := field.At(i).(type) {
				case string:
					bytes += int64(len(v))
				case *string:
					if v != nil {
						bytes += int64(len(*v))
					}
				case []byte:
					bytes += int64(len(v))
				case json.RawMessage:
					bytes += int64(len(v))
				case *json.RawMessage:
					if v != nil {
						bytes += int64(len(*v))
					}
				default:
					bytes += 8
				}
			}
		}
	}
	return bytes, cells
}

// limitAllocations is an analyzer rule that routes every expression that can
// build a string or JSON value through the query's limits. It runs before the
// analyzer folds constant expressions, since folding evaluates them.
func limitAllocations(limits *queryLimits) analyzer.RuleFunc {
	var rule analyzer.RuleFunc
	rule = func(ctx *mysql.Context, a *analyzer.Analyzer, n mysql.Node, scope *plan.Scope, sel analyzer.RuleSelector, qFlags *mysql.QueryFlags) (mysql.Node, transform.TreeIdentity, error) {
		return transform.NodeExprsWithOpaque(n, func(e mysql.Expression) (mysql.Expression, transform.TreeIdentity, error) {
			if withNodes, ok := e.(mysql.ExpressionWithNodes); ok {
				children := withNodes.NodeChildren()
				newChildren := make([]mysql.Node, len(children))
				same := transform.SameTree
				for i, child := range children {
					newChild, childSame, err := rule(ctx, a, child, scope, sel, qFlags)
					if err != nil {
						return nil, transform.SameTree, err
					}
					newChildren[i] = newChild
					same = same && childSame
				}
				if same {
					return e, transform.SameTree, nil
				}
				ne, err := withNodes.WithNodeChildren(newChildren...)
				if err != nil {
					return nil, transform.SameTree, err
				}
				return ne, transform.NewTree, nil
			}
			return limitExpression(e, limits)
		})
	}
	return rule
}

func limitExpression(e mysql.Expression, limits *queryLimits) (mysql.Expression, transform.TreeIdentity, error) {
	switch e := e.(type) {
	case *boundedExpr, *chargedExpr, *memoExpr:
		return e, transform.SameTree, nil
	case *aggregation.GroupConcat, *aggregation.JsonArray, *aggregation.JSONObjectAgg:
		// These keep every value they are given until the group is complete.
		children := e.Children()
		newChildren := make([]mysql.Expression, len(children))
		changed := false
		for i, child := range children {
			if _, ok := child.(*chargedExpr); ok {
				newChildren[i] = child
				continue
			}
			newChildren[i] = &chargedExpr{Expression: child, limits: limits}
			changed = true
		}
		if !changed {
			return e, transform.SameTree, nil
		}
		ne, err := e.WithChildren(newChildren...)
		if err != nil {
			return nil, transform.SameTree, err
		}
		return ne, transform.NewTree, nil
	case mysql.Aggregation, mysql.WindowAggregation:
		return e, transform.SameTree, nil
	case *expression.Convert:
		if !buildsValues(e.Type()) {
			return e, transform.SameTree, nil
		}
		return newBoundedExpr(e, "convert", limits)
	case mysql.FunctionExpression:
		name := strings.ToLower(e.FunctionName())
		switch name {
		case "if", "coalesce", "ifnull", "nullif", "least", "greatest":
			// These return one of their arguments, and some do not evaluate
			// every argument, so they are left as they are.
			return e, transform.SameTree, nil
		}
		if !buildsValues(e.Type()) {
			return e, transform.SameTree, nil
		}
		return newBoundedExpr(e, name, limits)
	default:
		return e, transform.SameTree, nil
	}
}

// buildsValues reports whether an expression of type t can return a value
// whose size is not fixed by its type.
func buildsValues(t mysql.Type) bool {
	return !(types.IsNumber(t) || types.IsBoolean(t) || types.IsTime(t) || types.IsTimespan(t) || types.IsYear(t))
}

// boundedExpr evaluates the arguments of fn, refuses the call if the value it
// could build does not fit in the remaining budget, and then calls fn with the
// arguments it already evaluated.
type boundedExpr struct {
	fn     mysql.Expression
	inner  mysql.Expression
	memos  []*memoExpr
	name   string
	limits *queryLimits
}

var _ mysql.Expression = (*boundedExpr)(nil)
var _ mysql.CollationCoercible = (*boundedExpr)(nil)

func newBoundedExpr(fn mysql.Expression, name string, limits *queryLimits) (mysql.Expression, transform.TreeIdentity, error) {
	children := fn.Children()
	memos := make([]*memoExpr, len(children))
	memoChildren := make([]mysql.Expression, len(children))
	for i, child := range children {
		memos[i] = &memoExpr{Expression: child}
		memoChildren[i] = memos[i]
	}
	inner := fn
	if len(children) > 0 {
		var err error
		inner, err = fn.WithChildren(memoChildren...)
		if err != nil {
			return nil, transform.SameTree, err
		}
	}
	return &boundedExpr{fn: fn, inner: inner, memos: memos, name: name, limits: limits}, transform.NewTree, nil
}

func (b *boundedExpr) Eval(ctx *mysql.Context, row mysql.Row) (interface{}, error) {
	args := make([]interface{}, len(b.memos))
	for i, m := range b.memos {
		v, err := m.Expression.Eval(ctx, row)
		if err != nil {
			return nil, err
		}
		args[i] = v
		m.val, m.set = v, true
	}
	if b.limits.maxValueBytes > 0 {
		if err := b.limits.reserve(estimateResultSize(ctx, b.name, args, b.limits.remainingBytes())); err != nil {
			return nil, err
		}
	}
	out, err := b.inner.Eval(ctx, row)
	for _, m := range b.memos {
		m.val, m.set = nil, false
	}
	if err != nil {
		return nil, err
	}
	if err := b.limits.chargeValue(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (b *boundedExpr) Children() []mysql.Expression { return b.fn.Children() }

func (b *boundedExpr) WithChildren(children ...mysql.Expression) (mysql.Expression, error) {
	fn, err := b.fn.WithChildren(children...)
	if err != nil {
		return nil, err
	}
	ne, _, err := newBoundedExpr(fn, b.name, b.limits)
	return ne, err
}

func (b *boundedExpr) Resolved() bool      { return b.fn.Resolved() }
func (b *boundedExpr) String() string      { return b.fn.String() }
func (b *boundedExpr) Type() mysql.Type    { return b.fn.Type() }
func (b *boundedExpr) IsNullable() bool    { return b.fn.IsNullable() }
func (b *boundedExpr) DebugString() string { return mysql.DebugString(b.fn) }
func (b *boundedExpr) CollationCoercibility(ctx *mysql.Context) (mysql.CollationID, byte) {
	return mysql.GetCoercibility(ctx, b.fn)
}

// memoExpr hands boundedExpr's inner function the argument value boundedExpr
// already evaluated, so arguments are evaluated once.
type memoExpr struct {
	mysql.Expression
	val interface{}
	set bool
}

var _ mysql.CollationCoercible = (*memoExpr)(nil)

func (m *memoExpr) Eval(ctx *mysql.Context, row mysql.Row) (interface{}, error) {
	if m.set {
		m.set = false
		return m.val, nil
	}
	return m.Expression.Eval(ctx, row)
}

func (m *memoExpr) WithChildren(children ...mysql.Expression) (mysql.Expression, error) {
	e, err := m.Expression.WithChildren(children...)
	if err != nil {
		return nil, err
	}
	return &memoExpr{Expression: e}, nil
}

func (m *memoExpr) CollationCoercibility(ctx *mysql.Context) (mysql.CollationID, byte) {
	return mysql.GetCoercibility(ctx, m.Expression)
}

// chargedExpr charges every value it returns, for aggregations that keep their
// inputs.
type chargedExpr struct {
	mysql.Expression
	limits *queryLimits
}

var _ mysql.CollationCoercible = (*chargedExpr)(nil)

func (c *chargedExpr) Eval(ctx *mysql.Context, row mysql.Row) (interface{}, error) {
	v, err := c.Expression.Eval(ctx, row)
	if err != nil {
		return nil, err
	}
	if err := c.limits.chargeValue(ctx, v); err != nil {
		return nil, err
	}
	return v, nil
}

func (c *chargedExpr) Children() []mysql.Expression { return []mysql.Expression{c.Expression} }

func (c *chargedExpr) WithChildren(children ...mysql.Expression) (mysql.Expression, error) {
	if len(children) != 1 {
		return nil, mysql.ErrInvalidChildrenNumber.New(c, len(children), 1)
	}
	return &chargedExpr{Expression: children[0], limits: c.limits}, nil
}

func (c *chargedExpr) CollationCoercibility(ctx *mysql.Context) (mysql.CollationID, byte) {
	return mysql.GetCoercibility(ctx, c.Expression)
}

// countingBuilder wraps the iterator of every plan node so the rows it emits
// are charged to the query's limits. Rows are charged as each operator emits
// them, before a parent such as a sort, join, or recursive CTE keeps them.
type countingBuilder struct {
	base     mysql.NodeExecBuilder
	limits   *queryLimits
	building bool
}

var _ mysql.NodeExecBuilder = (*countingBuilder)(nil)

func (c *countingBuilder) Build(ctx *mysql.Context, n mysql.Node, row mysql.Row) (mysql.RowIter, error) {
	// The base builder asks its priority builder first for every node it
	// builds, including n itself, so yield once to let it build n.
	if c.building {
		c.building = false
		return nil, nil
	}
	c.building = true
	iter, err := c.base.Build(ctx, n, row)
	c.building = false
	if err != nil {
		return nil, err
	}
	return &countingIter{iter: iter, limits: c.limits, chargeValues: buildsRowValues(n)}, nil
}

// buildsRowValues reports whether a node returns values that are not in its
// input rows, such as aggregate results or values read from a JSON document.
func buildsRowValues(n mysql.Node) bool {
	switch n.(type) {
	case *plan.GroupBy, *plan.Window, *plan.JSONTable:
		return true
	default:
		return false
	}
}

type countingIter struct {
	iter         mysql.RowIter
	limits       *queryLimits
	chargeValues bool
}

func (c *countingIter) Next(ctx *mysql.Context) (mysql.Row, error) {
	row, err := c.iter.Next(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.limits.chargeCells(len(row)); err != nil {
		return nil, err
	}
	if c.chargeValues {
		for _, v := range row {
			if err := c.limits.chargeValue(ctx, v); err != nil {
				return nil, err
			}
		}
	}
	return row, nil
}

func (c *countingIter) Close(ctx *mysql.Context) error { return c.iter.Close(ctx) }

func asLimitError(err error) (*limitExceededError, bool) {
	var le *limitExceededError
	if errors.As(err, &le) {
		return le, true
	}
	return nil, false
}

// estimateResultSize returns an upper bound on the bytes a call to the named
// function builds from args. limit lets it stop measuring once the bound is
// known to be larger.
func estimateResultSize(ctx context.Context, name string, args []interface{}, limit int64) int64 {
	slack := int64(64 + 16*len(args))
	size := func(i int) int64 {
		if i >= len(args) {
			return 0
		}
		return valueSize(ctx, args[i], limit)
	}
	sumArgs := func(factor int64) int64 {
		total := slack
		for i := range args {
			total = satAdd(total, satMul(size(i), factor))
			if total > limit {
				return total
			}
		}
		return total
	}

	switch name {
	case "repeat":
		count, ok := intArg(ctx, args, 1)
		if !ok || count <= 0 {
			return slack
		}
		return satAdd(slack, satMul(size(0), count))
	case "replace":
		str, okStr := stringArg(args, 0)
		from, okFrom := stringArg(args, 1)
		to, okTo := stringArg(args, 2)
		if okStr && okFrom && okTo {
			if from == "" || len(to) <= len(from) {
				return satAdd(slack, int64(len(str)))
			}
			grow := satMul(int64(strings.Count(str, from)), int64(len(to)-len(from)))
			return satAdd(slack, satAdd(int64(len(str)), grow))
		}
		s := size(0)
		return satAdd(slack, satAdd(s, satMul(s+1, size(2))))
	case "regexp_replace":
		// The pattern may match the empty string at every position, and
		// group references in the replacement may each expand to the whole
		// input.
		s := size(0)
		per := size(2)
		if repl, ok := stringArg(args, 2); ok && strings.ContainsAny(repl, `$\`) {
			per = satMul(per, s+1)
		}
		return satAdd(slack, satAdd(s, satMul(s+1, per)))
	case "json_pretty":
		return satAdd(slack, measureJSONArg(ctx, args, 0, measurePretty, limit))
	case "json_search":
		return satAdd(slack, measureJSONArg(ctx, args, 0, measureSearchPaths, limit))
	case "concat", "substring", "substring_index", "left", "right", "mid", "ltrim", "rtrim", "trim",
		"reverse", "elt", "regexp_substr", "from_base64", "convert",
		"json_extract", "json_unquote", "json_value", "json_keys", "json_remove",
		"json_merge", "json_merge_patch", "json_merge_preserve",
		"json_set", "json_insert", "json_replace", "json_array_append", "json_array_insert":
		return sumArgs(1)
	case "quote":
		return sumArgs(2)
	case "lower", "upper", "lcase", "ucase":
		return sumArgs(3)
	default:
		return sumArgs(6)
	}
}

func stringArg(args []interface{}, i int) (string, bool) {
	if i >= len(args) {
		return "", false
	}
	switch v := args[i].(type) {
	case string:
		return v, true
	case []byte:
		return string(v), true
	default:
		return "", false
	}
}

func intArg(ctx context.Context, args []interface{}, i int) (int64, bool) {
	if i >= len(args) || args[i] == nil {
		return 0, false
	}
	v, _, err := types.Int64.Convert(ctx, args[i])
	if err != nil {
		return 0, false
	}
	n, ok := v.(int64)
	return n, ok
}

// valueSize returns the number of bytes v takes once serialized. It stops
// counting once the size is known to be larger than limit, since a JSON
// document can share subtrees and be far larger than its memory footprint.
func valueSize(ctx context.Context, v interface{}, limit int64) int64 {
	switch x := v.(type) {
	case nil:
		return 0
	case string:
		return int64(len(x))
	case []byte:
		return int64(len(x))
	case mysql.JSONWrapper:
		m := jsonMeter{measure: measureCompact, limit: limit}
		m.walk(ctx, x, 0, 0)
		return m.total
	case mysql.AnyWrapper:
		return x.MaxByteLength()
	default:
		return 0
	}
}

type jsonMeasure int

const (
	// measureCompact is the length of the document as serialized by MySQL.
	measureCompact jsonMeasure = iota
	// measurePretty is the length of the document as written by JSON_PRETTY.
	measurePretty
	// measureSearchPaths is the length of JSON_SEARCH's result if every
	// string in the document matches.
	measureSearchPaths
)

func measureJSONArg(ctx context.Context, args []interface{}, i int, measure jsonMeasure, limit int64) int64 {
	if i >= len(args) || args[i] == nil {
		return 0
	}
	doc := args[i]
	if s, ok := stringArg(args, i); ok {
		parsed, _, err := types.JSON.Convert(ctx, s)
		if err != nil {
			return int64(len(s))
		}
		doc = parsed
	}
	m := jsonMeter{measure: measure, limit: limit}
	m.walk(ctx, doc, 0, 1)
	return m.total
}

type jsonMeter struct {
	measure jsonMeasure
	limit   int64
	total   int64
}

func (m *jsonMeter) add(n int64) bool {
	m.total = satAdd(m.total, n)
	return m.total <= m.limit
}

func (m *jsonMeter) container(depth int64, n int) bool {
	switch m.measure {
	case measureCompact:
		// Brackets, and ", " between elements.
		return m.add(2 + 2*int64(max(n-1, 0)))
	case measurePretty:
		// Brackets, a newline and indent before each element and before the
		// closing bracket, and a comma after all but the last element.
		return m.add(2 + int64(n+1)*(1+2*(depth+1)) + int64(n))
	case measureSearchPaths:
		if depth == 0 {
			return m.add(2)
		}
		return true
	}
	return true
}

func (m *jsonMeter) walk(ctx context.Context, v interface{}, depth, path int64) bool {
	switch x := v.(type) {
	case map[string]interface{}:
		if !m.container(depth, len(x)) {
			return false
		}
		for k, child := range x {
			key := quotedLen(k)
			if m.measure != measureSearchPaths && !m.add(key+2) {
				return false
			}
			if !m.walk(ctx, child, depth+1, satAdd(path, 2*key+1)) {
				return false
			}
		}
		return true
	case []interface{}:
		if !m.container(depth, len(x)) {
			return false
		}
		for i, child := range x {
			if !m.walk(ctx, child, depth+1, satAdd(path, digits(i)+2)) {
				return false
			}
		}
		return true
	case mysql.JSONWrapper:
		if b, ok := x.(types.JSONBytes); ok && m.measure == measureCompact {
			if raw, err := b.GetBytes(ctx); err == nil {
				return m.add(2 * int64(len(raw)))
			}
		}
		inner, err := x.ToInterface(ctx)
		if err != nil {
			return true
		}
		return m.walk(ctx, inner, depth, path)
	case string:
		if m.measure == measureSearchPaths {
			// The path, its quotes, and the ", " separator.
			return m.add(satAdd(path, 4))
		}
		return m.add(quotedLen(x))
	default:
		if m.measure == measureSearchPaths {
			return true
		}
		return m.add(scalarLen(x))
	}
}

// quotedLen is the length of s as a quoted JSON string, assuming the widest
// escape for every character that may be escaped.
func quotedLen(s string) int64 {
	n := int64(len(s)) + 2
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c < 0x20, c == '<', c == '>', c == '&':
			n += 5
		case c == '"', c == '\\':
			n++
		case c == 0xe2:
			// U+2028 and U+2029 are written as \u2028 and \u2029.
			n += 3
		}
	}
	return n
}

func scalarLen(v interface{}) int64 {
	switch x := v.(type) {
	case nil:
		return 4
	case bool:
		return 5
	case decimal.Decimal:
		return int64(x.NumDigits()) + int64(math.Abs(float64(x.Exponent()))) + 3
	case fmt.Stringer:
		return int64(len(x.String()))
	default:
		return 32
	}
}

func digits(i int) int64 {
	n := int64(1)
	for i >= 10 {
		i /= 10
		n++
	}
	return n
}

func satAdd(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

func satMul(a, b int64) int64 {
	if a <= 0 || b <= 0 {
		return 0
	}
	if a > math.MaxInt64/b {
		return math.MaxInt64
	}
	return a * b
}
