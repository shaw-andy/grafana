package template

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"text/template/parse"
	"time"
)

// MaxExpandedSize is the maximum number of bytes that the expansion of a single label or
// annotation template can write. Template functions share a second budget of the same size
// for the values they return, so that values passed between functions and variables cannot
// grow without bound either.
const MaxExpandedSize = 1 << 22 // 4 MiB

// ErrExpandedSizeExceeded is returned when a template writes, or its functions produce, more
// than MaxExpandedSize bytes.
var ErrExpandedSizeExceeded = errors.New("template expansion exceeds the maximum size")

const (
	// maxPrintfWidth is the largest width or precision fmt accepts for a verb.
	maxPrintfWidth = 1e6
	// maxScalarSize is more than fmt writes for any number, bool, func, chan or unsafe pointer.
	maxScalarSize = 64
)

// limitedWriter fails writes that would grow its contents past limit bytes. text/template stops
// executing on the first failed write, so output is never buffered past the limit.
type limitedWriter struct {
	buf   bytes.Buffer
	limit int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit-w.buf.Len() {
		return 0, fmt.Errorf("%w: output is longer than %d bytes", ErrExpandedSizeExceeded, w.limit)
	}
	return w.buf.Write(p)
}

func (w *limitedWriter) String() string {
	return w.buf.String()
}

// budget is the number of bytes template functions can still return during one expansion.
// Functions charge what they return, and check an upper bound of it before doing the work.
type budget struct {
	remaining int
}

func newBudget() *budget {
	return &budget{remaining: MaxExpandedSize}
}

func (b *budget) exceeded() error {
	return fmt.Errorf("%w: template functions returned more than %d bytes", ErrExpandedSizeExceeded, MaxExpandedSize)
}

// fits returns an error if a result of up to n bytes would not fit in the budget.
func (b *budget) fits(n int) error {
	if n < 0 || n > b.remaining {
		return b.exceeded()
	}
	return nil
}

// reserve charges n bytes to the budget.
func (b *budget) reserve(n int) error {
	if err := b.fits(n); err != nil {
		return err
	}
	b.remaining -= n
	return nil
}

func (b *budget) str(s string) (string, error) {
	if err := b.reserve(len(s)); err != nil {
		return "", err
	}
	return s, nil
}

// stringFunc wraps fn, whose result is at most factor times as long as its argument.
func (b *budget) stringFunc(factor int, fn func(string) string) func(string) (string, error) {
	return func(s string) (string, error) {
		if err := b.fits(factor * len(s)); err != nil {
			return "", err
		}
		return b.str(fn(s))
	}
}

// formatFunc wraps fn, a function such as fmt.Sprint or template.HTMLEscaper that formats its
// arguments and makes the result at most factor times as long.
func (b *budget) formatFunc(factor int, fn func(...any) string) func(...any) (string, error) {
	return func(args ...any) (string, error) {
		if err := b.fits(factor*argsSize(args, b.remaining) + len(args)); err != nil {
			return "", err
		}
		return b.str(fn(args...))
	}
}

func (b *budget) printf(format string, args ...any) (string, error) {
	sizes := make([]int, len(args))
	limit := b.remaining
	for i, a := range args {
		sizes[i] = valueSize(a, limit)
		limit -= sizes[i]
	}
	if err := b.fits(printfSize(format, sizes)); err != nil {
		return "", err
	}
	return b.str(fmt.Sprintf(format, args...))
}

// args charges what printing its result can write, because maps that share arguments can be
// nested into a value that prints exponentially more than the arguments themselves.
func (b *budget) args(args ...any) (map[string]any, error) {
	result := make(map[string]any, len(args))
	for i, a := range args {
		result[fmt.Sprintf("arg%d", i)] = a
	}
	return charge(b, result)
}

func (b *budget) reReplaceAll(pattern, repl, text string) (string, error) {
	re := regexp.MustCompile(pattern)
	matches, longest := 0, 0
	re.ReplaceAllStringFunc(text, func(m string) string {
		matches++
		longest = max(longest, len(m))
		return ""
	})
	// Each match is replaced by repl, where every $ reference expands to at most the whole match.
	perMatch := len(repl) + strings.Count(repl, "$")*longest
	room := b.remaining - len(text)
	if room < 0 || (perMatch > 0 && matches > room/perMatch) {
		return "", b.exceeded()
	}
	return b.str(re.ReplaceAllString(text, repl))
}

// charge charges what printing res can write to the budget.
func charge[T any](b *budget, res T) (T, error) {
	if err := b.reserve(valueSize(res, b.remaining)); err != nil {
		var zero T
		return zero, err
	}
	return res, nil
}

// argsSize is the sum of valueSize for args, counted up to limit.
func argsSize(args []any, limit int) int {
	n := 0
	for _, a := range args {
		if n > limit {
			break
		}
		n += valueSize(a, limit-n)
	}
	return n
}

// valueSize returns at least the number of bytes fmt writes when printing v with %v. It stops
// counting once the count is larger than limit.
func valueSize(v any, limit int) int {
	n := 0
	var walk func(reflect.Value)
	walk = func(v reflect.Value) {
		if n > limit {
			return
		}
		if !v.IsValid() {
			n += len("<nil>")
			return
		}
		switch v.Kind() {
		case reflect.Interface, reflect.Pointer, reflect.Map, reflect.Slice:
			if v.IsNil() {
				n += len("<nil>")
				return
			}
		default:
		}
		if v.CanInterface() {
			switch x := v.Interface().(type) {
			case error:
				n += len(x.Error())
				return
			case fmt.Stringer:
				n += len(x.String())
				return
			}
		}
		switch v.Kind() {
		case reflect.String:
			n += v.Len()
		case reflect.Interface:
			walk(v.Elem())
		case reflect.Pointer:
			n += len("0xc000000000&")
			walk(v.Elem())
		case reflect.Map:
			n += len("map[]")
			iter := v.MapRange()
			for iter.Next() && n <= limit {
				n += len(": ")
				walk(iter.Key())
				walk(iter.Value())
			}
		case reflect.Slice, reflect.Array:
			n += len("[]")
			for i := 0; i < v.Len() && n <= limit; i++ {
				n += len(" ")
				walk(v.Index(i))
			}
		case reflect.Struct:
			n += len("{}")
			for i := 0; i < v.NumField() && n <= limit; i++ {
				n += len(" ")
				walk(v.Field(i))
			}
		default:
			n += maxScalarSize
		}
	}
	walk(reflect.ValueOf(v))
	return n
}

// printfSize returns at least the length of fmt.Sprintf(format, args...), given at least the
// printed size of each argument.
func printfSize(format string, argSizes []int) int {
	n := len(format)
	verbs, indexed := 0, false
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		verbs++
	spec:
		for i++; i < len(format); i++ {
			switch c := format[i]; {
			case c >= '1' && c <= '9':
				j := i
				for j < len(format) && format[j] >= '0' && format[j] <= '9' {
					j++
				}
				// Out of range numbers parse to the maximum int, and fmt rejects anything over maxPrintfWidth.
				w, _ := strconv.Atoi(format[i:j])
				n += min(w, maxPrintfWidth)
				i = j - 1
			case c == '*':
				n += maxPrintfWidth
			case c == '[':
				indexed = true
			case strings.IndexByte("+-# 0.]", c) >= 0:
			default:
				break spec
			}
		}
	}
	argTotal, argMax := 0, 0
	for _, s := range argSizes {
		argTotal += s
		argMax = max(argMax, s)
	}
	if indexed {
		// Explicit argument indexes can print the same argument for every verb.
		argTotal = max(argTotal, verbs*argMax)
	}
	// %x, %X, %q, %U and the # flag can write several bytes for each byte of a string.
	if strings.ContainsAny(format, "xXqU#") {
		argTotal *= 6
	}
	// Covers the type names and markers fmt writes for missing, extra and mismatched arguments.
	return n + argTotal + verbs*16 + len(argSizes)*maxScalarSize
}

// boundedTime is what toTime returns. Format can return a string several times longer than its
// layout, so it is charged to the budget like template functions, and methods that return a time
// return a boundedTime so that the result cannot escape the budget.
type boundedTime struct {
	time.Time
	b *budget
}

// maxTimeFormatGrowth is more than the bytes time.Format writes for any byte of its layout.
const maxTimeFormatGrowth = 4

func (t boundedTime) wrap(u time.Time) boundedTime {
	return boundedTime{Time: u, b: t.b}
}

func (t boundedTime) Format(layout string) (string, error) {
	if err := t.b.fits(maxTimeFormatGrowth*len(layout) + maxScalarSize); err != nil {
		return "", err
	}
	return t.b.str(t.Time.Format(layout))
}

func (t boundedTime) AppendFormat(b []byte, layout string) ([]byte, error) {
	if err := t.b.fits(len(b) + maxTimeFormatGrowth*len(layout) + maxScalarSize); err != nil {
		return nil, err
	}
	res := t.Time.AppendFormat(b, layout)
	if err := t.b.reserve(len(res)); err != nil {
		return nil, err
	}
	return res, nil
}

func (t boundedTime) Add(d time.Duration) boundedTime { return t.wrap(t.Time.Add(d)) }
func (t boundedTime) AddDate(years, months, days int) boundedTime {
	return t.wrap(t.Time.AddDate(years, months, days))
}
func (t boundedTime) In(loc *time.Location) boundedTime    { return t.wrap(t.Time.In(loc)) }
func (t boundedTime) Local() boundedTime                   { return t.wrap(t.Time.Local()) }
func (t boundedTime) UTC() boundedTime                     { return t.wrap(t.Time.UTC()) }
func (t boundedTime) Round(d time.Duration) boundedTime    { return t.wrap(t.Time.Round(d)) }
func (t boundedTime) Truncate(d time.Duration) boundedTime { return t.wrap(t.Time.Truncate(d)) }
func (t boundedTime) Sub(u boundedTime) time.Duration      { return t.Time.Sub(u.Time) }
func (t boundedTime) Before(u boundedTime) bool            { return t.Time.Before(u.Time) }
func (t boundedTime) After(u boundedTime) bool             { return t.Time.After(u.Time) }
func (t boundedTime) Equal(u boundedTime) bool             { return t.Time.Equal(u.Time) }
func (t boundedTime) Compare(u boundedTime) int            { return t.Time.Compare(u.Time) }

// checkRecursion returns an error if a template invokes itself, directly or through other
// templates. Without recursion, how deeply templates can nest is bounded by how many are defined.
func checkRecursion(t *template.Template) error {
	calls := make(map[string][]string)
	for _, tt := range t.Templates() {
		if tt.Tree != nil {
			calls[tt.Name()] = templateCalls(tt.Root, nil)
		}
	}
	const (
		visiting = iota + 1
		visited
	)
	state := make(map[string]int, len(calls))
	var visit func(name string) error
	visit = func(name string) error {
		switch state[name] {
		case visiting:
			return fmt.Errorf("template %q invokes itself recursively", name)
		case visited:
			return nil
		}
		state[name] = visiting
		for _, callee := range calls[name] {
			if err := visit(callee); err != nil {
				return err
			}
		}
		state[name] = visited
		return nil
	}
	for _, tt := range t.Templates() {
		if err := visit(tt.Name()); err != nil {
			return err
		}
	}
	return nil
}

// templateCalls appends the names of the templates invoked under node to calls.
func templateCalls(node parse.Node, calls []string) []string {
	switch n := node.(type) {
	case *parse.ListNode:
		if n == nil {
			return calls
		}
		for _, c := range n.Nodes {
			calls = templateCalls(c, calls)
		}
	case *parse.IfNode:
		calls = templateCalls(n.ElseList, templateCalls(n.List, calls))
	case *parse.RangeNode:
		calls = templateCalls(n.ElseList, templateCalls(n.List, calls))
	case *parse.WithNode:
		calls = templateCalls(n.ElseList, templateCalls(n.List, calls))
	case *parse.TemplateNode:
		calls = append(calls, n.Name)
	}
	return calls
}
