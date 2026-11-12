package parse

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
)

// nestingStackLimit is the goroutine stack this test allows while parsing.
// Go 1.26 aborts the process in runtime.throw when a goroutine tries to grow
// past its stack limit (1000000000 bytes by default). The payloads below cross
// this smaller limit when the parser recurses once per level, and they are
// shorter than acceptedExpressionLength so a length check that still accepts
// that length cannot satisfy the test.
const nestingStackLimit = 256 << 10

// acceptedExpressionLength is a flat expression that must still parse.
// rejectedExpressionLength is a flat expression that must be rejected.
// The nesting payloads are all shorter than acceptedExpressionLength.
const (
	acceptedExpressionLength = 12000
	rejectedExpressionLength = 100000
)

func TestMathExpressionNestingIsRejected(t *testing.T) {
	if caseName := os.Getenv("MATH_NEST_CHILD"); caseName != "" {
		debug.SetMaxStack(nestingStackLimit)
		_, err := parseNested(caseName, attackDepth(caseName))
		if err == nil {
			t.Fatalf("parsed %s; nesting was not rejected before recursing", caseName)
		}
		fmt.Fprintf(os.Stderr, "parse error returned\n")
		return
	}

	for _, name := range []string{"paren", "minus", "not", "abs"} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestMathExpressionNestingIsRejected$", "-test.count=1")
			cmd.Env = append(os.Environ(), "MATH_NEST_CHILD="+name)
			out, err := cmd.CombinedOutput()
			if err != nil || !bytes.Contains(out, []byte("parse error returned")) {
				t.Fatalf("nested %s aborted the process or was accepted: %v\n%s", name, err, out)
			}
		})
	}
}

func TestMathExpressionLengthIsRejected(t *testing.T) {
	expr := flatSum(rejectedExpressionLength)
	if len(expr) < rejectedExpressionLength {
		t.Fatalf("flat expression is %d bytes, want at least %d", len(expr), rejectedExpressionLength)
	}
	_, err := Parse(expr)
	if err == nil {
		t.Fatal("parsed an expression past the length limit")
	}
}

func TestMathExpressionWithinLimitsParses(t *testing.T) {
	flat := flatSum(acceptedExpressionLength)
	if len(flat) < acceptedExpressionLength {
		t.Fatalf("flat expression is %d bytes, want at least %d", len(flat), acceptedExpressionLength)
	}

	cases := []struct {
		name string
		expr string
		abs  bool
	}{
		{name: "arithmetic", expr: "1 + 2 * 3"},
		{name: "paren", expr: nestedParens(32)},
		{name: "minus", expr: nestedUnary("-", 32)},
		{name: "not", expr: nestedUnary("!", 32)},
		{name: "abs", expr: nestedAbs(8), abs: true},
		{name: "flat", expr: flat},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				tree *Tree
				err  error
			)
			if tc.abs {
				tree, err = Parse(tc.expr, absFunc())
			} else {
				tree, err = Parse(tc.expr)
			}
			if err != nil {
				t.Fatalf("parse %s: %v", tc.expr, err)
			}
			if tree.Root == nil {
				t.Fatal("parse returned no root")
			}
		})
	}
}

func parseNested(kind string, depth int) (*Tree, error) {
	switch kind {
	case "abs":
		return Parse(nestedAbs(depth), absFunc())
	case "paren", "minus", "not":
		return Parse(nestedExpr(kind, depth))
	default:
		return nil, fmt.Errorf("unknown nesting case %q", kind)
	}
}

func attackDepth(kind string) int {
	// Each depth overflows nestingStackLimit. Thresholds measured on this
	// toolchain: parentheses past 300, spaced unary past 2000, abs() past 200.
	switch kind {
	case "paren":
		return 1000
	case "minus", "not":
		return 4000
	case "abs":
		return 800
	default:
		return 0
	}
}

func nestedExpr(kind string, depth int) string {
	switch kind {
	case "paren":
		return nestedParens(depth)
	case "minus":
		// The lexer consumes a run of symbol characters as one token, so the
		// unary operators have to be separated to become nested F calls.
		return nestedUnary("-", depth)
	case "not":
		return nestedUnary("!", depth)
	case "abs":
		return nestedAbs(depth)
	default:
		return ""
	}
}

func nestedParens(depth int) string {
	return strings.Repeat("(", depth) + "1" + strings.Repeat(")", depth)
}

func nestedUnary(op string, depth int) string {
	return strings.Repeat(op+" ", depth) + "1"
}

func nestedAbs(depth int) string {
	return strings.Repeat("abs(", depth) + "1" + strings.Repeat(")", depth)
}

func flatSum(minBytes int) string {
	term := "1+"
	n := minBytes / len(term)
	if n < 1 {
		n = 1
	}
	return strings.Repeat(term, n) + "1"
}

func absFunc() map[string]Func {
	return map[string]Func{
		"abs": {Args: []ReturnType{TypeScalar}, Return: TypeScalar},
	}
}
