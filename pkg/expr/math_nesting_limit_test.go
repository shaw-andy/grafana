package expr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/grafana/pkg/expr/mathexp"
	"github.com/grafana/grafana/pkg/expr/metrics"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
)

// Same bound as the parser tests: low enough that one recursion per nesting
// level aborts the process, high enough for pipeline setup to run.
const pipelineStackLimit = 256 << 10

func TestTransformDataRejectsDeepMathNesting(t *testing.T) {
	if caseName := os.Getenv("MATH_PIPELINE_CHILD"); caseName != "" {
		debug.SetMaxStack(pipelineStackLimit)
		exprText := pipelineAttackExpr(caseName)
		err := transformMath(exprText)
		if err == nil {
			t.Fatalf("pipeline parsed %s; nesting was not rejected", caseName)
		}
		if strings.Contains(err.Error(), "expressions are disabled") {
			t.Fatalf("expressions were disabled, parser was not reached: %v", err)
		}
		fmt.Fprintf(os.Stderr, "parse error returned\n")
		return
	}

	for _, name := range []string{"paren", "minus", "not", "abs"} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestTransformDataRejectsDeepMathNesting$", "-test.count=1")
			cmd.Env = append(os.Environ(), "MATH_PIPELINE_CHILD="+name)
			out, err := cmd.CombinedOutput()
			if err != nil || !bytes.Contains(out, []byte("parse error returned")) {
				t.Fatalf("pipeline %s aborted the process or was accepted: %v\n%s", name, err, out)
			}
		})
	}
}

func TestTransformDataAllowsShallowMathExpression(t *testing.T) {
	if err := transformMath("1+2*3"); err != nil {
		t.Fatal(err)
	}
	if _, err := mathexp.New(nestedAbs(8)); err != nil {
		t.Fatal(err)
	}
}

func transformMath(expression string) error {
	cfg := setting.NewCfg()
	cfg.ExpressionsEnabled = true
	// The binary-operation memory limit is the production default. It applies
	// while evaluating, after the expression has already been parsed.
	cfg.MathExpressionMemoryLimit = 1 << 30
	ds, err := DataSourceModelFromNodeType(TypeCMDNode)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{
		"refId":      "A",
		"datasource": map[string]any{"uid": DatasourceUID, "type": DatasourceType},
		"type":       "math",
		"expression": expression,
	})
	if err != nil {
		return err
	}
	svc := &Service{
		cfg:         cfg,
		features:    featuremgmt.WithFeatures(),
		tracer:      tracing.NewNoopTracerService(),
		metrics:     metrics.NewSSEMetrics(prometheus.NewRegistry()),
		dataService: &mockEndpoint{Responses: map[string]backend.DataResponse{}},
	}
	_, err = svc.TransformData(context.Background(), time.Unix(0, 0), &Request{
		Queries: []Query{{
			RefID:      "A",
			DataSource: ds,
			JSON:       body,
			TimeRange:  AbsoluteTimeRange{From: time.Unix(0, 0), To: time.Unix(60, 0)},
		}},
	})
	return err
}

func pipelineAttackExpr(kind string) string {
	switch kind {
	case "paren":
		return strings.Repeat("(", 1000) + "1" + strings.Repeat(")", 1000)
	case "minus":
		return strings.Repeat("- ", 4000) + "1"
	case "not":
		return strings.Repeat("! ", 4000) + "1"
	case "abs":
		return nestedAbs(800)
	default:
		return "1"
	}
}

func nestedAbs(depth int) string {
	return strings.Repeat("abs(", depth) + "1" + strings.Repeat(")", depth)
}
