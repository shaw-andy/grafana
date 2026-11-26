package utils

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/services/dashboardimport"
)

// maxInterpolatedBytes is the dashboard storage budget (mediumtext, 16 MiB).
// Interpolation has to stay within it. See pkg/services/apiserver/service.go MaxRequestBodyBytes.
const maxInterpolatedBytes = 16 << 20

// maxEvalAllocBytes is headroom for a builder that stops at maxInterpolatedBytes.
// On go1.26, writing 16 MiB with strings.Builder reports about 95 MiB of TotalAlloc
// because of buffer growth. Materializing a multi-ten-mebibyte expansion is far above this.
const maxEvalAllocBytes = 160 << 20

func TestEvalAllowsExpansionWithinStorageBudget(t *testing.T) {
	const valueSize = 64 << 10
	// 255 * 64 KiB is 64 KiB under the 16 MiB budget.
	const repeats = 255
	value := strings.Repeat("v", valueSize)
	template := constantTemplate(map[string]any{
		"title": strings.Repeat("${a}", repeats),
	})

	res, err := NewDashTemplateEvaluator(template, constantInputs(value)).Eval()
	require.NoError(t, err)
	got := res.Get("title").MustString()
	require.Len(t, got, repeats*valueSize)
	require.Equal(t, value, got[:valueSize])
}

func TestEvalRejectsSingleStringExpansionPastStorageBudget(t *testing.T) {
	const valueSize = 64 << 10
	const repeats = 1024 // 64 MiB once substituted
	value := strings.Repeat("v", valueSize)
	template := constantTemplate(map[string]any{
		"title": strings.Repeat("${a}", repeats),
	})

	res, alloc := evalAlloc(t, template, constantInputs(value))
	require.Nil(t, res)
	require.Less(t, alloc, uint64(maxEvalAllocBytes), "evaluation allocated %d bytes; the %d-byte expansion must be refused before it is built", alloc, repeats*valueSize)
}

func TestEvalRejectsCumulativeExpansionPastStorageBudget(t *testing.T) {
	const valueSize = 64 << 10
	const repeats = 128 // 8 MiB per field, under the per-string reading of the budget
	const fields = 8    // 64 MiB across the document
	value := strings.Repeat("v", valueSize)
	token := strings.Repeat("${a}", repeats)
	props := map[string]any{}
	for i := 0; i < fields; i++ {
		props[strings.Repeat("k", i+1)] = token
	}
	template := constantTemplate(props)

	res, alloc := evalAlloc(t, template, constantInputs(value))
	require.Nil(t, res)
	require.Less(t, alloc, uint64(maxEvalAllocBytes), "evaluation allocated %d bytes across %d fields", alloc, fields)
}

func TestEvalRejectsNestedArrayExpansionPastStorageBudget(t *testing.T) {
	const valueSize = 64 << 10
	const repeats = 128 // 8 MiB per element
	const elements = 8  // 64 MiB across the array
	value := strings.Repeat("v", valueSize)
	token := strings.Repeat("${a}", repeats)
	items := make([]any, elements)
	for i := range items {
		items[i] = token
	}
	template := constantTemplate(map[string]any{
		"panels": []any{
			map[string]any{"descriptions": items},
		},
	})

	res, alloc := evalAlloc(t, template, constantInputs(value))
	require.Nil(t, res)
	require.Less(t, alloc, uint64(maxEvalAllocBytes), "evaluation allocated %d bytes for nested strings", alloc)
}

func evalAlloc(t *testing.T, template *simplejson.Json, inputs []dashboardimport.ImportDashboardInput) (*simplejson.Json, uint64) {
	t.Helper()
	evaluator := NewDashTemplateEvaluator(template, inputs)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	res, err := evaluator.Eval()
	runtime.ReadMemStats(&after)
	alloc := after.TotalAlloc - before.TotalAlloc

	if err == nil {
		encoded, encErr := res.Encode()
		t.Fatalf("expected expansion past %d bytes to fail; encoded %d bytes (encode err %v) and allocated %d", maxInterpolatedBytes, len(encoded), encErr, alloc)
	}
	return res, alloc
}

func constantTemplate(props map[string]any) *simplejson.Json {
	template := simplejson.New()
	template.Set("__inputs", []any{
		map[string]any{"name": "a", "type": "constant"},
	})
	for key, value := range props {
		template.Set(key, value)
	}
	return template
}

func constantInputs(value string) []dashboardimport.ImportDashboardInput {
	return []dashboardimport.ImportDashboardInput{{
		Name:  "a",
		Type:  "constant",
		Value: value,
	}}
}
