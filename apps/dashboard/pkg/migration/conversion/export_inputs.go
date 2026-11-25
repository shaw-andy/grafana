package conversion

import (
	"fmt"
	"strings"
)

// maxExportInputExpansionBytes caps the total bytes constant __inputs values may
// add to a dashboard when their placeholders are resolved. It matches the
// apiserver request body limit: a stored spec is at most that size, so a
// legitimate export never needs more, while unbounded expansion grows as
// occurrences * value length and can exhaust memory.
const maxExportInputExpansionBytes = 16 << 20

// resolveConstantExportInputs substitutes ${VAR_*} placeholders produced by the
// classic "Export for sharing externally" flow with the constant values embedded
// in the dashboard's top-level __inputs section.
//
// Those exports are import templates: the exporter moves each constant variable's
// value into __inputs and replaces the variable's query/current with a
// "${VAR_<NAME>}" placeholder, expecting the import API to resolve it. A template
// written through any other path (Terraform's grafana_dashboard resource,
// provisioning, a direct POST) is stored verbatim as v0alpha1 with __inputs intact.
// The placeholder must therefore be resolved here, when the raw v0 spec is
// canonicalized to v1, before the schema migration drops __inputs and the constant
// value is no longer recoverable.
//
// Only constant inputs are resolved: they map to a plain value substitution.
// DS_* inputs carry no value to substitute, and __elements (library panels) would
// need a library-element resource recreated (a side effect); both are out of scope.
//
// The whole expansion is measured before anything is substituted, and the
// dashboard is left untouched when it would exceed maxExportInputExpansionBytes.
func resolveConstantExportInputs(dash map[string]interface{}) error {
	inputs, ok := dash["__inputs"].([]interface{})
	if !ok || len(inputs) == 0 {
		return nil
	}

	replacements := map[string]string{}
	for _, raw := range inputs {
		input, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := input["name"].(string)
		value, hasValue := input["value"].(string)
		if input["type"] == "constant" && name != "" && hasValue {
			replacements["${"+name+"}"] = value
		}
	}
	if len(replacements) == 0 {
		return nil
	}

	remaining := maxExportInputExpansionBytes
	for key, child := range dash {
		// the input definitions themselves keep their placeholder-free values
		if key == "__inputs" {
			continue
		}
		if !measureExportPlaceholders(child, replacements, &remaining) {
			return fmt.Errorf("constant __inputs expansion exceeds %d bytes", maxExportInputExpansionBytes)
		}
	}

	for key, child := range dash {
		if key == "__inputs" {
			continue
		}
		dash[key] = substituteExportPlaceholders(child, replacements)
	}
	return nil
}

// measureExportPlaceholders subtracts from remaining the bytes substitution would
// insert into node, and reports false as soon as remaining goes negative.
func measureExportPlaceholders(node interface{}, replacements map[string]string, remaining *int) bool {
	switch v := node.(type) {
	case string:
		forEachExportPlaceholder(v, replacements, func(_, _ int, value string) bool {
			*remaining -= len(value)
			return *remaining >= 0
		})
		return *remaining >= 0
	case map[string]interface{}:
		for _, child := range v {
			if !measureExportPlaceholders(child, replacements, remaining) {
				return false
			}
		}
	case []interface{}:
		for _, child := range v {
			if !measureExportPlaceholders(child, replacements, remaining) {
				return false
			}
		}
	}
	return true
}

func substituteExportPlaceholders(node interface{}, replacements map[string]string) interface{} {
	switch v := node.(type) {
	case string:
		return expandExportPlaceholders(v, replacements)
	case map[string]interface{}:
		for key, child := range v {
			v[key] = substituteExportPlaceholders(child, replacements)
		}
		return v
	case []interface{}:
		for i, child := range v {
			v[i] = substituteExportPlaceholders(child, replacements)
		}
		return v
	default:
		return node
	}
}

// expandExportPlaceholders replaces placeholders in a single left-to-right pass.
// Inserted values are never rescanned, so a value containing another placeholder
// cannot compound the expansion beyond what measureExportPlaceholders counted.
func expandExportPlaceholders(s string, replacements map[string]string) string {
	var b strings.Builder
	last := 0
	forEachExportPlaceholder(s, replacements, func(start, end int, value string) bool {
		b.WriteString(s[last:start])
		b.WriteString(value)
		last = end
		return true
	})
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// forEachExportPlaceholder calls fn with the bounds and value of every
// non-overlapping "${name}" in s that has a replacement, stopping when fn returns
// false. It runs in linear time: the closing brace for an opening "${" is only
// searched again once the scan has moved past the previously found one.
func forEachExportPlaceholder(s string, replacements map[string]string, fn func(start, end int, value string) bool) {
	closing := -1
	for i := 0; i < len(s); {
		open := strings.Index(s[i:], "${")
		if open < 0 {
			return
		}
		open += i
		if closing < open+2 {
			c := strings.IndexByte(s[open+2:], '}')
			if c < 0 {
				return
			}
			closing = open + 2 + c
		}
		if value, ok := replacements[s[open:closing+1]]; ok {
			if !fn(open, closing+1, value) {
				return
			}
			i = closing + 1
			continue
		}
		i = open + 2
	}
}
