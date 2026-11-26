package conversion

import (
	"regexp"
	"strings"
)

// maxResolvedExportInputBytes caps the bytes that resolving constant inputs may add
// to one dashboard. It matches the 16 MiB dashboard storage limit; a template that
// would expand past it is left as stored rather than materialized in memory.
const maxResolvedExportInputBytes = 16 << 20

// exportPlaceholderRegex is the placeholder syntax the import API resolves.
var exportPlaceholderRegex = regexp.MustCompile(`\$\{.+?\}`)

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
// Substitution is single-pass like the import API: substituted values are not
// scanned again, so one input's value cannot expand another input's placeholder.
func resolveConstantExportInputs(dash map[string]interface{}) {
	inputs, ok := dash["__inputs"].([]interface{})
	if !ok || len(inputs) == 0 {
		return
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
		return
	}

	r := &exportInputResolver{replacements: replacements}
	// Measure the whole document first so an oversized template is left untouched
	// instead of partially resolved.
	for key, child := range dash {
		// the input definitions themselves keep their placeholder-free values
		if key == "__inputs" {
			continue
		}
		if !r.fits(child) {
			return
		}
	}

	for key, child := range dash {
		if key == "__inputs" {
			continue
		}
		dash[key] = r.substitute(child)
	}
}

type exportInputResolver struct {
	replacements map[string]string
	added        int
}

// next returns the bounds and value of the first resolvable placeholder in s at or after from.
func (r *exportInputResolver) next(s string, from int) (int, int, string, bool) {
	for from < len(s) {
		loc := exportPlaceholderRegex.FindStringIndex(s[from:])
		if loc == nil {
			break
		}
		start, end := from+loc[0], from+loc[1]
		if value, ok := r.replacements[s[start:end]]; ok {
			return start, end, value, true
		}
		from = end
	}
	return 0, 0, "", false
}

// fits adds the bytes that resolving node would produce to the running total and
// reports whether the total is still within maxResolvedExportInputBytes.
func (r *exportInputResolver) fits(node interface{}) bool {
	switch v := node.(type) {
	case string:
		for _, end, value, ok := r.next(v, 0); ok; _, end, value, ok = r.next(v, end) {
			r.added += len(value)
			if r.added > maxResolvedExportInputBytes {
				return false
			}
		}
	case map[string]interface{}:
		for _, child := range v {
			if !r.fits(child) {
				return false
			}
		}
	case []interface{}:
		for _, child := range v {
			if !r.fits(child) {
				return false
			}
		}
	}
	return true
}

func (r *exportInputResolver) substitute(node interface{}) interface{} {
	switch v := node.(type) {
	case string:
		var b strings.Builder
		last := 0
		for start, end, value, ok := r.next(v, 0); ok; start, end, value, ok = r.next(v, end) {
			b.WriteString(v[last:start])
			b.WriteString(value)
			last = end
		}
		if last == 0 {
			return v
		}
		b.WriteString(v[last:])
		return b.String()
	case map[string]interface{}:
		for key, child := range v {
			v[key] = r.substitute(child)
		}
		return v
	case []interface{}:
		for i, child := range v {
			v[i] = r.substitute(child)
		}
		return v
	default:
		return node
	}
}
