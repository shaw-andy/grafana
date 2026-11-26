package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/expr"
	"github.com/grafana/grafana/pkg/services/dashboardimport"
)

// MaxInterpolatedBytes caps the bytes that input substitution may add to a dashboard.
// It matches the 16 MiB dashboard storage limit (mediumtext on MySQL); a template
// that expands past it could not be saved and would only consume server memory.
const MaxInterpolatedBytes = 16 << 20

var varRegex = regexp.MustCompile(`(\$\{.+?\})`)
var ErrDashboardInputMissing = errors.New("missing dashboard input variable")
var ErrDashboardTooLarge = fmt.Errorf("interpolated dashboard exceeds the maximum size of %d bytes", MaxInterpolatedBytes)

type inputKey struct {
	varType string
	name    string
}

type DashTemplateEvaluator struct {
	template   *simplejson.Json
	inputs     []dashboardimport.ImportDashboardInput
	inputIndex map[inputKey]int
	variables  map[string]string
	result     *simplejson.Json
	expanded   int
}

func NewDashTemplateEvaluator(template *simplejson.Json, inputs []dashboardimport.ImportDashboardInput) *DashTemplateEvaluator {
	return &DashTemplateEvaluator{
		template: template,
		inputs:   inputs,
	}
}

func (e *DashTemplateEvaluator) indexInputs() {
	e.inputIndex = make(map[inputKey]int, len(e.inputs))
	for i, input := range e.inputs {
		key := inputKey{varType: input.Type, name: input.Name}
		if _, exists := e.inputIndex[key]; !exists {
			e.inputIndex[key] = i
		}
	}
}

// findInput returns the first input, in request order, whose type matches and
// whose name is either varName or the "*" wildcard.
func (e *DashTemplateEvaluator) findInput(varName string, varType string) *dashboardimport.ImportDashboardInput {
	found := -1
	if i, ok := e.inputIndex[inputKey{varType: varType, name: varName}]; ok {
		found = i
	}
	if i, ok := e.inputIndex[inputKey{varType: varType, name: "*"}]; ok && (found == -1 || i < found) {
		found = i
	}
	if found == -1 {
		return nil
	}

	input := e.inputs[found]
	return &input
}

func (e *DashTemplateEvaluator) Eval() (*simplejson.Json, error) {
	e.result = simplejson.New()
	e.variables = make(map[string]string)
	e.expanded = 0
	e.indexInputs()

	// check that we have all inputs we need
	for _, inputDef := range e.template.Get("__inputs").MustArray() {
		inputDefJson := simplejson.NewFromAny(inputDef)
		inputName := inputDefJson.Get("name").MustString()
		inputType := inputDefJson.Get("type").MustString()
		input := e.findInput(inputName, inputType)

		// force expressions value to `__expr__`
		if inputDefJson.Get("pluginId").MustString() == expr.DatasourceType {
			input = &dashboardimport.ImportDashboardInput{
				Value: expr.DatasourceType,
			}
		}

		if input == nil {
			return nil, fmt.Errorf("dashboard import failed: %w %s", ErrDashboardInputMissing, inputName)
		}

		e.variables["${"+inputName+"}"] = input.Value
	}

	result, err := e.evalObject(e.template)
	if err != nil {
		return nil, err
	}
	return simplejson.NewFromAny(result), nil
}

// evalString substitutes known placeholders in v. The bytes added are counted
// across the whole evaluation so the budget holds no matter how the placeholders
// are spread over fields, and the check runs before each value is written.
func (e *DashTemplateEvaluator) evalString(v string) (string, error) {
	var b strings.Builder
	last := 0
	for last < len(v) {
		loc := varRegex.FindStringIndex(v[last:])
		if loc == nil {
			break
		}
		start, end := last+loc[0], last+loc[1]
		if replacement, exists := e.variables[v[start:end]]; exists {
			e.expanded += len(replacement)
			if e.expanded > MaxInterpolatedBytes {
				return "", fmt.Errorf("dashboard import failed: %w", ErrDashboardTooLarge)
			}
			b.WriteString(v[last:start])
			b.WriteString(replacement)
		} else {
			b.WriteString(v[last:end])
		}
		last = end
	}

	if last == 0 {
		return v, nil
	}
	b.WriteString(v[last:])
	return b.String(), nil
}

func (e *DashTemplateEvaluator) evalValue(source *simplejson.Json) (any, error) {
	sourceValue := source.Interface()

	switch v := sourceValue.(type) {
	case string:
		return e.evalString(v)
	case bool:
		return v, nil
	case json.Number:
		return v, nil
	case map[string]any:
		return e.evalObject(source)
	case []any:
		array := make([]any, 0)
		for _, item := range v {
			value, err := e.evalValue(simplejson.NewFromAny(item))
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		return array, nil
	}

	return nil, nil
}

func (e *DashTemplateEvaluator) evalObject(source *simplejson.Json) (any, error) {
	result := make(map[string]any)

	for key, value := range source.MustMap() {
		if key == "__inputs" {
			continue
		}
		evaluated, err := e.evalValue(simplejson.NewFromAny(value))
		if err != nil {
			return nil, err
		}
		result[key] = evaluated
	}

	return result, nil
}
