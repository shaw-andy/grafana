package resources

import (
	"encoding/json"
	"fmt"

	"github.com/grafana/grafana-aws-sdk/pkg/cloudWatchConsts"
)

func parseDimensionFilter(dimensionFilter string) ([]*Dimension, error) {
	dimensionFilters := map[string]any{}
	dimensionFilterJson := []byte(dimensionFilter)
	if len(dimensionFilterJson) > 0 {
		err := json.Unmarshal(dimensionFilterJson, &dimensionFilters)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling dimensionFilters: %v", err)
		}
	}

	dimensions := []*Dimension{}
	addDimension := func(key string, value string) {
		d := &Dimension{
			Name: key,
		}
		// if value is not specified or a wildcard is used, simply don't use the value field
		if value != "" && value != "*" {
			d.Value = value
		}
		dimensions = append(dimensions, d)
	}

	for k, v := range dimensionFilters {
		// due to legacy, value can be a string, a string slice or nil
		switch vv := v.(type) {
		case string:
			addDimension(k, vv)
		case []any:
			for _, item := range vv {
				s, ok := item.(string)
				if !ok {
					return nil, fmt.Errorf("invalid value for dimension filter %q: expected string, got %T", k, item)
				}
				addDimension(k, s)
			}
		case nil:
			addDimension(k, "")
		default:
			return nil, fmt.Errorf("invalid value for dimension filter %q: expected string, array of strings or null, got %T", k, v)
		}
	}

	return dimensions, nil
}

func isCustomNamespace(namespace string) bool {
	if _, ok := cloudWatchConsts.NamespaceMetricsMap[namespace]; ok {
		return false
	}
	return true
}
