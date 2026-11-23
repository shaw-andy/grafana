package resources

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// Non-string dimensionFilters values are caller-supplied query JSON. Both
// resource parsers must reject them with an error. A panic, or a success that
// drops the value, leaves the request handler unable to return 400.
func TestDimensionFilterRejectsNonStringValues(t *testing.T) {
	cases := []struct {
		name   string
		filter string
	}{
		{name: "number in array", filter: `{"InstanceId":[1]}`},
		{name: "null in array", filter: `{"InstanceId":[null]}`},
		{name: "object in array", filter: `{"InstanceId":[{}]}`},
		{name: "bool in array", filter: `{"InstanceId":[true]}`},
		{name: "string then number in array", filter: `{"InstanceId":["i-abc",1]}`},
		{name: "number value", filter: `{"InstanceId":1}`},
		{name: "bool value", filter: `{"InstanceId":false}`},
		{name: "object value", filter: `{"InstanceId":{"id":"i-abc"}}`},
	}

	for _, tc := range cases {
		t.Run("dimension-keys/"+tc.name, func(t *testing.T) {
			_, err := GetDimensionKeysRequest(dimensionFilterParams(tc.filter, false))
			require.Error(t, err)
		})
		t.Run("dimension-values/"+tc.name, func(t *testing.T) {
			_, err := GetDimensionValuesRequest(dimensionFilterParams(tc.filter, true))
			require.Error(t, err)
		})
	}
}

func TestDimensionFilterKeepsStringAndNullValues(t *testing.T) {
	cases := []struct {
		name   string
		filter string
		want   int
	}{
		{name: "string", filter: `{"InstanceId":"i-abc"}`, want: 1},
		{name: "string array", filter: `{"InstanceId":["i-abc","i-def"]}`, want: 2},
		{name: "wildcard array", filter: `{"InstanceId":["*"]}`, want: 1},
		{name: "null", filter: `{"InstanceId":null}`, want: 1},
		{name: "empty", filter: ``, want: 0},
	}

	for _, tc := range cases {
		t.Run("dimension-keys/"+tc.name, func(t *testing.T) {
			got, err := GetDimensionKeysRequest(dimensionFilterParams(tc.filter, false))
			require.NoError(t, err)
			require.Len(t, got.DimensionFilter, tc.want)
		})
		t.Run("dimension-values/"+tc.name, func(t *testing.T) {
			got, err := GetDimensionValuesRequest(dimensionFilterParams(tc.filter, true))
			require.NoError(t, err)
			require.Len(t, got.DimensionFilter, tc.want)
		})
	}
}

func dimensionFilterParams(filter string, withKey bool) url.Values {
	params := url.Values{
		"region":    {"us-east-1"},
		"namespace": {"AWS/EC2"},
	}
	if withKey {
		params.Set("dimensionKey", "InstanceId")
	}
	if filter != "" {
		params.Set("dimensionFilters", filter)
	}
	return params
}
