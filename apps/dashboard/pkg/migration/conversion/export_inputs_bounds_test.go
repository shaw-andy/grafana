package conversion

import (
	"encoding/json"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	dashv0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	dashv1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	dashv1beta1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1beta1"
	dashv2 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2"
	dashv2alpha1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2alpha1"
	dashv2beta1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2beta1"
	"github.com/grafana/grafana/apps/dashboard/pkg/migration"
	"github.com/grafana/grafana/apps/dashboard/pkg/migration/schemaversion"
	migrationtestutil "github.com/grafana/grafana/apps/dashboard/pkg/migration/testutil"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
)

// maxExportExpansionBytes is the largest total constant-placeholder expansion a
// v0 dashboard conversion may materialize. It is the same 16 MiB ceiling the
// apiserver applies to a request body (MaxRequestBodyBytes). Each stored string
// below is under that ceiling on its own; together they are not. A fix that
// only caps one string, or that replaces first and checks afterwards, still fails.
const maxExportExpansionBytes = 16 << 20

// exportExpansionAllocBudget is how much heap the conversion may allocate while
// refusing. It is far below one expanded field, so a check that still calls
// strings.ReplaceAll fails even when the function then returns an error.
const exportExpansionAllocBudget = 4 << 20

func TestConstantExportPlaceholderExpansionIsBounded(t *testing.T) {
	dsProvider := migrationtestutil.NewDataSourceProvider(migrationtestutil.StandardTestConfig)
	leProvider := migrationtestutil.NewTestLibraryElementProvider()
	migration.Initialize(dsProvider, leProvider, migration.DefaultCacheTTL)

	t.Run("v0 to v1", func(t *testing.T) {
		in := repeatedConstantPlaceholderDashboard()
		out := &dashv1.Dashboard{}
		requireBoundedExportConversion(t, in, func() error {
			return Convert_V0_to_V1(in, out, nil)
		}, func() int { return sumStringBytes(out.Spec.Object) })
	})

	t.Run("v0 to v2alpha1", func(t *testing.T) {
		in := repeatedConstantPlaceholderDashboard()
		out := &dashv2alpha1.Dashboard{}
		requireBoundedExportConversion(t, in, func() error {
			return Convert_V0_to_V2alpha1(in, out, nil, dsProvider, leProvider)
		}, func() int { return sumStringBytes(out) })
	})

	t.Run("v0 to v2beta1", func(t *testing.T) {
		in := repeatedConstantPlaceholderDashboard()
		out := &dashv2beta1.Dashboard{}
		requireBoundedExportConversion(t, in, func() error {
			return Convert_V0_to_V2beta1(in, out, nil, dsProvider, leProvider)
		}, func() int { return sumStringBytes(out) })
	})

	t.Run("v0 to v2", func(t *testing.T) {
		in := repeatedConstantPlaceholderDashboard()
		out := &dashv2.Dashboard{}
		requireBoundedExportConversion(t, in, func() error {
			return Convert_V0_to_V2(in, out, nil, dsProvider, leProvider)
		}, func() int { return sumStringBytes(out) })
	})

	// v1beta1 is a type alias of v1, so the scheme has one conversion for both.
	// Decoding stored v0 JSON into each requested version is the read path the
	// apiserver storage uses (codec.Decode into the version's object).
	for _, target := range []struct {
		name    string
		version schema.GroupVersion
		into    func() k8sruntime.Object
		sum     func(k8sruntime.Object) int
		failed  func(k8sruntime.Object) bool
	}{
		{
			name:    "stored v0 decoded as v1",
			version: schema.GroupVersion{Group: dashv1.GROUP, Version: dashv1.VERSION},
			into:    func() k8sruntime.Object { return &dashv1.Dashboard{} },
			sum: func(obj k8sruntime.Object) int {
				return sumStringBytes(obj.(*dashv1.Dashboard).Spec.Object)
			},
			failed: func(obj k8sruntime.Object) bool {
				status := obj.(*dashv1.Dashboard).Status.Conversion
				return status != nil && status.Failed
			},
		},
		{
			name:    "stored v0 decoded as v1beta1",
			version: schema.GroupVersion{Group: dashv1beta1.GROUP, Version: dashv1beta1.VERSION},
			into:    func() k8sruntime.Object { return &dashv1beta1.Dashboard{} },
			sum: func(obj k8sruntime.Object) int {
				return sumStringBytes(obj.(*dashv1beta1.Dashboard).Spec.Object)
			},
			failed: func(obj k8sruntime.Object) bool {
				status := obj.(*dashv1beta1.Dashboard).Status.Conversion
				return status != nil && status.Failed
			},
		},
		{
			name:    "stored v0 decoded as v2alpha1",
			version: schema.GroupVersion{Group: dashv2alpha1.GROUP, Version: dashv2alpha1.VERSION},
			into:    func() k8sruntime.Object { return &dashv2alpha1.Dashboard{} },
			sum:     func(obj k8sruntime.Object) int { return sumStringBytes(obj) },
			failed: func(obj k8sruntime.Object) bool {
				status := obj.(*dashv2alpha1.Dashboard).Status.Conversion
				return status != nil && status.Failed
			},
		},
		{
			name:    "stored v0 decoded as v2beta1",
			version: schema.GroupVersion{Group: dashv2beta1.GROUP, Version: dashv2beta1.VERSION},
			into:    func() k8sruntime.Object { return &dashv2beta1.Dashboard{} },
			sum:     func(obj k8sruntime.Object) int { return sumStringBytes(obj) },
			failed: func(obj k8sruntime.Object) bool {
				status := obj.(*dashv2beta1.Dashboard).Status.Conversion
				return status != nil && status.Failed
			},
		},
		{
			name:    "stored v0 decoded as v2",
			version: schema.GroupVersion{Group: dashv2.GROUP, Version: dashv2.VERSION},
			into:    func() k8sruntime.Object { return &dashv2.Dashboard{} },
			sum:     func(obj k8sruntime.Object) int { return sumStringBytes(obj) },
			failed: func(obj k8sruntime.Object) bool {
				status := obj.(*dashv2.Dashboard).Status.Conversion
				return status != nil && status.Failed
			},
		},
	} {
		t.Run(target.name, func(t *testing.T) {
			scheme := newTestScheme(t)
			require.NoError(t, dashv0.AddToScheme(scheme))
			require.NoError(t, dashv1.AddToScheme(scheme))
			require.NoError(t, dashv1beta1.AddToScheme(scheme))
			require.NoError(t, dashv2alpha1.AddToScheme(scheme))
			require.NoError(t, dashv2beta1.AddToScheme(scheme))
			require.NoError(t, dashv2.AddToScheme(scheme))

			stored := repeatedConstantPlaceholderDashboard()
			raw, err := json.Marshal(stored)
			require.NoError(t, err)
			require.Less(t, len(raw), maxExportExpansionBytes, "payload must fit in a request the apiserver accepts")

			codec := serializer.NewCodecFactory(scheme).LegacyCodec(
				schema.GroupVersion{Group: dashv0.GROUP, Version: dashv0.VERSION},
				target.version,
			)
			into := target.into()
			var decodeErr error
			allocated := heapAllocated(func() {
				_, _, decodeErr = codec.Decode(raw, nil, into)
			})
			require.NoError(t, decodeErr)
			require.Less(t, target.sum(into), maxExportExpansionBytes, "decoded dashboard expanded constant placeholders")
			require.True(t, target.failed(into), "conversion must report failure instead of serving the expanded dashboard")
			require.Less(t, allocated, uint64(exportExpansionAllocBudget), "conversion allocated the expanded value before refusing")
		})
	}
}

// requireBoundedExportConversion fails unless converting in refuses before the
// placeholder expansion is allocated. The registered scheme wrapper swallows
// conversion errors, so callers that go through scheme.Convert assert the
// recorded failure and the output size separately.
func requireBoundedExportConversion(t *testing.T, in *dashv0.Dashboard, convert func() error, resultBytes func() int) {
	t.Helper()
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	require.Less(t, len(raw), maxExportExpansionBytes, "payload must fit in a request the apiserver accepts")

	var convertErr error
	allocated := heapAllocated(func() {
		convertErr = convert()
	})
	require.Error(t, convertErr, "conversion accepted an unbounded constant placeholder expansion")
	require.Less(t, resultBytes(), maxExportExpansionBytes, "conversion wrote the expanded strings before returning an error")
	require.Less(t, sumStringBytes(in.Spec.Object), maxExportExpansionBytes, "conversion expanded the stored spec in place")
	require.Less(t, allocated, uint64(exportExpansionAllocBudget), "conversion allocated the expanded value before refusing")
}

// repeatedConstantPlaceholderDashboard is a v0 spec a caller can store as-is.
// One constant value is repeated in two separate strings. Each expanded string
// stays under maxExportExpansionBytes; the sum does not. The JSON stays far
// under that ceiling.
func repeatedConstantPlaceholderDashboard() *dashv0.Dashboard {
	const valueLen = 200_000
	const repeats = 50
	value := strings.Repeat("V", valueLen)
	field := strings.Repeat("${A}", repeats)
	return &dashv0.Dashboard{
		TypeMeta: metav1.TypeMeta{APIVersion: dashv0.APIVERSION, Kind: "Dashboard"},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "export-expansion",
		},
		Spec: common.Unstructured{Object: map[string]interface{}{
			"title":         "export expansion",
			"schemaVersion": schemaversion.LATEST_VERSION,
			"description":   field,
			"panels": []interface{}{
				map[string]interface{}{
					"id":          float64(1),
					"type":        "text",
					"description": field,
				},
			},
			"__inputs": []interface{}{
				map[string]interface{}{
					"name":  "A",
					"type":  "constant",
					"value": value,
				},
			},
		}},
	}
}

func heapAllocated(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func sumStringBytes(v interface{}) int {
	return sumStringValue(reflect.ValueOf(v))
}

func sumStringValue(v reflect.Value) int {
	if !v.IsValid() {
		return 0
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return 0
		}
		return sumStringValue(v.Elem())
	case reflect.String:
		return v.Len()
	case reflect.Struct:
		total := 0
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			if field.CanInterface() {
				total += sumStringValue(field)
			}
		}
		return total
	case reflect.Map:
		total := 0
		iter := v.MapRange()
		for iter.Next() {
			total += sumStringValue(iter.Value())
		}
		return total
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return 0
		}
		total := 0
		for i := 0; i < v.Len(); i++ {
			total += sumStringValue(v.Index(i))
		}
		return total
	default:
		return 0
	}
}
