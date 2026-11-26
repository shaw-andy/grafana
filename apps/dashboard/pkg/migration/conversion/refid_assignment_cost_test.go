package conversion

import (
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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

// apiBodyLimit is the apiserver request body cap from
// pkg/services/apiserver/service.go (MaxRequestBodyBytes). A dashboard at this
// size is accepted by the save APIs.
const apiBodyLimit = 16 * 1024 * 1024

// smallTargets and largeTargets differ by growthFactor. Assigning a refId by
// rescanning from "A" on every target is quadratic, so the large conversion
// takes about growthFactor^2 times as long as the small one. A cursor that
// resumes from the last assigned name is linear, so it takes about
// growthFactor times as long. maxLinearRatio sits between those two.
const (
	smallTargets   = 500
	largeTargets   = 2000
	growthFactor   = 4
	maxLinearRatio = float64(growthFactor) * 2
	samples        = 3
)

func TestV2ReadOfStoredDashboardAssignsMissingRefIDsLinearly(t *testing.T) {
	codec := newDashboardStorageCodec(t)

	cases := []struct {
		name       string
		apiVersion string
		into       func() runtime.Object
	}{
		{name: "v0alpha1 stored dashboard read as v2alpha1", apiVersion: dashv0.APIVERSION, into: func() runtime.Object { return &dashv2alpha1.Dashboard{} }},
		{name: "v0alpha1 stored dashboard read as v2beta1", apiVersion: dashv0.APIVERSION, into: func() runtime.Object { return &dashv2beta1.Dashboard{} }},
		{name: "v0alpha1 stored dashboard read as v2", apiVersion: dashv0.APIVERSION, into: func() runtime.Object { return &dashv2.Dashboard{} }},
		{name: "v1 stored dashboard read as v2alpha1", apiVersion: dashv1.APIVERSION, into: func() runtime.Object { return &dashv2alpha1.Dashboard{} }},
		{name: "v1 stored dashboard read as v2beta1", apiVersion: dashv1.APIVERSION, into: func() runtime.Object { return &dashv2beta1.Dashboard{} }},
		{name: "v1 stored dashboard read as v2", apiVersion: dashv1.APIVERSION, into: func() runtime.Object { return &dashv2.Dashboard{} }},
		{name: "v1beta1 stored dashboard read as v2beta1", apiVersion: dashv1beta1.APIVERSION, into: func() runtime.Object { return &dashv2beta1.Dashboard{} }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			smallRaw := storedDashboard(t, tc.apiVersion, smallTargets, false, false)
			largeRaw := storedDashboard(t, tc.apiVersion, largeTargets, false, false)
			require.Less(t, len(largeRaw), apiBodyLimit, "the timed dashboard must fit in one save request")

			small := medianDecode(t, codec, smallRaw, tc.into)
			large := medianDecode(t, codec, largeRaw, tc.into)
			requireLinear(t, small, large)

			out := tc.into()
			_, _, err := codec.Decode(largeRaw, nil, out)
			require.NoError(t, err)
			requireSequentialRefIDs(t, collectQueryRefIDs(t, out), largeTargets)
		})
	}
}

func TestCollapsedRowTargetsAssignRefIDsLinearly(t *testing.T) {
	codec := newDashboardStorageCodec(t)
	into := func() runtime.Object { return &dashv2beta1.Dashboard{} }

	smallRaw := storedDashboard(t, dashv0.APIVERSION, smallTargets, false, true)
	largeRaw := storedDashboard(t, dashv0.APIVERSION, largeTargets, false, true)
	require.Less(t, len(largeRaw), apiBodyLimit)

	small := medianDecode(t, codec, smallRaw, into)
	large := medianDecode(t, codec, largeRaw, into)
	requireLinear(t, small, large)

	out := into()
	_, _, err := codec.Decode(largeRaw, nil, out)
	require.NoError(t, err)
	requireSequentialRefIDs(t, collectQueryRefIDs(t, out), largeTargets)
}

func TestTargetsLeftUnlabeledBySaveMigrationStillConvertLinearly(t *testing.T) {
	// v1 admission runs migration.Migrate before the object is stored. That
	// helper only fills the single letters A through Z, so every target after
	// those twenty-six is still unlabeled when a v2 read converts the object.
	migration.Initialize(
		migrationtestutil.NewDataSourceProvider(migrationtestutil.StandardTestConfig),
		migrationtestutil.NewTestLibraryElementProvider(),
		migration.DefaultCacheTTL,
	)

	spec := panelSpec(40, false, false)
	require.NoError(t, migration.Migrate(t.Context(), spec, schemaversion.LATEST_VERSION))
	missing := unlabeledTargetCount(t, spec)
	require.Positive(t, missing, "save migration left every target with a refId, so conversion has nothing to assign")

	codec := newDashboardStorageCodec(t)
	into := func() runtime.Object { return &dashv2beta1.Dashboard{} }
	// The letters A-Z are already taken. Conversion must continue at AA.
	smallRaw := storedDashboard(t, dashv1.APIVERSION, smallTargets, true, false)
	largeRaw := storedDashboard(t, dashv1.APIVERSION, largeTargets, true, false)
	require.Less(t, len(largeRaw), apiBodyLimit)

	small := medianDecode(t, codec, smallRaw, into)
	large := medianDecode(t, codec, largeRaw, into)
	requireLinear(t, small, large)

	out := into()
	_, _, err := codec.Decode(largeRaw, nil, out)
	require.NoError(t, err)
	requireSequentialRefIDs(t, collectQueryRefIDs(t, out), largeTargets)
}

func TestV1StrictAdmissionAcceptsUnlabeledTargets(t *testing.T) {
	// Default field validation is strict. The v1 schema must accept the
	// dashboard the timing tests convert, or the direct v1 save API would
	// reject it before it could be stored.
	dash := &dashv1.Dashboard{
		TypeMeta: metav1.TypeMeta{APIVersion: dashv1.APIVERSION, Kind: "Dashboard"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unlabeled",
			Namespace: "default",
		},
		Spec: common.Unstructured{Object: panelSpec(largeTargets, false, false)},
	}
	errs, schemaErrs := dashv1.ValidateDashboardSpec(dash, false)
	require.Empty(t, schemaErrs)
	require.Empty(t, errs)

	raw, err := json.Marshal(dash)
	require.NoError(t, err)
	require.Less(t, len(raw), apiBodyLimit)
}

func TestHundredThousandUnlabeledTargetsFitUnderAPIBodyLimit(t *testing.T) {
	raw := storedDashboard(t, dashv0.APIVERSION, 100_000, false, false)
	require.Less(t, len(raw), apiBodyLimit)
}

func newDashboardStorageCodec(t *testing.T) runtime.Codec {
	t.Helper()
	// v0 reads migrate before converting. The server calls migration.Initialize
	// at startup; without it Migrate blocks on the ready channel.
	migration.Initialize(
		migrationtestutil.NewDataSourceProvider(migrationtestutil.StandardTestConfig),
		migrationtestutil.NewTestLibraryElementProvider(),
		migration.DefaultCacheTTL,
	)

	scheme := runtime.NewScheme()
	require.NoError(t, dashv0.AddToScheme(scheme))
	require.NoError(t, dashv1beta1.AddToScheme(scheme))
	require.NoError(t, dashv1.AddToScheme(scheme))
	require.NoError(t, dashv2alpha1.AddToScheme(scheme))
	require.NoError(t, dashv2beta1.AddToScheme(scheme))
	require.NoError(t, dashv2.AddToScheme(scheme))
	require.NoError(t, RegisterConversions(
		scheme,
		migrationtestutil.NewDataSourceProvider(migrationtestutil.StandardTestConfig),
		migrationtestutil.NewTestLibraryElementProvider(),
	))

	// Same order InstallSchema / GetGroupVersions registers, which is the order
	// passed to LegacyCodec for the apiserver storage codec.
	groupVersions := []schema.GroupVersion{
		dashv2.DashboardResourceInfo.GroupVersion(),
		dashv2beta1.DashboardResourceInfo.GroupVersion(),
		dashv2alpha1.DashboardResourceInfo.GroupVersion(),
		dashv0.DashboardResourceInfo.GroupVersion(),
		dashv1.DashboardResourceInfo.GroupVersion(),
		dashv1beta1.DashboardResourceInfo.GroupVersion(),
	}
	return serializer.NewCodecFactory(scheme).LegacyCodec(groupVersions...)
}

func storedDashboard(t *testing.T, apiVersion string, targets int, preassignAZ, collapsedRow bool) []byte {
	t.Helper()
	spec := panelSpec(targets, preassignAZ, collapsedRow)
	var obj runtime.Object
	switch apiVersion {
	case dashv0.APIVERSION:
		obj = &dashv0.Dashboard{
			TypeMeta:   metav1.TypeMeta{APIVersion: apiVersion, Kind: "Dashboard"},
			ObjectMeta: metav1.ObjectMeta{Name: "bomb", Namespace: "default"},
			Spec:       common.Unstructured{Object: spec},
		}
	case dashv1.APIVERSION, dashv1beta1.APIVERSION:
		// v1beta1 is a type alias of v1, and one conversion registration covers both.
		obj = &dashv1.Dashboard{
			TypeMeta:   metav1.TypeMeta{APIVersion: apiVersion, Kind: "Dashboard"},
			ObjectMeta: metav1.ObjectMeta{Name: "bomb", Namespace: "default"},
			Spec:       common.Unstructured{Object: spec},
		}
	default:
		t.Fatalf("unsupported stored apiVersion %s", apiVersion)
	}
	// preserveGVK storage writes the object with encoding/json, which keeps the
	// apiVersion of the object that was saved.
	raw, err := json.Marshal(obj)
	require.NoError(t, err)
	return raw
}

func panelSpec(targets int, preassignAZ, collapsedRow bool) map[string]any {
	items := make([]any, targets)
	for i := range items {
		target := map[string]any{}
		if preassignAZ && i < 26 {
			target["refId"] = string(rune('A' + i))
		}
		items[i] = target
	}
	panel := map[string]any{
		"id":      float64(2),
		"type":    "timeseries",
		"targets": items,
	}
	var panels []any
	if collapsedRow {
		panels = []any{map[string]any{
			"id":        float64(1),
			"type":      "row",
			"collapsed": true,
			"panels":    []any{panel},
		}}
	} else {
		panel["id"] = float64(1)
		panels = []any{panel}
	}
	return map[string]any{
		"title":         "bomb",
		"schemaVersion": float64(schemaversion.LATEST_VERSION),
		"panels":        panels,
	}
}

func medianDecode(t *testing.T, codec runtime.Codec, raw []byte, into func() runtime.Object) time.Duration {
	t.Helper()
	measured := make([]time.Duration, 0, samples)
	for range samples {
		start := time.Now()
		_, _, err := codec.Decode(raw, nil, into())
		elapsed := time.Since(start)
		require.NoError(t, err)
		measured = append(measured, elapsed)
	}
	sort.Slice(measured, func(i, j int) bool { return measured[i] < measured[j] })
	median := measured[len(measured)/2]
	t.Logf("%d stored bytes decoded in %s (median of %d)", len(raw), median, len(measured))
	return median
}

func requireLinear(t *testing.T, small, large time.Duration) {
	t.Helper()
	if small <= 0 {
		t.Fatalf("small conversion took no measurable time")
	}
	ratio := float64(large) / float64(small)
	if ratio > maxLinearRatio {
		t.Fatalf("assigning refIds grew faster than linearly: %d targets took %s, %d targets took %s (ratio %.2f, limit %.2f)",
			smallTargets, small, largeTargets, large, ratio, maxLinearRatio)
	}
}

func requireSequentialRefIDs(t *testing.T, got []string, n int) {
	t.Helper()
	require.Len(t, got, n)
	seen := make(map[string]struct{}, n)
	for i, refID := range got {
		require.Equal(t, spreadsheetRefID(i), refID, "query %d", i)
		_, dup := seen[refID]
		require.False(t, dup, "duplicate refId %s", refID)
		seen[refID] = struct{}{}
	}
}

func spreadsheetRefID(index int) string {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	if index < len(letters) {
		return string(letters[index])
	}
	return spreadsheetRefID(index/len(letters)-1) + string(letters[index%len(letters)])
}

func unlabeledTargetCount(t *testing.T, spec map[string]any) int {
	t.Helper()
	panels, ok := spec["panels"].([]any)
	require.True(t, ok)
	missing := 0
	for _, panel := range panels {
		panelMap, ok := panel.(map[string]any)
		require.True(t, ok)
		targets, ok := panelMap["targets"].([]any)
		if !ok {
			continue
		}
		for _, target := range targets {
			targetMap, ok := target.(map[string]any)
			require.True(t, ok)
			refID, _ := targetMap["refId"].(string)
			if refID == "" {
				missing++
			}
		}
	}
	return missing
}

func collectQueryRefIDs(t *testing.T, obj runtime.Object) []string {
	t.Helper()
	raw, err := json.Marshal(obj)
	require.NoError(t, err)
	var decoded any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	ids := collectQueryRefIDsFrom(decoded)
	require.NotEmpty(t, ids)
	return ids
}

func collectQueryRefIDsFrom(v any) []string {
	switch typed := v.(type) {
	case map[string]any:
		var ids []string
		for _, child := range typed {
			ids = append(ids, collectQueryRefIDsFrom(child)...)
		}
		return ids
	case []any:
		if refs, ok := asQueryRefIDs(typed); ok {
			return refs
		}
		var ids []string
		for _, child := range typed {
			ids = append(ids, collectQueryRefIDsFrom(child)...)
		}
		return ids
	default:
		return nil
	}
}

func asQueryRefIDs(items []any) ([]string, bool) {
	if len(items) == 0 {
		return nil, false
	}
	refs := make([]string, 0, len(items))
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		spec, ok := obj["spec"].(map[string]any)
		if !ok {
			return nil, false
		}
		if _, hasQuery := spec["query"]; !hasQuery {
			return nil, false
		}
		refID, ok := spec["refId"].(string)
		if !ok || refID == "" {
			return nil, false
		}
		refs = append(refs, refID)
	}
	return refs, true
}
