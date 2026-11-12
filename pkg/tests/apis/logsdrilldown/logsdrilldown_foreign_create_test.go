package logsdrilldown

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	logsdrilldownv1alpha1 "github.com/grafana/grafana/apps/logsdrilldown/pkg/apis/logsdrilldown/v1alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/tests/testsuite"
	"github.com/grafana/grafana/pkg/util/testutil"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

// TestIntegrationLogsDrilldownForeignSettings checks that an editor who can
// save their own logs drilldown preferences cannot write the object another
// user loads. Create authorization does not carry metadata.name, so the
// rejection has to happen on the stored object itself.
func TestIntegrationLogsDrilldownForeignSettings(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	helper := apis.NewK8sTestHelper(t, testinfra.GrafanaOpts{
		AppModeProduction: false,
		DisableAnonymous:  true,
		EnableFeatureToggles: []string{
			featuremgmt.FlagKubernetesLogsDrilldown,
		},
	})

	gvr := logsdrilldownv1alpha1.LogsDrilldownKind().GroupVersionResource()
	attacker := helper.Org1.Editor
	victim := helper.CreateUser("victim", apis.Org1, org.RoleEditor, nil)
	viewer := helper.Org1.Viewer

	attackerName := logsDrilldownObjectName(t, attacker.Identity)
	victimName := logsDrilldownObjectName(t, victim.Identity)
	require.NotEqual(t, attackerName, victimName)

	attackerClient := helper.GetResourceClient(apis.ResourceClientArgs{User: attacker, GVR: gvr})
	victimClient := helper.GetResourceClient(apis.ResourceClientArgs{User: victim, GVR: gvr})
	viewerClient := helper.GetResourceClient(apis.ResourceClientArgs{User: viewer, GVR: gvr})
	// Grafana Admin reads bypass the logs drilldown authorizer, so a get here
	// reports what unified storage kept, not what the caller's role can see.
	adminClient := helper.GetResourceClient(apis.ResourceClientArgs{User: helper.Org1.Admin, GVR: gvr})

	ctx := context.Background()

	t.Run("api is installed", func(t *testing.T) {
		rsp := apis.DoRequest(helper, apis.RequestParams{
			User: helper.Org1.Admin,
			Path: "/apis/logsdrilldown.grafana.app/v1alpha1",
		}, &metav1.APIResourceList{})
		require.Equal(t, 200, rsp.Response.StatusCode, "body: %s", rsp.Body)
		require.NotNil(t, rsp.Result)
		var found bool
		for _, resource := range rsp.Result.APIResources {
			if resource.Name == gvr.Resource {
				found = true
				break
			}
		}
		require.True(t, found, "logsdrilldowns resource missing from %s", rsp.Body)
	})

	t.Run("editor stores and reads their own settings", func(t *testing.T) {
		want := attackerSpec()
		created, err := attackerClient.Resource.Create(ctx, logsDrilldownObject(attackerName, want), metav1.CreateOptions{})
		require.NoError(t, err)
		require.Equal(t, attackerName, created.GetName())
		require.Equal(t, want, specOf(t, created))

		got, err := attackerClient.Resource.Get(ctx, attackerName, metav1.GetOptions{})
		require.NoError(t, err)
		require.Equal(t, want, specOf(t, got))
	})

	t.Run("editor cannot create another user's settings", func(t *testing.T) {
		// Label names the attacker while metadata.name names the victim. A check
		// against the label, or against the empty create-request name, still
		// stores this object and must fail.
		obj := logsDrilldownObject(victimName, injectedSpec())
		require.NoError(t, unstructured.SetNestedField(obj.Object, attacker.Identity.GetRawIdentifier(), "metadata", "labels", "user"))

		created, err := attackerClient.Resource.Create(ctx, obj, metav1.CreateOptions{})
		if err == nil {
			stored, adminErr := adminClient.Resource.Get(ctx, created.GetName(), metav1.GetOptions{})
			loaded, victimErr := victimClient.Resource.Get(ctx, victimName, metav1.GetOptions{})
			shown := stored
			if loaded != nil {
				shown = loaded
			}
			t.Fatalf("editor create of %s was accepted (stored name %s, admin get err %v, victim get err %v, spec %v)", victimName, created.GetName(), adminErr, victimErr, specOf(t, shown))
		}
		require.Truef(t, apierrors.IsForbidden(err) || apierrors.IsInvalid(err), "create error = %v", err)
		requireAbsent(t, adminClient, victimName)
		requireAbsent(t, victimClient, victimName)
	})

	t.Run("editor cannot replace an existing user's settings", func(t *testing.T) {
		owner := helper.CreateUser("owner", apis.Org1, org.RoleEditor, nil)
		ownerClient := helper.GetResourceClient(apis.ResourceClientArgs{User: owner, GVR: gvr})
		ownerName := logsDrilldownObjectName(t, owner.Identity)

		original := victimSpec()
		created, err := ownerClient.Resource.Create(ctx, logsDrilldownObject(ownerName, original), metav1.CreateOptions{})
		require.NoError(t, err)

		replacement := logsDrilldownObject(ownerName, injectedSpec())
		replacement.SetResourceVersion(created.GetResourceVersion())
		_, err = attackerClient.Resource.Update(ctx, replacement, metav1.UpdateOptions{})
		require.Error(t, err)
		require.Truef(t, apierrors.IsForbidden(err), "update error = %v", err)
		requireSpec(t, ownerClient, ownerName, original)

		patch := []byte(`{"spec":{"defaultFields":["injected-field"],"prettifyJSON":true,"wrapLogMessage":true,"interceptDismissed":true}}`)
		_, err = attackerClient.Resource.Patch(ctx, ownerName, types.MergePatchType, patch, metav1.PatchOptions{})
		require.Error(t, err)
		require.Truef(t, apierrors.IsForbidden(err), "patch error = %v", err)
		requireSpec(t, ownerClient, ownerName, original)

		err = attackerClient.Resource.Delete(ctx, ownerName, metav1.DeleteOptions{})
		require.Error(t, err)
		require.Truef(t, apierrors.IsForbidden(err), "delete error = %v", err)
		requireSpec(t, ownerClient, ownerName, original)

		// A second create must not replace the object the owner already stored.
		_, err = attackerClient.Resource.Create(ctx, logsDrilldownObject(ownerName, injectedSpec()), metav1.CreateOptions{})
		require.Error(t, err)
		require.Truef(t, apierrors.IsAlreadyExists(err) || apierrors.IsForbidden(err) || apierrors.IsInvalid(err), "second create error = %v", err)
		requireSpec(t, ownerClient, ownerName, original)
	})

	t.Run("editor update and apply do not create another user's settings", func(t *testing.T) {
		other := helper.CreateUser("other", apis.Org1, org.RoleEditor, nil)
		otherName := logsDrilldownObjectName(t, other.Identity)

		obj := logsDrilldownObject(otherName, injectedSpec())
		_, err := attackerClient.Resource.Update(ctx, obj, metav1.UpdateOptions{})
		require.Error(t, err)
		require.Truef(t, apierrors.IsForbidden(err) || apierrors.IsNotFound(err), "update error = %v", err)
		requireAbsent(t, adminClient, otherName)

		_, err = attackerClient.Resource.Apply(ctx, otherName, obj, metav1.ApplyOptions{FieldManager: "editor", Force: true})
		require.Error(t, err)
		require.Truef(t, apierrors.IsForbidden(err) || apierrors.IsNotFound(err) || apierrors.IsInvalid(err), "apply error = %v", err)
		requireAbsent(t, adminClient, otherName)
	})

	t.Run("viewer cannot create another user's settings", func(t *testing.T) {
		viewerVictim := helper.CreateUser("viewer-victim", apis.Org1, org.RoleEditor, nil)
		name := logsDrilldownObjectName(t, viewerVictim.Identity)
		_, err := viewerClient.Resource.Create(ctx, logsDrilldownObject(name, injectedSpec()), metav1.CreateOptions{})
		require.Error(t, err)
		require.Truef(t, apierrors.IsForbidden(err), "viewer create error = %v", err)
		requireAbsent(t, adminClient, name)
	})
}

func logsDrilldownObjectName(t *testing.T, user identity.Requester) string {
	t.Helper()
	parts := strings.Split(user.GetUID(), ":")
	require.Len(t, parts, 2)
	require.NotEmpty(t, parts[1])
	require.NotContains(t, parts[1], ":")
	return "service:" + parts[1]
}

type drilldownSpec struct {
	defaultFields      []any
	prettifyJSON       bool
	wrapLogMessage     bool
	interceptDismissed bool
}

func attackerSpec() drilldownSpec {
	return drilldownSpec{defaultFields: []any{"own-field"}, prettifyJSON: false, wrapLogMessage: true, interceptDismissed: false}
}

func victimSpec() drilldownSpec {
	return drilldownSpec{defaultFields: []any{"victim-field"}, prettifyJSON: false, wrapLogMessage: false, interceptDismissed: false}
}

func injectedSpec() drilldownSpec {
	return drilldownSpec{defaultFields: []any{"injected-field"}, prettifyJSON: true, wrapLogMessage: true, interceptDismissed: true}
}

func logsDrilldownObject(name string, spec drilldownSpec) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": logsdrilldownv1alpha1.LogsDrilldownKind().GroupVersionKind().GroupVersion().String(),
		"kind":       logsdrilldownv1alpha1.LogsDrilldownKind().Kind(),
		"metadata": map[string]any{
			"name": name,
		},
		"spec": map[string]any{
			"defaultFields":      spec.defaultFields,
			"prettifyJSON":       spec.prettifyJSON,
			"wrapLogMessage":     spec.wrapLogMessage,
			"interceptDismissed": spec.interceptDismissed,
		},
	}}
}

func specOf(t *testing.T, obj *unstructured.Unstructured) drilldownSpec {
	t.Helper()
	require.NotNil(t, obj)
	fields, found, err := unstructured.NestedSlice(obj.Object, "spec", "defaultFields")
	require.NoError(t, err)
	require.True(t, found)
	prettify, found, err := unstructured.NestedBool(obj.Object, "spec", "prettifyJSON")
	require.NoError(t, err)
	require.True(t, found)
	wrap, found, err := unstructured.NestedBool(obj.Object, "spec", "wrapLogMessage")
	require.NoError(t, err)
	require.True(t, found)
	dismissed, found, err := unstructured.NestedBool(obj.Object, "spec", "interceptDismissed")
	require.NoError(t, err)
	require.True(t, found)
	return drilldownSpec{
		defaultFields:      fields,
		prettifyJSON:       prettify,
		wrapLogMessage:     wrap,
		interceptDismissed: dismissed,
	}
}

func requireSpec(t *testing.T, client *apis.K8sResourceClient, name string, want drilldownSpec) {
	t.Helper()
	got, err := client.Resource.Get(context.Background(), name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, want, specOf(t, got))
}

func requireAbsent(t *testing.T, client *apis.K8sResourceClient, name string) {
	t.Helper()
	got, err := client.Resource.Get(context.Background(), name, metav1.GetOptions{})
	if err == nil {
		t.Fatalf("LogsDrilldown %s was stored with spec %v", name, specOf(t, got))
	}
	require.Truef(t, apierrors.IsNotFound(err), "get %s error = %v", name, err)
}
