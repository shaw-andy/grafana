package historian

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/tests/testsuite"
	"github.com/grafana/grafana/pkg/util/testutil"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

const (
	historianGroup   = "historian.alerting.grafana.app"
	historianVersion = "v0alpha1"
	dummyResource    = "dummys"
	historianAPI     = historianGroup + "/" + historianVersion
)

// TestIntegrationHistorianDummyAuthorization is the spec for historian Dummy
// authorization. It fails while every historian request is allowed.
//
// A Viewer and a user with no organization role must not create, replace,
// patch, delete, or delete-collect Dummy objects, and must not write status.
// A refused call must not change what is stored. Viewers keep read access in
// their own organization. Admins and editors keep write access.
//
// Anonymous callers, when anonymous access is enabled, must not write Dummy
// objects in their own organization. Writes aimed at another organization are
// refused as well.
func TestIntegrationHistorianDummyAuthorization(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	helper := apis.NewK8sTestHelper(t, testinfra.GrafanaOpts{
		AppModeProduction: false,
		DisableAnonymous:  false,
		AnonymousUserRole: org.RoleViewer,
	})

	org1NS := helper.Namespacer(helper.Org1.OrgID)
	orgBNS := helper.Namespacer(helper.OrgB.OrgID)
	require.NotEqual(t, org1NS, orgBNS)

	admin := helper.Org1.Admin
	editor := helper.Org1.Editor
	viewer := helper.Org1.Viewer
	none := helper.Org1.None
	orgBAdmin := helper.OrgB.Admin

	t.Run("admin and editor can store a dummy", func(t *testing.T) {
		created := createDummy(t, helper, admin, org1NS, "admin-control", 1)
		require.Equal(t, int64(1), created.Spec.DummyField)
		created = createDummy(t, helper, editor, org1NS, "editor-control", 2)
		require.Equal(t, int64(2), created.Spec.DummyField)
	})

	readSeed := createDummy(t, helper, admin, org1NS, "read-seed", 7)

	t.Run("viewer can read dummys in their own org", func(t *testing.T) {
		got := getDummy(t, helper, viewer, org1NS, readSeed.Name)
		require.Equal(t, http.StatusOK, got.Response.StatusCode, string(got.Body))
		require.NotNil(t, got.Result)
		require.Equal(t, int64(7), got.Result.Spec.DummyField)

		listed := listDummys(t, helper, viewer, org1NS)
		require.Equal(t, http.StatusOK, listed.Response.StatusCode, string(listed.Body))
		require.NotNil(t, listed.Result)
		require.True(t, listHasName(*listed.Result, readSeed.Name))
	})

	t.Run("none cannot read dummys", func(t *testing.T) {
		listed := listDummys(t, helper, none, org1NS)
		requireForbidden(t, listed.Response.StatusCode, listed.Body)

		got := getDummy(t, helper, none, org1NS, readSeed.Name)
		requireForbidden(t, got.Response.StatusCode, got.Body)

		searched := writeDummy(t, helper, none, http.MethodPost, collectionPath(org1NS)+"/search", []byte(`{}`), "")
		requireForbidden(t, searched.Response.StatusCode, searched.Body)
	})

	for _, tc := range []struct {
		name string
		user apis.User
	}{
		{name: "viewer", user: viewer},
		{name: "none", user: none},
	} {
		t.Run(tc.name+" cannot create a dummy", func(t *testing.T) {
			for _, name := range []string{tc.name + "-create-a", tc.name + "-create-b"} {
				resp := writeDummy(t, helper, tc.user, http.MethodPost, collectionPath(org1NS), dummyBody(name, 11), "")
				requireForbidden(t, resp.Response.StatusCode, resp.Body)
				requireAbsent(t, helper, admin, org1NS, name)
			}
		})

		t.Run(tc.name+" cannot replace a dummy", func(t *testing.T) {
			target := createDummy(t, helper, admin, org1NS, tc.name+"-replace", 4)
			body := dummyBody(target.Name, 99)
			var obj map[string]any
			require.NoError(t, json.Unmarshal(body, &obj))
			obj["metadata"].(map[string]any)["resourceVersion"] = target.ResourceVersion
			encoded, err := json.Marshal(obj)
			require.NoError(t, err)

			resp := writeDummy(t, helper, tc.user, http.MethodPut, itemPath(org1NS, target.Name), encoded, "")
			requireForbidden(t, resp.Response.StatusCode, resp.Body)
			requireStoredField(t, helper, admin, org1NS, target.Name, 4)
		})

		t.Run(tc.name+" cannot patch a dummy", func(t *testing.T) {
			target := createDummy(t, helper, admin, org1NS, tc.name+"-patch", 5)
			resp := writeDummy(t, helper, tc.user, http.MethodPatch, itemPath(org1NS, target.Name), []byte(`{"spec":{"dummyField":77}}`), "application/merge-patch+json")
			requireForbidden(t, resp.Response.StatusCode, resp.Body)
			requireStoredField(t, helper, admin, org1NS, target.Name, 5)
		})

		t.Run(tc.name+" cannot replace dummy status", func(t *testing.T) {
			target := createDummy(t, helper, admin, org1NS, tc.name+"-status", 6)
			putStatus(t, helper, admin, org1NS, target, map[string]any{"source": "admin", "note": "kept"})
			target = getDummy(t, helper, admin, org1NS, target.Name).Result
			require.NotNil(t, target)

			body, err := json.Marshal(map[string]any{
				"apiVersion": historianAPI,
				"kind":       "Dummy",
				"metadata": map[string]any{
					"name":            target.Name,
					"resourceVersion": target.ResourceVersion,
				},
				"status": map[string]any{
					"additionalFields": map[string]any{
						"source":  tc.name,
						"payload": "low-priv-json",
						"nested":  map[string]any{"ok": true},
					},
				},
			})
			require.NoError(t, err)
			resp := writeDummy(t, helper, tc.user, http.MethodPut, itemPath(org1NS, target.Name)+"/status", body, "")
			requireForbidden(t, resp.Response.StatusCode, resp.Body)
			requireStatusNote(t, helper, admin, org1NS, target.Name, "kept")
		})

		t.Run(tc.name+" cannot patch dummy status", func(t *testing.T) {
			target := createDummy(t, helper, admin, org1NS, tc.name+"-status-patch", 6)
			putStatus(t, helper, admin, org1NS, target, map[string]any{"source": "admin", "note": "kept"})

			resp := writeDummy(t, helper, tc.user, http.MethodPatch, itemPath(org1NS, target.Name)+"/status",
				[]byte(`{"status":{"additionalFields":{"source":"patched-by-low-priv","payload":"low-priv-json"}}}`),
				"application/merge-patch+json")
			requireForbidden(t, resp.Response.StatusCode, resp.Body)
			requireStatusNote(t, helper, admin, org1NS, target.Name, "kept")
		})

		t.Run(tc.name+" cannot delete a dummy", func(t *testing.T) {
			target := createDummy(t, helper, admin, org1NS, tc.name+"-delete", 8)
			other := createDummy(t, helper, admin, org1NS, tc.name+"-delete-other", 9)
			resp := writeDummy(t, helper, tc.user, http.MethodDelete, itemPath(org1NS, target.Name), nil, "")
			requireForbidden(t, resp.Response.StatusCode, resp.Body)
			requireStoredField(t, helper, admin, org1NS, target.Name, 8)
			requireStoredField(t, helper, admin, org1NS, other.Name, 9)
		})
	}

	t.Run("viewer cannot write into another organization", func(t *testing.T) {
		name := "viewer-cross-org"
		resp := writeDummy(t, helper, viewer, http.MethodPost, collectionPath(orgBNS), dummyBody(name, 3), "")
		requireForbidden(t, resp.Response.StatusCode, resp.Body)
		requireAbsent(t, helper, orgBAdmin, orgBNS, name)
	})

	t.Run("none cannot read alert state history", func(t *testing.T) {
		history := getRaw(t, helper, none, http.MethodGet, customPath(org1NS, "/alertstate/history"))
		requireForbidden(t, history.Response.StatusCode, history.Body)
	})

	t.Run("none cannot query notification history", func(t *testing.T) {
		query := writeDummy(t, helper, none, http.MethodPost, customPath(org1NS, "/notification/query"), []byte(`{}`), "")
		requireForbidden(t, query.Response.StatusCode, query.Body)
	})

	t.Run("none cannot query notification alerts", func(t *testing.T) {
		alerts := writeDummy(t, helper, none, http.MethodPost, customPath(org1NS, "/notifications/queryalerts"), []byte(`{}`), "")
		requireForbidden(t, alerts.Response.StatusCode, alerts.Body)
	})

	t.Run("none cannot watch dummys", func(t *testing.T) {
		requireWatchForbidden(t, none, org1NS)
	})

	orgBSeed := createDummy(t, helper, orgBAdmin, orgBNS, "orgb-seed", 9)

	t.Run("anonymous cannot create in its own org", func(t *testing.T) {
		resp := writeDummy(t, helper, apis.User{}, http.MethodPost, collectionPath(org1NS), dummyBody("anon-home", 4), "")
		requireForbidden(t, resp.Response.StatusCode, resp.Body)
		requireAbsent(t, helper, admin, org1NS, "anon-home")
	})

	t.Run("anonymous cannot write another organization", func(t *testing.T) {
		created := writeDummy(t, helper, apis.User{}, http.MethodPost, collectionPath(orgBNS), dummyBody("anon-cross-org", 5), "")
		requireForbidden(t, created.Response.StatusCode, created.Body)
		requireAbsent(t, helper, orgBAdmin, orgBNS, "anon-cross-org")

		replaced := writeDummy(t, helper, apis.User{}, http.MethodPut, itemPath(orgBNS, orgBSeed.Name), dummyBody(orgBSeed.Name, 6), "")
		requireForbidden(t, replaced.Response.StatusCode, replaced.Body)

		patched := writeDummy(t, helper, apis.User{}, http.MethodPatch, itemPath(orgBNS, orgBSeed.Name), []byte(`{"spec":{"dummyField":6}}`), "application/merge-patch+json")
		requireForbidden(t, patched.Response.StatusCode, patched.Body)

		statused := writeDummy(t, helper, apis.User{}, http.MethodPut, itemPath(orgBNS, orgBSeed.Name)+"/status", statusBody(orgBSeed.Name, orgBSeed.ResourceVersion, map[string]any{"source": "anonymous"}), "")
		requireForbidden(t, statused.Response.StatusCode, statused.Body)

		statusPatch := writeDummy(t, helper, apis.User{}, http.MethodPatch, itemPath(orgBNS, orgBSeed.Name)+"/status", []byte(`{"status":{"additionalFields":{"source":"anonymous"}}}`), "application/merge-patch+json")
		requireForbidden(t, statusPatch.Response.StatusCode, statusPatch.Body)

		deleted := writeDummy(t, helper, apis.User{}, http.MethodDelete, itemPath(orgBNS, orgBSeed.Name), nil, "")
		requireForbidden(t, deleted.Response.StatusCode, deleted.Body)

		collection := writeDummy(t, helper, apis.User{}, http.MethodDelete, collectionPath(orgBNS), nil, "")
		requireForbidden(t, collection.Response.StatusCode, collection.Body)

		requireStoredField(t, helper, orgBAdmin, orgBNS, orgBSeed.Name, 9)
	})

	// Collection deletes are last: a successful delete removes every Dummy in the namespace.
	t.Run("viewer and none cannot delete the dummy collection", func(t *testing.T) {
		keptA := createDummy(t, helper, admin, org1NS, "collection-a", 21)
		keptB := createDummy(t, helper, admin, org1NS, "collection-b", 22)
		for _, user := range []apis.User{viewer, none} {
			resp := writeDummy(t, helper, user, http.MethodDelete, collectionPath(org1NS), nil, "")
			requireForbidden(t, resp.Response.StatusCode, resp.Body)
			requireStoredField(t, helper, admin, org1NS, keptA.Name, 21)
			requireStoredField(t, helper, admin, org1NS, keptB.Name, 22)
		}
		anon := writeDummy(t, helper, apis.User{}, http.MethodDelete, collectionPath(org1NS), nil, "")
		requireForbidden(t, anon.Response.StatusCode, anon.Body)
		requireStoredField(t, helper, admin, org1NS, keptA.Name, 21)
		requireStoredField(t, helper, admin, org1NS, keptB.Name, 22)
	})
}

func collectionPath(ns string) string {
	return fmt.Sprintf("/apis/%s/%s/namespaces/%s/%s", historianGroup, historianVersion, ns, dummyResource)
}

func itemPath(ns, name string) string {
	return collectionPath(ns) + "/" + name
}

func customPath(ns, route string) string {
	return fmt.Sprintf("/apis/%s/%s/namespaces/%s%s", historianGroup, historianVersion, ns, route)
}

type dummyObject struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              struct {
		DummyField int64 `json:"dummyField"`
	} `json:"spec"`
	Status struct {
		AdditionalFields map[string]any `json:"additionalFields,omitempty"`
	} `json:"status,omitempty"`
}

type dummyList struct {
	metav1.TypeMeta `json:",inline"`
	Items           []dummyObject `json:"items"`
}

func dummyBody(name string, field int64) []byte {
	body, err := json.Marshal(map[string]any{
		"apiVersion": historianAPI,
		"kind":       "Dummy",
		"metadata":   map[string]any{"name": name},
		"spec":       map[string]any{"dummyField": field},
	})
	if err != nil {
		panic(err)
	}
	return body
}

func statusBody(name, rv string, fields map[string]any) []byte {
	body, err := json.Marshal(map[string]any{
		"apiVersion": historianAPI,
		"kind":       "Dummy",
		"metadata": map[string]any{
			"name":            name,
			"resourceVersion": rv,
		},
		"status": map[string]any{"additionalFields": fields},
	})
	if err != nil {
		panic(err)
	}
	return body
}

func createDummy(t *testing.T, helper *apis.K8sTestHelper, user apis.User, ns, name string, field int64) *dummyObject {
	t.Helper()
	resp := writeDummy(t, helper, user, http.MethodPost, collectionPath(ns), dummyBody(name, field), "")
	require.Containsf(t, []int{http.StatusOK, http.StatusCreated}, resp.Response.StatusCode, "create %s: %s", name, resp.Body)
	require.NotNil(t, resp.Result)
	return resp.Result
}

func putStatus(t *testing.T, helper *apis.K8sTestHelper, user apis.User, ns string, obj *dummyObject, fields map[string]any) {
	t.Helper()
	current := getDummy(t, helper, helper.Org1.Admin, ns, obj.Name)
	require.Equal(t, http.StatusOK, current.Response.StatusCode, string(current.Body))
	require.NotNil(t, current.Result)
	resp := writeDummy(t, helper, user, http.MethodPut, itemPath(ns, obj.Name)+"/status", statusBody(obj.Name, current.Result.ResourceVersion, fields), "")
	require.Containsf(t, []int{http.StatusOK, http.StatusCreated}, resp.Response.StatusCode, "status update %s: %s", obj.Name, resp.Body)
}

func writeDummy(t *testing.T, helper *apis.K8sTestHelper, user apis.User, method, path string, body []byte, contentType string) apis.K8sResponse[dummyObject] {
	t.Helper()
	return apis.DoRequest(helper, apis.RequestParams{
		User:        user,
		Method:      method,
		Path:        path,
		Body:        body,
		ContentType: contentType,
	}, &dummyObject{})
}

func getRaw(t *testing.T, helper *apis.K8sTestHelper, user apis.User, method, path string) apis.K8sResponse[dummyObject] {
	t.Helper()
	return writeDummy(t, helper, user, method, path, nil, "")
}

func getDummy(t *testing.T, helper *apis.K8sTestHelper, user apis.User, ns, name string) apis.K8sResponse[dummyObject] {
	t.Helper()
	return getRaw(t, helper, user, http.MethodGet, itemPath(ns, name))
}

func listDummys(t *testing.T, helper *apis.K8sTestHelper, user apis.User, ns string) apis.K8sResponse[dummyList] {
	t.Helper()
	return apis.DoRequest(helper, apis.RequestParams{
		User:   user,
		Method: http.MethodGet,
		Path:   collectionPath(ns),
	}, &dummyList{})
}

func requireForbidden(t *testing.T, code int, body []byte) {
	t.Helper()
	require.Equalf(t, http.StatusForbidden, code, "body: %s", body)
}

func requireAbsent(t *testing.T, helper *apis.K8sTestHelper, reader apis.User, ns, name string) {
	t.Helper()
	got := getDummy(t, helper, reader, ns, name)
	require.Equalf(t, http.StatusNotFound, got.Response.StatusCode, "object %s was stored: %s", name, got.Body)
}

func requireStoredField(t *testing.T, helper *apis.K8sTestHelper, reader apis.User, ns, name string, field int64) {
	t.Helper()
	got := getDummy(t, helper, reader, ns, name)
	require.Equalf(t, http.StatusOK, got.Response.StatusCode, "object %s: %s", name, got.Body)
	require.NotNil(t, got.Result)
	require.Equal(t, field, got.Result.Spec.DummyField)
}

func requireStatusNote(t *testing.T, helper *apis.K8sTestHelper, reader apis.User, ns, name, note string) {
	t.Helper()
	got := getDummy(t, helper, reader, ns, name)
	require.Equalf(t, http.StatusOK, got.Response.StatusCode, "object %s: %s", name, got.Body)
	require.NotNil(t, got.Result)
	require.NotNil(t, got.Result.Status.AdditionalFields)
	require.Equal(t, note, got.Result.Status.AdditionalFields["note"])
	require.Equal(t, "admin", got.Result.Status.AdditionalFields["source"])
}

func listHasName(list dummyList, name string) bool {
	for _, item := range list.Items {
		if item.Name == name {
			return true
		}
	}
	return false
}

func requireWatchForbidden(t *testing.T, user apis.User, ns string) {
	t.Helper()
	gv := schema.GroupVersion{Group: historianGroup, Version: historianVersion}
	client := user.RESTClient(t, &gv)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := client.Get().Namespace(ns).Resource(dummyResource).Param("watch", "true").Do(ctx)
	var code int
	result.StatusCode(&code)
	require.Equalf(t, http.StatusForbidden, code, "watch error: %v", result.Error())
}
