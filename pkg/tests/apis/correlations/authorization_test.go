package correlations

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	correlationsV0 "github.com/grafana/grafana/apps/correlations/pkg/apis/correlation/v0alpha1"
	grafanarest "github.com/grafana/grafana/pkg/apiserver/rest"
	"github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/correlations"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

const (
	sourceAUID   = "ds-a"
	sourceBUID   = "ds-b"
	sourceAGroup = "testdata"
	fieldName    = "traceID"
	adminLink    = "https://admin.example.invalid/link"
	editorLink   = "https://editor.example.invalid/link"
	otherLink    = "https://other.example.invalid/link"
)

// TestIntegrationCorrelationKubernetesAPIRequiresDatasourceWrite is the spec for
// correlations.grafana.app authorization. It fails while an Editor can create,
// update, or delete correlations without datasources:write on the source
// datasource the request names.
func TestIntegrationCorrelationKubernetesAPIRequiresDatasourceWrite(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	helper := newCorrelationAPIHelper(t, true)
	ns := helper.Namespacer(helper.Org1.OrgID)
	otherNS := helper.Namespacer(helper.OrgB.OrgID)

	helper.CreateDS(&datasources.AddDataSourceCommand{
		OrgID: helper.Org1.OrgID,
		Name:  sourceAUID,
		UID:   sourceAUID,
		Type:  sourceAGroup,
	})
	helper.CreateDS(&datasources.AddDataSourceCommand{
		OrgID: helper.Org1.OrgID,
		Name:  sourceBUID,
		UID:   sourceBUID,
		Type:  sourceAGroup,
	})
	helper.CreateDS(&datasources.AddDataSourceCommand{
		OrgID: helper.OrgB.OrgID,
		Name:  sourceAUID,
		UID:   sourceAUID,
		Type:  sourceAGroup,
	})

	editor := helper.Org1.Editor
	viewer := helper.Org1.Viewer
	none := helper.Org1.None
	writerOnA := helper.CreateUser("writer-on-a", apis.Org1, org.RoleEditor, []resourcepermissions.SetResourcePermissionCommand{{
		Actions:           []string{datasources.ActionWrite, datasources.ActionRead},
		Resource:          "datasources",
		ResourceAttribute: "uid",
		ResourceID:        sourceAUID,
	}})
	readerOnA := helper.CreateUser("reader-on-a", apis.Org1, org.RoleNone, []resourcepermissions.SetResourcePermissionCommand{{
		Actions:           []string{datasources.ActionRead},
		Resource:          "datasources",
		ResourceAttribute: "uid",
		ResourceID:        sourceAUID,
	}})

	t.Run("http api rejects an editor without datasources:write", func(t *testing.T) {
		rsp := postLegacyCorrelation(t, helper, editor, sourceAUID, "http-editor", editorLink)
		require.Equal(t, http.StatusForbidden, rsp.Response.StatusCode, string(rsp.Body))
		require.Empty(t, storedCorrelations(t, helper, helper.Org1.Admin, ns))
	})

	t.Run("editor cannot create a correlation through the kubernetes api", func(t *testing.T) {
		rsp := postCorrelation(t, helper, editor, ns, sourceAUID, "editor-create", editorLink)
		requireNotWritten(t, rsp.Response.StatusCode, rsp.Body)
		requireNoCorrelation(t, helper, ns, "editor-create")
	})

	t.Run("datasources:write on the source datasource can create that source only", func(t *testing.T) {
		legacyAllowed := postLegacyCorrelation(t, helper, writerOnA, sourceAUID, "writer-http", editorLink)
		require.Equal(t, http.StatusOK, legacyAllowed.Response.StatusCode, string(legacyAllowed.Body))
		legacyRejected := postLegacyCorrelation(t, helper, writerOnA, sourceBUID, "writer-http-b", otherLink)
		require.Equal(t, http.StatusForbidden, legacyRejected.Response.StatusCode, string(legacyRejected.Body))

		allowed := postCorrelation(t, helper, writerOnA, ns, sourceAUID, "writer-create", editorLink)
		require.Contains(t, []int{http.StatusOK, http.StatusCreated}, allowed.Response.StatusCode, string(allowed.Body))
		stored := requireCorrelation(t, helper, ns, sourceAUID, "writer-create", editorLink)
		require.Equal(t, sourceAUID, stored.Spec.Source.Name, "stored source must be the datasource the write was authorized for")

		rejected := postCorrelation(t, helper, writerOnA, ns, sourceBUID, "writer-other-source", otherLink)
		requireNotWritten(t, rejected.Response.StatusCode, rejected.Body)
		requireNoCorrelation(t, helper, ns, "writer-other-source")
	})

	adminCreated := postLegacyCorrelation(t, helper, helper.Org1.Admin, sourceAUID, "admin-link", adminLink)
	require.Equal(t, http.StatusOK, adminCreated.Response.StatusCode, string(adminCreated.Body))
	adminUID := adminCreated.Result.Result.UID
	require.NotEmpty(t, adminUID)
	adminOnB := postLegacyCorrelation(t, helper, helper.Org1.Admin, sourceBUID, "admin-b", adminLink)
	require.Equal(t, http.StatusOK, adminOnB.Response.StatusCode, string(adminOnB.Body))
	adminBUID := adminOnB.Result.Result.UID
	require.NotEmpty(t, adminBUID)

	t.Run("editor cannot update an existing correlation", func(t *testing.T) {
		current := getCorrelation(t, helper, editor, ns, adminUID)
		require.Equal(t, http.StatusOK, current.Response.StatusCode, string(current.Body))

		updated := correlationObject(ns, adminUID, sourceAUID, "admin-link", otherLink)
		updated.ResourceVersion = current.Result.ResourceVersion
		put := putCorrelation(t, helper, editor, ns, adminUID, updated)
		requireNotWritten(t, put.Response.StatusCode, put.Body)
		requireCorrelation(t, helper, ns, sourceAUID, "admin-link", adminLink)
	})

	t.Run("editor cannot patch an existing correlation", func(t *testing.T) {
		created := postLegacyCorrelation(t, helper, helper.Org1.Admin, sourceAUID, "admin-patch", adminLink)
		require.Equal(t, http.StatusOK, created.Response.StatusCode, string(created.Body))
		patched := patchCorrelation(t, helper, editor, ns, created.Result.Result.UID, otherLink)
		requirePatchRejected(t, patched.Response.StatusCode, patched.Body)
		requireCorrelation(t, helper, ns, sourceAUID, "admin-patch", adminLink)
	})

	t.Run("editor cannot delete an existing correlation", func(t *testing.T) {
		created := postLegacyCorrelation(t, helper, helper.Org1.Admin, sourceAUID, "admin-delete", adminLink)
		require.Equal(t, http.StatusOK, created.Response.StatusCode, string(created.Body))
		del := deleteCorrelation(t, helper, editor, ns, created.Result.Result.UID)
		requireNotWritten(t, del.Response.StatusCode, del.Body)
		requireCorrelation(t, helper, ns, sourceAUID, "admin-delete", adminLink)
	})

	t.Run("datasources:write on A cannot update a correlation whose source is B", func(t *testing.T) {
		current := getCorrelation(t, helper, writerOnA, ns, adminBUID)
		require.Equal(t, http.StatusOK, current.Response.StatusCode, string(current.Body))
		updated := correlationObject(ns, adminBUID, sourceBUID, "admin-b", otherLink)
		updated.ResourceVersion = current.Result.ResourceVersion
		put := putCorrelation(t, helper, writerOnA, ns, adminBUID, updated)
		requireNotWritten(t, put.Response.StatusCode, put.Body)
		require.Equal(t, adminLink, targetURL(requireCorrelation(t, helper, ns, sourceBUID, "admin-b", adminLink)))
	})

	t.Run("datasources:write on A cannot delete a correlation whose source is B", func(t *testing.T) {
		created := postLegacyCorrelation(t, helper, helper.Org1.Admin, sourceBUID, "admin-delete-b", adminLink)
		require.Equal(t, http.StatusOK, created.Response.StatusCode, string(created.Body))
		del := deleteCorrelation(t, helper, writerOnA, ns, created.Result.Result.UID)
		requireNotWritten(t, del.Response.StatusCode, del.Body)
		requireCorrelation(t, helper, ns, sourceBUID, "admin-delete-b", adminLink)
	})

	t.Run("datasources:write on A cannot delete the collection for source B", func(t *testing.T) {
		created := postLegacyCorrelation(t, helper, helper.Org1.Admin, sourceBUID, "admin-collection-b", adminLink)
		require.Equal(t, http.StatusOK, created.Response.StatusCode, string(created.Body))
		collection := deleteCorrelationCollection(t, helper, writerOnA, ns, sourceBUID)
		requireNotWritten(t, collection.Response.StatusCode, collection.Body)
		requireCorrelation(t, helper, ns, sourceBUID, "admin-collection-b", adminLink)
	})

	t.Run("datasources:write on A can update and delete a correlation for A", func(t *testing.T) {
		owned := postCorrelation(t, helper, writerOnA, ns, sourceAUID, "writer-owned", editorLink)
		require.Contains(t, []int{http.StatusOK, http.StatusCreated}, owned.Response.StatusCode, string(owned.Body))
		stored := requireCorrelation(t, helper, ns, sourceAUID, "writer-owned", editorLink)

		updated := correlationObject(ns, stored.Name, sourceAUID, "writer-owned", otherLink)
		updated.ResourceVersion = stored.ResourceVersion
		put := putCorrelation(t, helper, writerOnA, ns, stored.Name, updated)
		require.Contains(t, []int{http.StatusOK, http.StatusCreated}, put.Response.StatusCode, string(put.Body))
		replaced := requireCorrelation(t, helper, ns, sourceAUID, "writer-owned", otherLink)
		require.Equal(t, sourceAUID, replaced.Spec.Source.Name)

		del := deleteCorrelation(t, helper, writerOnA, ns, stored.Name)
		require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, del.Response.StatusCode, string(del.Body))
		requireNoCorrelation(t, helper, ns, "writer-owned")
	})

	t.Run("a write into another organization namespace does not persist", func(t *testing.T) {
		rsp := postCorrelation(t, helper, editor, otherNS, sourceAUID, "cross-org", editorLink)
		requireNotWritten(t, rsp.Response.StatusCode, rsp.Body)
		require.Empty(t, storedCorrelations(t, helper, helper.OrgB.Admin, otherNS))
	})

	t.Run("reads follow datasources:read on the source datasource", func(t *testing.T) {
		readable := getCorrelation(t, helper, viewer, ns, adminUID)
		require.Equal(t, http.StatusOK, readable.Response.StatusCode, string(readable.Body))
		require.Equal(t, sourceAUID, readable.Result.Spec.Source.Name)

		hidden := getCorrelation(t, helper, none, ns, adminUID)
		require.Equal(t, http.StatusForbidden, hidden.Response.StatusCode, string(hidden.Body))

		listed := listCorrelations(t, helper, viewer, ns, sourceAUID)
		require.Equal(t, http.StatusOK, listed.Response.StatusCode, string(listed.Body))
		require.NotEmpty(t, listed.Result.Items)

		scoped := getCorrelation(t, helper, readerOnA, ns, adminUID)
		require.Equal(t, http.StatusOK, scoped.Response.StatusCode, string(scoped.Body))
		require.Equal(t, sourceAUID, scoped.Result.Spec.Source.Name)

		otherSource := getCorrelation(t, helper, readerOnA, ns, adminBUID)
		require.Equal(t, http.StatusForbidden, otherSource.Response.StatusCode, string(otherSource.Body))

		unlisted := listCorrelations(t, helper, none, ns, sourceAUID)
		require.Equal(t, http.StatusForbidden, unlisted.Response.StatusCode, string(unlisted.Body))
	})
}

func newCorrelationAPIHelper(t *testing.T, kubernetes bool) *apis.K8sTestHelper {
	t.Helper()
	opts := testinfra.GrafanaOpts{
		DisableAnonymous: true,
		UnifiedStorageConfig: map[string]setting.UnifiedStorageConfig{
			"correlation.correlations.grafana.app": {
				DualWriterMode: grafanarest.Mode0,
			},
		},
	}
	if kubernetes {
		opts.EnableFeatureToggles = []string{featuremgmt.FlagKubernetesCorrelations}
	}
	return apis.NewK8sTestHelper(t, opts)
}

func correlationObject(namespace, name, sourceUID, label, link string) *correlationsV0.Correlation {
	obj := &correlationsV0.Correlation{
		TypeMeta: metav1.TypeMeta{
			APIVersion: correlationsV0.GroupVersion.String(),
			Kind:       "Correlation",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
		},
	}
	if name == "" {
		obj.GenerateName = "corr-"
	} else {
		obj.Name = name
	}
	obj.Spec = correlationsV0.CorrelationSpec{
		Type:  correlationsV0.CorrelationCorrelationTypeExternal,
		Label: label,
		Source: correlationsV0.CorrelationDataSourceRef{
			Group: sourceAGroup,
			Name:  sourceUID,
		},
		Config: correlationsV0.CorrelationConfigSpec{
			Field: fieldName,
			Target: correlationsV0.CorrelationTargetSpec{
				"url": link,
			},
		},
	}
	return obj
}

func postCorrelation(t *testing.T, helper *apis.K8sTestHelper, user apis.User, namespace, sourceUID, label, link string) apis.K8sResponse[correlationsV0.Correlation] {
	t.Helper()
	body, err := json.Marshal(correlationObject(namespace, "", sourceUID, label, link))
	require.NoError(t, err)
	return apis.DoRequest(helper, apis.RequestParams{
		User:   user,
		Method: http.MethodPost,
		Path:   fmt.Sprintf("/apis/correlations.grafana.app/v0alpha1/namespaces/%s/correlations", namespace),
		Body:   body,
	}, &correlationsV0.Correlation{})
}

func putCorrelation(t *testing.T, helper *apis.K8sTestHelper, user apis.User, namespace, name string, obj *correlationsV0.Correlation) apis.K8sResponse[correlationsV0.Correlation] {
	t.Helper()
	body, err := json.Marshal(obj)
	require.NoError(t, err)
	return apis.DoRequest(helper, apis.RequestParams{
		User:   user,
		Method: http.MethodPut,
		Path:   fmt.Sprintf("/apis/correlations.grafana.app/v0alpha1/namespaces/%s/correlations/%s", namespace, name),
		Body:   body,
	}, &correlationsV0.Correlation{})
}

func patchCorrelation(t *testing.T, helper *apis.K8sTestHelper, user apis.User, namespace, name, link string) apis.K8sResponse[correlationsV0.Correlation] {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"spec": map[string]any{
			"config": map[string]any{
				"target": map[string]any{"url": link},
			},
		},
	})
	require.NoError(t, err)
	return apis.DoRequest(helper, apis.RequestParams{
		User:        user,
		Method:      http.MethodPatch,
		Path:        fmt.Sprintf("/apis/correlations.grafana.app/v0alpha1/namespaces/%s/correlations/%s", namespace, name),
		Body:        body,
		ContentType: "application/merge-patch+json",
	}, &correlationsV0.Correlation{})
}

func deleteCorrelation(t *testing.T, helper *apis.K8sTestHelper, user apis.User, namespace, name string) apis.K8sResponse[metav1.Status] {
	t.Helper()
	return apis.DoRequest(helper, apis.RequestParams{
		User:   user,
		Method: http.MethodDelete,
		Path:   fmt.Sprintf("/apis/correlations.grafana.app/v0alpha1/namespaces/%s/correlations/%s", namespace, name),
	}, &metav1.Status{})
}

func deleteCorrelationCollection(t *testing.T, helper *apis.K8sTestHelper, user apis.User, namespace, sourceUID string) apis.K8sResponse[metav1.Status] {
	t.Helper()
	selector := url.QueryEscape(fmt.Sprintf("%s=%s.%s.false", "correlations.grafana.app/sourceDSProv-ref", sourceAGroup, sourceUID))
	return apis.DoRequest(helper, apis.RequestParams{
		User:   user,
		Method: http.MethodDelete,
		Path:   fmt.Sprintf("/apis/correlations.grafana.app/v0alpha1/namespaces/%s/correlations?labelSelector=%s", namespace, selector),
	}, &metav1.Status{})
}

func getCorrelation(t *testing.T, helper *apis.K8sTestHelper, user apis.User, namespace, name string) apis.K8sResponse[correlationsV0.Correlation] {
	t.Helper()
	return apis.DoRequest(helper, apis.RequestParams{
		User:   user,
		Method: http.MethodGet,
		Path:   fmt.Sprintf("/apis/correlations.grafana.app/v0alpha1/namespaces/%s/correlations/%s", namespace, name),
	}, &correlationsV0.Correlation{})
}

func listCorrelations(t *testing.T, helper *apis.K8sTestHelper, user apis.User, namespace, sourceUID string) apis.K8sResponse[correlationsV0.CorrelationList] {
	t.Helper()
	selector := url.QueryEscape(fmt.Sprintf("%s=%s.%s", "correlations.grafana.app/sourceDS-ref", sourceAGroup, sourceUID))
	return apis.DoRequest(helper, apis.RequestParams{
		User:   user,
		Method: http.MethodGet,
		Path:   fmt.Sprintf("/apis/correlations.grafana.app/v0alpha1/namespaces/%s/correlations?labelSelector=%s", namespace, selector),
	}, &correlationsV0.CorrelationList{})
}

func postLegacyCorrelation(t *testing.T, helper *apis.K8sTestHelper, user apis.User, sourceUID, label, link string) apis.K8sResponse[correlations.CreateCorrelationResponseBody] {
	t.Helper()
	body, err := json.Marshal(correlations.CreateCorrelationCommand{
		Label: label,
		Type:  correlations.CorrelationType("external"),
		Config: correlations.CorrelationConfig{
			Field:  fieldName,
			Target: map[string]any{"url": link},
		},
	})
	require.NoError(t, err)
	return apis.DoRequest(helper, apis.RequestParams{
		User:   user,
		Method: http.MethodPost,
		Path:   "/api/datasources/uid/" + sourceUID + "/correlations",
		Body:   body,
	}, &correlations.CreateCorrelationResponseBody{})
}

func storedCorrelations(t *testing.T, helper *apis.K8sTestHelper, user apis.User, namespace string) []correlationsV0.Correlation {
	t.Helper()
	rsp := apis.DoRequest(helper, apis.RequestParams{
		User:   user,
		Method: http.MethodGet,
		Path:   fmt.Sprintf("/apis/correlations.grafana.app/v0alpha1/namespaces/%s/correlations", namespace),
	}, &correlationsV0.CorrelationList{})
	require.Equal(t, http.StatusOK, rsp.Response.StatusCode, string(rsp.Body))
	if rsp.Result == nil {
		return nil
	}
	return rsp.Result.Items
}

func requireNotWritten(t *testing.T, statusCode int, body []byte) {
	t.Helper()
	require.NotContains(t, []int{http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent}, statusCode, string(body))
	require.Equal(t, http.StatusForbidden, statusCode, string(body))
}

func requirePatchRejected(t *testing.T, statusCode int, body []byte) {
	t.Helper()
	switch statusCode {
	case http.StatusMethodNotAllowed, http.StatusUnsupportedMediaType, http.StatusNotFound:
		return
	default:
		requireNotWritten(t, statusCode, body)
	}
}

func requireNoCorrelation(t *testing.T, helper *apis.K8sTestHelper, namespace, label string) {
	t.Helper()
	for _, item := range storedCorrelations(t, helper, helper.Org1.Admin, namespace) {
		require.NotEqualf(t, label, item.Spec.Label, "correlation %s for %s was stored", item.Name, item.Spec.Source.Name)
	}
}

func requireCorrelation(t *testing.T, helper *apis.K8sTestHelper, namespace, sourceUID, label, link string) correlationsV0.Correlation {
	t.Helper()
	for _, item := range storedCorrelations(t, helper, helper.Org1.Admin, namespace) {
		if item.Spec.Label == label {
			require.Equal(t, link, targetURL(item))
			require.Equal(t, sourceUID, item.Spec.Source.Name)
			return item
		}
	}
	t.Fatalf("correlation label %q was not stored for %s", label, sourceUID)
	return correlationsV0.Correlation{}
}

func targetURL(item correlationsV0.Correlation) string {
	if item.Spec.Config.Target == nil {
		return ""
	}
	link, _ := item.Spec.Config.Target["url"].(string)
	return link
}
