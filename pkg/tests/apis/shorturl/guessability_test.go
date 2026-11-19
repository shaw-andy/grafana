package shorturl

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/shorturls"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/testinfra"
)

// minShortURLIDLength is the shortest id that can carry 128 bits when every
// character is drawn from the Kubernetes DNS-1123 alphabet [a-z0-9].
// log2(36) is about 5.170, and 128/log2(36) is about 24.76, so 25 characters
// are required. A hyphen is not available in every position, and a smaller
// alphabet needs a longer id, so this is a lower bound.
const minShortURLIDLength = 25

// shortURLLookupLimit is the number of read attempts one signed-in user may
// make against a short-URL read route before the server must refuse. The
// refusal has to happen on that route: a later lookup of a different id must
// not succeed once the limit is reached.
const shortURLLookupLimit = 30

const hiddenPath = "d/hidden-board/view?panel=9"

func TestShortURLGuessability(t *testing.T) {
	helper := apis.NewK8sTestHelper(t, testinfra.GrafanaOpts{
		AppModeProduction: true,
		DisableAnonymous:  true,
	})

	author := helper.Org1.None
	reader := helper.Org1.Viewer
	namespace := helper.Namespacer(helper.Org1.OrgID)

	t.Run("legacy create assigns an unguessable id and another user can open it", func(t *testing.T) {
		created := createLegacyShortURL(t, helper, author, hiddenPath, "")
		requireOtherUserCanRead(t, helper, reader, created.UID, hiddenPath)
		requireServerChosenID(t, created.UID)
	})

	t.Run("app api create with the ui prefix assigns an unguessable id", func(t *testing.T) {
		// The short-URL client sets metadata.generateName to "s" when the caller
		// does not supply a name. That is the request the UI sends.
		created := createAppShortURL(t, helper, author, namespace, map[string]any{
			"generateName": "s",
		}, hiddenPath)
		requireOtherUserCanRead(t, helper, reader, created.GetName(), hiddenPath)
		requireServerChosenID(t, created.GetName())
	})

	t.Run("legacy create ignores a caller supplied uid", func(t *testing.T) {
		const chosen = "pickedlegacy"
		created := createLegacyShortURL(t, helper, author, "d/picked/legacy", chosen)
		require.NotEqual(t, chosen, created.UID)
		requireServerChosenID(t, created.UID)
		requireChosenNameDoesNotResolve(t, helper, reader, namespace, chosen, "d/picked/legacy")
	})

	t.Run("app api create ignores a caller supplied name", func(t *testing.T) {
		const chosen = "pickedapp"
		created := createAppShortURL(t, helper, author, namespace, map[string]any{
			"name": chosen,
		}, "d/picked/app")
		require.NotEqual(t, chosen, created.GetName())
		requireServerChosenID(t, created.GetName())
		requireChosenNameDoesNotResolve(t, helper, reader, namespace, chosen, "d/picked/app")
	})

	t.Run("app api create ignores a caller supplied generateName", func(t *testing.T) {
		const prefix = "clientpickprefix"
		created := createAppShortURL(t, helper, author, namespace, map[string]any{
			"generateName": prefix,
		}, "d/picked/prefix")
		require.Falsef(t, strings.HasPrefix(created.GetName(), prefix),
			"server kept the caller prefix in %q", created.GetName())
		requireServerChosenID(t, created.GetName())
	})

	t.Run("listing short urls stays forbidden for a non admin", func(t *testing.T) {
		res := apis.DoRequest(helper, apis.RequestParams{
			User:   reader,
			Method: http.MethodGet,
			Path:   appCollectionPath(namespace),
		}, &unstructured.UnstructuredList{})
		require.Equal(t, http.StatusForbidden, res.Response.StatusCode, "body: %s", res.Body)
		require.NotContains(t, string(res.Body), hiddenPath)
	})

	prober := helper.CreateUser("shorturl-prober", apis.Org1, org.RoleViewer, nil)
	for _, route := range []struct {
		name string
		path func(id string) string
	}{
		{name: "legacy get", path: legacyShortURLPath},
		{name: "legacy goto", path: func(id string) string { return "/goto/" + id }},
		{name: "app api get", path: func(id string) string { return appCollectionPath(namespace) + "/" + id }},
		{name: "app api goto", path: func(id string) string { return appCollectionPath(namespace) + "/" + id + "/goto" }},
	} {
		t.Run(route.name+" is rate limited", func(t *testing.T) {
			requireRateLimited(t, helper, prober, route.path)
		})
	}
}

func requireServerChosenID(t *testing.T, id string) {
	t.Helper()
	require.GreaterOrEqualf(t, len(id), minShortURLIDLength,
		"short URL id %q is %d characters; a DNS-1123 id needs at least %d characters from [a-z0-9] to hold 128 bits",
		id, len(id), minShortURLIDLength)
}

func requireOtherUserCanRead(t *testing.T, helper *apis.K8sTestHelper, reader apis.User, id, path string) {
	t.Helper()

	got := apis.DoRequest(helper, apis.RequestParams{
		User:   reader,
		Method: http.MethodGet,
		Path:   legacyShortURLPath(id),
	}, &shorturls.ShortUrl{})
	require.Equal(t, http.StatusOK, got.Response.StatusCode, "body: %s", got.Body)
	require.NotNil(t, got.Result)
	require.Equal(t, path, got.Result.Path)
	require.Equal(t, id, got.Result.Uid)

	redirect := apis.DoRequest(helper, apis.RequestParams{
		User:   reader,
		Method: http.MethodGet,
		Path:   "/goto/" + id,
	}, (*struct{})(nil))
	require.Equal(t, http.StatusFound, redirect.Response.StatusCode, "body: %s", redirect.Body)
	require.Contains(t, redirect.Response.Header.Get("Location"), path)
}

func requireChosenNameDoesNotResolve(t *testing.T, helper *apis.K8sTestHelper, reader apis.User, namespace, chosen, path string) {
	t.Helper()

	legacy := apis.DoRequest(helper, apis.RequestParams{
		User:   reader,
		Method: http.MethodGet,
		Path:   legacyShortURLPath(chosen),
	}, &shorturls.ShortUrl{})
	require.NotEqual(t, http.StatusOK, legacy.Response.StatusCode, "body: %s", legacy.Body)
	require.NotContains(t, string(legacy.Body), path)

	app := apis.DoRequest(helper, apis.RequestParams{
		User:   reader,
		Method: http.MethodGet,
		Path:   appCollectionPath(namespace) + "/" + chosen,
	}, &unstructured.Unstructured{})
	require.NotContains(t, string(app.Body), path)
	if app.Response.StatusCode == http.StatusOK && app.Result != nil {
		stored, _, _ := unstructured.NestedString(app.Result.Object, "spec", "path")
		require.NotEqual(t, path, stored)
	}
}

func requireRateLimited(t *testing.T, helper *apis.K8sTestHelper, user apis.User, pathFor func(id string) string) {
	t.Helper()

	seen := make([]int, 0, shortURLLookupLimit)
	for i := 0; i < shortURLLookupLimit; i++ {
		// Ids are valid short UIDs, so format rejection cannot stand in for a limit.
		id := fmt.Sprintf("probe%04d", i)
		res := apis.DoRequest(helper, apis.RequestParams{
			User:   user,
			Method: http.MethodGet,
			Path:   pathFor(id),
		}, (*struct{})(nil))
		code := res.Response.StatusCode
		seen = append(seen, code)
		if code == http.StatusTooManyRequests {
			return
		}
	}
	t.Fatalf("no HTTP 429 within %d lookups, statuses: %v", shortURLLookupLimit, seen)
}

func createLegacyShortURL(t *testing.T, helper *apis.K8sTestHelper, user apis.User, path, uid string) dtos.ShortURL {
	t.Helper()

	body := []byte(fmt.Sprintf(`{"path":%q,"uid":%q}`, path, uid))
	if uid == "" {
		body = []byte(fmt.Sprintf(`{"path":%q}`, path))
	}
	res := apis.DoRequest(helper, apis.RequestParams{
		User:   user,
		Method: http.MethodPost,
		Path:   "/api/short-urls",
		Body:   body,
	}, &dtos.ShortURL{})
	require.Equal(t, http.StatusOK, res.Response.StatusCode, "body: %s", res.Body)
	require.NotNil(t, res.Result)
	require.NotEmpty(t, res.Result.UID)
	return *res.Result
}

func createAppShortURL(t *testing.T, helper *apis.K8sTestHelper, user apis.User, namespace string, metadata map[string]any, path string) unstructured.Unstructured {
	t.Helper()

	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "shorturl.grafana.app/v1beta1",
		"kind":       "ShortURL",
		"metadata":   metadata,
		"spec": map[string]any{
			"path": path,
		},
	}}
	raw, err := obj.MarshalJSON()
	require.NoError(t, err)

	res := apis.DoRequest(helper, apis.RequestParams{
		User:   user,
		Method: http.MethodPost,
		Path:   appCollectionPath(namespace),
		Body:   raw,
	}, &unstructured.Unstructured{})
	require.Truef(t, res.Response.StatusCode == http.StatusOK || res.Response.StatusCode == http.StatusCreated,
		"status %d body %s", res.Response.StatusCode, res.Body)
	require.NotNil(t, res.Result)
	require.NotEmpty(t, res.Result.GetName())
	return *res.Result
}

func legacyShortURLPath(id string) string {
	return "/api/short-urls/" + id
}

func appCollectionPath(namespace string) string {
	return fmt.Sprintf("/apis/shorturl.grafana.app/v1beta1/namespaces/%s/shorturls", namespace)
}
