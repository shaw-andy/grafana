package playlist

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"

	playlistapp "github.com/grafana/grafana/pkg/registry/apps/playlist"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// maxPlaylistItems is the largest item array a playlist write may store.
// Search loads stored playlist bodies before it applies a page cap, so an
// uncapped item array is how a writer forces the list path to hold a large body.
const maxPlaylistItems = 256

// TestIntegrationPlaylistSearchLimitAndItemCap exercises the legacy playlist
// routes a signed-in viewer and editor can call.
//
// GET /api/playlists?limit=1 must return at most one playlist. POST and PUT
// /api/playlists, and the playlist app create, must reject an item list longer
// than maxPlaylistItems. These assertions fail until that bound exists.
func TestIntegrationPlaylistSearchLimitAndItemCap(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	helper := apis.NewK8sTestHelper(t, testinfra.GrafanaOpts{
		AppModeProduction: true,
		DisableAnonymous:  true,
	})

	editor := helper.Org1.Editor
	viewer := helper.Org1.Viewer

	for i := range 3 {
		status, body := postPlaylist(t, helper, editor, smallPlaylist(fmt.Sprintf("listed-%d", i)))
		require.Equalf(t, http.StatusOK, status, "create playlist: %s", body)
	}

	t.Run("viewer search honors limit", func(t *testing.T) {
		rsp := apis.DoRequest(helper, apis.RequestParams{
			User:   viewer,
			Method: http.MethodGet,
			Path:   "/api/playlists?limit=1",
		}, &playlistapp.Playlists{})
		require.Equal(t, http.StatusOK, rsp.Response.StatusCode, string(rsp.Body))
		require.NotNil(t, rsp.Result)
		require.LessOrEqual(t, len(*rsp.Result), 1,
			"GET /api/playlists?limit=1 returned %d playlists", len(*rsp.Result))
	})

	oversized := playlistWithItems(maxPlaylistItems + 1)

	t.Run("legacy create rejects an oversized item list", func(t *testing.T) {
		status, _ := postPlaylist(t, helper, editor, oversized)
		require.GreaterOrEqual(t, status, 400, "create status %d", status)
		require.Less(t, status, 500, "create status %d", status)
	})

	t.Run("legacy update rejects an oversized item list", func(t *testing.T) {
		status, body := postPlaylist(t, helper, editor, smallPlaylist("to-update"))
		require.Equal(t, http.StatusOK, status, string(body))
		created := &playlistapp.PlaylistDTO{}
		require.NoError(t, json.Unmarshal(body, created))
		require.NotEmpty(t, created.Uid)

		raw, err := json.Marshal(map[string]any{
			"name":     "to-update",
			"interval": "5s",
			"items":    itemList(maxPlaylistItems + 1),
		})
		require.NoError(t, err)
		rsp := apis.DoRequest(helper, apis.RequestParams{
			User:   editor,
			Method: http.MethodPut,
			Path:   "/api/playlists/" + created.Uid,
			Body:   raw,
		}, &playlistapp.PlaylistDTO{})
		require.GreaterOrEqual(t, rsp.Response.StatusCode, 400, "update status %d", rsp.Response.StatusCode)
		require.Less(t, rsp.Response.StatusCode, 500, "update status %d", rsp.Response.StatusCode)

		// The playlist that existed before the rejected update is unchanged.
		got := apis.DoRequest(helper, apis.RequestParams{
			User:   viewer,
			Method: http.MethodGet,
			Path:   "/api/playlists/" + created.Uid + "/items",
		}, &[]playlistapp.PlaylistItemDTO{})
		require.Equal(t, http.StatusOK, got.Response.StatusCode, string(got.Body))
		require.NotNil(t, got.Result)
		require.Len(t, *got.Result, 1)
	})

	t.Run("app create rejects an oversized item list", func(t *testing.T) {
		client := helper.GetResourceClient(apis.ResourceClientArgs{
			User: editor,
			GVR:  gvr,
		})
		const name = "oversized-app"
		obj := playlistObject(name, maxPlaylistItems+1)
		_, err := client.Resource.Create(context.Background(), obj, metav1.CreateOptions{})
		require.Error(t, err)
		_, err = client.Resource.Get(context.Background(), name, metav1.GetOptions{})
		require.True(t, apierrors.IsNotFound(err), "app create persisted the playlist before refusing it")
	})

	t.Run("app update rejects an oversized item list", func(t *testing.T) {
		client := helper.GetResourceClient(apis.ResourceClientArgs{
			User: editor,
			GVR:  gvr,
		})
		const name = "app-to-update"
		created, err := client.Resource.Create(context.Background(), playlistObject(name, 1), metav1.CreateOptions{})
		require.NoError(t, err)

		updated := playlistObject(name, maxPlaylistItems+1)
		updated.SetResourceVersion(created.GetResourceVersion())
		_, err = client.Resource.Update(context.Background(), updated, metav1.UpdateOptions{})
		require.Error(t, err)

		got, err := client.Resource.Get(context.Background(), name, metav1.GetOptions{})
		require.NoError(t, err)
		items, found, err := unstructured.NestedSlice(got.Object, "spec", "items")
		require.NoError(t, err)
		require.True(t, found)
		require.Len(t, items, 1)
		require.Equal(t, created.GetResourceVersion(), got.GetResourceVersion())
	})

	t.Run("app patch rejects an oversized item list", func(t *testing.T) {
		client := helper.GetResourceClient(apis.ResourceClientArgs{
			User: editor,
			GVR:  gvr,
		})
		const name = "app-to-patch"
		created, err := client.Resource.Create(context.Background(), playlistObject(name, 1), metav1.CreateOptions{})
		require.NoError(t, err)

		raw, err := json.Marshal([]map[string]any{{
			"op":    "replace",
			"path":  "/spec/items",
			"value": itemList(maxPlaylistItems + 1),
		}})
		require.NoError(t, err)
		_, err = client.Resource.Patch(context.Background(), name, k8stypes.JSONPatchType, raw, metav1.PatchOptions{})
		require.Error(t, err)

		got, err := client.Resource.Get(context.Background(), name, metav1.GetOptions{})
		require.NoError(t, err)
		items, found, err := unstructured.NestedSlice(got.Object, "spec", "items")
		require.NoError(t, err)
		require.True(t, found)
		require.Len(t, items, 1)
		require.Equal(t, created.GetResourceVersion(), got.GetResourceVersion())
	})

	t.Run("v0alpha1 create rejects an oversized item list", func(t *testing.T) {
		client := helper.GetResourceClient(apis.ResourceClientArgs{
			User: editor,
			GVR: schema.GroupVersionResource{
				Group:    gvr.Group,
				Version:  "v0alpha1",
				Resource: gvr.Resource,
			},
		})
		const name = "oversized-v0"
		obj := playlistObject(name, maxPlaylistItems+1)
		obj.SetAPIVersion("playlist.grafana.app/v0alpha1")
		_, err := client.Resource.Create(context.Background(), obj, metav1.CreateOptions{})
		require.Error(t, err)
		_, err = client.Resource.Get(context.Background(), name, metav1.GetOptions{})
		require.True(t, apierrors.IsNotFound(err), "v0alpha1 create persisted the playlist before refusing it")
	})
}

func playlistObject(name string, items int) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "playlist.grafana.app/v1",
		"kind":       "Playlist",
		"metadata": map[string]any{
			"name": name,
		},
		"spec": map[string]any{
			"title":    name,
			"interval": "5s",
			"items":    itemList(items),
		},
	}}
}

func postPlaylist(t *testing.T, helper *apis.K8sTestHelper, user apis.User, payload []byte) (int, []byte) {
	t.Helper()
	rsp := apis.DoRequest(helper, apis.RequestParams{
		User:   user,
		Method: http.MethodPost,
		Path:   "/api/playlists",
		Body:   payload,
	}, &playlistapp.PlaylistDTO{})
	return rsp.Response.StatusCode, rsp.Body
}

func smallPlaylist(name string) []byte {
	raw, err := json.Marshal(map[string]any{
		"name":     name,
		"interval": "5s",
		"items":    itemList(1),
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func playlistWithItems(n int) []byte {
	raw, err := json.Marshal(map[string]any{
		"name":     "oversized",
		"interval": "5s",
		"items":    itemList(n),
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func itemList(n int) []map[string]string {
	items := make([]map[string]string, n)
	for i := range items {
		items[i] = map[string]string{
			"type":  "dashboard_by_uid",
			"value": fmt.Sprintf("dash-%d", i),
		}
	}
	return items
}
