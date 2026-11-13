package playlist

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	playlistapp "github.com/grafana/grafana/pkg/registry/apps/playlist"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

const (
	playlistTitle     = "Org playlist titles are private"
	playlistInterval  = "45s"
	dashboardByUID    = "dash-uid-private"
	dashboardByTag    = "dash-tag-private"
	dashboardByID     = "424242"
	playlistLegacyAPI = "/api/playlists"
)

// TestIntegrationNoneRoleCannotReadPlaylistsWhenRBACDisabled starts Grafana with
// playlistsRBAC left at its shipped default (off). An organization administrator
// creates a playlist. A signed-in user with organization role None, and a
// service account with organization role None, must not be able to list or read
// that playlist through the legacy API or the app API. The response must not
// include the playlist title, interval, or dashboard references.
func TestIntegrationNoneRoleCannotReadPlaylistsWhenRBACDisabled(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	helper := apis.NewK8sTestHelper(t, testinfra.GrafanaOpts{
		AppModeProduction: true,
		DisableAnonymous:  true,
	})

	legacyPayload := `{
		"name": "` + playlistTitle + `",
		"interval": "` + playlistInterval + `",
		"items": [
			{"type": "dashboard_by_uid", "value": "` + dashboardByUID + `"},
			{"type": "dashboard_by_tag", "value": "` + dashboardByTag + `"},
			{"type": "dashboard_by_id", "value": "` + dashboardByID + `"}
		]
	}`
	created := apis.DoRequest(helper, apis.RequestParams{
		User:   helper.Org1.Admin,
		Method: http.MethodPost,
		Path:   playlistLegacyAPI,
		Body:   []byte(legacyPayload),
	}, &playlistapp.Playlist{})
	require.Equal(t, http.StatusOK, created.Response.StatusCode, "admin create body: %s", created.Body)
	require.NotNil(t, created.Result)
	uid := created.Result.UID
	require.NotEmpty(t, uid)
	t.Cleanup(func() {
		apis.DoRequest(helper, apis.RequestParams{
			User:   helper.Org1.Admin,
			Method: http.MethodDelete,
			Path:   playlistLegacyAPI + "/" + uid,
		}, &playlistapp.PlaylistDTO{})
	})

	// Viewer still receives the playlist while the RBAC toggle is off, which is
	// the org-role authorizer. This pins the object the None identities must not see.
	viewerList := apis.DoRequest(helper, apis.RequestParams{
		User: helper.Org1.Viewer,
		Path: playlistLegacyAPI,
	}, &playlistapp.Playlists{})
	require.Equal(t, http.StatusOK, viewerList.Response.StatusCode, "viewer list body: %s", viewerList.Body)
	require.Contains(t, string(viewerList.Body), playlistTitle)
	require.Contains(t, string(viewerList.Body), playlistInterval)

	noneSA := helper.CreateServiceAccount(helper.Org1.Admin, "none-playlist-reader", helper.Org1.OrgID, org.RoleNone)
	noneSAToken := helper.CreateServiceAccountToken(helper.Org1.Admin, noneSA.Id, helper.Org1.OrgID, "none-playlist-reader", 0)

	readers := []struct {
		name    string
		user    apis.User
		headers map[string]string
		token   string
	}{
		{name: "user", user: helper.Org1.None},
		{name: "serviceaccount", headers: map[string]string{"Authorization": "Bearer " + noneSAToken}, token: noneSAToken},
	}

	for _, reader := range readers {
		t.Run(reader.name, func(t *testing.T) {
			t.Run("legacy list", func(t *testing.T) {
				rsp := apis.DoRequest(helper, apis.RequestParams{
					User:    reader.user,
					Headers: reader.headers,
					Path:    playlistLegacyAPI,
				}, &playlistapp.Playlists{})
				requireNoPlaylistLeak(t, rsp.Response.StatusCode, rsp.Body)
			})

			t.Run("legacy get", func(t *testing.T) {
				rsp := apis.DoRequest(helper, apis.RequestParams{
					User:    reader.user,
					Headers: reader.headers,
					Path:    playlistLegacyAPI + "/" + uid,
				}, &playlistapp.PlaylistDTO{})
				requireNoPlaylistLeak(t, rsp.Response.StatusCode, rsp.Body)
			})

			t.Run("legacy items", func(t *testing.T) {
				rsp := apis.DoRequest(helper, apis.RequestParams{
					User:    reader.user,
					Headers: reader.headers,
					Path:    playlistLegacyAPI + "/" + uid + "/items",
				}, &[]playlistapp.PlaylistItemDTO{})
				requireNoPlaylistLeak(t, rsp.Response.StatusCode, rsp.Body)
			})

			for _, gvr := range []schema.GroupVersionResource{
				{Group: "playlist.grafana.app", Version: "v1", Resource: "playlists"},
				{Group: "playlist.grafana.app", Version: "v0alpha1", Resource: "playlists"},
			} {
				t.Run(gvr.Version, func(t *testing.T) {
					args := apis.ResourceClientArgs{GVR: gvr, Namespace: "default"}
					if reader.token != "" {
						args.ServiceAccountToken = reader.token
					} else {
						args.User = reader.user
					}
					client := helper.GetResourceClient(args).Resource

					t.Run("get", func(t *testing.T) {
						got, err := client.Get(context.Background(), uid, metav1.GetOptions{})
						require.Nil(t, got)
						requireForbidden(t, err)
					})

					t.Run("list", func(t *testing.T) {
						got, err := client.List(context.Background(), metav1.ListOptions{})
						require.Nil(t, got)
						requireForbidden(t, err)
					})

					t.Run("watch", func(t *testing.T) {
						ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
						defer cancel()
						watcher, err := client.Watch(ctx, metav1.ListOptions{
							FieldSelector: "metadata.name=" + uid,
						})
						if watcher != nil {
							watcher.Stop()
						}
						require.Nil(t, watcher)
						requireForbidden(t, err)
					})

					t.Run("get status", func(t *testing.T) {
						got, err := client.Get(context.Background(), uid, metav1.GetOptions{}, "status")
						require.Nil(t, got)
						requireForbidden(t, err)
					})
				})
			}
		})
	}
}

func requireForbidden(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	require.Truef(t, apierrors.IsForbidden(err), "expected forbidden, got %v", err)
}

func requireNoPlaylistLeak(t *testing.T, status int, body []byte) {
	t.Helper()
	text := string(body)
	require.Equalf(t, http.StatusForbidden, status, "body: %s", text)
	for _, secret := range []string{playlistTitle, playlistInterval, dashboardByUID, dashboardByTag, dashboardByID} {
		require.Falsef(t, strings.Contains(text, secret), "response leaked %q: %s", secret, text)
	}
}
