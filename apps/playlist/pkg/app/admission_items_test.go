package app

import (
	"context"
	"testing"

	"github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/resource"
	"k8s.io/client-go/rest"

	"github.com/grafana/grafana/apps/playlist/pkg/apis/manifestdata"
	playlistv0 "github.com/grafana/grafana/apps/playlist/pkg/apis/playlist/v0alpha1"
	playlistv1 "github.com/grafana/grafana/apps/playlist/pkg/apis/playlist/v1"
)

// maxPlaylistItems is the most items a playlist create or update may store.
// The play page issues one dashboard search per stored item, so an unbounded
// list becomes a burst of searches as soon as the playlist is opened.
const maxPlaylistItems = 100

func TestPlaylistWriteAdmissionCapsItems(t *testing.T) {
	playlistApp := newPlaylistApp(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		version string
		action  resource.AdmissionAction
		items   int
		wantErr bool
	}{
		{name: "v1 create at cap", version: playlistv1.APIVersion, action: resource.AdmissionActionCreate, items: maxPlaylistItems},
		{name: "v1 create over cap", version: playlistv1.APIVersion, action: resource.AdmissionActionCreate, items: maxPlaylistItems + 1, wantErr: true},
		{name: "v1 update at cap", version: playlistv1.APIVersion, action: resource.AdmissionActionUpdate, items: maxPlaylistItems},
		{name: "v1 update over cap", version: playlistv1.APIVersion, action: resource.AdmissionActionUpdate, items: maxPlaylistItems + 1, wantErr: true},
		{name: "v0alpha1 create at cap", version: playlistv0.APIVersion, action: resource.AdmissionActionCreate, items: maxPlaylistItems},
		{name: "v0alpha1 create over cap", version: playlistv0.APIVersion, action: resource.AdmissionActionCreate, items: maxPlaylistItems + 1, wantErr: true},
		{name: "v0alpha1 update at cap", version: playlistv0.APIVersion, action: resource.AdmissionActionUpdate, items: maxPlaylistItems},
		{name: "v0alpha1 update over cap", version: playlistv0.APIVersion, action: resource.AdmissionActionUpdate, items: maxPlaylistItems + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := playlistWithTagItems(tt.version, tt.items)
			err := playlistApp.Validate(ctx, &app.AdmissionRequest{
				Action:  tt.action,
				Kind:    "Playlist",
				Group:   playlistv1.APIGroup,
				Version: tt.version,
				Object:  obj,
			})
			if tt.wantErr && err == nil {
				t.Fatalf("admission accepted a playlist with %d items", tt.items)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("admission rejected a playlist with %d items: %v", tt.items, err)
			}
		})
	}
}

func newPlaylistApp(t *testing.T) app.App {
	t.Helper()
	manifest := manifestdata.LocalManifest().ManifestData
	if manifest == nil {
		t.Fatal("playlist manifest data is nil")
	}
	playlistApp, err := New(app.Config{
		KubeConfig:     rest.Config{},
		ManifestData:   *manifest,
		SpecificConfig: &PlaylistConfig{},
	})
	if err != nil {
		t.Fatalf("new playlist app: %v", err)
	}
	return playlistApp
}

func playlistWithTagItems(version string, count int) resource.Object {
	switch version {
	case playlistv0.APIVersion:
		playlist := playlistv0.NewPlaylist()
		playlist.SetName("wall")
		playlist.Spec.Title = "wall"
		playlist.Spec.Interval = "5m"
		playlist.Spec.Items = make([]playlistv0.PlaylistItem, count)
		for i := range playlist.Spec.Items {
			playlist.Spec.Items[i] = playlistv0.PlaylistItem{
				Type:  playlistv0.PlaylistPlaylistItemTypeDashboardByTag,
				Value: "tag",
			}
		}
		return playlist
	default:
		playlist := playlistv1.NewPlaylist()
		playlist.SetName("wall")
		playlist.Spec.Title = "wall"
		playlist.Spec.Interval = "5m"
		playlist.Spec.Items = make([]playlistv1.PlaylistItem, count)
		for i := range playlist.Spec.Items {
			playlist.Spec.Items[i] = playlistv1.PlaylistItem{
				Type:  playlistv1.PlaylistPlaylistItemTypeDashboardByTag,
				Value: "tag",
			}
		}
		return playlist
	}
}
