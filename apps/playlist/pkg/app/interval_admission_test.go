package app

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"

	"github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/resource"
	"github.com/grafana/grafana/apps/playlist/pkg/apis/manifestdata"
	playlistv0 "github.com/grafana/grafana/apps/playlist/pkg/apis/playlist/v0alpha1"
	playlistv1 "github.com/grafana/grafana/apps/playlist/pkg/apis/playlist/v1"
)

// nonPositiveIntervals are the strings PlaylistSrv turns into a delay that is not
// positive. describeInterval parses the count with parseInt, so "0.5s" and "0.0s"
// are 0ms and "-0.1s" is negative zero. Create and update must reject those values
// on every playlist version that shares the admission validator.
var nonPositiveIntervals = []string{"0s", "-1s", "0ms", "-1", "0.5s", "00s", "0.0s", "-0.1s"}

func TestPlaylistAdmissionRejectsNonPositiveInterval(t *testing.T) {
	playlistApp := newPlaylistApp(t)

	for _, interval := range nonPositiveIntervals {
		t.Run("v1/create/"+interval, func(t *testing.T) {
			req := v1Admission(resource.AdmissionActionCreate, interval, "")
			require.Error(t, playlistApp.Validate(context.Background(), req))
			require.Equal(t, interval, req.Object.(*playlistv1.Playlist).Spec.Interval)
		})

		t.Run("v1/update/"+interval, func(t *testing.T) {
			// The stored playlist is a normal 5m rotation. The object being admitted
			// is the update, and that is the interval that must be rejected.
			req := v1Admission(resource.AdmissionActionUpdate, interval, "5m")
			require.Error(t, playlistApp.Validate(context.Background(), req))
			require.Equal(t, interval, req.Object.(*playlistv1.Playlist).Spec.Interval)
			require.Equal(t, "5m", req.OldObject.(*playlistv1.Playlist).Spec.Interval)
		})

		t.Run("v0alpha1/create/"+interval, func(t *testing.T) {
			req := v0Admission(resource.AdmissionActionCreate, interval, "")
			require.Error(t, playlistApp.Validate(context.Background(), req))
			require.Equal(t, interval, req.Object.(*playlistv0.Playlist).Spec.Interval)
		})

		t.Run("v0alpha1/update/"+interval, func(t *testing.T) {
			req := v0Admission(resource.AdmissionActionUpdate, interval, "5m")
			require.Error(t, playlistApp.Validate(context.Background(), req))
			require.Equal(t, interval, req.Object.(*playlistv0.Playlist).Spec.Interval)
			require.Equal(t, "5m", req.OldObject.(*playlistv0.Playlist).Spec.Interval)
		})
	}
}

func TestPlaylistAdmissionAcceptsPositiveInterval(t *testing.T) {
	playlistApp := newPlaylistApp(t)

	for _, interval := range []string{"1s", "5s", "10s", "5m", "1h"} {
		t.Run("v1/create/"+interval, func(t *testing.T) {
			req := v1Admission(resource.AdmissionActionCreate, interval, "")
			require.NoError(t, playlistApp.Validate(context.Background(), req))
		})
		t.Run("v1/update/"+interval, func(t *testing.T) {
			req := v1Admission(resource.AdmissionActionUpdate, interval, "5m")
			require.NoError(t, playlistApp.Validate(context.Background(), req))
		})
		t.Run("v0alpha1/create/"+interval, func(t *testing.T) {
			req := v0Admission(resource.AdmissionActionCreate, interval, "")
			require.NoError(t, playlistApp.Validate(context.Background(), req))
		})
		t.Run("v0alpha1/update/"+interval, func(t *testing.T) {
			req := v0Admission(resource.AdmissionActionUpdate, interval, "5m")
			require.NoError(t, playlistApp.Validate(context.Background(), req))
		})
	}
}

func newPlaylistApp(t *testing.T) app.App {
	t.Helper()
	manifest := manifestdata.LocalManifest()
	require.NotNil(t, manifest.ManifestData)

	playlistApp, err := New(app.Config{
		KubeConfig:     rest.Config{},
		ManifestData:   *manifest.ManifestData,
		SpecificConfig: &PlaylistConfig{EnableReconcilers: false},
	})
	require.NoError(t, err)
	return playlistApp
}

func v1Admission(action resource.AdmissionAction, interval string, oldInterval string) *app.AdmissionRequest {
	kind := playlistv1.PlaylistKind().GroupVersionKind()
	req := &app.AdmissionRequest{
		Action:  action,
		Group:   kind.Group,
		Version: kind.Version,
		Kind:    kind.Kind,
		Object:  v1Playlist(interval),
	}
	if action == resource.AdmissionActionUpdate {
		req.OldObject = v1Playlist(oldInterval)
	}
	return req
}

func v0Admission(action resource.AdmissionAction, interval string, oldInterval string) *app.AdmissionRequest {
	kind := playlistv0.PlaylistKind().GroupVersionKind()
	req := &app.AdmissionRequest{
		Action:  action,
		Group:   kind.Group,
		Version: kind.Version,
		Kind:    kind.Kind,
		Object:  v0Playlist(interval),
	}
	if action == resource.AdmissionActionUpdate {
		req.OldObject = v0Playlist(oldInterval)
	}
	return req
}

func v1Playlist(interval string) *playlistv1.Playlist {
	playlist := playlistv1.NewPlaylist()
	playlist.SetName("wall")
	playlist.Spec.Title = "Wall"
	playlist.Spec.Interval = interval
	playlist.Spec.Items = []playlistv1.PlaylistItem{{
		Type:  playlistv1.PlaylistPlaylistItemTypeDashboardByUid,
		Value: "dash",
	}}
	return playlist
}

func v0Playlist(interval string) *playlistv0.Playlist {
	playlist := playlistv0.NewPlaylist()
	playlist.SetName("wall")
	playlist.Spec.Title = "Wall"
	playlist.Spec.Interval = interval
	playlist.Spec.Items = []playlistv0.PlaylistItem{{
		Type:  playlistv0.PlaylistPlaylistItemTypeDashboardByUid,
		Value: "dash",
	}}
	return playlist
}
