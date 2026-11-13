package app

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/grafana/grafana-app-sdk/app"
	playlistv0alpha1 "github.com/grafana/grafana/apps/playlist/pkg/apis/playlist/v0alpha1"
	playlistv1 "github.com/grafana/grafana/apps/playlist/pkg/apis/playlist/v1"
)

// MaxPlaylistItems is the most items a playlist may store. Playback runs a
// dashboard search for every item, so this bounds the work a single playlist
// can cause each time it is opened.
const MaxPlaylistItems = 100

func validatePlaylist(_ context.Context, req *app.AdmissionRequest) error {
	var (
		name  string
		items int
	)
	switch p := req.Object.(type) {
	case *playlistv1.Playlist:
		name, items = p.GetName(), len(p.Spec.Items)
	case *playlistv0alpha1.Playlist:
		name, items = p.GetName(), len(p.Spec.Items)
	default:
		return apierrors.NewBadRequest(fmt.Sprintf("expected Playlist object, got %T", req.Object))
	}

	if items > MaxPlaylistItems {
		return apierrors.NewInvalid(
			playlistv1.PlaylistKind().GroupVersionKind().GroupKind(),
			name,
			field.ErrorList{field.TooMany(field.NewPath("spec", "items"), items, MaxPlaylistItems)},
		)
	}
	return nil
}
