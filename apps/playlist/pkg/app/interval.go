package app

import (
	"fmt"
	"math"
	"regexp"
	"strconv"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/resource"
	playlistv0alpha1 "github.com/grafana/grafana/apps/playlist/pkg/apis/playlist/v0alpha1"
	playlistv1 "github.com/grafana/grafana/apps/playlist/pkg/apis/playlist/v1"
)

const (
	minIntervalMs int64 = 1000
	// Browsers run a setTimeout delay above a signed 32-bit integer immediately.
	maxIntervalMs int64 = math.MaxInt32
)

// The playlist player truncates the count to an integer and treats a value with
// no unit as seconds, so the same is done here to measure the delay it will use.
var intervalPattern = regexp.MustCompile(`^(\d+)(?:\.\d+)?(ms|[Mwdhmsy])?$`)

var intervalUnitMs = map[string]int64{
	"":   1000,
	"ms": 1,
	"s":  1000,
	"m":  60 * 1000,
	"h":  60 * 60 * 1000,
	"d":  24 * 60 * 60 * 1000,
	"w":  7 * 24 * 60 * 60 * 1000,
	"M":  30 * 24 * 60 * 60 * 1000,
	"y":  365 * 24 * 60 * 60 * 1000,
}

func validatePlaylistInterval(req *app.AdmissionRequest) error {
	if req.Action != resource.AdmissionActionCreate && req.Action != resource.AdmissionActionUpdate {
		return nil
	}
	switch obj := req.Object.(type) {
	case *playlistv1.Playlist:
		return validateInterval(obj.Spec.Interval)
	case *playlistv0alpha1.Playlist:
		return validateInterval(obj.Spec.Interval)
	default:
		return apierrors.NewBadRequest(fmt.Sprintf("expected a playlist object, got %T", req.Object))
	}
}

func validateInterval(interval string) error {
	invalid := apierrors.NewBadRequest(fmt.Sprintf("invalid playlist interval %q: must be a duration such as 30s or 5m, between 1s and 24d", interval))

	matches := intervalPattern.FindStringSubmatch(interval)
	if matches == nil {
		return invalid
	}
	count, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return invalid
	}
	unitMs, ok := intervalUnitMs[matches[2]]
	if !ok || count > maxIntervalMs/unitMs {
		return invalid
	}
	if ms := count * unitMs; ms < minIntervalMs || ms > maxIntervalMs {
		return invalid
	}
	return nil
}
