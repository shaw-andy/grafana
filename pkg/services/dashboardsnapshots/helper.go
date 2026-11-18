package dashboardsnapshots

import (
	"fmt"
	"regexp"

	"github.com/grafana/grafana/pkg/apimachinery/errutil"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
)

// Snapshot keys are placed directly into URL paths (view links, delete links and
// k8s object names), so they must never contain separators, dots or escapes that
// a browser could resolve into a different route.
var validSnapshotKey = regexp.MustCompile(`^[A-Za-z0-9_-]{1,190}$`)

var ErrInvalidSnapshotKey = errutil.BadRequest("dashboardsnapshots.invalidKey",
	errutil.WithPublicMessage("Snapshot key and delete key may only contain letters, digits, '-' and '_'"),
)

// ValidateSnapshotKeys rejects caller-supplied keys that are not safe to use as a
// single URL path segment. Empty keys are allowed and are generated later.
func ValidateSnapshotKeys(cmd *CreateDashboardSnapshotCommand) error {
	if cmd.Key != "" && !validSnapshotKey.MatchString(cmd.Key) {
		return ErrInvalidSnapshotKey.Errorf("invalid snapshot key")
	}
	if cmd.DeleteKey != "" && !validSnapshotKey.MatchString(cmd.DeleteKey) {
		return ErrInvalidSnapshotKey.Errorf("invalid snapshot delete key")
	}
	return nil
}

// PrepareLocalSnapshot prepares the command for a local snapshot and returns the snapshot URL.
func PrepareLocalSnapshot(cmd *CreateDashboardSnapshotCommand, originalDashboardURL string) (string, error) {
	if err := ValidateSnapshotKeys(cmd); err != nil {
		return "", err
	}

	cmd.Dashboard.SetNestedField(originalDashboardURL, "snapshot", "originalUrl")

	if cmd.Name == "" {
		cmd.Name = "Unnamed snapshot"
	}

	if cmd.Key == "" {
		key, err := util.GetRandomString(32)
		if err != nil {
			return "", err
		}
		cmd.Key = key
	}

	if cmd.DeleteKey == "" {
		deleteKey, err := util.GetRandomString(32)
		if err != nil {
			return "", err
		}
		cmd.DeleteKey = deleteKey
	}

	return setting.ToAbsUrl("dashboard/snapshot/" + cmd.Key), nil
}

func CreateOriginalDashboardURL(cmd *CreateDashboardSnapshotCommand) (string, error) {
	dashUID := cmd.Dashboard.GetNestedString("uid")
	if ok := util.IsValidShortUID(dashUID); !ok {
		return "", fmt.Errorf("invalid dashboard UID")
	}

	return fmt.Sprintf("/d/%v", dashUID), nil
}
