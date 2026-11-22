package dashboardsnapshots

import (
	"fmt"
	"regexp"

	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
)

// Snapshot keys are returned to the browser, which places them in same-origin
// request paths (view, delete). They must never contain separators, dots or
// percent-encoding that could move such a request to another API route.
var isValidSnapshotKey = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString

func validSnapshotKeys(keys ...string) bool {
	for _, key := range keys {
		if key != "" && !isValidSnapshotKey(key) {
			return false
		}
	}
	return true
}

// ValidateRequestedSnapshotKeys checks the optional keys a caller may supply when creating a snapshot.
func ValidateRequestedSnapshotKeys(cmd *CreateDashboardSnapshotCommand) error {
	if !validSnapshotKeys(cmd.Key, cmd.DeleteKey) {
		return ErrInvalidSnapshotKey.Errorf("invalid snapshot key in create request")
	}
	return nil
}

// ValidateExternalSnapshotKeys checks the keys returned by the external snapshot server before they are stored.
func ValidateExternalSnapshotKeys(key, deleteKey string) error {
	if !validSnapshotKeys(key, deleteKey) {
		return ErrExternalSnapshotInvalidKey.Errorf("external snapshot server returned an invalid key or delete key")
	}
	return nil
}

// PrepareLocalSnapshot prepares the command for a local snapshot and returns the snapshot URL.
func PrepareLocalSnapshot(cmd *CreateDashboardSnapshotCommand, originalDashboardURL string) (string, error) {
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
