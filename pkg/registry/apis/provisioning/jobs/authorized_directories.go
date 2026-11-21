package jobs

import (
	"encoding/json"
	"fmt"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
)

// AnnoAuthorizedDirectories records, for every directory a delete job removes, the
// fingerprint of the directory contents that the job creator was authorized to delete.
// It is written by job admission from the same repository read that was authorized and
// cannot be set or changed by the creator. The delete worker refuses to remove a
// directory on the configured branch whose contents no longer match.
const AnnoAuthorizedDirectories = "provisioning.grafana.app/authorizedDirectories"

// SetAuthorizedDirectories replaces the authorized directory fingerprints on the job.
func SetAuthorizedDirectories(job *provisioning.Job, fingerprints map[string]string) error {
	if len(fingerprints) == 0 {
		delete(job.Annotations, AnnoAuthorizedDirectories)
		return nil
	}
	value, err := json.Marshal(fingerprints)
	if err != nil {
		return fmt.Errorf("encode authorized directories: %w", err)
	}
	if job.Annotations == nil {
		job.Annotations = map[string]string{}
	}
	job.Annotations[AnnoAuthorizedDirectories] = string(value)
	return nil
}

// AuthorizedDirectories returns the authorized directory fingerprints recorded on the job.
func AuthorizedDirectories(job provisioning.Job) (map[string]string, error) {
	value, ok := job.Annotations[AnnoAuthorizedDirectories]
	if !ok {
		return map[string]string{}, nil
	}
	fingerprints := map[string]string{}
	if err := json.Unmarshal([]byte(value), &fingerprints); err != nil {
		return nil, fmt.Errorf("decode authorized directories: %w", err)
	}
	return fingerprints, nil
}
