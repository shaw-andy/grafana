package resources

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/safepath"
)

// EntriesInDirectory returns the tree entries strictly below dir. Directory entries
// are returned with a trailing slash. The root directory ("", "." or "/") contains
// every entry.
func EntriesInDirectory(tree []repository.FileTreeEntry, dir string) []repository.FileTreeEntry {
	dir = safepath.EnsureTrailingSlash(dir)
	out := make([]repository.FileTreeEntry, 0)
	for _, entry := range tree {
		p := strings.TrimPrefix(entry.Path, "/")
		if !entry.Blob {
			p = safepath.EnsureTrailingSlash(p)
		}
		if p == "" || p == dir || !strings.HasPrefix(p, dir) {
			continue
		}
		entry.Path = p
		out = append(out, entry)
	}
	return out
}

// DirectoryFingerprint identifies the contents of a directory: the path of every nested
// entry and the content hash of every nested file. Two reads of a directory produce the
// same fingerprint only when no entry below it was added, removed or changed.
func DirectoryFingerprint(entries []repository.FileTreeEntry) string {
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Blob {
			lines = append(lines, "f\x00"+entry.Path+"\x00"+entry.Hash)
		} else {
			lines = append(lines, "d\x00"+entry.Path)
		}
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, line := range lines {
		_, _ = h.Write([]byte(line))
		_, _ = h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}
