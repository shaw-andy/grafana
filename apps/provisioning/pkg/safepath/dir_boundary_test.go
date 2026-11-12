package safepath

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestInDirRequiresDirectoryBoundary is the directory-boundary contract for InDir.
// A path is inside dir only when the two are equal, or the path continues with a
// separator, after trailing slashes are ignored. A sibling whose name merely
// begins with dir must not match.
func TestInDirRequiresDirectoryBoundary(t *testing.T) {
	const prefix = "/var/lib/grafana/devenv/dev-dashboards"

	tests := []struct {
		name     string
		filePath string
		dir      string
		want     bool
	}{
		{
			name:     "sibling without separator is outside",
			filePath: prefix + "-without-uid",
			dir:      prefix,
			want:     false,
		},
		{
			name:     "file in a sibling is outside",
			filePath: prefix + "-without-uid/file.txt",
			dir:      prefix,
			want:     false,
		},
		{
			name:     "sibling stays outside when the prefix keeps its slash",
			filePath: prefix + "-without-uid/",
			dir:      prefix + "/",
			want:     false,
		},
		{
			name:     "shorter path that is only a string prefix of the directory is outside",
			filePath: "/var/lib/grafana/devenv/dev",
			dir:      prefix,
			want:     false,
		},
		{
			name:     "the directory itself is inside",
			filePath: prefix,
			dir:      prefix,
			want:     true,
		},
		{
			name:     "the directory itself is inside when only the prefix has a slash",
			filePath: prefix,
			dir:      prefix + "/",
			want:     true,
		},
		{
			name:     "the directory itself is inside when only the path has a slash",
			filePath: prefix + "/",
			dir:      prefix,
			want:     true,
		},
		{
			name:     "child file is inside a prefix that has no slash",
			filePath: prefix + "/nested/file.txt",
			dir:      prefix,
			want:     true,
		},
		{
			name:     "child directory is inside",
			filePath: prefix + "/nested/",
			dir:      prefix + "/",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, InDir(tt.filePath, tt.dir))
		})
	}
}
