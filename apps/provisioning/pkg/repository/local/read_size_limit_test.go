package local

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
)

// Local repositories already compare the file size from stat before reading
// the bytes. This locks that behavior so a git fix does not regress it.
func TestLocalReadRejectsOversizedFileBeforeReadingBytes(t *testing.T) {
	dir := t.TempDir()
	const fileBytes = 1 << 20
	const capBytes int64 = 1024
	require.NoError(t, os.WriteFile(filepath.Join(dir, "big.json"), make([]byte, fileBytes), 0o644))

	repo := NewRepository(&provisioning.Repository{
		Spec: provisioning.RepositorySpec{
			Type:  provisioning.LocalRepositoryType,
			Local: &provisioning.LocalRepositoryConfig{Path: dir},
		},
	}, &LocalFolderResolver{PermittedPrefixes: []string{dir}}, nil)
	repo.WithMaxFileSize(capBytes)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	info, err := repo.Read(context.Background(), "big.json", "")

	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	require.Nil(t, info)
	require.Truef(t, apierrors.IsRequestEntityTooLargeError(err), "got %v", err)
	allocated := after.TotalAlloc - before.TotalAlloc
	require.Lessf(t, allocated, uint64(fileBytes/2),
		"local read allocated %d bytes for a %d byte file it should have rejected from stat",
		allocated, fileBytes)
}
