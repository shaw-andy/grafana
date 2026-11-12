package local

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
)

const outsideFileMarker = "outside-file-marker"

// The files API installs this cap before it calls Read. A second stat still
// reports 0 for a fifo or for /dev/zero, so re-checking the size does not make
// the read safe.
const filesAPIMaxBytes int64 = 5 * 1024 * 1024

func TestLocalReadRejectsPathsOutsideRepository(t *testing.T) {
	repoDir, outside := testRepository(t)
	repo := newCappedRepository(t, repoDir)

	secret := filepath.Join(outside, "secret.json")
	require.NoError(t, os.WriteFile(secret, []byte(outsideFileMarker), 0o600))
	missing := filepath.Join(outside, "missing.json")
	directory := filepath.Join(outside, "subdir")
	require.NoError(t, os.Mkdir(directory, 0o700))

	secretWatch := newOpenWatch(t, secret)
	secretInfo, secretErr := repo.Read(context.Background(), traversal(t, repoDir, secret), "")
	missingInfo, missingErr := repo.Read(context.Background(), traversal(t, repoDir, missing), "")
	dirInfo, dirErr := repo.Read(context.Background(), traversal(t, repoDir, directory), "")

	require.False(t, secretWatch.opened(), "Read opened a regular file outside the repository")
	require.Nil(t, secretInfo)
	require.Nil(t, missingInfo)
	require.Nil(t, dirInfo)
	require.Error(t, secretErr)
	require.Error(t, missingErr)
	require.Error(t, dirErr)
	require.NotContains(t, secretErr.Error(), outsideFileMarker)
	// Echoing the caller-supplied path is fine. A difference that remains after
	// that path is removed is the read telling the caller whether the target exists.
	require.Equal(t,
		redactPaths(missingErr.Error(), missing, traversal(t, repoDir, missing)),
		redactPaths(secretErr.Error(), secret, traversal(t, repoDir, secret)))
	require.Equal(t,
		redactPaths(dirErr.Error(), directory, traversal(t, repoDir, directory)),
		redactPaths(missingErr.Error(), missing, traversal(t, repoDir, missing)))

	body, err := os.ReadFile(secret)
	require.NoError(t, err)
	require.Equal(t, outsideFileMarker, string(body))
}

func TestLocalReadDoesNotReadZeroSizeNonRegularFile(t *testing.T) {
	dev, err := os.Stat("/dev/zero")
	require.NoError(t, err)
	require.Zero(t, dev.Size())
	require.False(t, dev.Mode().IsRegular())

	repoDir, outside := testRepository(t)
	repo := newCappedRepository(t, repoDir)

	t.Run("outside the repository", func(t *testing.T) {
		fifo := filepath.Join(outside, "zero-fifo")
		assertZeroSizeReadIsRejected(t, repo, repoDir, fifo)
	})
	t.Run("inside the repository", func(t *testing.T) {
		fifo := filepath.Join(repoDir, "zero-fifo")
		assertZeroSizeReadIsRejected(t, repo, repoDir, fifo)
	})
}

func assertZeroSizeReadIsRejected(t *testing.T, repo *localRepository, repoDir, fifo string) {
	t.Helper()
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	info, err := os.Stat(fifo)
	require.NoError(t, err)
	require.Zero(t, info.Size())
	require.False(t, info.Mode().IsRegular())
	require.LessOrEqual(t, info.Size(), filesAPIMaxBytes)

	watch := newOpenWatch(t, fifo)
	// The request context expires the way the files connector's timeout does.
	// Read must stop because the target is not a contained regular file, not
	// because a later read happens to notice the deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, readErr := repo.Read(ctx, traversal(t, repoDir, fifo), "")
		done <- readErr
	}()

	select {
	case readErr := <-done:
		require.Error(t, readErr)
		require.False(t, watch.opened(), "Read opened a zero-size non-regular file")
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not return; a zero-size non-regular file is read without a bound")
	}
}

func testRepository(t *testing.T) (repoDir, outside string) {
	t.Helper()
	root := t.TempDir()
	repoDir = filepath.Join(root, "repo")
	outside = filepath.Join(root, "outside")
	require.NoError(t, os.Mkdir(repoDir, 0o700))
	require.NoError(t, os.Mkdir(outside, 0o700))
	return repoDir, outside
}

func newCappedRepository(t *testing.T, repoDir string) *localRepository {
	t.Helper()
	cfg := &provisioning.Repository{
		Spec: provisioning.RepositorySpec{
			Type:      provisioning.LocalRepositoryType,
			Workflows: []provisioning.Workflow{provisioning.WriteWorkflow},
			Local:     &provisioning.LocalRepositoryConfig{Path: repoDir},
		},
	}
	repo := NewRepository(cfg, &LocalFolderResolver{
		PermittedPrefixes: []string{repoDir},
		HomePath:          repoDir,
	}, nil)
	repo.WithMaxFileSize(filesAPIMaxBytes)
	return repo
}

func redactPaths(message string, paths ...string) string {
	for _, p := range paths {
		message = strings.ReplaceAll(message, p, "PATH")
		message = strings.ReplaceAll(message, filepath.ToSlash(p), "PATH")
	}
	return message
}

func traversal(t *testing.T, repoDir, target string) string {
	t.Helper()
	rel, err := filepath.Rel(repoDir, target)
	require.NoError(t, err)
	require.NotEqual(t, target, rel)
	return filepath.ToSlash(rel)
}

type openWatch struct {
	t  *testing.T
	fd int
}

func newOpenWatch(t *testing.T, path string) *openWatch {
	t.Helper()
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	require.NoError(t, err)
	t.Cleanup(func() { _ = syscall.Close(fd) })
	_, err = syscall.InotifyAddWatch(fd, path, syscall.IN_OPEN)
	require.NoError(t, err)
	return &openWatch{t: t, fd: fd}
}

func (w *openWatch) opened() bool {
	w.t.Helper()
	buf := make([]byte, 4096)
	opened := false
	for {
		n, err := syscall.Read(w.fd, buf)
		if n >= syscall.SizeofInotifyEvent && consumeOpenEvents(buf[:n]) {
			opened = true
		}
		if err != nil || n < syscall.SizeofInotifyEvent {
			return opened
		}
	}
}

func consumeOpenEvents(buf []byte) bool {
	opened := false
	for off := 0; off+syscall.SizeofInotifyEvent <= len(buf); {
		mask := uint32(buf[off+4]) | uint32(buf[off+5])<<8 | uint32(buf[off+6])<<16 | uint32(buf[off+7])<<24
		nameLen := int(uint32(buf[off+12]) | uint32(buf[off+13])<<8 | uint32(buf[off+14])<<16 | uint32(buf[off+15])<<24)
		if mask&syscall.IN_OPEN != 0 {
			opened = true
		}
		next := off + syscall.SizeofInotifyEvent + nameLen
		if next <= off || next > len(buf) {
			break
		}
		off = next
	}
	return opened
}
