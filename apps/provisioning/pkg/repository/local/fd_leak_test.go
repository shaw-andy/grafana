//go:build linux

package local

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
)

// These tests describe the local repository file-descriptor leak.
// calculateFileHash opens every file it hashes and returns without closing it.
// Read and ReadTree both call it, so a directory listing holds one descriptor
// per file until a garbage collection runs the os.File finalizer. The tests
// disable collection so a finalizer cannot hide that. They also require the
// tree walk to reject a file larger than the configured max before opening it,
// including when a symlink's own size is under the cap and its target is not.

func TestLocalRepository_ReadTree_ClosesFiles(t *testing.T) {
	pinGarbageCollection(t)
	root := t.TempDir()
	files := map[string][]byte{
		"a.txt":        []byte("alpha"),
		"nested/b.txt": []byte("beta"),
		"nested/c.txt": []byte("gamma"),
	}
	writeRepoFiles(t, root, files)
	repo := newFDTestRepo(t, root)

	tree, err := repo.ReadTree(context.Background(), "")
	require.NoError(t, err)

	got := map[string]string{}
	for _, entry := range tree {
		if entry.Blob {
			got[entry.Path] = entry.Hash
		}
	}
	for rel, content := range files {
		require.Equal(t, sha1Hex(content), got[rel], "listing must still hash %s", rel)
		require.Zero(t, openCount(t, filepath.Join(root, rel)), "descriptor for %s still open after ReadTree", rel)
	}
}

func TestLocalRepository_ReadTree_RepeatedListingDoesNotAccumulateDescriptors(t *testing.T) {
	pinGarbageCollection(t)
	root := t.TempDir()
	const filesPerListing = 8
	const listings = 4
	for i := range filesPerListing {
		name := "f" + strconv.Itoa(i) + ".txt"
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(name), 0o600))
	}
	repo := newFDTestRepo(t, root)

	for range listings {
		_, err := repo.ReadTree(context.Background(), "")
		require.NoError(t, err)
	}

	for i := range filesPerListing {
		path := filepath.Join(root, "f"+strconv.Itoa(i)+".txt")
		require.Zero(t, openCount(t, path), "descriptors for %s accumulated across listings", path)
	}
}

func TestLocalRepository_Read_ClosesHashDescriptor(t *testing.T) {
	pinGarbageCollection(t)
	root := t.TempDir()
	content := []byte("single-file-body")
	require.NoError(t, os.WriteFile(filepath.Join(root, "one.txt"), content, 0o600))
	repo := newFDTestRepo(t, root)

	for range 3 {
		info, err := repo.Read(context.Background(), "one.txt", "")
		require.NoError(t, err)
		require.Equal(t, content, info.Data)
		require.Equal(t, sha1Hex(content), info.Hash)
	}

	require.Zero(t, openCount(t, filepath.Join(root, "one.txt")), "Read left the hash descriptor open")
}

func TestLocalRepository_ReadTree_ClosesDescriptorWhenHashCopyFails(t *testing.T) {
	pinGarbageCollection(t)
	root := t.TempDir()
	// Walk lstats the symlink, so it is not a directory, and then hashes it.
	// Opening the symlink follows it to the directory, and copying a directory
	// fails. The descriptor opened for that copy must still be closed.
	target := filepath.Join(root, "target-dir")
	require.NoError(t, os.Mkdir(target, 0o750))
	require.NoError(t, os.Symlink("target-dir", filepath.Join(root, "link-to-dir")))
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.txt"), []byte("kept"), 0o600))
	repo := newFDTestRepo(t, root)

	_, err := repo.ReadTree(context.Background(), "")
	require.Error(t, err)
	require.Zero(t, openCount(t, target), "directory descriptor leaked on the hash error path")
	require.Zero(t, openCount(t, filepath.Join(root, "a.txt")), "earlier file descriptor leaked when a later hash failed")
}

func TestLocalRepository_calculateFileHash_ClosesDescriptorWhenCopyFails(t *testing.T) {
	pinGarbageCollection(t)
	root := t.TempDir()
	dir := filepath.Join(root, "not-a-regular-file")
	require.NoError(t, os.Mkdir(dir, 0o750))
	repo := newFDTestRepo(t, root)

	_, _, err := repo.calculateFileHash(dir)
	require.Error(t, err)
	require.Zero(t, openCount(t, dir), "calculateFileHash leaked the descriptor after copy failed")
}

func TestLocalRepository_ReadTree_UnlimitedSizeStillClosesFiles(t *testing.T) {
	pinGarbageCollection(t)
	root := t.TempDir()
	content := bytesOf(64 * 1024)
	require.NoError(t, os.WriteFile(filepath.Join(root, "wide.txt"), content, 0o600))
	repo := newFDTestRepo(t, root)
	repo.WithMaxFileSize(0)

	tree, err := repo.ReadTree(context.Background(), "")
	require.NoError(t, err)
	require.Equal(t, sha1Hex(content), blobHash(t, tree, "wide.txt"))
	require.Zero(t, openCount(t, filepath.Join(root, "wide.txt")))
}

func TestLocalRepository_ReadTree_RefusesOversizedFileBeforeOpen(t *testing.T) {
	pinGarbageCollection(t)
	root := t.TempDir()
	small := []byte("ok")
	big := bytesOf(256 * 1024)
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.txt"), small, 0o600))
	bigPath := filepath.Join(root, "zzz-big.bin")
	require.NoError(t, os.WriteFile(bigPath, big, 0o600))
	repo := newFDTestRepo(t, root)
	repo.WithMaxFileSize(int64(len(small)))

	watch := watchOpens(t, bigPath)
	require.Zero(t, watch.count(), "creating the watch must not record an open")
	_, statErr := os.Stat(bigPath)
	require.NoError(t, statErr)
	require.Zero(t, watch.count(), "stat of the oversized file must not count as opening it")
	probe, probeErr := os.Open(bigPath)
	require.NoError(t, probeErr)
	require.Equal(t, 1, watch.count(), "open watch must observe an open of the oversized file")
	require.NoError(t, probe.Close())

	before := readRChar(t)
	_, err := repo.ReadTree(context.Background(), "")
	readDuringWalk := readRChar(t) - before

	require.Error(t, err)
	require.True(t, apierrors.IsRequestEntityTooLargeError(err), "got %v", err)
	require.Zero(t, watch.count(), "tree walk opened %s before refusing it", bigPath)
	require.Less(t, readDuringWalk, int64(len(big)), "tree walk read the oversized file (%d bytes of process reads)", readDuringWalk)
	require.Zero(t, openCount(t, bigPath))
	require.Zero(t, openCount(t, filepath.Join(root, "a.txt")))
}

func TestLocalRepository_ReadTree_RefusesSymlinkToOversizedTargetBeforeOpen(t *testing.T) {
	pinGarbageCollection(t)
	root := t.TempDir()
	// The symlink's own lstat size is the length of the target name, which is
	// under the cap. The target is not. A check of the walk's FileInfo, then
	// an open of the same path, follows the symlink and hashes the target.
	const targetName = "payload"
	payload := bytesOf(128 * 1024)
	payloadPath := filepath.Join(root, targetName)
	require.NoError(t, os.WriteFile(payloadPath, payload, 0o600))
	linkPath := filepath.Join(root, "link")
	require.NoError(t, os.Symlink(targetName, linkPath))
	linkInfo, err := os.Lstat(linkPath)
	require.NoError(t, err)
	require.Less(t, linkInfo.Size(), int64(64), "symlink lstat size must be under the cap for this test")

	repo := newFDTestRepo(t, root)
	repo.WithMaxFileSize(64)

	watch := watchOpens(t, payloadPath)
	probe, probeErr := os.Open(payloadPath)
	require.NoError(t, probeErr)
	require.Equal(t, 1, watch.count(), "open watch must observe an open of the symlink target")
	require.NoError(t, probe.Close())

	before := readRChar(t)
	_, err = repo.ReadTree(context.Background(), "")
	readDuringWalk := readRChar(t) - before

	require.Error(t, err)
	require.True(t, apierrors.IsRequestEntityTooLargeError(err), "got %v", err)
	require.Zero(t, watch.count(), "tree walk opened the symlink target")
	require.Less(t, readDuringWalk, int64(len(payload)), "tree walk read the symlink target (%d bytes of process reads)", readDuringWalk)
	require.Zero(t, openCount(t, payloadPath))
	require.Zero(t, openCount(t, linkPath))
}

func TestLocalRepository_ReadTree_SucceedsWhenSpareDescriptorsAreFewerThanFiles(t *testing.T) {
	pinGarbageCollection(t)
	root := t.TempDir()
	// One successfully closed file uses a single descriptor. Leaving each file
	// open makes the walk hit the process limit before the last file.
	const spare = 32
	const extra = 40
	for i := range spare + extra {
		name := "n" + strconv.Itoa(i) + ".txt"
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(name), 0o600))
	}
	repo := newFDTestRepo(t, root)

	restore := tightenFileLimit(t, spare)
	t.Cleanup(restore)

	tree, err := repo.ReadTree(context.Background(), "")
	require.NoError(t, err)
	blobs := 0
	for _, entry := range tree {
		if entry.Blob {
			blobs++
		}
	}
	require.Equal(t, spare+extra, blobs)
	for i := range spare + extra {
		require.Zero(t, openCount(t, filepath.Join(root, "n"+strconv.Itoa(i)+".txt")))
	}
}

func newFDTestRepo(t *testing.T, root string) *localRepository {
	t.Helper()
	repo := NewRepository(&provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: "local"},
		Spec: provisioning.RepositorySpec{
			Type: provisioning.LocalRepositoryType,
			Local: &provisioning.LocalRepositoryConfig{
				Path: root,
			},
		},
	}, &LocalFolderResolver{
		PermittedPrefixes: []string{root},
		HomePath:          root,
	}, nil)
	require.NotEmpty(t, repo.path)
	return repo
}

func writeRepoFiles(t *testing.T, root string, files map[string][]byte) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(t, os.WriteFile(path, content, 0o600))
	}
}

func sha1Hex(content []byte) string {
	sum := sha1.Sum(content)
	return hex.EncodeToString(sum[:])
}

func blobHash(t *testing.T, tree []repository.FileTreeEntry, path string) string {
	t.Helper()
	for _, entry := range tree {
		if entry.Path == path && entry.Blob {
			return entry.Hash
		}
	}
	t.Fatalf("blob %s not in tree", path)
	return ""
}

func bytesOf(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// pinGarbageCollection keeps os.File finalizers from closing descriptors the
// repository itself did not close. Collection is restored, then run, after the
// test so later tests are not stuck with the leaked descriptors.
func pinGarbageCollection(t *testing.T) {
	t.Helper()
	prevLimit := debug.SetMemoryLimit(math.MaxInt64)
	prevPercent := debug.SetGCPercent(-1)
	t.Cleanup(func() {
		debug.SetGCPercent(prevPercent)
		debug.SetMemoryLimit(prevLimit)
		runtime.GC()
		runtime.GC()
	})
}

func openCount(t *testing.T, path string) int {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		require.NoError(t, err)
	}
	proc, err := os.Open("/proc/self/fd")
	require.NoError(t, err)
	defer func() { _ = proc.Close() }()
	names, err := proc.Readdirnames(-1)
	require.NoError(t, err)
	self := int(proc.Fd())
	count := 0
	for _, name := range names {
		fd, convErr := strconv.Atoi(name)
		if convErr != nil || fd == self {
			continue
		}
		var got syscall.Stat_t
		if err := syscall.Fstat(fd, &got); err != nil {
			continue
		}
		if got.Dev == st.Dev && got.Ino == st.Ino {
			count++
		}
	}
	return count
}

type openWatch struct {
	t  *testing.T
	fd int
}

func watchOpens(t *testing.T, path string) *openWatch {
	t.Helper()
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	require.NoError(t, err)
	t.Cleanup(func() { _ = syscall.Close(fd) })
	_, err = syscall.InotifyAddWatch(fd, path, syscall.IN_OPEN)
	require.NoError(t, err)
	w := &openWatch{t: t, fd: fd}
	// Drop anything queued while the watch was installed.
	_ = w.count()
	return w
}

func (w *openWatch) count() int {
	w.t.Helper()
	buf := make([]byte, 4096)
	opens := 0
	for {
		n, err := syscall.Read(w.fd, buf)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) {
				return opens
			}
			require.NoError(w.t, err)
		}
		if n == 0 {
			return opens
		}
		offset := 0
		for offset+syscall.SizeofInotifyEvent <= n {
			mask := binary.LittleEndian.Uint32(buf[offset+4 : offset+8])
			length := binary.LittleEndian.Uint32(buf[offset+12 : offset+16])
			require.Zero(w.t, mask&syscall.IN_Q_OVERFLOW, "inotify queue overflowed")
			if mask&syscall.IN_OPEN != 0 {
				opens++
			}
			step := syscall.SizeofInotifyEvent + int(length)
			if step <= 0 || offset+step > n {
				break
			}
			offset += step
		}
	}
}

func readRChar(t *testing.T) int64 {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/io")
	require.NoError(t, err)
	const prefix = "rchar:"
	for line := range splitLines(string(raw)) {
		if len(line) >= len(prefix) && line[:len(prefix)] == prefix {
			n, convErr := strconv.ParseInt(trimSpace(line[len(prefix):]), 10, 64)
			require.NoError(t, convErr)
			return n
		}
	}
	t.Fatal("rchar not found in /proc/self/io")
	return 0
}

func splitLines(s string) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		start := 0
		for i := 0; i < len(s); i++ {
			if s[i] == '\n' {
				if !yield(s[start:i]) {
					return
				}
				start = i + 1
			}
		}
		if start < len(s) {
			yield(s[start:])
		}
	}
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	return s
}

// tightenFileLimit lowers the soft NOFILE limit to the descriptors already
// open plus spare. The previous limit is restored by the returned function.
func tightenFileLimit(t *testing.T, spare int) func() {
	t.Helper()
	proc, err := os.Open("/proc/self/fd")
	require.NoError(t, err)
	names, err := proc.Readdirnames(-1)
	require.NoError(t, err)
	openNow := len(names)
	require.NoError(t, proc.Close())

	var lim syscall.Rlimit
	require.NoError(t, syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim))
	updated := lim
	next := uint64(openNow + spare)
	require.Less(t, next, lim.Max, "hard NOFILE limit leaves no room to tighten the soft limit")
	updated.Cur = next
	require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_NOFILE, &updated))
	return func() {
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}
}
