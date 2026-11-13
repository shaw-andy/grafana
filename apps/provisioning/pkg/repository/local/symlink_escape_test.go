package local

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
)

// outsideMarker is a stand-in for bytes stored outside the repository. It is not a credential.
const outsideMarker = "OUTSIDE-MARKER-f4504840"

// defaultMaxFileSize is conf/defaults.ini provisioning.max_file_size (5 MiB).
const defaultMaxFileSize int64 = 5 * 1024 * 1024

func newSymlinkRepo(t *testing.T, root string) *localRepository {
	t.Helper()
	repo := NewRepository(&provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: "local-repo"},
		Spec: provisioning.RepositorySpec{
			Type: provisioning.LocalRepositoryType,
			Sync: provisioning.SyncOptions{Target: provisioning.SyncTargetTypeFolder},
			Local: &provisioning.LocalRepositoryConfig{
				Path: root,
			},
		},
	}, &LocalFolderResolver{
		PermittedPrefixes: []string{root},
		HomePath:          root,
	}, testMetrics)
	repo.WithMaxFileSize(defaultMaxFileSize)
	return repo
}

func writeOutside(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func requireNoOutsideRead(t *testing.T, data []byte) {
	t.Helper()
	if bytes.Contains(data, []byte(outsideMarker)) {
		t.Fatalf("repository read returned bytes from outside the repository root")
	}
}

func requireOutsideUnchanged(t *testing.T, path string, original []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, got, "operation changed a file outside the repository root")
}

func requireOutsideAbsent(t *testing.T, path string) {
	t.Helper()
	_, err := os.Lstat(path)
	require.ErrorIs(t, err, os.ErrNotExist, "operation created a file outside the repository root")
}

// TestLocalSymlink_ReadFinalLink is the files API read: a name inside the root
// whose final component is a symlink to a file outside the root.
func TestLocalSymlink_ReadFinalLink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := writeOutside(t, outside, "target.txt", []byte(outsideMarker))
	require.NoError(t, os.Symlink(target, filepath.Join(root, "notes.md")))

	info, err := newSymlinkRepo(t, root).Read(context.Background(), "notes.md", "")
	if info != nil {
		requireNoOutsideRead(t, info.Data)
	}
	require.Error(t, err)
}

func TestLocalSymlink_ReadRelativeLink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := writeOutside(t, outside, "target.txt", []byte(outsideMarker))
	rel, err := filepath.Rel(root, target)
	require.NoError(t, err)
	require.NoError(t, os.Symlink(rel, filepath.Join(root, "notes.md")))

	info, err := newSymlinkRepo(t, root).Read(context.Background(), "notes.md", "")
	if info != nil {
		requireNoOutsideRead(t, info.Data)
	}
	require.Error(t, err)
}

func TestLocalSymlink_ReadLinkChain(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := writeOutside(t, outside, "target.txt", []byte(outsideMarker))
	require.NoError(t, os.Symlink(target, filepath.Join(root, "hop")))
	require.NoError(t, os.Symlink("hop", filepath.Join(root, "notes.md")))

	info, err := newSymlinkRepo(t, root).Read(context.Background(), "notes.md", "")
	if info != nil {
		requireNoOutsideRead(t, info.Data)
	}
	require.Error(t, err)
}

func TestLocalSymlink_ReadThroughDirectoryLink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeOutside(t, outside, "notes.md", []byte(outsideMarker))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "linked")))

	info, err := newSymlinkRepo(t, root).Read(context.Background(), "linked/notes.md", "")
	if info != nil {
		requireNoOutsideRead(t, info.Data)
	}
	require.Error(t, err)
}

func TestLocalSymlink_ReadUnderDefaultSizeLimit(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	payload := bytes.Repeat([]byte(outsideMarker), 40)
	require.Less(t, int64(len(payload)), defaultMaxFileSize)
	target := writeOutside(t, outside, "target.txt", payload)
	require.NoError(t, os.Symlink(target, filepath.Join(root, "notes.md")))

	info, err := newSymlinkRepo(t, root).Read(context.Background(), "notes.md", "")
	if info != nil {
		requireNoOutsideRead(t, info.Data)
	}
	require.Error(t, err)
}

func TestLocalSymlink_ReadTreeHashesTarget(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	payload := []byte(outsideMarker)
	target := writeOutside(t, outside, "target.txt", payload)
	require.NoError(t, os.Symlink(target, filepath.Join(root, "notes.md")))
	sum := sha1.Sum(payload)
	outsideHash := hex.EncodeToString(sum[:])

	entries, err := newSymlinkRepo(t, root).ReadTree(context.Background(), "")
	if err != nil {
		return
	}
	for _, entry := range entries {
		require.NotEqual(t, outsideHash, entry.Hash, "listing hashed the symlink target")
	}
}

func TestLocalSymlink_ReadTreeHashesTargetLargerThanMax(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	payload := bytes.Repeat([]byte(outsideMarker), 4096)
	require.Greater(t, int64(len(payload)), int64(1024))
	target := writeOutside(t, outside, "target.txt", payload)
	require.NoError(t, os.Symlink(target, filepath.Join(root, "notes.md")))
	sum := sha1.Sum(payload)
	outsideHash := hex.EncodeToString(sum[:])

	repo := newSymlinkRepo(t, root)
	repo.WithMaxFileSize(1024)
	entries, err := repo.ReadTree(context.Background(), "")
	if err != nil {
		return
	}
	for _, entry := range entries {
		require.NotEqual(t, outsideHash, entry.Hash, "listing copied the symlink target with no size cap")
	}
}

func TestLocalSymlink_ReadPipeDoesNotBlock(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	fifo := filepath.Join(outside, "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	require.NoError(t, os.Symlink(fifo, filepath.Join(root, "notes.md")))

	assertReturnsWithoutOpeningPipe(t, fifo, func() error {
		_, err := newSymlinkRepo(t, root).Read(context.Background(), "notes.md", "")
		return err
	})
}

func TestLocalSymlink_ReadTreePipeDoesNotBlock(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	fifo := filepath.Join(outside, "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	require.NoError(t, os.Symlink(fifo, filepath.Join(root, "notes.md")))

	assertReturnsWithoutOpeningPipe(t, fifo, func() error {
		_, err := newSymlinkRepo(t, root).ReadTree(context.Background(), "")
		return err
	})
}

// assertReturnsWithoutOpeningPipe fails when fn follows the symlink and blocks
// in open or copy. A writer is attached only after the deadline, and kept
// available until fn returns: Read opens the target once to load it and again
// to hash it, and each open waits until a writer is present.
func assertReturnsWithoutOpeningPipe(t *testing.T, fifo string, fn func() error) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = fn()
	}()

	select {
	case <-done:
		return
	case <-time.After(500 * time.Millisecond):
	}

	stop := make(chan struct{})
	var writerDone sync.WaitGroup
	writerDone.Add(1)
	go func() {
		defer writerDone.Done()
		for {
			select {
			case <-stop:
				return
			case <-done:
				return
			default:
			}
			writer, err := os.OpenFile(fifo, os.O_WRONLY, 0)
			if err != nil {
				continue
			}
			_ = writer.Close()
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	close(stop)
	writerDone.Wait()
	t.Fatal("open followed a symlink to a pipe and blocked")
}

func TestLocalSymlink_UpdateWritesTarget(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	original := []byte(outsideMarker)
	target := writeOutside(t, outside, "target.txt", original)
	require.NoError(t, os.Symlink(target, filepath.Join(root, "dash.json")))

	err := newSymlinkRepo(t, root).Update(context.Background(), "dash.json", "", []byte("replacement"), "")
	requireOutsideUnchanged(t, target, original)
	require.Error(t, err)
}

func TestLocalSymlink_UpdateThroughDirectoryLink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	original := []byte(outsideMarker)
	target := writeOutside(t, outside, "dash.json", original)
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "linked")))

	err := newSymlinkRepo(t, root).Update(context.Background(), "linked/dash.json", "", []byte("replacement"), "")
	requireOutsideUnchanged(t, target, original)
	require.Error(t, err)
}

func TestLocalSymlink_WriteWritesTarget(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	original := []byte(outsideMarker)
	target := writeOutside(t, outside, "target.txt", original)
	require.NoError(t, os.Symlink(target, filepath.Join(root, "dash.json")))

	err := newSymlinkRepo(t, root).Write(context.Background(), "dash.json", "", []byte("replacement"), "")
	requireOutsideUnchanged(t, target, original)
	require.Error(t, err)
}

func TestLocalSymlink_WriteThroughDirectoryLink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "linked")))
	target := filepath.Join(outside, "dash.json")

	err := newSymlinkRepo(t, root).Write(context.Background(), "linked/dash.json", "", []byte("replacement"), "")
	requireOutsideAbsent(t, target)
	require.Error(t, err)
}

func TestLocalSymlink_CreateDanglingLinkCreatesTarget(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "created.json")
	require.NoError(t, os.Symlink(target, filepath.Join(root, "created.json")))

	err := newSymlinkRepo(t, root).Create(context.Background(), "created.json", "", []byte("created"), "")
	requireOutsideAbsent(t, target)
	require.Error(t, err)
}

func TestLocalSymlink_CreateThroughDirectoryLink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "linked")))
	target := filepath.Join(outside, "created.json")

	err := newSymlinkRepo(t, root).Create(context.Background(), "linked/created.json", "", []byte("created"), "")
	requireOutsideAbsent(t, target)
	require.Error(t, err)
}

func TestLocalSymlink_MkdirThroughDirectoryLink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "linked")))
	created := filepath.Join(outside, "newdir")

	err := newSymlinkRepo(t, root).Create(context.Background(), "linked/newdir/", "", nil, "")
	_, statErr := os.Lstat(created)
	require.ErrorIs(t, statErr, os.ErrNotExist, "mkdir followed a directory symlink")
	require.Error(t, err)
}

func TestLocalSymlink_DeleteFinalLinkLeavesTarget(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	original := []byte(outsideMarker)
	target := writeOutside(t, outside, "target.txt", original)
	require.NoError(t, os.Symlink(target, filepath.Join(root, "notes.md")))

	_ = newSymlinkRepo(t, root).Delete(context.Background(), "notes.md", "", "")
	requireOutsideUnchanged(t, target, original)
}

func TestLocalSymlink_DeleteThroughDirectoryLink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	original := []byte(outsideMarker)
	target := writeOutside(t, outside, "secret.json", original)
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "linked")))

	err := newSymlinkRepo(t, root).Delete(context.Background(), "linked/secret.json", "", "")
	requireOutsideUnchanged(t, target, original)
	require.Error(t, err)
}

func TestLocalSymlink_MoveFromOutsideThroughDirectoryLink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	original := []byte(outsideMarker)
	target := writeOutside(t, outside, "secret.json", original)
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "linked")))

	err := newSymlinkRepo(t, root).Move(context.Background(), "linked/secret.json", "stolen.json", "", "")
	requireOutsideUnchanged(t, target, original)
	require.Error(t, err)
	_, statErr := os.Lstat(filepath.Join(root, "stolen.json"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestLocalSymlink_MoveCreatesFileOutsideThroughDirectoryLink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "local.json"), []byte("local"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "linked")))
	target := filepath.Join(outside, "planted.json")

	err := newSymlinkRepo(t, root).Move(context.Background(), "local.json", "linked/planted.json", "", "")
	requireOutsideAbsent(t, target)
	_, stillThere := os.Lstat(filepath.Join(root, "local.json"))
	require.NoError(t, stillThere, "move removed the source while writing outside the repository")
	require.Error(t, err)
}

func TestLocalSymlink_MoveOntoOutsideThroughDirectoryLink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	original := []byte(outsideMarker)
	target := writeOutside(t, outside, "victim.json", original)
	require.NoError(t, os.WriteFile(filepath.Join(root, "local.json"), []byte("local"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "linked")))

	err := newSymlinkRepo(t, root).Move(context.Background(), "local.json", "linked/victim.json", "", "")
	requireOutsideUnchanged(t, target, original)
	require.Error(t, err)
}

func TestLocalSymlink_ReplacedRepositoryRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	require.NoError(t, os.Mkdir(root, 0o750))
	repo := newSymlinkRepo(t, root)

	outside := t.TempDir()
	writeOutside(t, outside, "notes.md", []byte(outsideMarker))
	require.NoError(t, os.Rename(root, root+"-real"))
	require.NoError(t, os.Symlink(outside, root))
	t.Cleanup(func() {
		_ = os.Remove(root)
		_ = os.Rename(root+"-real", root)
	})

	info, err := repo.Read(context.Background(), "notes.md", "")
	if info != nil {
		requireNoOutsideRead(t, info.Data)
	}
	require.Error(t, err)
}

// TestLocalSymlink_SwapBetweenCheckAndUse fails if a containment check looks up
// the path and a later open looks it up again. The directory entry is exchanged
// with a symlink to an outside directory between those two lookups.
func TestLocalSymlink_SwapBetweenCheckAndUse(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	original := []byte(outsideMarker)
	writeOutside(t, outside, "notes.md", original)

	realSub := filepath.Join(root, "real-sub")
	require.NoError(t, os.Mkdir(realSub, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(realSub, "notes.md"), []byte("inside"), 0o600))
	link := filepath.Join(root, "sub")
	require.NoError(t, os.Rename(realSub, link))
	holding := filepath.Join(root, "holding")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if err := os.Rename(link, holding); err != nil {
				continue
			}
			if err := os.Symlink(outside, link); err != nil {
				_ = os.Rename(holding, link)
				continue
			}
			_ = os.Remove(link)
			_ = os.Rename(holding, link)
		}
	}()

	repo := newSymlinkRepo(t, root)
	deadline := time.Now().Add(time.Second)
	var leaked string
	for time.Now().Before(deadline) && leaked == "" {
		info, err := repo.Read(context.Background(), "sub/notes.md", "")
		if err == nil && info != nil && bytes.Contains(info.Data, []byte(outsideMarker)) {
			leaked = "read"
			break
		}
		_ = repo.Update(context.Background(), "sub/notes.md", "", []byte("WRITTEN-THROUGH-LINK"), "")
		got, readErr := os.ReadFile(filepath.Join(outside, "notes.md"))
		if readErr == nil && !bytes.Equal(got, original) {
			leaked = "update"
			break
		}
	}
	cancel()
	wg.Wait()
	// Put the real directory back so TempDir cleanup does not follow a leftover symlink.
	_ = os.Remove(link)
	_ = os.Rename(holding, link)

	require.Empty(t, leaked, "operation followed a symlink swapped in after the path check")
	requireOutsideUnchanged(t, filepath.Join(outside, "notes.md"), original)
}
