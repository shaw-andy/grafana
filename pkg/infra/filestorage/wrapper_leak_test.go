package filestorage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"

	"github.com/grafana/grafana/pkg/infra/log"
)

// Stack frame of the helper started by wrapper.List. The helper sends on an
// unbuffered channel and, when the listing is non-empty or returns an error,
// nobody receives, so the helper stays blocked in this frame.
const wrapperListHelperFrame = ".List.func1"

func TestWrapperListOfNonEmptyFolderDoesNotLeakHelperGoroutine(t *testing.T) {
	storage, _ := newDiskStorageWithPublicRoots(t)
	ctx := context.Background()

	// Same options the storage tree passes for a grafana datasource list query.
	opts := &ListOptions{
		Recursive:   false,
		WithFolders: true,
		WithFiles:   true,
		Filter:      NewAllowAllPathFilter(),
	}

	baseline := listHelperGoroutines()
	resp, err := storage.List(ctx, "/img", &Paging{Limit: 100}, opts)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Files)

	requireListHelpersFinished(t, baseline)
}

func TestWrapperListErrorDoesNotLeakHelperGoroutine(t *testing.T) {
	inner := &scriptedStorage{
		listFn: func(context.Context, string, *Paging, *ListOptions) (*ListResponse, error) {
			return nil, errors.New("list failed")
		},
		getFn: func(context.Context, string, *GetFileOptions) (*File, bool, error) {
			return nil, false, errors.New("not a file")
		},
	}
	storage := newWrapper(log.NewNopLogger(), inner, NewAllowAllPathFilter(), "")

	baseline := listHelperGoroutines()
	_, err := storage.List(context.Background(), "/img", &Paging{Limit: 10}, &ListOptions{
		WithFiles:   true,
		WithFolders: true,
	})
	require.Error(t, err)

	requireListHelpersFinished(t, baseline)
}

func TestWrapperListOfNonEmptyFolderDoesNotLeakWhenLookupSucceeds(t *testing.T) {
	// Covers the send of a non-nil file: the helper's Get succeeds and the
	// listing is non-empty, so List returns without receiving.
	inner := &scriptedStorage{
		listFn: func(context.Context, string, *Paging, *ListOptions) (*ListResponse, error) {
			return &ListResponse{
				Files: []*File{{
					FileMetadata: FileMetadata{Name: "icon.png", FullPath: "/img/icon.png"},
				}},
			}, nil
		},
		getFn: func(context.Context, string, *GetFileOptions) (*File, bool, error) {
			return &File{FileMetadata: FileMetadata{Name: "img", FullPath: "/img"}}, true, nil
		},
	}
	storage := newWrapper(log.NewNopLogger(), inner, NewAllowAllPathFilter(), "")

	baseline := listHelperGoroutines()
	resp, err := storage.List(context.Background(), "/img", &Paging{Limit: 10}, &ListOptions{WithFiles: true})
	require.NoError(t, err)
	require.NotEmpty(t, resp.Files)

	requireListHelpersFinished(t, baseline)
}

func TestWrapperDeleteOfNonEmptyFolderDoesNotLeakHelperGoroutine(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "img"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "img", "icon.png"), []byte("png"), 0o644))
	bucket, err := blob.OpenBucket(context.Background(), "file://"+dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = bucket.Close() })
	storage := NewCdkBlobStorage(log.NewNopLogger(), bucket, "", NewAllowAllPathFilter())

	baseline := listHelperGoroutines()
	err = storage.DeleteFolder(context.Background(), "/img", &DeleteFolderOptions{Force: false})
	require.EqualError(t, err, "folder /img is not empty - cant remove it")

	// Refusal happens after List. The file must still be on disk, and the helper must have finished.
	_, err = os.Stat(filepath.Join(dir, "img", "icon.png"))
	require.NoError(t, err)
	requireListHelpersFinished(t, baseline)
}

func TestWrapperListOfEmptyFolderAndFilePathDoNotLeak(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "empty"), 0o750))

	bucket, err := blob.OpenBucket(context.Background(), "file://"+dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = bucket.Close() })
	storage := NewCdkBlobStorage(log.NewNopLogger(), bucket, "", NewAllowAllPathFilter())

	require.NoError(t, storage.Upsert(context.Background(), &UpsertFileCommand{
		Path:     "/img/icon.png",
		Contents: []byte("png"),
	}))

	baseline := listHelperGoroutines()

	empty, err := storage.List(context.Background(), "/empty", &Paging{Limit: 10}, &ListOptions{
		WithFiles:   true,
		WithFolders: true,
	})
	require.NoError(t, err)
	require.Empty(t, empty.Files)

	file, err := storage.List(context.Background(), "/img/icon.png", &Paging{Limit: 10}, &ListOptions{
		WithFiles: true,
	})
	require.NoError(t, err)
	require.Len(t, file.Files, 1)
	require.Equal(t, "/img/icon.png", file.Files[0].FullPath)

	requireListHelpersFinished(t, baseline)
}

func newDiskStorageWithPublicRoots(t *testing.T) (FileStorage, string) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "img"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "img", "icon.png"), []byte("png"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "img", "logo.svg"), []byte("<svg/>"), 0o644))

	bucket, err := blob.OpenBucket(context.Background(), "file://"+dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = bucket.Close() })

	// Roots match the built-in public static disk storage.
	storage := NewCdkBlobStorage(log.NewNopLogger(), bucket, "", NewPathFilter(
		[]string{"/testdata/", "/img/", "/gazetteer/", "/maps/"},
		nil, nil, nil,
	))
	return storage, dir
}

type scriptedStorage struct {
	listFn func(ctx context.Context, folderPath string, paging *Paging, options *ListOptions) (*ListResponse, error)
	getFn  func(ctx context.Context, path string, options *GetFileOptions) (*File, bool, error)
}

func (s *scriptedStorage) Get(ctx context.Context, path string, options *GetFileOptions) (*File, bool, error) {
	return s.getFn(ctx, path, options)
}

func (s *scriptedStorage) Delete(context.Context, string) error { return nil }

func (s *scriptedStorage) Upsert(context.Context, *UpsertFileCommand) error { return nil }

func (s *scriptedStorage) List(ctx context.Context, folderPath string, paging *Paging, options *ListOptions) (*ListResponse, error) {
	return s.listFn(ctx, folderPath, paging, options)
}

func (s *scriptedStorage) CreateFolder(context.Context, string) error { return nil }

func (s *scriptedStorage) DeleteFolder(context.Context, string, *DeleteFolderOptions) error {
	return nil
}

func (s *scriptedStorage) close() error { return nil }

func listHelperGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), wrapperListHelperFrame)
		}
		buf = make([]byte, len(buf)*2)
	}
}

func listHelperStacks() string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, len(buf)*2)
	}
	var b strings.Builder
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(stack, wrapperListHelperFrame) || strings.Contains(stack, "filestorage.(*wrapper).List") {
			b.WriteString(stack)
			b.WriteString("\n\n")
		}
	}
	return b.String()
}

func requireListHelpersFinished(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if extra := listHelperGoroutines() - baseline; extra > 0 {
		t.Fatalf("filestorage wrapper List left %d helper goroutine(s) running\n%s", extra, listHelperStacks())
	}
}
