package local

import (
	"context"
	"path"

	// Git still uses sha1 for the most part: https://git-scm.com/docs/hash-function-transition
	//nolint:gosec
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/safepath"
)

type LocalFolderResolver struct {
	PermittedPrefixes []string
	HomePath          string
}

type InvalidLocalFolderError struct {
	Path           string
	AdditionalInfo string
}

var (
	_ error               = (*InvalidLocalFolderError)(nil)
	_ apierrors.APIStatus = (*InvalidLocalFolderError)(nil)
)

func (e *InvalidLocalFolderError) Error() string {
	return fmt.Sprintf("the path given ('%s') is invalid for a local repository (%s)", e.Path, e.AdditionalInfo)
}

func (e *InvalidLocalFolderError) Status() metav1.Status {
	return metav1.Status{
		Status:  metav1.StatusFailure,
		Code:    http.StatusBadRequest,
		Reason:  metav1.StatusReasonBadRequest,
		Message: e.Error(),
	}
}

func (r *LocalFolderResolver) LocalPath(p string) (string, error) {
	if len(r.PermittedPrefixes) == 0 {
		return "", &InvalidLocalFolderError{p, "no permitted prefixes were configured"}
	}

	originalPath := p
	if !path.IsAbs(p) {
		p = safepath.Join(r.HomePath, p)
	} else {
		p = safepath.Clean(p)
	}

	for _, permitted := range r.PermittedPrefixes {
		if safepath.InDir(p, permitted) {
			return p, nil
		}
	}
	return "", &InvalidLocalFolderError{originalPath, "the path matches no permitted prefix"}
}

var (
	_ repository.Repository = (*localRepository)(nil)
	_ repository.Writer     = (*localRepository)(nil)
	_ repository.Reader     = (*localRepository)(nil)
)

type localRepository struct {
	config   *provisioning.Repository
	resolver *LocalFolderResolver
	metrics  *repository.OperationRecorder

	// validated path that can be read if not empty
	path     string
	maxBytes atomic.Int64

	// identity of the repository directory when the repository was built, nil
	// if it did not exist yet
	rootInfo fs.FileInfo
}

func NewRepository(config *provisioning.Repository, resolver *LocalFolderResolver, metrics *repository.OperationMetrics) *localRepository {
	r := &localRepository{
		config:   config,
		resolver: resolver,
		metrics:  metrics.Recorder(config.Spec.Type),
	}

	if config.Spec.Local != nil {
		r.path, _ = resolver.LocalPath(config.Spec.Local.Path)
		if r.path != "" && !safepath.IsDir(r.path) {
			r.path += "/"
		}

		for i, permitted := range r.resolver.PermittedPrefixes {
			r.resolver.PermittedPrefixes[i] = safepath.Clean(permitted)
		}

		if root, err := r.openRoot(false); err == nil {
			r.rootInfo, _ = root.Stat(".")
			_ = root.Close()
		}
	}

	return r
}

// rootLocation splits the repository path into the permitted prefix directory
// that contains it and the repository path relative to that directory.
func (r *localRepository) rootLocation() (anchor string, rel string, err error) {
	repoPath := safepath.Clean(r.path)
	if r.resolver == nil || repoPath == "" {
		return "", "", &InvalidLocalFolderError{r.path, "no repository path is configured"}
	}

	for _, permitted := range r.resolver.PermittedPrefixes {
		permitted = safepath.Clean(permitted)
		if !safepath.InDir(repoPath, permitted) {
			continue
		}

		switch {
		case permitted == "" && safepath.IsAbs(repoPath):
			anchor = "/"
		case permitted == "":
			anchor = "."
		case repoPath == permitted || strings.HasPrefix(repoPath, permitted+"/"):
			anchor = permitted
		default:
			// The prefix ends inside a path element, so anchor at its parent.
			anchor = path.Dir(permitted)
		}

		switch {
		case repoPath == anchor:
			rel = "."
		case anchor == ".":
			rel = repoPath
		default:
			rel = strings.TrimPrefix(strings.TrimPrefix(repoPath, anchor), "/")
		}
		return anchor, rel, nil
	}

	return "", "", &InvalidLocalFolderError{r.path, "the path matches no permitted prefix"}
}

// openRoot opens the repository directory beneath the permitted prefix that
// contains it. All file access must go through the returned root: it resolves
// every path, including symlink targets, without leaving the directory, so a
// symlink placed in the repository cannot reach files outside of it.
func (r *localRepository) openRoot(create bool) (*os.Root, error) {
	anchor, rel, err := r.rootLocation()
	if err != nil {
		return nil, err
	}

	if create {
		if err := os.MkdirAll(anchor, 0700); err != nil {
			return nil, fmt.Errorf("create permitted path: %w", err)
		}
	}
	prefix, err := os.OpenRoot(anchor)
	if err != nil {
		return nil, err
	}
	defer func() { _ = prefix.Close() }()

	if create {
		if err := prefix.MkdirAll(rel, 0700); err != nil {
			return nil, fmt.Errorf("create repository path: %w", err)
		}
	}
	root, err := prefix.OpenRoot(rel)
	if err != nil {
		return nil, err
	}

	if r.rootInfo != nil {
		info, err := root.Stat(".")
		if err != nil {
			_ = root.Close()
			return nil, fmt.Errorf("stat repository path: %w", err)
		}
		if !os.SameFile(r.rootInfo, info) {
			_ = root.Close()
			return nil, apierrors.NewConflict(schema.GroupResource{}, r.path, errors.New("the repository path was replaced"))
		}
	}

	return root, nil
}

// openInRoot opens name inside root without blocking on FIFOs or devices, so
// that callers can check the file type of what was opened before using it.
func openInRoot(root *os.Root, name string, flag int, perm os.FileMode) (*os.File, fs.FileInfo, error) {
	f, err := root.OpenFile(name, flag|openNonBlocking, perm)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

func notRegularFileError(p string) error {
	return apierrors.NewBadRequest(fmt.Sprintf("the path '%s' is not a regular file", p))
}

// writeRegularFile writes data to name inside root, refusing anything that is
// not a regular file once opened.
func writeRegularFile(root *os.Root, name, displayPath string, data []byte, flag int) error {
	f, info, err := openInRoot(root, name, os.O_WRONLY|flag, 0600)
	if errors.Is(err, syscall.EISDIR) {
		return apierrors.NewBadRequest("path exists but it is a directory")
	} else if err != nil {
		return err
	}
	if info.IsDir() {
		_ = f.Close()
		return apierrors.NewBadRequest("path exists but it is a directory")
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return notRegularFileError(displayPath)
	}
	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (r *localRepository) Config() *provisioning.Repository {
	return r.config
}

// Test implements provisioning.Repository.
// NOTE: Validate has been called (and passed) before this function should be called
func (r *localRepository) Test(ctx context.Context) (*provisioning.TestResults, error) {
	path := field.NewPath("spec", "local", "path")
	if r.config.Spec.Local.Path == "" {
		return repository.FromFieldError(field.Required(path, "no path is configured")), nil
	}

	_, err := r.resolver.LocalPath(r.config.Spec.Local.Path)
	if err != nil {
		return repository.FromFieldError(field.Invalid(path, r.config.Spec.Local.Path, err.Error())), nil
	}

	_, err = os.Stat(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return repository.FromFieldError(field.NotFound(path, r.config.Spec.Local.Path)), nil
	}

	return &provisioning.TestResults{
		Code:    http.StatusOK,
		Success: true,
	}, nil
}

// Test implements provisioning.Repository.
func (r *localRepository) validateRequest(ref string) error {
	if ref != "" {
		return apierrors.NewBadRequest("local repository does not support ref")
	}

	return nil
}

// resolvePath converts a repository path into a name relative to the
// repository root, for use with the root returned by openRoot. It blocks path
// traversal (e.g. "../") that can be introduced by unsanitized resource or
// folder titles during export. Symlinks are handled by the root itself.
func (r *localRepository) resolvePath(p string) (string, error) {
	// Normalize OS-specific separators and collapse the path first, so a
	// Windows-style traversal like "..\..\etc" is resolved here instead of
	// being interpreted by the filesystem.
	clean := strings.TrimPrefix(safepath.Clean(p), "/")
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", apierrors.NewBadRequest(fmt.Sprintf("the path '%s' escapes the repository root", p))
	}
	if clean == "" {
		return ".", nil
	}
	return clean, nil
}

// ReadResource implements provisioning.Repository.
func (r *localRepository) Read(ctx context.Context, filePath string, ref string) (out *repository.FileInfo, err error) {
	start := time.Now()
	defer func() { r.metrics.Read(start, out, err) }()

	if err := r.validateRequest(ref); err != nil {
		return nil, err
	}

	name, err := r.resolvePath(filePath)
	if err != nil {
		return nil, err
	}
	root, err := r.openRoot(false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, repository.ErrFileNotFound
	} else if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	f, info, err := openInRoot(root, name, os.O_RDONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, repository.ErrFileNotFound
	} else if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if info.IsDir() {
		return &repository.FileInfo{
			Path: filePath,
			Modified: &metav1.Time{
				Time: info.ModTime(),
			},
		}, nil
	}

	if !info.Mode().IsRegular() {
		return nil, notRegularFileError(filePath)
	}

	max := r.maxBytes.Load()
	if max > 0 && info.Size() > max {
		return nil, apierrors.NewRequestEntityTooLargeError(
			fmt.Sprintf("file %q is %d bytes; max allowed is %d bytes", filePath, info.Size(), max),
		)
	}

	var reader io.Reader = f
	if max > 0 {
		// The file can grow after it was checked.
		reader = io.LimitReader(f, max+1)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if max > 0 && int64(len(data)) > max {
		return nil, apierrors.NewRequestEntityTooLargeError(
			fmt.Sprintf("file %q is larger than the max allowed %d bytes", filePath, max),
		)
	}

	//nolint:gosec
	sum := sha1.Sum(data)

	return &repository.FileInfo{
		Path: filePath,
		Data: data,
		Hash: hex.EncodeToString(sum[:]),
		Modified: &metav1.Time{
			Time: info.ModTime(),
		},
	}, nil
}

func (r *localRepository) WithMaxFileSize(maxBytes int64) {
	r.maxBytes.Store(maxBytes)
}

// ReadResource implements provisioning.Repository.
func (r *localRepository) ReadTree(ctx context.Context, ref string) (tree []repository.FileTreeEntry, err error) {
	start := time.Now()
	defer func() { r.metrics.List(start, err) }()

	if err := r.validateRequest(ref); err != nil {
		return nil, err
	}

	// Return an empty list when folder does not exist
	root, err := r.openRoot(false)
	if errors.Is(err, fs.ErrNotExist) {
		return []repository.FileTreeEntry{}, nil
	} else if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	entries := make([]repository.FileTreeEntry, 0, 100)
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil // skip the root file
		}

		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			entries = append(entries, repository.FileTreeEntry{
				// ensure trailing slash for directories
				Path: path + "/",
				Size: info.Size(),
			})
			return nil
		}

		hash, size, err := calculateFileHash(root, path)
		if err != nil {
			return fmt.Errorf("read and calculate hash of path %s: %w", path, err)
		}
		entries = append(entries, repository.FileTreeEntry{
			Path: path,
			Size: size,
			Hash: hash,
			Blob: true,
		})
		return nil
	})

	return entries, err
}

func calculateFileHash(root *os.Root, name string) (string, int64, error) {
	file, info, err := openInRoot(root, name, os.O_RDONLY, 0)
	if err != nil {
		return "", 0, fmt.Errorf("open file: %w", err)
	}
	defer func() { _ = file.Close() }()
	if !info.Mode().IsRegular() {
		return "", 0, notRegularFileError(name)
	}

	// TODO: Define what hashing algorithm we want to use for the entire repository. Maybe a config option?
	hasher := sha1.New()
	// TODO: context-aware io.Copy? Is that even possible with a reasonable impl?
	size, err := io.Copy(hasher, file)
	if err != nil {
		return "", 0, fmt.Errorf("copy file: %w", err)
	}
	// NOTE: EncodeToString (& hex.Encode for that matter) return lower-case hex.
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

func (r *localRepository) Create(ctx context.Context, filepath string, ref string, data []byte, comment string) (err error) {
	start := time.Now()
	defer func() { r.metrics.Write(start, len(data), err) }()

	if err := r.validateRequest(ref); err != nil {
		return err
	}

	name, err := r.resolvePath(filepath)
	if err != nil {
		return err
	}
	root, err := r.openRoot(true)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	_, err = root.Lstat(name)
	if !errors.Is(err, fs.ErrNotExist) {
		if err != nil {
			return apierrors.NewInternalError(fmt.Errorf("failed to check if file exists: %w", err))
		}
		return apierrors.NewAlreadyExists(schema.GroupResource{}, filepath)
	}

	if safepath.IsDir(filepath) {
		if data != nil {
			return apierrors.NewBadRequest("data cannot be provided for a directory")
		}

		if err := root.MkdirAll(name, 0700); err != nil {
			return apierrors.NewInternalError(fmt.Errorf("failed to create path: %w", err))
		}

		return nil
	}

	if err := root.MkdirAll(path.Dir(name), 0700); err != nil {
		return apierrors.NewInternalError(fmt.Errorf("failed to create path: %w", err))
	}

	err = writeRegularFile(root, name, filepath, data, os.O_CREATE|os.O_EXCL)
	if errors.Is(err, fs.ErrExist) {
		return apierrors.NewAlreadyExists(schema.GroupResource{}, filepath)
	}
	return err
}

func (r *localRepository) Update(ctx context.Context, path string, ref string, data []byte, comment string) (err error) {
	start := time.Now()
	defer func() { r.metrics.Write(start, len(data), err) }()

	if err := r.validateRequest(ref); err != nil {
		return err
	}

	name, err := r.resolvePath(path)
	if err != nil {
		return err
	}
	if safepath.IsDir(path) {
		return apierrors.NewBadRequest("cannot update a directory")
	}

	root, err := r.openRoot(false)
	if errors.Is(err, fs.ErrNotExist) {
		return repository.ErrFileNotFound
	} else if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	err = writeRegularFile(root, name, path, data, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return repository.ErrFileNotFound
	}
	return err
}

func (r *localRepository) Write(ctx context.Context, fpath, ref string, data []byte, comment string) (err error) {
	start := time.Now()
	defer func() { r.metrics.Write(start, len(data), err) }()

	if err := r.validateRequest(ref); err != nil {
		return err
	}

	name, err := r.resolvePath(fpath)
	if err != nil {
		return err
	}
	root, err := r.openRoot(true)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	if safepath.IsDir(fpath) {
		return root.MkdirAll(name, 0700)
	}

	if err := root.MkdirAll(path.Dir(name), 0700); err != nil {
		return apierrors.NewInternalError(fmt.Errorf("failed to create path: %w", err))
	}

	return writeRegularFile(root, name, fpath, data, os.O_CREATE)
}

func (r *localRepository) Delete(ctx context.Context, path string, ref string, comment string) (err error) {
	start := time.Now()
	defer func() { r.metrics.Delete(start, err) }()

	if err := r.validateRequest(ref); err != nil {
		return err
	}

	name, err := r.resolvePath(path)
	if err != nil {
		return err
	}
	root, err := r.openRoot(false)
	if errors.Is(err, fs.ErrNotExist) {
		return repository.ErrFileNotFound
	} else if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	switch {
	case safepath.IsDir(path) && name == ".":
		err = removeContents(root)
	case safepath.IsDir(path):
		// if it is a folder, delete all of its contents
		err = root.RemoveAll(name)
	default:
		err = root.Remove(name)
	}
	if err != nil {
		if os.IsNotExist(err) {
			return repository.ErrFileNotFound
		}
		return err
	}

	return nil
}

func (r *localRepository) Move(ctx context.Context, oldPath, newPath, ref, comment string) (err error) {
	start := time.Now()
	defer func() { r.metrics.Move(start, err) }()

	if err := r.validateRequest(ref); err != nil {
		return err
	}

	oldName, err := r.resolvePath(oldPath)
	if err != nil {
		return err
	}
	newName, err := r.resolvePath(newPath)
	if err != nil {
		return err
	}
	root, err := r.openRoot(false)
	if errors.Is(err, fs.ErrNotExist) {
		return repository.ErrFileNotFound
	} else if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	// Check if source exists
	sourceInfo, err := root.Stat(oldName)
	if errors.Is(err, fs.ErrNotExist) {
		return repository.ErrFileNotFound
	} else if err != nil {
		return fmt.Errorf("check source: %w", err)
	}

	// Check if destination already exists
	if _, err := root.Lstat(newName); !errors.Is(err, fs.ErrNotExist) {
		if err != nil {
			return fmt.Errorf("check destination: %w", err)
		}
		return repository.ErrFileAlreadyExists
	}

	// Validate move types
	sourceIsDir := sourceInfo.IsDir()
	targetIsDir := safepath.IsDir(newPath)

	if sourceIsDir != targetIsDir {
		return apierrors.NewBadRequest("cannot move between file and directory types")
	}

	// Create the parent directory of the destination, but not the destination
	// itself (Rename will create it)
	if destParent := path.Dir(newName); destParent != "." {
		if err := root.MkdirAll(destParent, 0700); err != nil {
			return fmt.Errorf("create destination directory: %w", err)
		}
	}

	// Move the file or directory
	if err := root.Rename(oldName, newName); err != nil {
		return fmt.Errorf("move: %w", err)
	}

	return nil
}

// removeContents deletes everything inside root while keeping root itself.
func removeContents(root *os.Root) error {
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := root.RemoveAll(entry.Name()); err != nil {
			return err
		}
	}
	return nil
}
