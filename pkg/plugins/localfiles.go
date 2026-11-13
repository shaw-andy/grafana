package plugins

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var (
	_ fs.File = &LocalFile{}

	_ FS = &LocalFS{}
	_ FS = &StaticFS{}
)

// LocalFS is a plugins.FS that allows accessing files on the local file system.
type LocalFS struct {
	// basePath is the basePath that will be prepended to all the files to get their absolute path.
	basePath string

	// resolvedBasePath is basePath with symbolic links resolved when the LocalFS was created.
	// Files are always opened beneath it, so re-pointing basePath later does not change which directory is served.
	resolvedBasePath string
}

// NewLocalFS returns a new LocalFS that can access any file in the specified base path on the filesystem.
// basePath must use os-specific path separator for Open() to work properly.
func NewLocalFS(basePath string) LocalFS {
	return LocalFS{basePath: basePath, resolvedBasePath: resolvePath(basePath)}
}

func resolvePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}

// openRoot opens the base directory resolved when the LocalFS was created. Its last element is opened beneath
// its parent, so swapping the directory for a symbolic link cannot point it outside that parent.
func (f LocalFS) openRoot() (*os.Root, error) {
	base := f.resolvedBasePath
	if base == "" {
		base = resolvePath(f.basePath)
	}
	parent, name := filepath.Dir(base), filepath.Base(base)
	if parent == base {
		return os.OpenRoot(base)
	}
	parentRoot, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	defer func() { _ = parentRoot.Close() }()
	return parentRoot.OpenRoot(name)
}

func (f LocalFS) Type() FSType {
	return FSTypeLocal
}

// fileIsAllowed takes an absolute path to a file and an os.FileInfo for that file, and it checks if access to that
// file is allowed or not. Access to a file is allowed if the file is in the FS's Base() directory, and if it's a
// symbolic link it should not end up outside the plugin's directory.
func (f LocalFS) fileIsAllowed(basePath string, absolutePath string, info os.FileInfo) (bool, error) {
	upperLevelPrefix := ".." + string(filepath.Separator)
	if info.Mode()&os.ModeSymlink == os.ModeSymlink {
		symlinkPath, err := filepath.EvalSymlinks(absolutePath)
		if err != nil {
			return false, err
		}

		symlink, err := os.Stat(symlinkPath)
		if err != nil {
			return false, err
		}

		// verify that symlinked file is within plugin directory
		p, err := filepath.Rel(basePath, symlinkPath)
		if err != nil {
			return false, err
		}
		if p == ".." || strings.HasPrefix(p, upperLevelPrefix) {
			return false, fmt.Errorf("file '%s' not inside of plugin directory", p)
		}

		// skip adding symlinked directories
		if symlink.IsDir() {
			return false, nil
		}
	}

	// skip directories
	if info.IsDir() {
		return false, nil
	}

	// verify that file is within plugin directory
	file, err := filepath.Rel(f.Base(), absolutePath)
	if err != nil {
		return false, err
	}
	if strings.HasPrefix(file, upperLevelPrefix) {
		return false, fmt.Errorf("file '%s' not inside of plugin directory", file)
	}
	return true, nil
}

func (f LocalFS) Rel(p string) (string, error) {
	return filepath.Rel(f.basePath, p)
}

// walkFunc returns a filepath.WalkFunc that accumulates absolute file paths into acc by walking over f.Base().
// f.fileIsAllowed is used as WalkFunc, see its documentation for more information on which files are collected.
func (f LocalFS) walkFunc(basePath string, acc map[string]struct{}) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		ok, err := f.fileIsAllowed(basePath, path, info)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		acc[path] = struct{}{}
		return nil
	}
}

// Open opens the specified file on the local filesystem.
// The provided name must be a relative file name that uses os-specific path separators.
// The function returns the corresponding fs.File for accessing the file on the local filesystem.
// If a nil error is returned, the caller should take care of calling Close() the returned fs.File.
// If the file does not exist, or resolves (through symbolic links) to a location outside the base path,
// ErrFileNotExist is returned.
func (f LocalFS) Open(name string) (fs.File, error) {
	cleanPath, err := CleanRelativePath(name)
	if err != nil {
		return nil, err
	}
	// The file is resolved and opened relative to a handle on the base directory, so symbolic links cannot
	// lead outside of it, and the returned file is bound to the descriptor that passed that check: replacing
	// the name afterwards does not change what is read.
	root, err := f.openRoot()
	if err != nil {
		return nil, ErrFileNotExist
	}
	defer func() { _ = root.Close() }()

	file, err := root.Open(cleanPath)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, ErrPluginFileRead
		}
		return nil, ErrFileNotExist
	}
	fi, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, ErrPluginFileRead
	}
	if !fi.Mode().IsRegular() {
		_ = file.Close()
		return nil, ErrFileNotExist
	}
	return &LocalFile{f: file}, nil
}

// Base returns the base path for the LocalFS.
// The returned string uses os-specific path separator.
func (f LocalFS) Base() string {
	return f.basePath
}

// Files returns a slice of all the relative file paths on the LocalFS.
// The returned strings can be passed to Open() to open those files.
// The returned strings use os-specific path separator.
func (f LocalFS) Files() ([]string, error) {
	// Accumulate all files into filesMap by calling f.collectFilesFunc, which will write into the accumulator.
	// Those are absolute because filepath.Walk uses absolute file paths.
	absFilePaths := make(map[string]struct{})
	if err := filepath.Walk(f.basePath, f.walkFunc(f.Base(), absFilePaths)); err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}
	// Convert the accumulator into a slice of relative path strings
	relFiles := make([]string, 0, len(absFilePaths))
	base := f.Base()
	for fn := range absFilePaths {
		relPath, err := filepath.Rel(base, fn)
		if err != nil {
			return nil, err
		}
		clenRelPath, err := CleanRelativePath(relPath)
		if err != nil {
			continue
		}
		relFiles = append(relFiles, clenRelPath)
	}
	return relFiles, nil
}

// Remove removes a plugin from the local filesystem by deleting all files in the folder.
// It returns ErrUninstallInvalidPluginDir is the plugin does not contain plugin.json nor dist/plugin.json.
func (f LocalFS) Remove() error {
	// extra security check to ensure we only remove a directory that looks like a plugin
	if _, err := os.Stat(filepath.Join(f.basePath, "plugin.json")); os.IsNotExist(err) {
		if _, err = os.Stat(filepath.Join(f.basePath, "dist/plugin.json")); os.IsNotExist(err) {
			return ErrUninstallInvalidPluginDir
		}
	}
	return os.RemoveAll(f.basePath)
}

// staticFilesMap is a set-like map that contains files that can be accessed from a plugins.FS.
type staticFilesMap map[string]struct{}

// isAllowed returns true if the provided path is allowed.
// path is a string accepted by an FS Open() method.
func (a staticFilesMap) isAllowed(path string) bool {
	_, ok := a[path]
	return ok
}

// newStaticFilesMap creates a new staticFilesMap from a list of allowed file paths.
func newStaticFilesMap(files ...string) staticFilesMap {
	m := staticFilesMap(make(map[string]struct{}, len(files)))
	for _, k := range files {
		m[k] = struct{}{}
	}
	return m
}

// StaticFS wraps an FS and allows accessing only the files in the allowList.
// This is a more secure implementation of a FS suitable for production environments.
// The keys of the allow list must be in the same format used by the underlying FS' Open() method.
type StaticFS struct {
	FS

	// staticFilesMap is a map of allowed paths (accepted by FS.Open())
	staticFilesMap staticFilesMap
}

// NewStaticFS returns a new StaticFS that can access the files on an underlying FS,
// but only if they are also specified in a static list, which is constructed when creating the object
// by calling Files() on the underlying FS.
func NewStaticFS(fs FS) (StaticFS, error) {
	files, err := fs.Files()
	if err != nil {
		return StaticFS{}, err
	}
	return StaticFS{
		FS:             fs,
		staticFilesMap: newStaticFilesMap(files...),
	}, nil
}

func (f StaticFS) Type() FSType {
	return f.FS.Type()
}

// Open checks that name is an allowed file and, if so, it returns a fs.File to access it, by calling the
// underlying FS' Open() method.
// If access is denied, the function returns ErrFileNotExist.
func (f StaticFS) Open(name string) (fs.File, error) {
	// Ensure access to the file is allowed
	if !f.staticFilesMap.isAllowed(name) {
		return nil, ErrFileNotExist
	}
	// Use the wrapped FS to access the file
	return f.FS.Open(name)
}

// Files returns a slice of all static file paths relative to the base path.
func (f StaticFS) Files() ([]string, error) {
	files := make([]string, 0, len(f.staticFilesMap))
	for fn := range f.staticFilesMap {
		files = append(files, fn)
	}
	return files, nil
}

func (f StaticFS) Remove() error {
	if remover, ok := f.FS.(FSRemover); ok {
		if err := remover.Remove(); err != nil {
			return err
		}
	}
	return nil
}

// LocalFile implements a fs.File for accessing the local filesystem.
// It wraps a file opened by LocalFS.Open and never re-resolves the file by its path.
type LocalFile struct {
	f *os.File
}

// Stat returns a FileInfo describing the file.
// It returns ErrFileNotExist if the file was never opened, or ErrPluginFileRead if another error occurs.
func (p *LocalFile) Stat() (fs.FileInfo, error) {
	if p.f == nil {
		return nil, ErrFileNotExist
	}
	fi, err := p.f.Stat()
	if err != nil {
		return nil, ErrPluginFileRead
	}
	return fi, nil
}

// Read reads up to len(b) bytes from the File and stores them in b.
// It returns the number of bytes read and any error encountered.
// At end of file, Read returns 0, io.EOF.
// The file is not closed at the end of the read operation. If a non-nil error is returned, it
// must be manually closed by the caller by calling Close().
func (p *LocalFile) Read(b []byte) (int, error) {
	if p.f == nil {
		return 0, ErrFileNotExist
	}
	return p.f.Read(b)
}

// Close closes the file.
// If the file was never open, nil is returned.
// If the file is already closed, an error is returned.
func (p *LocalFile) Close() error {
	if p.f == nil {
		return nil
	}
	return p.f.Close()
}
