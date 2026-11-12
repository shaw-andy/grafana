package local

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
)

// Prefixes are joined the way pkg/setting.makeAbsolute joins a relative
// permitted_provisioning_paths entry onto the Grafana home path. The default
// entries in conf/defaults.ini have no trailing separator.

const (
	siblingMarkerName = "sibling-only-marker.txt"
	siblingMarker     = "sibling-marker"
	insideName        = "inside.txt"
	insideMarker      = "inside-marker"
)

func TestLocalPrefixRejectsSiblingDirectories(t *testing.T) {
	ctx := context.Background()
	fix := newPrefixFixture(t, false)
	t.Chdir(fix.work)

	allowed := []string{
		"devenv/dev-dashboards",
		"devenv/dev-dashboards/nested",
		"conf/provisioning",
	}
	siblings := []string{
		"devenv/dev-dashboards-without-uid",
		"conf/provisioning-backup",
	}

	t.Run("admission allows paths inside a prefix", func(t *testing.T) {
		for _, rel := range allowed {
			t.Run(rel, func(t *testing.T) {
				list := fix.validator(t).Validate(ctx, fix.repo(rel))
				require.Empty(t, list, "path inside the allowlist was rejected")
			})
		}
	})

	t.Run("admission rejects a sibling of a prefix", func(t *testing.T) {
		for _, rel := range siblings {
			t.Run(rel, func(t *testing.T) {
				list := fix.validator(t).Validate(ctx, fix.repo(rel))
				require.NotEmpty(t, list, "admission accepted %q, which is not inside a permitted prefix", rel)
			})
			abs := filepath.Join(fix.home, rel)
			t.Run(abs, func(t *testing.T) {
				list := fix.validator(t).Validate(ctx, fix.repo(abs))
				require.NotEmpty(t, list, "admission accepted absolute sibling %q", abs)
			})
		}
	})

	t.Run("repository test does not succeed for a sibling", func(t *testing.T) {
		fac, _ := fix.open(t)
		repo, err := fix.build(t, ctx, fac, "devenv/dev-dashboards-without-uid")
		if err != nil {
			return
		}
		result, err := repo.Test(ctx)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.Success, "Test succeeded for a directory outside the allowlist")
	})

	t.Run("allowed repository can read its own file", func(t *testing.T) {
		fac, _ := fix.open(t)
		repo, err := fix.build(t, ctx, fac, "devenv/dev-dashboards")
		require.NoError(t, err)
		info, err := repo.Read(ctx, insideName, "")
		require.NoError(t, err)
		require.Equal(t, []byte(insideMarker), info.Data)
	})
}

func TestLocalSiblingPrefixCannotReadOrWrite(t *testing.T) {
	ctx := context.Background()
	rel := "devenv/dev-dashboards-without-uid"

	t.Run("read", func(t *testing.T) {
		fix := newPrefixFixture(t, false)
		t.Chdir(fix.work)
		before := fix.signatures()
		fac, _ := fix.open(t)
		repo, buildErr := fix.build(t, ctx, fac, rel)
		if buildErr != nil {
			fix.requireUntouched(t, before)
			return
		}
		info, err := repo.Read(ctx, siblingMarkerName, "")
		if info != nil {
			require.NotEqual(t, []byte(siblingMarker), info.Data, "Read returned the sibling file")
		}
		require.Error(t, err, "Read of a file outside the allowlist succeeded")
		fix.requireUntouched(t, before)
	})

	t.Run("read tree", func(t *testing.T) {
		fix := newPrefixFixture(t, false)
		t.Chdir(fix.work)
		before := fix.signatures()
		fac, _ := fix.open(t)
		repo, buildErr := fix.build(t, ctx, fac, rel)
		if buildErr != nil {
			fix.requireUntouched(t, before)
			return
		}
		tree, _ := repo.ReadTree(ctx, "")
		fix.requireUntouched(t, before)
		for _, entry := range tree {
			require.NotContains(t, entry.Path, siblingMarkerName, "ReadTree listed a file outside the allowlist")
			require.NotContains(t, entry.Path, "subdir", "ReadTree listed a directory outside the allowlist")
		}
	})

	mutations := []struct {
		name string
		fn   func(repository.ReaderWriter) error
	}{
		{
			name: "create file",
			fn: func(rw repository.ReaderWriter) error {
				return rw.Create(ctx, "created.txt", "", []byte("created"), "create")
			},
		},
		{
			name: "create directory",
			fn: func(rw repository.ReaderWriter) error {
				return rw.Create(ctx, "created-dir/", "", nil, "create")
			},
		},
		{
			name: "update",
			fn: func(rw repository.ReaderWriter) error {
				return rw.Update(ctx, siblingMarkerName, "", []byte("changed"), "update")
			},
		},
		{
			name: "write file",
			fn: func(rw repository.ReaderWriter) error {
				return rw.Write(ctx, "written.txt", "", []byte("written"), "write")
			},
		},
		{
			name: "write directory",
			fn: func(rw repository.ReaderWriter) error {
				return rw.Write(ctx, "written-dir/", "", nil, "write")
			},
		},
		{
			name: "delete file",
			fn: func(rw repository.ReaderWriter) error {
				return rw.Delete(ctx, siblingMarkerName, "", "delete")
			},
		},
		{
			name: "delete directory",
			fn: func(rw repository.ReaderWriter) error {
				return rw.Delete(ctx, "subdir/", "", "delete")
			},
		},
		{
			name: "move",
			fn: func(rw repository.ReaderWriter) error {
				return rw.Move(ctx, siblingMarkerName, "moved.txt", "", "move")
			},
		},
	}

	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			fix := newPrefixFixture(t, false)
			t.Chdir(fix.work)
			before := fix.signatures()
			fac, _ := fix.open(t)
			repo, buildErr := fix.build(t, ctx, fac, rel)
			if buildErr != nil {
				fix.requireUntouched(t, before)
				return
			}
			err := mutation.fn(repo)
			fix.requireUntouched(t, before)
			require.Errorf(t, err, "%s changed files for a repository outside the allowlist", mutation.name)
		})
	}
}

// TestCreatingRepositoryKeepsPrefixBoundary covers a prefix that was configured
// with a trailing slash. Building any local repository cleans every prefix, and
// the cleaned value must still reject siblings.
func TestCreatingRepositoryKeepsPrefixBoundary(t *testing.T) {
	ctx := context.Background()
	fix := newPrefixFixture(t, true)
	t.Chdir(fix.work)
	fac, validator := fix.open(t)
	sibling := fix.repo("devenv/dev-dashboards-without-uid")
	child := fix.repo("devenv/dev-dashboards/nested")

	before := validator.Validate(ctx, sibling)
	require.NotEmpty(t, before, "sibling matched a prefix that still ended with a separator")

	childErrors := validator.Validate(ctx, child)
	require.Empty(t, childErrors, "child of a slash-terminated prefix was rejected")

	// Building a repository that is actually inside the prefix must not widen it.
	_, err := fix.build(t, ctx, fac, "devenv/dev-dashboards/nested")
	require.NoError(t, err)

	t.Run("admission after build", func(t *testing.T) {
		after := validator.Validate(ctx, sibling)
		require.NotEmpty(t, after, "building a repository made the sibling match the cleaned prefix")
	})

	t.Run("read after build", func(t *testing.T) {
		beforeTrees := fix.signatures()
		repo, buildErr := fix.build(t, ctx, fac, "devenv/dev-dashboards-without-uid")
		if buildErr != nil {
			fix.requireUntouched(t, beforeTrees)
			return
		}
		info, err := repo.Read(ctx, siblingMarkerName, "")
		if info != nil {
			require.NotEqual(t, []byte(siblingMarker), info.Data, "Read returned the sibling file after prefixes were cleaned")
		}
		require.Error(t, err, "Read succeeded for a sibling after a repository build cleaned the prefixes")
		fix.requireUntouched(t, beforeTrees)
	})
}

type prefixFixture struct {
	t       *testing.T
	home    string
	work    string
	allowed []string
	dirs    []string
}

func newPrefixFixture(t *testing.T, slashTerminated bool) *prefixFixture {
	t.Helper()
	home := t.TempDir()
	work := t.TempDir()

	allowedDir := filepath.Join(home, "devenv", "dev-dashboards")
	siblingDir := filepath.Join(home, "devenv", "dev-dashboards-without-uid")
	provisioningDir := filepath.Join(home, "conf", "provisioning")
	backupDir := filepath.Join(home, "conf", "provisioning-backup")

	require.NoError(t, os.MkdirAll(filepath.Join(allowedDir, "nested"), 0o750))
	require.NoError(t, os.MkdirAll(filepath.Join(siblingDir, "subdir"), 0o750))
	require.NoError(t, os.MkdirAll(provisioningDir, 0o750))
	require.NoError(t, os.MkdirAll(backupDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(allowedDir, insideName), []byte(insideMarker), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(allowedDir, "nested", "nested.txt"), []byte("nested"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(siblingDir, siblingMarkerName), []byte(siblingMarker), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(siblingDir, "subdir", "nested.txt"), []byte("nested-sibling"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(provisioningDir, "keep.txt"), []byte("keep"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(backupDir, "backup-marker.txt"), []byte("backup"), 0o600))

	// makeAbsolute is filepath.Join(root, configured). It does not add a trailing separator.
	prefixes := []string{
		filepath.Join(home, "devenv/dev-dashboards"),
		filepath.Join(home, "conf/provisioning"),
	}
	if slashTerminated {
		for i := range prefixes {
			prefixes[i] += "/"
		}
	}

	return &prefixFixture{
		t:       t,
		home:    home,
		work:    work,
		allowed: prefixes,
		dirs:    []string{home, work},
	}
}

func (f *prefixFixture) repo(path string) *provisioning.Repository {
	return &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "local-repo",
			Finalizers: []string{repository.CleanFinalizer},
		},
		Spec: provisioning.RepositorySpec{
			Title: "Local",
			Type:  provisioning.LocalRepositoryType,
			Local: &provisioning.LocalRepositoryConfig{Path: path},
		},
	}
}

func (f *prefixFixture) factory(t *testing.T) repository.Factory {
	t.Helper()
	// Copy the slice. Building a repository rewrites the shared prefix entries.
	prefixes := append([]string{}, f.allowed...)
	fac, err := repository.ProvideFactory(
		map[provisioning.RepositoryType]struct{}{
			provisioning.LocalRepositoryType: {},
		},
		[]repository.Extra{Extra(f.home, prefixes, nil)},
		noop.NewTracerProvider().Tracer("prefix-boundary"),
	)
	require.NoError(t, err)
	return fac
}

func (f *prefixFixture) open(t *testing.T) (repository.Factory, repository.Validator) {
	t.Helper()
	fac := f.factory(t)
	return fac, repository.NewValidator(true, fac)
}

func (f *prefixFixture) validator(t *testing.T) repository.Validator {
	t.Helper()
	_, validator := f.open(t)
	return validator
}

func (f *prefixFixture) build(t *testing.T, ctx context.Context, fac repository.Factory, path string) (repository.ReaderWriter, error) {
	t.Helper()
	built, err := fac.Build(ctx, f.repo(path))
	if err != nil {
		return nil, err
	}
	rw, ok := built.(repository.ReaderWriter)
	require.True(t, ok)
	return rw, nil
}

func (f *prefixFixture) signatures() map[string][]string {
	out := make(map[string][]string, len(f.dirs))
	for _, dir := range f.dirs {
		out[dir] = directorySignature(f.t, dir)
	}
	return out
}

func (f *prefixFixture) requireUntouched(t *testing.T, before map[string][]string) {
	t.Helper()
	for _, dir := range f.dirs {
		require.Equal(t, before[dir], directorySignature(t, dir), "files changed under %s", dir)
	}
}

func directorySignature(t *testing.T, root string) []string {
	t.Helper()
	lines := []string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			lines = append(lines, rel+"/")
			return nil
		}
		// Follow the directory entry the walk reported. A signature that skipped
		// unreadable files would hide a file the product had already created.
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		lines = append(lines, fmt.Sprintf("%s %x", rel, sum))
		return nil
	})
	require.NoError(t, err)
	sort.Strings(lines)
	return lines
}
