package sync

import (
	"context"

	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/safepath"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/resources"
)

type pathScopeKey struct{}

// pathScope limits a sync to the repository paths a delete or move job changed.
type pathScope struct {
	files     map[string]struct{}
	dirs      []string
	ancestors map[string]struct{}
}

// WithPathScope restricts any sync run with the returned context to the given
// repository paths. Files match exactly; directories (trailing slash) match
// themselves and everything below them. The parent directories of each path
// are included only so that a folder can be created for a move target or
// removed once the job has left it empty in the repository.
//
// The repository root is never part of a scope, so a scoped sync cannot widen
// into a full sync. A scoped sync applies only changes the job's own
// authorization covers, so it never advances the repository's last synced ref.
func WithPathScope(ctx context.Context, paths []string) context.Context {
	scope := &pathScope{
		files:     make(map[string]struct{}, len(paths)),
		ancestors: make(map[string]struct{}),
	}
	for _, p := range paths {
		if safepath.IsDir(p) {
			dir := safepath.EnsureTrailingSlash(p)
			if dir == "" {
				continue
			}
			scope.dirs = append(scope.dirs, dir)
		} else {
			scope.files[p] = struct{}{}
		}
		for dir := safepath.Dir(p); dir != ""; dir = safepath.Dir(dir) {
			scope.ancestors[dir] = struct{}{}
		}
	}
	return context.WithValue(ctx, pathScopeKey{}, scope)
}

func pathScopeFrom(ctx context.Context) (*pathScope, bool) {
	scope, ok := ctx.Value(pathScopeKey{}).(*pathScope)
	return scope, ok && scope != nil
}

func (s *pathScope) contains(p string) bool {
	if _, ok := s.files[p]; ok {
		return true
	}
	for _, dir := range s.dirs {
		if safepath.InDir(p, dir) {
			return true
		}
	}
	return false
}

func (s *pathScope) includes(change ResourceFileChange) bool {
	isDir := safepath.IsDir(change.Path)
	existingPath := ""
	if change.Existing != nil {
		existingPath = change.Existing.Path
		if isDir && existingPath != "" {
			existingPath = safepath.EnsureTrailingSlash(existingPath)
		}
	}

	if s.contains(change.Path) && (existingPath == "" || s.contains(existingPath)) {
		return true
	}

	if !isDir || change.OrphanCleanup || change.FolderRenamed {
		return false
	}
	if _, ok := s.ancestors[change.Path]; !ok {
		return false
	}
	switch change.Action {
	case repository.FileActionCreated:
		return change.Existing == nil
	case repository.FileActionDeleted:
		return existingPath == "" || existingPath == change.Path
	default:
		return false
	}
}

func (s *pathScope) filterChanges(changes []ResourceFileChange) []ResourceFileChange {
	filtered := make([]ResourceFileChange, 0, len(changes))
	for _, change := range changes {
		if s.includes(change) {
			filtered = append(filtered, change)
		}
	}
	return filtered
}

// scopedCompare wraps compare so that only changes inside scope are returned.
func scopedCompare(compare CompareFn, scope *pathScope) CompareFn {
	return func(ctx context.Context, repo repository.Reader, repositoryResources resources.RepositoryResources, ref string, folderMetadataEnabled bool) ([]ResourceFileChange, []string, []*resources.InvalidFolderMetadata, error) {
		changes, missingFolderMetadata, invalidFolderMetadata, err := compare(ctx, repo, repositoryResources, ref, folderMetadataEnabled)
		if err != nil {
			return nil, nil, nil, err
		}

		missing := make([]string, 0, len(missingFolderMetadata))
		for _, p := range missingFolderMetadata {
			if s := safepath.EnsureTrailingSlash(p); s != "" && (scope.contains(s) || isAncestor(scope, s)) {
				missing = append(missing, p)
			}
		}
		invalid := make([]*resources.InvalidFolderMetadata, 0, len(invalidFolderMetadata))
		for _, item := range invalidFolderMetadata {
			if item != nil && (scope.contains(item.Path) || isAncestor(scope, item.Path)) {
				invalid = append(invalid, item)
			}
		}

		return scope.filterChanges(changes), missing, invalid, nil
	}
}

func isAncestor(scope *pathScope, p string) bool {
	_, ok := scope.ancestors[p]
	return ok
}
