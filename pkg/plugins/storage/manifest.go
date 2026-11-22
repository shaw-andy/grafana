package storage

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/auth"
)

// maxPluginJSONSize bounds how much of an archived plugin.json is read into memory.
const maxPluginJSONSize = 5 << 20

// ArchiveManifest is what the plugin.json files of an archive declare, read from the archive itself
// before anything is extracted.
type ArchiveManifest struct {
	// Dependencies are the plugins required by the top-level plugin.json, the one Extract reads.
	Dependencies []*Dependency
	// Permissions holds every IAM permission requested by any plugin.json in the archive.
	Permissions []auth.Permission
}

// ReadArchiveManifest reads every plugin.json in pluginArchive. Extracting the same archive with
// Extract cannot produce a plugin.json requesting permissions that are not listed here: the plugin
// loader discovers any file named plugin.json, at any depth and through symlinked directories, so
// every member with that name is read, and a member with that name that is itself a symlink, whose
// content the archive could point at any other member, is refused.
func ReadArchiveManifest(pluginID string, dirNameFunc DirNameGeneratorFunc, pluginArchive *zip.ReadCloser) (*ArchiveManifest, error) {
	pluginDirName := dirNameFunc(pluginID)
	// Only the position of a member relative to the install directory matters here, so any
	// absolute plugins directory resolves member names the same way extractFiles does.
	pluginsDir := filepath.Join(string(filepath.Separator), "plugins")
	installDir := filepath.Join(pluginsDir, pluginDirName)

	var rootJSON, distJSON []byte
	manifest := &ArchiveManifest{}
	for _, zf := range pluginArchive.File {
		if !isPluginJSONName(zf.Name) || zf.FileInfo().IsDir() {
			continue
		}

		if isSymlink(zf) {
			return nil, fmt.Errorf("archive member %q is a symlink named plugin.json, which is not allowed", zf.Name)
		}

		data, err := readArchiveMember(zf, maxPluginJSONSize)
		if err != nil {
			return nil, err
		}

		if rel, err := installRelPath(pluginsDir, installDir, removeGitBuildFromName(zf.Name, pluginDirName)); err == nil {
			switch strings.ToLower(filepath.ToSlash(rel)) {
			case "plugin.json":
				rootJSON = data
			case "dist/plugin.json":
				distJSON = data
			}
		}

		// The loader parses plugin.json with the same function and skips a plugin whose file it
		// cannot parse, so such a file requests nothing.
		jsonData, err := plugins.ReadPluginJSON(bytes.NewReader(data))
		if err != nil {
			continue
		}
		if jsonData.IAM != nil {
			manifest.Permissions = append(manifest.Permissions, jsonData.IAM.Permissions...)
		}
	}

	if rootJSON == nil {
		rootJSON = distJSON
	}
	if rootJSON == nil {
		return nil, fmt.Errorf("could not find plugin.json or dist/plugin.json in the archive of %s", pluginID)
	}

	root, err := plugins.ReadPluginJSON(bytes.NewReader(rootJSON))
	if err != nil {
		return nil, fmt.Errorf("%v: %w", "failed to convert to plugin DTO", err)
	}
	manifest.Dependencies = make([]*Dependency, 0, len(root.Dependencies.Plugins))
	for _, dep := range root.Dependencies.Plugins {
		manifest.Dependencies = append(manifest.Dependencies, &Dependency{ID: dep.ID})
	}

	return manifest, nil
}

// isPluginJSONName matches regardless of case and of the separator used, so that neither a
// case-insensitive filesystem nor a platform treating backslashes as separators can turn a member
// skipped here into a plugin.json on disk.
func isPluginJSONName(name string) bool {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	return strings.EqualFold(name, "plugin.json")
}

func readArchiveMember(zf *zip.File, limit int64) ([]byte, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to read archive member %q: %w", zf.Name, err)
	}
	defer func() {
		_ = rc.Close()
	}()

	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read archive member %q: %w", zf.Name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("archive member %q exceeds the maximum plugin.json size of %d bytes", zf.Name, limit)
	}
	return data, nil
}
