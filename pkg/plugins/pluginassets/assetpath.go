package pluginassets

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"unicode"
)

// ErrInvalidAssetPath is returned for a plugin ID or plugin.json asset path that could
// resolve outside the plugin's asset directory once it is used as a browser URL.
var ErrInvalidAssetPath = errors.New("invalid plugin asset path")

// ValidateAssetPath checks that every element of assetPath stays inside the plugin's asset
// directory. Browsers treat "\" as "/", strip tabs and newlines, and resolve percent-encoded
// dot segments, so those are rejected along with "..".
func ValidateAssetPath(assetPath ...string) error {
	for _, p := range assetPath {
		decoded, err := decodeAssetPath(p)
		if err != nil {
			return err
		}
		for _, segment := range strings.Split(decoded, "/") {
			if segment == ".." {
				return fmt.Errorf("%w: %q", ErrInvalidAssetPath, p)
			}
		}
	}
	return nil
}

// JoinAssetPath joins assetPath under base/pluginID and refuses any result that is not inside it.
func JoinAssetPath(base, pluginID string, assetPath ...string) (string, error) {
	id, err := decodeAssetPath(pluginID)
	if err != nil {
		return "", err
	}
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, "/?#") {
		return "", fmt.Errorf("%w: plugin id %q", ErrInvalidAssetPath, pluginID)
	}
	if err := ValidateAssetPath(assetPath...); err != nil {
		return "", err
	}
	dir := path.Join(base, pluginID)
	joined := path.Join(dir, path.Join(assetPath...))
	if joined != dir && !strings.HasPrefix(joined, dir+"/") {
		return "", fmt.Errorf("%w: %q", ErrInvalidAssetPath, path.Join(assetPath...))
	}
	return joined, nil
}

func decodeAssetPath(p string) (string, error) {
	decoded, err := url.PathUnescape(p)
	if err != nil || strings.ContainsRune(decoded, '\\') || strings.ContainsFunc(decoded, unicode.IsControl) {
		return "", fmt.Errorf("%w: %q", ErrInvalidAssetPath, p)
	}
	return decoded, nil
}
