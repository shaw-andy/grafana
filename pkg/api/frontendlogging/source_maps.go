package frontendlogging

import (
	"container/list"
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"sync"

	sourcemap "github.com/go-sourcemap/sourcemap"
	"golang.org/x/sync/singleflight"

	"github.com/grafana/grafana/pkg/api/webassets"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/setting"
)

var logger = log.New("frontendlogging")

const (
	// maxResolvedFramesPerRequest caps how many stack frames one request may
	// try to map, across every exception it carries.
	maxResolvedFramesPerRequest = 32
	// maxSourceMapLoadsPerRequest caps how many source maps that are not yet
	// cached one request may read and parse.
	maxSourceMapLoadsPerRequest = 8
	maxCachedSourceMaps         = 64
	maxCachedSourceMapBytes     = 128 << 20
)

type sourceMapLocation struct {
	dir      string
	path     string
	pluginID string
}

type sourceMap struct {
	consumer *sourcemap.Consumer
	pluginID string
	key      string
	size     int
	elem     *list.Element
}

type ReadSourceMapFn func(dir string, path string) ([]byte, error)

func ReadSourceMapFromFS(dir string, path string) ([]byte, error) {
	file, err := http.Dir(dir).Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Error("Failed to close source map file", "err", err)
		}
	}()
	return io.ReadAll(file)
}

// SourceMapStore caches parsed source maps by the file they were read from,
// so any number of client URLs that resolve to one file share one entry.
type SourceMapStore struct {
	sync.Mutex
	cache         map[string]*sourceMap
	lru           *list.List
	cacheBytes    int
	loads         singleflight.Group
	cfg           *setting.Cfg
	readSourceMap ReadSourceMapFn
	routeResolver plugins.StaticRouteResolver
}

func NewSourceMapStore(cfg *setting.Cfg, routeResolver plugins.StaticRouteResolver, readSourceMap ReadSourceMapFn) *SourceMapStore {
	return &SourceMapStore{
		cache:         make(map[string]*sourceMap),
		lru:           list.New(),
		cfg:           cfg,
		routeResolver: routeResolver,
		readSourceMap: readSourceMap,
	}
}

/* guessSourceMapLocation will attempt to guess location of a source map on fs.
 * it does not read the source file or make any web requests,
 * just assumes that a [source filename].map file might exist in the same dir as the source file
 * and only considers sources coming from grafana core or plugins`
 */
func (store *SourceMapStore) guessSourceMapLocation(ctx context.Context, sourceURL string) (*sourceMapLocation, error) {
	u, err := url.Parse(sourceURL)
	if err != nil {
		return nil, err
	}

	// determine if source comes from grafana core, locally or CDN, look in public build dir on fs
	if strings.HasPrefix(u.Path, "/public/build/") || (store.cfg.CDNRootURL != nil &&
		strings.HasPrefix(sourceURL, store.cfg.CDNRootURL.String()) && strings.Contains(u.Path, "/public/build/")) {
		// The remainder carries the rspack/ segment for rspack assets, so one
		// directory resolves both bundlers.
		pathParts := strings.SplitN(u.Path, "/public/build/", 2)
		if len(pathParts) == 2 {
			return &sourceMapLocation{
				dir:      store.cfg.StaticRootPath,
				path:     filepath.Join(webassets.BuildDir, pathParts[1]+".map"),
				pluginID: "",
			}, nil
		}
		// if source comes from a plugin, look in plugin dir
	} else if strings.HasPrefix(u.Path, "/public/plugins/") {
		for _, route := range store.routeResolver.Routes(ctx) {
			pluginPrefix := filepath.Join("/public/plugins/", route.PluginID)
			if strings.HasPrefix(u.Path, pluginPrefix) {
				return &sourceMapLocation{
					dir:      route.Directory,
					path:     u.Path[len(pluginPrefix):] + ".map",
					pluginID: route.PluginID,
				}, nil
			}
		}
	}
	return nil, nil
}

// locate returns the source map location for sourceURL and the cache key of
// the file it names, or nil when the URL is not a core or plugin asset.
func (store *SourceMapStore) locate(ctx context.Context, sourceURL string) (*sourceMapLocation, string, error) {
	location, err := store.guessSourceMapLocation(ctx, sourceURL)
	if err != nil || location == nil {
		return nil, "", err
	}
	location.path = strings.ReplaceAll(location.path, "../", "") // just in case
	// http.Dir resolves the path the same way, so the key names the file that is read.
	key := location.pluginID + "\x00" + location.dir + "\x00" + pathpkg.Clean("/"+filepath.ToSlash(location.path))
	return location, key, nil
}

func (store *SourceMapStore) cached(key string) *sourceMap {
	store.Lock()
	defer store.Unlock()
	smap, ok := store.cache[key]
	if !ok {
		return nil
	}
	store.lru.MoveToFront(smap.elem)
	return smap
}

// load reads and parses the source map without holding the store lock.
// It returns nil when the file does not exist; misses are not cached.
func (store *SourceMapStore) load(location *sourceMapLocation, key string) (*sourceMap, error) {
	v, err, _ := store.loads.Do(key, func() (any, error) {
		content, err := store.readSourceMap(location.dir, location.path)
		if err != nil {
			if os.IsNotExist(err) {
				return (*sourceMap)(nil), nil
			}
			return nil, err
		}
		// Parse with no URL so that relative sources are not resolved against a
		// client-supplied URL, which would differ between requests for one file.
		consumer, err := sourcemap.Parse("", content)
		if err != nil {
			return nil, err
		}
		smap := &sourceMap{
			consumer: consumer,
			pluginID: location.pluginID,
			key:      key,
			size:     len(content),
		}
		store.add(smap)
		return smap, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*sourceMap), nil
}

func (store *SourceMapStore) add(smap *sourceMap) {
	if smap.size > maxCachedSourceMapBytes {
		return
	}
	store.Lock()
	defer store.Unlock()
	if _, ok := store.cache[smap.key]; ok {
		return
	}
	smap.elem = store.lru.PushFront(smap)
	store.cache[smap.key] = smap
	store.cacheBytes += smap.size
	for len(store.cache) > maxCachedSourceMaps || store.cacheBytes > maxCachedSourceMapBytes {
		oldest := store.lru.Remove(store.lru.Back()).(*sourceMap)
		delete(store.cache, oldest.key)
		store.cacheBytes -= oldest.size
	}
}

// SourceMapResolver maps stack frames for a single request. It limits how many
// frames the request may map and how many source maps it may load.
type SourceMapResolver struct {
	store      *SourceMapStore
	framesLeft int
	loadsLeft  int
	seen       map[string]*sourceMap
}

func (store *SourceMapStore) NewResolver() *SourceMapResolver {
	return &SourceMapResolver{
		store:      store,
		framesLeft: maxResolvedFramesPerRequest,
		loadsLeft:  maxSourceMapLoadsPerRequest,
		seen:       make(map[string]*sourceMap),
	}
}

func (r *SourceMapResolver) getSourceMap(ctx context.Context, sourceURL string) (*sourceMap, error) {
	location, key, err := r.store.locate(ctx, sourceURL)
	if err != nil || location == nil {
		return nil, err
	}
	if smap, ok := r.seen[key]; ok {
		return smap, nil
	}
	smap := r.store.cached(key)
	if smap == nil {
		if r.loadsLeft <= 0 {
			return nil, nil
		}
		r.loadsLeft--
		smap, err = r.store.load(location, key)
		if err != nil {
			return nil, err
		}
	}
	r.seen[key] = smap
	return smap, nil
}

func (r *SourceMapResolver) resolveSourceLocation(ctx context.Context, frame Frame) (*Frame, error) {
	if r.framesLeft <= 0 {
		return nil, nil
	}
	r.framesLeft--
	smap, err := r.getSourceMap(ctx, frame.Filename)
	if err != nil {
		return nil, err
	}
	if smap == nil {
		return nil, nil
	}
	file, function, line, col, ok := smap.consumer.Source(frame.Lineno, frame.Colno)
	if !ok {
		return nil, nil
	}
	// unfortunately in many cases go-sourcemap fails to determine the original function name.
	// not a big issue as long as file, line and column are correct
	if len(function) == 0 {
		function = "?"
	}
	module := "core"
	if len(smap.pluginID) > 0 {
		module = smap.pluginID
	}
	return &Frame{
		Filename: file,
		Lineno:   line,
		Colno:    col,
		Function: function,
		Module:   module,
	}, nil
}
