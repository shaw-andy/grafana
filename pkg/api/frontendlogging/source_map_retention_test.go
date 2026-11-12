package frontendlogging

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/setting"
)

// Bounds the process-wide source map store must enforce. Distinct client stack
// URLs, including query strings on one real bundle, must not each retain a
// parsed source map or a negative-cache entry for the life of the process.
const (
	maxParsedMapsPerAsset  = 1
	maxRetainedLookups     = 32
	distinctClientURLCount = 200
	sourceMapLookupTimeout = 250 * time.Millisecond
)

func TestSourceMapStore_QueryVariantsDoNotRetainAnotherParsedMap(t *testing.T) {
	t.Parallel()

	mapBytes := readTestSourceMap(t)
	coreDir := t.TempDir()
	pluginDir := t.TempDir()
	writeSourceMap(t, filepath.Join(coreDir, "build", "foo.js.map"), mapBytes)
	writeSourceMap(t, filepath.Join(pluginDir, "foo.js.map"), mapBytes)

	cdnRoot, err := url.Parse("https://cdn.example/grafana")
	require.NoError(t, err)
	cfg := &setting.Cfg{StaticRootPath: coreDir, CDNRootURL: cdnRoot}
	routes := staticRouteStub{routes: []*plugins.StaticRoute{{
		PluginID:  "telepathic",
		Directory: pluginDir,
	}}}

	tests := []struct {
		name string
		url  func(i int) string
	}{
		{
			name: "core bundle",
			url: func(i int) string {
				return fmt.Sprintf("http://grafana.example/public/build/foo.js?uniq=%d", i)
			},
		},
		{
			name: "cdn bundle",
			url: func(i int) string {
				return fmt.Sprintf("%s/public/build/foo.js?uniq=%d", cdnRoot.String(), i)
			},
		},
		{
			name: "plugin bundle",
			url: func(i int) string {
				return fmt.Sprintf("http://grafana.example/public/plugins/telepathic/foo.js?uniq=%d", i)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var reads int
			store := NewSourceMapStore(cfg, routes, func(dir, path string) ([]byte, error) {
				reads++
				return ReadSourceMapFromFS(dir, path)
			})

			for i := 0; i < distinctClientURLCount; i++ {
				TransformException(context.Background(), exceptionWithFrames(tt.url(i)), store)
			}
			// The same URL again must not be a separate retained entry either.
			TransformException(context.Background(), exceptionWithFrames(tt.url(0)), store)

			require.LessOrEqual(t, parsedSourceMaps(store), maxParsedMapsPerAsset,
				"parsed source maps retained for one asset")
			require.LessOrEqual(t, cacheSize(store), maxParsedMapsPerAsset,
				"cache entries retained for one asset")
			require.LessOrEqual(t, reads, maxParsedMapsPerAsset,
				"filesystem reads for one asset")
		})
	}
}

func TestSourceMapStore_MissesDoNotAccumulate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := &setting.Cfg{StaticRootPath: dir}
	store := NewSourceMapStore(cfg, staticRouteStub{routes: []*plugins.StaticRoute{{
		PluginID:  "telepathic",
		Directory: dir,
	}}}, ReadSourceMapFromFS)

	for i := 0; i < distinctClientURLCount; i++ {
		urls := []string{
			fmt.Sprintf("http://evil.example/stack.js?uniq=%d", i),
			fmt.Sprintf("http://grafana.example/public/build/missing-%d.js", i),
			fmt.Sprintf("http://grafana.example/public/plugins/telepathic/missing-%d.js", i),
		}
		for _, sourceURL := range urls {
			TransformException(context.Background(), exceptionWithFrames(sourceURL), store)
		}
	}

	require.LessOrEqual(t, cacheSize(store), maxRetainedLookups,
		"negative lookups retained")
}

func TestSourceMapStore_ReadDoesNotHoldStoreLock(t *testing.T) {
	t.Parallel()

	mapBytes := readTestSourceMap(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	store := NewSourceMapStore(&setting.Cfg{StaticRootPath: t.TempDir()}, staticRouteStub{}, func(dir, path string) ([]byte, error) {
		if strings.Contains(path, "slow.js") {
			once.Do(func() { close(started) })
			<-release
		}
		return mapBytes, nil
	})

	fastURL := "http://grafana.example/public/build/fast.js"
	TransformException(context.Background(), exceptionWithFrames(fastURL), store)

	doneSlow := make(chan struct{})
	go func() {
		defer close(doneSlow)
		TransformException(context.Background(), exceptionWithFrames("http://grafana.example/public/build/slow.js"), store)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for source map read")
	}

	doneFast := make(chan struct{})
	go func() {
		defer close(doneFast)
		TransformException(context.Background(), exceptionWithFrames(fastURL), store)
	}()

	select {
	case <-doneFast:
	case <-time.After(sourceMapLookupTimeout):
		close(release)
		<-doneSlow
		t.Fatal("cached source map lookup blocked while another map was read")
	}
	close(release)
	<-doneSlow
}

func TestSourceMapStore_KnownBundleStillResolves(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeSourceMap(t, filepath.Join(dir, "build", "foo.js.map"), readTestSourceMap(t))
	store := NewSourceMapStore(&setting.Cfg{StaticRootPath: dir}, staticRouteStub{}, ReadSourceMapFromFS)

	got := TransformException(context.Background(), exceptionWithFrames("http://grafana.example/public/build/foo.js"), store)
	require.Contains(t, got.Stacktrace.Frames[0].Filename, "some_source.ts")
	require.LessOrEqual(t, parsedSourceMaps(store), maxParsedMapsPerAsset)
}

type staticRouteStub struct {
	routes []*plugins.StaticRoute
}

func (s staticRouteStub) Routes(context.Context) []*plugins.StaticRoute {
	return s.routes
}

func exceptionWithFrames(filenames ...string) *Exception {
	frames := make([]Frame, 0, len(filenames))
	for _, filename := range filenames {
		frames = append(frames, Frame{Filename: filename, Function: "fn", Lineno: 2, Colno: 5})
	}
	return &Exception{
		Type:       "Error",
		Value:      "boom",
		Stacktrace: &Stacktrace{Frames: frames},
	}
}

func readTestSourceMap(t *testing.T) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("test-data", "foo.js.map"))
	require.NoError(t, err)
	return contents
}

func writeSourceMap(t *testing.T, path string, contents []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, contents, 0o644))
}

func cacheSize(store *SourceMapStore) int {
	store.Lock()
	defer store.Unlock()
	return len(store.cache)
}

func parsedSourceMaps(store *SourceMapStore) int {
	store.Lock()
	defer store.Unlock()
	n := 0
	for _, entry := range store.cache {
		if entry != nil && entry.consumer != nil {
			n++
		}
	}
	return n
}
