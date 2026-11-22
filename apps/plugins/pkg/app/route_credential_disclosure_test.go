package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/grafana/grafana-app-sdk/logging"
	"github.com/grafana/grafana-app-sdk/resource"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pluginsv0alpha1 "github.com/grafana/grafana/apps/plugins/pkg/apis/plugins/v0alpha1"
	"github.com/grafana/grafana/apps/plugins/pkg/app/meta"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/config"
	pluginsLoader "github.com/grafana/grafana/pkg/plugins/manager/loader"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/bootstrap"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/discovery"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/initialization"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/termination"
	"github.com/grafana/grafana/pkg/plugins/manager/pipeline/validation"
	"github.com/grafana/grafana/pkg/plugins/manager/registry"
	"github.com/grafana/grafana/pkg/plugins/manager/signature"
	"github.com/grafana/grafana/pkg/plugins/manager/sources"
	"github.com/grafana/grafana/pkg/plugins/pluginassets"
	"github.com/grafana/grafana/pkg/plugins/pluginassets/modulehash"
	"github.com/grafana/grafana/pkg/plugins/pluginerrs"
	"github.com/grafana/grafana/pkg/plugins/pluginscdn"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
)

const (
	routeHeaderCredential   = "route-header-credential-placeholder"
	routeURLParamCredential = "route-url-param-credential-placeholder"
	routeTokenClientSecret  = "route-token-client-secret-placeholder"
	routeJWTPrivateKey      = "route-jwt-private-key-placeholder"
	routeBodyCredential     = "route-body-credential-placeholder"
	routeChildPrivateKey    = "route-child-jwt-private-key-placeholder"

	routePluginVersion = "1.2.3"
)

// TestMetaStorage_OmitsInstalledPluginRouteCredentials loads plugin.json the way an
// installed plugin is loaded, then reads it back through the metadata API storage
// used for GET and LIST. Route authentication material must not be in either response.
func TestMetaStorage_OmitsInstalledPluginRouteCredentials(t *testing.T) {
	const externalID = "route-secret-external"
	const coreID = "route-secret-core"

	externalDir := filepath.Join(t.TempDir(), externalID)
	writeRoutePlugin(t, externalDir, externalID, routeJWTPrivateKey)

	staticRoot := t.TempDir()
	writeRoutePlugin(t, filepath.Join(staticRoot, "app", "plugins", coreID), coreID, routeJWTPrivateKey)

	reg := registry.NewInMemory()
	cfg := &config.PluginManagementCfg{PluginsAllowUnsigned: []string{externalID}}
	store := loadExternalPluginStore(t, cfg, reg, externalDir)
	t.Cleanup(func() {
		store.StopAsync()
		_ = store.AwaitTerminated(context.Background())
	})

	loaded, ok := store.Plugin(context.Background(), externalID)
	require.True(t, ok, "installed plugin must be in the plugin store")
	require.Equal(t, routeTokenClientSecret, loaded.Routes[0].TokenAuth.Params["client_secret"])
	require.Equal(t, routeJWTPrivateKey, loaded.Routes[0].JwtTokenAuth.Params["private_key"])
	require.Equal(t, routeHeaderCredential, loaded.Routes[0].Headers[0].Content)
	require.Equal(t, routeURLParamCredential, loaded.Routes[0].URLParams[0].Content)

	coreProvider := meta.NewCoreProviderWithTTL(&logging.NoOpLogger{}, staticRoot, false, 0)
	require.NoError(t, coreProvider.Init(context.Background()))
	calc := modulehash.NewCalculator(cfg, reg, pluginscdn.ProvideService(cfg), signature.DefaultCalculator(cfg))
	manager := meta.NewProviderManager(coreProvider, meta.NewLocalProvider(store, calc))

	pluginsByName := map[string]pluginsv0alpha1.Plugin{
		externalID: installedPlugin(externalID),
		coreID:     installedPlugin(coreID),
	}
	storage := NewMetaStorage(&logging.NoOpLogger{}, manager, func(context.Context) (*pluginsv0alpha1.PluginClient, error) {
		return pluginsv0alpha1.NewPluginClient(&installedPluginClient{plugins: pluginsByName}), nil
	})

	ctx := testContext("default")
	for _, id := range []string{externalID, coreID} {
		t.Run("get/"+id, func(t *testing.T) {
			obj, err := storage.Get(ctx, id, &metav1.GetOptions{})
			require.NoError(t, err)
			got := obj.(*pluginsv0alpha1.Meta)
			require.Equal(t, id, got.Name)
			require.Equal(t, id, got.Spec.PluginJson.Id)
			assertRouteCredentialsOmitted(t, got.Spec, id)
		})
	}

	t.Run("list", func(t *testing.T) {
		obj, err := storage.List(ctx, nil)
		require.NoError(t, err)
		list := obj.(*pluginsv0alpha1.MetaList)
		require.Len(t, list.Items, 2)
		seen := map[string]bool{}
		for _, item := range list.Items {
			require.Equal(t, item.Name, item.Spec.PluginJson.Id)
			assertRouteCredentialsOmitted(t, item.Spec, item.Name)
			seen[item.Name] = true
		}
		require.Equal(t, map[string]bool{externalID: true, coreID: true}, seen)
	})
}

func TestCatalogProvider_OmitsRouteCredentials(t *testing.T) {
	const parentID = "route-secret-catalog"
	const childID = "route-secret-catalog-child"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/plugins/"+parentID+"/versions/"+routePluginVersion, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(catalogVersionBody(parentID, childID))
	}))
	t.Cleanup(server.Close)

	provider := meta.NewCatalogProvider(&logging.NoOpLogger{}, server.URL+"/api/plugins", "")
	ctx := context.Background()

	t.Run("parent", func(t *testing.T) {
		parent, err := provider.GetMeta(ctx, meta.PluginRef{ID: parentID, Version: routePluginVersion})
		require.NoError(t, err)
		assertRouteCredentialsOmitted(t, parent.Meta, parentID)
	})

	t.Run("child", func(t *testing.T) {
		parentRef := parentID
		child, err := provider.GetMeta(ctx, meta.PluginRef{ID: childID, Version: routePluginVersion, ParentID: &parentRef})
		require.NoError(t, err)
		require.Equal(t, childID, child.Meta.PluginJson.Id)
		raw, err := json.Marshal(child.Meta)
		require.NoError(t, err)
		require.NotContains(t, string(raw), routeChildPrivateKey)
		require.Contains(t, string(raw), routePluginVersion)
	})
}

func assertRouteCredentialsOmitted(t *testing.T, spec pluginsv0alpha1.MetaSpec, pluginID string) {
	t.Helper()
	raw, err := json.Marshal(spec)
	require.NoError(t, err)
	body := string(raw)
	require.Contains(t, body, pluginID)
	require.Contains(t, body, routePluginVersion)
	for _, secret := range []string{
		routeHeaderCredential,
		routeURLParamCredential,
		routeTokenClientSecret,
		routeJWTPrivateKey,
		routeBodyCredential,
		routeChildPrivateKey,
	} {
		require.NotContains(t, body, secret)
	}
	require.NotContains(t, body, `"client_secret"`)
	require.NotContains(t, body, `"private_key"`)
}

func loadExternalPluginStore(t *testing.T, cfg *config.PluginManagementCfg, reg registry.Service, pluginDir string) *pluginstore.Service {
	t.Helper()
	disc := discovery.New(cfg, discovery.Opts{
		FilterFuncs: []discovery.FilterFunc{
			discovery.NewPermittedPluginTypesFilterStep([]plugins.Type{
				plugins.TypeDataSource, plugins.TypeApp, plugins.TypePanel,
			}),
		},
	})
	boot := bootstrap.New(cfg, bootstrap.Opts{
		ConstructFunc: bootstrap.DefaultConstructFunc(cfg, signature.DefaultCalculator(cfg), pluginassets.NewLocalProvider()),
		DecorateFuncs: bootstrap.DefaultDecorateFuncs(cfg, pluginscdn.ProvideService(cfg)),
	})
	// Signature validation is the production check. Unsigned plugins load when the
	// id is listed in plugins_allow_unsigned; that check does not rewrite routes.
	valid := validation.New(cfg, validation.Opts{
		ValidateFuncs: validation.DefaultValidateFuncs(cfg),
	})
	init := initialization.New(cfg, initialization.Opts{
		InitializeFuncs: []initialization.InitializeFunc{
			initialization.PluginRegistrationStep(reg),
		},
	})
	term, err := termination.New(cfg, termination.Opts{})
	require.NoError(t, err)
	ldr := pluginsLoader.New(cfg, disc, boot, valid, init, term, pluginerrs.ProvideErrorTracker())
	store, err := pluginstore.NewPluginStoreForTest(reg, ldr, sourceList{sources.NewLocalSource(plugins.ClassExternal, []string{pluginDir})})
	require.NoError(t, err)
	return store
}

type sourceList struct {
	src plugins.PluginSource
}

func (s sourceList) List(context.Context) []plugins.PluginSource {
	return []plugins.PluginSource{s.src}
}

func installedPlugin(id string) pluginsv0alpha1.Plugin {
	return pluginsv0alpha1.Plugin{
		ObjectMeta: metav1.ObjectMeta{Name: id, Namespace: "default"},
		Spec:       pluginsv0alpha1.PluginSpec{Id: id, Version: routePluginVersion},
	}
}

type installedPluginClient struct {
	resource.Client
	plugins map[string]pluginsv0alpha1.Plugin
}

func (c *installedPluginClient) Get(_ context.Context, id resource.Identifier) (resource.Object, error) {
	plugin, ok := c.plugins[id.Name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return &plugin, nil
}

func (c *installedPluginClient) List(context.Context, string, resource.ListOptions) (resource.ListObject, error) {
	items := make([]pluginsv0alpha1.Plugin, 0, len(c.plugins))
	for _, plugin := range c.plugins {
		items = append(items, plugin)
	}
	return &pluginsv0alpha1.PluginList{Items: items}, nil
}

func (c *installedPluginClient) ListInto(_ context.Context, namespace string, opts resource.ListOptions, into resource.ListObject) error {
	list, err := c.List(context.Background(), namespace, opts)
	if err != nil {
		return err
	}
	into.SetItems(list.GetItems())
	return nil
}

func writeRoutePlugin(t *testing.T, dir, id, privateKey string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "plugin.json"), []byte(routePluginJSON(id, privateKey)), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "module.js"), []byte("export {}\n"), 0o644))
}

func routePluginJSON(id, privateKey string) string {
	payload := map[string]any{
		"type": "datasource",
		"name": id,
		"id":   id,
		"info": map[string]any{
			"version": routePluginVersion,
			"updated": "2026-01-01",
			"author":  map[string]any{"name": "fixture"},
			"logos":   map[string]any{"small": "img/logo.svg", "large": "img/logo.svg"},
		},
		"routes": []any{
			map[string]any{
				"path":   "secure",
				"method": "GET",
				"url":    "https://upstream.example.test/api",
				"headers": []any{
					map[string]any{"name": "Authorization", "content": routeHeaderCredential},
				},
				"urlParams": []any{
					map[string]any{"name": "access_token", "content": routeURLParamCredential},
				},
				"tokenAuth": map[string]any{
					"url":    "https://upstream.example.test/token",
					"scopes": []any{"read"},
					"params": map[string]any{
						"grant_type":    "client_credentials",
						"client_id":     "route-token-client-id-placeholder",
						"client_secret": routeTokenClientSecret,
					},
				},
				"jwtTokenAuth": map[string]any{
					"url": "https://upstream.example.test/jwt",
					"params": map[string]any{
						"token_uri":    "https://upstream.example.test/jwt-token",
						"client_email": "route-jwt-client-email-placeholder",
						"private_key":  privateKey,
					},
				},
				"body": map[string]any{"password": routeBodyCredential},
			},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func catalogVersionBody(parentID, childID string) []byte {
	body := map[string]any{
		"pluginSlug": parentID,
		"version":    routePluginVersion,
		"cdnUrl":     "https://cdn.example.test/plugins/" + parentID + "/" + routePluginVersion + "/",
		"json":       json.RawMessage(routePluginJSON(parentID, routeJWTPrivateKey)),
		"children": []any{
			map[string]any{
				"slug": childID,
				"path": "child",
				"json": json.RawMessage(routePluginJSON(childID, routeChildPrivateKey)),
			},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return raw
}
