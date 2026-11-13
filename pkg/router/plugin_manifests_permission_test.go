package router

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	authnlib "github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"k8s.io/kube-openapi/pkg/spec3"

	"github.com/grafana/grafana-app-sdk/app"
	pluginv3 "github.com/grafana/grafana-app-sdk/plugin/genproto/grafana/plugin/v3"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	searchv0 "github.com/grafana/grafana/pkg/apis/search/v0alpha1"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/definition"
	"github.com/grafana/grafana/pkg/services/apiserver/kindstore"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginaccesscontrol"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// TestPluginManifestRouterRequiresPluginAccess drives the plugins_url backend
// the cloud router installs: poll wires pluginManifestAccessControl into the
// plugin handler, the wrapper authenticates X-Access-Token, and the plugin
// authorizer decides custom routes and cluster-scoped reads.
//
// A caller is allowed only when their own permissions grant plugins.app:access
// on the plugin id of the backend that serves the request. A valid token with
// no such grant, a grant for a different plugin, or a different action must be
// refused before the plugin backend or storage is called.
func TestPluginManifestRouterRequiresPluginAccess(t *testing.T) {
	const (
		alphaID    = "alpha-app"
		betaID     = "beta-app"
		alphaGroup = "alpha.ext.grafana.app"
		betaGroup  = "beta.ext.grafana.app"
		version    = "v1alpha1"
	)

	routeServer := &permissionRouteServer{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcServer := grpc.NewServer()
	pluginv3.RegisterRouteServiceServer(grpcServer, routeServer)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)

	store := &permissionRecordingStore{}
	pluginsBody, err := json.Marshal(definition.PluginDeployments{
		Key: "permission-test",
		Plugins: []definition.PluginDeployment{
			{Definition: permissionPlugin(alphaID, alphaGroup), Host: listener.Addr().String()},
			{Definition: permissionPlugin(betaID, betaGroup), Host: listener.Addr().String()},
		},
	})
	require.NoError(t, err)
	manifests := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pluginsBody)
	}))
	t.Cleanup(manifests.Close)

	realAuth, signed := newPermissionTokenAuthenticator(t)
	callers := map[string]identity.Requester{
		"placeholder-no-permissions": permissionUser(nil),
		"placeholder-grafana-admin": &identity.StaticRequester{
			Type: types.TypeUser, UserID: 1, UserUID: "admin", OrgID: 1, Namespace: "default",
			IsGrafanaAdmin: true, Login: "admin",
		},
		"placeholder-other-action": permissionUser(map[string][]string{
			"plugins:write": {pluginaccesscontrol.ScopeProvider.GetResourceScope(alphaID)},
		}),
		"placeholder-other-plugin": permissionUser(map[string][]string{
			pluginaccesscontrol.ActionAppAccess: {pluginaccesscontrol.ScopeProvider.GetResourceScope(betaID)},
		}),
		"placeholder-near-scope": permissionUser(map[string][]string{
			pluginaccesscontrol.ActionAppAccess: {pluginaccesscontrol.ScopeProvider.GetResourceScope(alphaID + "-extra")},
		}),
		"placeholder-alpha": permissionUser(map[string][]string{
			pluginaccesscontrol.ActionAppAccess: {pluginaccesscontrol.ScopeProvider.GetResourceScope(alphaID)},
		}),
		"placeholder-all": permissionUser(map[string][]string{
			pluginaccesscontrol.ActionAppAccess: {pluginaccesscontrol.ScopeProvider.GetResourceAllScope()},
		}),
		"placeholder-all-ids": permissionUser(map[string][]string{
			pluginaccesscontrol.ActionAppAccess: {pluginaccesscontrol.ScopeProvider.GetResourceAllIDScope()},
		}),
		"placeholder-alpha-prefix": permissionUser(map[string][]string{
			pluginaccesscontrol.ActionAppAccess: {"plugins:id:alpha-*"},
		}),
		"placeholder-policy": &identity.StaticRequester{
			Type: types.TypeAccessPolicy, UserUID: "policy", OrgID: 1, Namespace: "default", Name: "policy",
		},
		"placeholder-policy-alpha": &identity.StaticRequester{
			Type: types.TypeAccessPolicy, UserUID: "policy-alpha", OrgID: 1, Namespace: "default", Name: "policy-alpha",
			Permissions: map[int64]map[string][]string{
				1: {pluginaccesscontrol.ActionAppAccess: {pluginaccesscontrol.ScopeProvider.GetResourceScope(alphaID)}},
			},
		},
	}
	authenticator := permissionAuthenticatorFunc(func(ctx context.Context, token string) (identity.Requester, error) {
		if requester, ok := callers[token]; ok {
			return requester, nil
		}
		return realAuth.AuthenticateToken(ctx, token)
	})

	cfg := setting.NewCfg()
	cfg.SectionWithEnvOverrides("grafana-apiserver").Key("enable_keys_api").SetValue("true")
	target, err := newPluginManifestsTarget(manifests.URL, nil, manifests.Client(), PluginDependencies{
		Unified: store,
		Cfg:     cfg,
	}, authenticator)
	require.NoError(t, err)
	t.Cleanup(target.closeConnections)
	target.poll(t.Context(), make(chan struct{}, 1))
	require.Len(t, target.Backends(), 2)

	handlers := map[string]http.Handler{}
	for _, backend := range target.Backends() {
		handler, err := backend.Load(t.Context())
		require.NoError(t, err)
		t.Cleanup(handler.(*authenticatingWrapper).Handler.(interface{ Destroy() }).Destroy)
		handlers[backend.Group().Name] = handler
	}

	alpha := permissionAPI{group: alphaGroup, version: version, handler: handlers[alphaGroup]}
	beta := permissionAPI{group: betaGroup, version: version, handler: handlers[betaGroup]}
	settingBody := permissionObject(alphaGroup, version, "Setting", "", "created")
	searchBody := `{"apiVersion":"` + searchv0.APIVERSION + `","kind":"` + searchv0.KindSearchQuery + `"}`

	// Every operation the plugin authorizer releases once plugins.app:access is
	// allowed for the served plugin. Stored-object calls are included because
	// this router authorizes them before storage sees the request.
	denied := []permissionRequest{
		{name: "version cluster route", method: http.MethodGet, path: alpha.clusterRoute("catalog")},
		{name: "version namespaced route", method: http.MethodGet, path: alpha.namespacedRoute("board")},
		{name: "cluster kind route", method: http.MethodGet, path: alpha.clusterSubresource("settings", "example", "reload")},
		{name: "namespaced kind route", method: http.MethodGet, path: alpha.namespacedSubresource("widgets", "example", "poke")},
		{name: "unreadable cluster kind route", method: http.MethodPost, path: alpha.clusterSubresource("secrets", "example", "rotate")},
		{name: "user-readable cluster get", method: http.MethodGet, path: alpha.clusterObject("settings", "example")},
		{name: "user-readable cluster list", method: http.MethodGet, path: alpha.clusterCollection("settings")},
		{name: "user-readable cluster watch", method: http.MethodGet, path: alpha.clusterCollection("settings") + "?watch=true"},
		{name: "user-readable cluster create", method: http.MethodPost, path: alpha.clusterCollection("settings"), body: settingBody},
		{name: "unreadable cluster get", method: http.MethodGet, path: alpha.clusterObject("secrets", "example")},
		{name: "unreadable cluster delete", method: http.MethodDelete, path: alpha.clusterObject("secrets", "example")},
		{name: "namespaced get", method: http.MethodGet, path: alpha.namespacedObject("widgets", "example")},
		{name: "namespaced search", method: http.MethodPost, path: alpha.namespacedCollection("widgets") + "/search", body: searchBody},
		{name: "namespaced list-keys", method: http.MethodPost, path: alpha.namespacedCollection("widgets") + "/list-keys"},
	}

	unauthorized := []struct {
		name  string
		token string
	}{
		{name: "access policy token", token: signed.accessPolicy},
		{name: "on-behalf-of user token", token: signed.user},
		{name: "user without permissions", token: "placeholder-no-permissions"},
		{name: "grafana admin without the plugin grant", token: "placeholder-grafana-admin"},
		{name: "plugins write on this plugin", token: "placeholder-other-action"},
		{name: "app access on the other plugin", token: "placeholder-other-plugin"},
		{name: "app access on a longer plugin id", token: "placeholder-near-scope"},
		{name: "access policy without the plugin grant", token: "placeholder-policy"},
	}
	for _, caller := range unauthorized {
		for _, req := range denied {
			t.Run(caller.name+"/"+req.name, func(t *testing.T) {
				before := permissionEffects{routes: routeServer.count(), storage: store.count()}
				res := permissionCall(t, alpha.handler, req, caller.token)
				require.Equal(t, before, permissionEffects{routes: routeServer.count(), storage: store.count()},
					"plugin and storage must not run when the caller lacks this plugin's access; got %d %s", res.Code, res.Body.String())
				require.Equal(t, http.StatusForbidden, res.Code, res.Body.String())
			})
		}
	}

	t.Run("missing token", func(t *testing.T) {
		before := permissionEffects{routes: routeServer.count(), storage: store.count()}
		res := permissionCall(t, alpha.handler, denied[0], "")
		require.Equal(t, http.StatusUnauthorized, res.Code, res.Body.String())
		require.Equal(t, before, permissionEffects{routes: routeServer.count(), storage: store.count()})
	})
	t.Run("invalid token", func(t *testing.T) {
		before := permissionEffects{routes: routeServer.count(), storage: store.count()}
		res := permissionCall(t, alpha.handler, denied[0], "placeholder-not-a-token")
		require.Equal(t, http.StatusUnauthorized, res.Code, res.Body.String())
		require.Equal(t, before, permissionEffects{routes: routeServer.count(), storage: store.count()})
	})

	// The grant is for alpha only. The same caller must still be refused on beta,
	// including when the requested object is a different plugin's copy of the same kind.
	for _, req := range []permissionRequest{
		{name: "beta route", method: http.MethodGet, path: beta.clusterRoute("catalog")},
		{name: "beta cluster get", method: http.MethodGet, path: beta.clusterObject("settings", "example")},
		{name: "beta namespaced get", method: http.MethodGet, path: beta.namespacedObject("widgets", "example")},
	} {
		t.Run("alpha grant/"+req.name, func(t *testing.T) {
			before := permissionEffects{routes: routeServer.count(), storage: store.count()}
			res := permissionCall(t, beta.handler, req, "placeholder-alpha")
			require.Equal(t, before, permissionEffects{routes: routeServer.count(), storage: store.count()},
				"a grant for alpha must not reach beta; got %d %s", res.Code, res.Body.String())
			require.Equal(t, http.StatusForbidden, res.Code, res.Body.String())
		})
	}

	t.Run("alpha grant allows this plugin", func(t *testing.T) {
		res := permissionCall(t, alpha.handler, permissionRequest{method: http.MethodGet, path: alpha.clusterRoute("catalog")}, "placeholder-alpha")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		require.Equal(t, alphaGroup+" catalog", routeServer.last())

		res = permissionCall(t, alpha.handler, permissionRequest{method: http.MethodGet, path: alpha.namespacedRoute("board")}, "placeholder-alpha")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		require.Equal(t, alphaGroup+" board", routeServer.last())

		res = permissionCall(t, alpha.handler, permissionRequest{method: http.MethodGet, path: alpha.clusterSubresource("settings", "example", "reload")}, "placeholder-alpha")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		require.Equal(t, alphaGroup+" reload", routeServer.last())
		require.Equal(t, "read", store.last().method)
		require.Equal(t, alphaGroup, store.last().group)
		require.Equal(t, "settings", store.last().resource)
		require.Equal(t, "example", store.last().name)

		res = permissionCall(t, alpha.handler, permissionRequest{method: http.MethodGet, path: alpha.namespacedSubresource("widgets", "example", "poke")}, "placeholder-alpha")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		require.Equal(t, alphaGroup+" poke", routeServer.last())
		require.Equal(t, alphaGroup, store.last().group)
		require.Equal(t, "widgets", store.last().resource)

		res = permissionCall(t, alpha.handler, permissionRequest{method: http.MethodPost, path: alpha.clusterSubresource("secrets", "example", "rotate")}, "placeholder-alpha")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		require.Equal(t, alphaGroup+" rotate", routeServer.last())
		require.Equal(t, "secrets", store.last().resource)

		res = permissionCall(t, alpha.handler, permissionRequest{method: http.MethodGet, path: alpha.clusterObject("settings", "example")}, "placeholder-alpha")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		require.Contains(t, res.Body.String(), `"name":"example"`)
		require.Equal(t, permissionOp{method: "read", group: alphaGroup, resource: "settings", name: "example"}, store.last())

		res = permissionCall(t, alpha.handler, permissionRequest{method: http.MethodGet, path: alpha.clusterCollection("settings")}, "placeholder-alpha")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		require.Contains(t, res.Body.String(), `"name":"example"`)
		require.Equal(t, "list", store.last().method)
		require.Equal(t, alphaGroup, store.last().group)
		require.Equal(t, "settings", store.last().resource)

		res = permissionCall(t, alpha.handler, permissionRequest{method: http.MethodGet, path: alpha.namespacedObject("widgets", "example")}, "placeholder-alpha")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		require.Contains(t, res.Body.String(), `"name":"example"`)
		require.Equal(t, permissionOp{method: "read", group: alphaGroup, resource: "widgets", namespace: "default", name: "example"}, store.last())

		before := store.count()
		res = permissionCall(t, alpha.handler, permissionRequest{method: http.MethodPost, path: alpha.namespacedCollection("widgets") + "/search", body: searchBody}, "placeholder-alpha")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		require.Greater(t, store.count(), before)
		require.Equal(t, "search", store.last().method)
		require.Equal(t, alphaGroup, store.last().group)
		require.Equal(t, "widgets", store.last().resource)

		before = store.count()
		res = permissionCall(t, alpha.handler, permissionRequest{method: http.MethodPost, path: alpha.namespacedCollection("widgets") + "/list-keys"}, "placeholder-alpha")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		require.Greater(t, store.count(), before)
		require.Equal(t, "list", store.last().method)
		require.Equal(t, alphaGroup, store.last().group)
		require.Equal(t, "widgets", store.last().resource)

		// A user who can open the plugin still cannot write cluster objects or
		// read a cluster kind the manifest does not mark user-readable.
		beforeEffects := permissionEffects{routes: routeServer.count(), storage: store.count()}
		for _, req := range []permissionRequest{
			{method: http.MethodPost, path: alpha.clusterCollection("settings"), body: settingBody},
			{method: http.MethodGet, path: alpha.clusterObject("secrets", "example")},
			{method: http.MethodDelete, path: alpha.clusterObject("secrets", "example")},
		} {
			res = permissionCall(t, alpha.handler, req, "placeholder-alpha")
			require.Equal(t, http.StatusForbidden, res.Code, res.Body.String())
		}
		require.Equal(t, beforeEffects, permissionEffects{routes: routeServer.count(), storage: store.count()})
	})

	t.Run("wildcard grants match only the scopes they name", func(t *testing.T) {
		for _, token := range []string{"placeholder-all", "placeholder-all-ids"} {
			res := permissionCall(t, beta.handler, permissionRequest{method: http.MethodGet, path: beta.clusterObject("settings", "example")}, token)
			require.Equal(t, http.StatusOK, res.Code, res.Body.String())
			require.Equal(t, betaGroup, store.last().group)
			require.Equal(t, "settings", store.last().resource)
		}
		res := permissionCall(t, alpha.handler, permissionRequest{method: http.MethodGet, path: alpha.clusterRoute("catalog")}, "placeholder-alpha-prefix")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		require.Equal(t, alphaGroup+" catalog", routeServer.last())
		before := permissionEffects{routes: routeServer.count(), storage: store.count()}
		res = permissionCall(t, beta.handler, permissionRequest{method: http.MethodGet, path: beta.clusterRoute("catalog")}, "placeholder-alpha-prefix")
		require.Equal(t, http.StatusForbidden, res.Code, res.Body.String())
		require.Equal(t, before, permissionEffects{routes: routeServer.count(), storage: store.count()})
	})

	t.Run("access policy with this plugin grant can operate cluster kinds", func(t *testing.T) {
		res := permissionCall(t, alpha.handler, permissionRequest{method: http.MethodPost, path: alpha.clusterCollection("settings"), body: settingBody}, "placeholder-policy-alpha")
		require.Equal(t, http.StatusCreated, res.Code, res.Body.String())
		require.Equal(t, permissionOp{method: "create", group: alphaGroup, resource: "settings", name: "created"}, store.last())

		res = permissionCall(t, alpha.handler, permissionRequest{method: http.MethodGet, path: alpha.clusterObject("secrets", "example")}, "placeholder-policy-alpha")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		require.Equal(t, permissionOp{method: "read", group: alphaGroup, resource: "secrets", name: "example"}, store.last())

		res = permissionCall(t, alpha.handler, permissionRequest{method: http.MethodDelete, path: alpha.clusterObject("secrets", "example")}, "placeholder-policy-alpha")
		require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, res.Code, res.Body.String())
		require.Equal(t, permissionOp{method: "delete", group: alphaGroup, resource: "secrets", name: "example"}, store.last())

		before := permissionEffects{routes: routeServer.count(), storage: store.count()}
		res = permissionCall(t, beta.handler, permissionRequest{method: http.MethodPost, path: beta.clusterCollection("settings"), body: permissionObject(betaGroup, version, "Setting", "", "created")}, "placeholder-policy-alpha")
		require.Equal(t, http.StatusForbidden, res.Code, res.Body.String())
		require.Equal(t, before, permissionEffects{routes: routeServer.count(), storage: store.count()})
	})

	t.Run("watch reaches storage only after the plugin grant", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req := httptest.NewRequest(http.MethodGet, alpha.clusterCollection("settings")+"?watch=true", nil).WithContext(ctx)
		req.Header.Set("X-Access-Token", "placeholder-alpha")
		before := store.count()
		res := &permissionFlushRecorder{ResponseRecorder: httptest.NewRecorder()}
		alpha.handler.ServeHTTP(res, req)
		require.NotEqual(t, http.StatusForbidden, res.Code, res.Body.String())
		require.Greater(t, store.count(), before)
		require.Equal(t, "watch", store.last().method)
		require.Equal(t, alphaGroup, store.last().group)
		require.Equal(t, "settings", store.last().resource)
	})
}

type permissionRequest struct {
	name   string
	method string
	path   string
	body   string
}

type permissionAPI struct {
	group   string
	version string
	handler http.Handler
}

func (a permissionAPI) root() string {
	return "/apis/" + a.group + "/" + a.version
}

func (a permissionAPI) clusterRoute(path string) string {
	return a.root() + "/" + path
}

func (a permissionAPI) namespacedRoute(path string) string {
	return a.root() + "/namespaces/default/" + path
}

func (a permissionAPI) clusterCollection(resource string) string {
	return a.root() + "/" + resource
}

func (a permissionAPI) clusterObject(resource, name string) string {
	return a.clusterCollection(resource) + "/" + name
}

func (a permissionAPI) clusterSubresource(resource, name, sub string) string {
	return a.clusterObject(resource, name) + "/" + sub
}

func (a permissionAPI) namespacedCollection(resource string) string {
	return a.root() + "/namespaces/default/" + resource
}

func (a permissionAPI) namespacedObject(resource, name string) string {
	return a.namespacedCollection(resource) + "/" + name
}

func (a permissionAPI) namespacedSubresource(resource, name, sub string) string {
	return a.namespacedObject(resource, name) + "/" + sub
}

type permissionEffects struct {
	routes  int
	storage int
}

func permissionCall(t *testing.T, handler http.Handler, req permissionRequest, token string) *httptest.ResponseRecorder {
	t.Helper()
	httpReq := httptest.NewRequest(req.method, req.path, strings.NewReader(req.body))
	if req.body != "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		httpReq.Header.Set("X-Access-Token", token)
	}
	res := &permissionFlushRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(res, httpReq)
	return res.ResponseRecorder
}

// permissionFlushRecorder implements http.Flusher. A watch that authorization
// has already allowed asks the writer to flush; without it the request fails
// for a reason other than access control.
type permissionFlushRecorder struct {
	*httptest.ResponseRecorder
}

func (permissionFlushRecorder) Flush() {}

func permissionUser(actions map[string][]string) *identity.StaticRequester {
	var permissions map[int64]map[string][]string
	if actions != nil {
		permissions = map[int64]map[string][]string{1: actions}
	}
	return &identity.StaticRequester{
		Type: types.TypeUser, UserID: 42, UserUID: "user-42", OrgID: 1, Namespace: "default",
		Login: "limited", Name: "limited", Permissions: permissions,
	}
}

func permissionPlugin(id, group string) definition.PluginDefinition {
	folderScoped := false
	operation := func(operationID string) *spec3.Operation {
		return &spec3.Operation{OperationProps: spec3.OperationProps{
			OperationId: operationID,
			Responses: &spec3.Responses{ResponsesProps: spec3.ResponsesProps{
				Default: &spec3.Response{ResponseProps: spec3.ResponseProps{Description: "OK"}},
			}},
		}}
	}
	return definition.PluginDefinition{
		JSONData: plugins.JSONData{ID: id, Type: plugins.TypeApp, Name: id},
		Manifest: &app.ManifestData{
			AppName:          id,
			Group:            group,
			PreferredVersion: "v1alpha1",
			Versions: []app.ManifestVersion{{
				Name:   "v1alpha1",
				Served: true,
				Routes: app.ManifestVersionRoutes{
					Cluster:    map[string]spec3.PathProps{"/catalog": {Get: operation("getCatalog")}},
					Namespaced: map[string]spec3.PathProps{"/board": {Get: operation("getBoard")}},
				},
				Kinds: []app.ManifestVersionKind{
					{
						Kind: "Setting", Plural: "settings", Scope: kindstore.ClusterScope, UserReadable: true,
						Routes: map[string]spec3.PathProps{"/reload": {Get: operation("reloadSetting")}},
					},
					{
						Kind: "Secret", Plural: "secrets", Scope: kindstore.ClusterScope,
						Routes: map[string]spec3.PathProps{"/rotate": {Post: operation("rotateSecret")}},
					},
					{
						Kind: "Widget", Plural: "widgets", Scope: "Namespaced", FolderScoped: &folderScoped,
						Routes: map[string]spec3.PathProps{"/poke": {Get: operation("pokeWidget")}},
					},
				},
			}},
		},
	}
}

func permissionObject(group, version, kind, namespace, name string) string {
	meta := map[string]string{"name": name}
	if namespace != "" {
		meta["namespace"] = namespace
	}
	body, err := json.Marshal(map[string]any{
		"apiVersion": group + "/" + version,
		"kind":       kind,
		"metadata":   meta,
	})
	if err != nil {
		panic(err)
	}
	return string(body)
}

type permissionOp struct {
	method    string
	group     string
	resource  string
	namespace string
	name      string
}

type permissionRecordingStore struct {
	resource.ResourceClient
	mu  sync.Mutex
	ops []permissionOp
}

func (s *permissionRecordingStore) record(op permissionOp) {
	s.mu.Lock()
	s.ops = append(s.ops, op)
	s.mu.Unlock()
}

func (s *permissionRecordingStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ops)
}

func (s *permissionRecordingStore) last() permissionOp {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ops[len(s.ops)-1]
}

func (s *permissionRecordingStore) Read(_ context.Context, req *resourcepb.ReadRequest, _ ...grpc.CallOption) (*resourcepb.ReadResponse, error) {
	key := req.GetKey()
	s.record(permissionOp{method: "read", group: key.GetGroup(), resource: key.GetResource(), namespace: key.GetNamespace(), name: key.GetName()})
	return &resourcepb.ReadResponse{ResourceVersion: 1, Value: permissionObjectBytes(key, key.GetName())}, nil
}

func (s *permissionRecordingStore) List(_ context.Context, req *resourcepb.ListRequest, _ ...grpc.CallOption) (*resourcepb.ListResponse, error) {
	key := req.GetOptions().GetKey()
	s.record(permissionOp{method: "list", group: key.GetGroup(), resource: key.GetResource(), namespace: key.GetNamespace()})
	return &resourcepb.ListResponse{
		ResourceVersion: 1,
		Items:           []*resourcepb.ResourceWrapper{{ResourceVersion: 1, Value: permissionObjectBytes(key, "example")}},
	}, nil
}

func (s *permissionRecordingStore) Create(_ context.Context, req *resourcepb.CreateRequest, _ ...grpc.CallOption) (*resourcepb.CreateResponse, error) {
	key := req.GetKey()
	s.record(permissionOp{method: "create", group: key.GetGroup(), resource: key.GetResource(), namespace: key.GetNamespace(), name: key.GetName()})
	return &resourcepb.CreateResponse{ResourceVersion: 1}, nil
}

func (s *permissionRecordingStore) Delete(_ context.Context, req *resourcepb.DeleteRequest, _ ...grpc.CallOption) (*resourcepb.DeleteResponse, error) {
	key := req.GetKey()
	s.record(permissionOp{method: "delete", group: key.GetGroup(), resource: key.GetResource(), namespace: key.GetNamespace(), name: key.GetName()})
	return &resourcepb.DeleteResponse{ResourceVersion: 1}, nil
}

func (s *permissionRecordingStore) Watch(_ context.Context, req *resourcepb.WatchRequest, _ ...grpc.CallOption) (resourcepb.ResourceStore_WatchClient, error) {
	key := req.GetOptions().GetKey()
	s.record(permissionOp{method: "watch", group: key.GetGroup(), resource: key.GetResource(), namespace: key.GetNamespace()})
	return nil, context.Canceled
}

func (s *permissionRecordingStore) Search(_ context.Context, req *resourcepb.ResourceSearchRequest, _ ...grpc.CallOption) (*resourcepb.ResourceSearchResponse, error) {
	key := req.GetOptions().GetKey()
	s.record(permissionOp{method: "search", group: key.GetGroup(), resource: key.GetResource(), namespace: key.GetNamespace()})
	return &resourcepb.ResourceSearchResponse{}, nil
}

func permissionObjectBytes(key *resourcepb.ResourceKey, name string) []byte {
	kind := "Widget"
	switch key.GetResource() {
	case "settings":
		kind = "Setting"
	case "secrets":
		kind = "Secret"
	}
	return []byte(permissionObject(key.GetGroup(), "v1alpha1", kind, key.GetNamespace(), name))
}

type permissionRouteServer struct {
	pluginv3.UnimplementedRouteServiceServer
	mu     sync.Mutex
	routes []string
}

func (s *permissionRouteServer) CallRoute(req *pluginv3.CallRouteRequest, stream grpc.ServerStreamingServer[pluginv3.CallRouteResponse]) error {
	s.mu.Lock()
	s.routes = append(s.routes, req.GetGroup()+" "+req.GetPath())
	s.mu.Unlock()
	resp := &pluginv3.CallRouteResponse{}
	resp.SetCode(http.StatusOK)
	resp.SetBody([]byte("reached"))
	return stream.Send(resp)
}

func (s *permissionRouteServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.routes)
}

func (s *permissionRouteServer) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routes[len(s.routes)-1]
}

type permissionAuthenticatorFunc func(context.Context, string) (identity.Requester, error)

func (f permissionAuthenticatorFunc) AuthenticateToken(ctx context.Context, token string) (identity.Requester, error) {
	return f(ctx, token)
}

type signedPermissionTokens struct {
	accessPolicy string
	user         string
}

func newPermissionTokenAuthenticator(t *testing.T) (*authn.GrafanaTokenAuthenticator, signedPermissionTokens) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: "permission-test", Algorithm: string(jose.ES256), Use: "sig",
		}}}))
	}))
	t.Cleanup(keys.Close)
	cfg := setting.NewCfg()
	cfg.ExtJWTAuth.JWKSUrl = keys.URL
	cfg.ExtJWTAuth.Audiences = []string{"grafana"}
	authenticator, err := authn.NewGrafanaTokenAuthenticator(cfg)
	require.NoError(t, err)

	sign := func(claims authnlib.Claims[authnlib.AccessTokenClaims]) string {
		t.Helper()
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
			(&jose.SignerOptions{}).WithType(jose.ContentType(authnlib.TokenTypeAccess)).WithHeader("kid", "permission-test"))
		require.NoError(t, err)
		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)
		return token
	}
	base := func() authnlib.Claims[authnlib.AccessTokenClaims] {
		return authnlib.Claims[authnlib.AccessTokenClaims]{
			Claims: jwt.Claims{
				Subject:  "access-policy:policy-1",
				Audience: jwt.Audience{"grafana"},
				Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			Rest: authnlib.AccessTokenClaims{Namespace: "default"},
		}
	}
	policy := base()
	policy.Rest.Permissions = []string{"folders:read"}
	user := base()
	user.Rest.DelegatedPermissions = []string{"datasources:query"}
	user.Rest.Actor = &authnlib.ActorClaims{
		Subject: "access-policy:intermediate",
		Actor: &authnlib.ActorClaims{
			Subject: types.NewTypeID(types.TypeUser, "42"),
			IDTokenClaims: authnlib.IDTokenClaims{
				Type: types.TypeUser, Identifier: "user-uid", Username: "alice",
				Email: "alice@example.com", EmailVerified: true,
			},
		},
	}
	return authenticator, signedPermissionTokens{accessPolicy: sign(policy), user: sign(user)}
}
