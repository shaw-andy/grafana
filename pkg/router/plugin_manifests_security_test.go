package router

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/grafana/authlib/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"k8s.io/kube-openapi/pkg/spec3"

	"github.com/grafana/grafana-app-sdk/app"
	pluginv3 "github.com/grafana/grafana-app-sdk/plugin/genproto/grafana/plugin/v3"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/definition"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// Placeholders stand in for caller material. They are not credentials.
const (
	plaintextAccessToken = "placeholder-access-token"
	plaintextRouteBody   = "placeholder-route-body"
	plaintextObjectBody  = "placeholder-object-body"
	attackerMutation     = "attacker-controlled"
)

// TestCleartextPluginManifestCannotReachUnverifiedHost exercises the cloud
// router path that polls plugins_url and dials each manifest host. An
// unauthenticated cleartext manifest response must not be able to aim that
// dial at an arbitrary process, and that process must not observe the caller
// credential, route body, or admission object, or change what is stored.
//
// The v2 client is built on the same connection, but this loader clears
// PluginClient and ContextProvider, so the settings CallResource and
// CheckHealth routes are not mounted. v3 ConvertObjects has no caller on this
// handler. Those three stay untested.
func TestCleartextPluginManifestCannotReachUnverifiedHost(t *testing.T) {
	peer := newPlaintextPluginPeer(t)
	fetch := &manifestFetchRecorder{}
	manifest := httptest.NewServer(fetch.handler(peer.addr, manifestWithAdmissionAndRoutes()))
	t.Cleanup(manifest.Close)

	storage := &securityResourceClient{}
	// The authenticator mirrors GrafanaTokenAuthenticator: the presented access
	// token is retained, and no ID token is set, so nothing rewrites X-Grafana-Id.
	target, err := newPluginManifestsTarget(manifest.URL, nil, manifest.Client(), PluginDependencies{Unified: storage},
		manifestTokenAuthenticatorFunc(func(_ context.Context, got string) (identity.Requester, error) {
			return &identity.StaticRequester{
				Type:        types.TypeUser,
				UserUID:     "caller",
				OrgID:       1,
				Namespace:   "default",
				AccessToken: got,
			}, nil
		}))
	var handler http.Handler
	if err == nil {
		t.Cleanup(target.closeConnections)
		target.poll(t.Context(), make(chan struct{}, 1))
		if backends := target.Backends(); len(backends) > 0 {
			handler, err = backends[0].Load(t.Context())
			if err == nil {
				t.Cleanup(destroyHandler(handler))
			}
		}
	}

	var create, versionRoute, kindRoute, update, del *httptest.ResponseRecorder
	if handler != nil {
		root := "/apis/appsdktest.ext.grafana.app/v1alpha1/namespaces/default"
		object := `{"apiVersion":"appsdktest.ext.grafana.app/v1alpha1","kind":"Thing","metadata":{"name":"example"},"spec":{"note":"` + plaintextObjectBody + `"}}`
		create = callPluginHandler(handler, http.MethodPost, root+"/things", object)
		versionRoute = callPluginHandler(handler, http.MethodPost, root+"/foobar", plaintextRouteBody)
		kindRoute = callPluginHandler(handler, http.MethodPost, root+"/things/example/reload", plaintextRouteBody)
		updated := `{"apiVersion":"appsdktest.ext.grafana.app/v1alpha1","kind":"Thing","metadata":{"name":"example","resourceVersion":"1"},"spec":{"note":"` + plaintextObjectBody + `","rev":"2"}}`
		update = callPluginHandler(handler, http.MethodPut, root+"/things/example", updated)
		del = callPluginHandler(handler, http.MethodDelete, root+"/things/example", "")
	}

	wire := peer.wire.Bytes()
	routes, reviews := peer.snapshot()
	stored := storage.snapshot()
	tokenOnWire := bytes.Contains(wire, []byte(plaintextAccessToken))
	bodyOnWire := bytes.Contains(wire, []byte(plaintextRouteBody))
	objectOnWire := bytes.Contains(wire, []byte(plaintextObjectBody))
	mutated := bytes.Contains(stored.created, []byte(attackerMutation)) ||
		bytes.Contains(stored.updated, []byte(attackerMutation))
	reached := peer.accepts.Load() > 0 || len(routes) > 0 || len(reviews) > 0 ||
		tokenOnWire || bodyOnWire || objectOnWire || peerSawMaterial(routes, reviews) || mutated
	if !reached {
		return
	}

	t.Fatalf("unauthenticated cleartext plugin manifest (fetches=%d tls=%v authorization=%q) dialed %s (%d accepts, create=%s route=%s kind=%s update=%s delete=%s). route calls=%d admission calls=%d access token on wire=%v access token in route headers=%v route body on wire=%v object on wire=%v parent object forwarded=%v stored mutation=%v",
		fetch.count.Load(), fetch.tls.Load(), fetch.authorization.Load(), peer.addr, peer.accepts.Load(),
		statusOf(create), statusOf(versionRoute), statusOf(kindRoute), statusOf(update), statusOf(del),
		len(routes), len(reviews), tokenOnWire, accessTokenInRoutes(routes), bodyOnWire, objectOnWire, parentForwarded(routes), mutated)
}

func accessTokenInRoutes(routes []*pluginv3.CallRouteRequest) bool {
	for _, req := range routes {
		if headerValuesContain(req.GetHeaders(), plaintextAccessToken) {
			return true
		}
	}
	return false
}

func parentForwarded(routes []*pluginv3.CallRouteRequest) bool {
	for _, req := range routes {
		if bytes.Contains(req.GetParent().GetRaw(), []byte(plaintextObjectBody)) {
			return true
		}
	}
	return false
}

func destroyHandler(handler http.Handler) func() {
	return func() {
		if wrapper, ok := handler.(*authenticatingWrapper); ok {
			handler = wrapper.Handler
		}
		if destroyer, ok := handler.(interface{ Destroy() }); ok {
			destroyer.Destroy()
		}
	}
}

func statusOf(res *httptest.ResponseRecorder) string {
	if res == nil {
		return "not-called"
	}
	return http.StatusText(res.Code)
}

func manifestWithAdmissionAndRoutes() *app.ManifestData {
	operation := func(id string) *spec3.Operation {
		return &spec3.Operation{OperationProps: spec3.OperationProps{
			OperationId: id,
			Responses: &spec3.Responses{ResponsesProps: spec3.ResponsesProps{
				Default: &spec3.Response{ResponseProps: spec3.ResponseProps{Description: "OK"}},
			}},
		}}
	}
	folderScoped := false
	return &app.ManifestData{
		AppName:          "grafana-appsdktest-app",
		Group:            "appsdktest.ext.grafana.app",
		PreferredVersion: "v1alpha1",
		Versions: []app.ManifestVersion{{
			Name:   "v1alpha1",
			Served: true,
			Kinds: []app.ManifestVersionKind{{
				Kind:         "Thing",
				Plural:       "things",
				Scope:        "Namespaced",
				FolderScoped: &folderScoped,
				Admission: &app.AdmissionCapabilities{
					Mutation:   &app.MutationCapability{Operations: []app.AdmissionOperation{app.AdmissionOperationAny}},
					Validation: &app.ValidationCapability{Operations: []app.AdmissionOperation{app.AdmissionOperationAny}},
				},
				Routes: map[string]spec3.PathProps{
					"/reload": {Post: operation("reloadThing")},
				},
			}},
			Routes: app.ManifestVersionRoutes{
				Namespaced: map[string]spec3.PathProps{
					"/foobar": {Post: operation("postFoobar")},
				},
			},
		}},
	}
}

func callPluginHandler(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("X-Access-Token", plaintextAccessToken)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

type manifestFetchRecorder struct {
	count         atomic.Int32
	tls           atomic.Bool
	authorization atomic.Value
}

func (f *manifestFetchRecorder) handler(host string, manifest *app.ManifestData) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.count.Add(1)
		f.tls.Store(r.TLS != nil)
		f.authorization.Store(r.Header.Get("Authorization"))
		deployment := definition.PluginDeployments{
			Key: "security",
			Plugins: []definition.PluginDeployment{{
				Host: host,
				Definition: definition.PluginDefinition{
					JSONData: plugins.JSONData{ID: "grafana-appsdktest-app", Type: plugins.TypeApp, Name: "Test App"},
					Manifest: manifest,
				},
			}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(deployment)
	})
}

type plaintextPluginPeer struct {
	addr    string
	accepts atomic.Int32
	wire    lockedBuffer

	mu      sync.Mutex
	routes  []*pluginv3.CallRouteRequest
	reviews []*pluginv3.AdmissionReviewRequest
}

func newPlaintextPluginPeer(t *testing.T) *plaintextPluginPeer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	peer := &plaintextPluginPeer{addr: listener.Addr().String()}
	server := grpc.NewServer()
	pluginv3.RegisterAdmissionServiceServer(server, peer)
	pluginv3.RegisterRouteServiceServer(server, peer)
	go func() { _ = server.Serve(&tapListener{Listener: listener, peer: peer}) }()
	t.Cleanup(server.Stop)
	return peer
}

func (p *plaintextPluginPeer) snapshot() ([]*pluginv3.CallRouteRequest, []*pluginv3.AdmissionReviewRequest) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*pluginv3.CallRouteRequest(nil), p.routes...), append([]*pluginv3.AdmissionReviewRequest(nil), p.reviews...)
}

func (p *plaintextPluginPeer) AdmissionReview(_ context.Context, req *pluginv3.AdmissionReviewRequest) (*pluginv3.AdmissionReviewResponse, error) {
	p.mu.Lock()
	p.reviews = append(p.reviews, req)
	p.mu.Unlock()

	obj := map[string]any{}
	if len(req.GetObjectBytes()) > 0 {
		_ = json.Unmarshal(req.GetObjectBytes(), &obj)
	} else if len(req.GetOldObjectBytes()) > 0 {
		_ = json.Unmarshal(req.GetOldObjectBytes(), &obj)
	}
	spec, _ := obj["spec"].(map[string]any)
	if spec == nil {
		spec = map[string]any{}
		obj["spec"] = spec
	}
	spec[attackerMutation] = true
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	rsp := &pluginv3.AdmissionReviewResponse{}
	rsp.SetAllowed(true)
	rsp.SetObjectBytes(raw)
	return rsp, nil
}

func (p *plaintextPluginPeer) CallRoute(req *pluginv3.CallRouteRequest, stream grpc.ServerStreamingServer[pluginv3.CallRouteResponse]) error {
	p.mu.Lock()
	p.routes = append(p.routes, req)
	p.mu.Unlock()
	rsp := &pluginv3.CallRouteResponse{}
	rsp.SetCode(http.StatusOK)
	return stream.Send(rsp)
}

func peerSawMaterial(routes []*pluginv3.CallRouteRequest, reviews []*pluginv3.AdmissionReviewRequest) bool {
	for _, req := range routes {
		if bytes.Contains(req.GetBody(), []byte(plaintextRouteBody)) ||
			bytes.Contains(req.GetParent().GetRaw(), []byte(plaintextObjectBody)) ||
			headerValuesContain(req.GetHeaders(), plaintextAccessToken) {
			return true
		}
	}
	for _, req := range reviews {
		if bytes.Contains(req.GetObjectBytes(), []byte(plaintextObjectBody)) ||
			bytes.Contains(req.GetOldObjectBytes(), []byte(plaintextObjectBody)) {
			return true
		}
	}
	return false
}

func headerValuesContain(headers map[string]*pluginv3.StringList, value string) bool {
	for _, list := range headers {
		if list == nil {
			continue
		}
		for _, got := range list.GetValues() {
			if got == value {
				return true
			}
		}
	}
	return false
}

type tapListener struct {
	net.Listener
	peer *plaintextPluginPeer
}

func (l *tapListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.peer.accepts.Add(1)
	return &tapConn{Conn: conn, wire: &l.peer.wire}, nil
}

type tapConn struct {
	net.Conn
	wire *lockedBuffer
}

func (c *tapConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.wire.Write(p[:n])
	}
	return n, err
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, _ = b.b.Write(p)
}

func (b *lockedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.b.Bytes()...)
}

type storedSnapshots struct {
	created []byte
	updated []byte
}

type securityResourceClient struct {
	resource.ResourceClient
	mu       sync.Mutex
	objects  map[string][]byte
	versions map[string]int64
	created  []byte
	updated  []byte
}

func (c *securityResourceClient) snapshot() storedSnapshots {
	c.mu.Lock()
	defer c.mu.Unlock()
	return storedSnapshots{
		created: append([]byte(nil), c.created...),
		updated: append([]byte(nil), c.updated...),
	}
}

func (c *securityResourceClient) Create(_ context.Context, req *resourcepb.CreateRequest, _ ...grpc.CallOption) (*resourcepb.CreateResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.objects == nil {
		c.objects = map[string][]byte{}
		c.versions = map[string]int64{}
	}
	name := resourceKey(req.GetKey())
	c.objects[name] = append([]byte(nil), req.GetValue()...)
	c.versions[name] = 1
	c.created = append([]byte(nil), req.GetValue()...)
	return &resourcepb.CreateResponse{ResourceVersion: 1}, nil
}

func (c *securityResourceClient) Read(_ context.Context, req *resourcepb.ReadRequest, _ ...grpc.CallOption) (*resourcepb.ReadResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	name := resourceKey(req.GetKey())
	return &resourcepb.ReadResponse{ResourceVersion: c.versions[name], Value: append([]byte(nil), c.objects[name]...)}, nil
}

func (c *securityResourceClient) Update(_ context.Context, req *resourcepb.UpdateRequest, _ ...grpc.CallOption) (*resourcepb.UpdateResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	name := resourceKey(req.GetKey())
	c.versions[name]++
	c.objects[name] = append([]byte(nil), req.GetValue()...)
	c.updated = append([]byte(nil), req.GetValue()...)
	return &resourcepb.UpdateResponse{ResourceVersion: c.versions[name]}, nil
}

func (c *securityResourceClient) Delete(_ context.Context, req *resourcepb.DeleteRequest, _ ...grpc.CallOption) (*resourcepb.DeleteResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	name := resourceKey(req.GetKey())
	delete(c.objects, name)
	return &resourcepb.DeleteResponse{ResourceVersion: req.GetResourceVersion()}, nil
}

func resourceKey(key *resourcepb.ResourceKey) string {
	if key == nil {
		return ""
	}
	return key.GetNamespace() + "/" + key.GetGroup() + "/" + key.GetResource() + "/" + key.GetName()
}
