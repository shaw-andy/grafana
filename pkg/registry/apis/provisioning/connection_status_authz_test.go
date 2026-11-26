package provisioning

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/oauth2"
	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	jsonserializer "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage"

	authlib "github.com/grafana/authlib/types"
	appadmission "github.com/grafana/grafana/apps/provisioning/pkg/apis/admission"
	"github.com/grafana/grafana/apps/provisioning/pkg/apis/auth"
	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/connection"
	ghconnection "github.com/grafana/grafana/apps/provisioning/pkg/connection/github"
	"github.com/grafana/grafana/apps/provisioning/pkg/connection/githuboauth"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	grafanaregistry "github.com/grafana/grafana/pkg/apiserver/registry/generic"
	"github.com/grafana/grafana/pkg/services/apiserver/builder"
	"github.com/grafana/grafana/pkg/services/authz/rbac"
)

const (
	connectionStatusNamespace = "default"
	storedInstallationID      = "111"
	replacedInstallationID    = "999"
	storedAppID               = "123456"
	replacedAppID             = "654321"
	storedPrivateKeyName      = "stored-private-key"
	replacedPrivateKeyName    = "replaced-private-key"
	storedTokenName           = "stored-token"
)

// permissionClient is the access client the provisioning authorizer calls.
// It translates the check with the RBAC mapper the API server ships, then
// allows the call only when the principal holds that action.
type permissionClient struct {
	mu      sync.Mutex
	allowed map[string]bool
	checks  []authlib.CheckRequest
}

func (p *permissionClient) Check(_ context.Context, _ authlib.AuthInfo, req authlib.CheckRequest, _ string) (authlib.CheckResponse, error) {
	p.mu.Lock()
	p.checks = append(p.checks, req)
	p.mu.Unlock()

	mapping, ok := rbac.NewMapperRegistry().Get(req.Group, req.Resource, req.Subresource)
	if !ok {
		return authlib.CheckResponse{}, nil
	}
	action, ok := mapping.Action(req.Verb)
	if !ok || !p.allowed[action] {
		return authlib.CheckResponse{}, nil
	}
	return authlib.CheckResponse{Allowed: true}, nil
}

func (p *permissionClient) last() authlib.CheckRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.checks[len(p.checks)-1]
}

func viewer(namespace string) *identity.StaticRequester {
	return &identity.StaticRequester{
		Type:      authlib.TypeUser,
		UserID:    7,
		UserUID:   "connection-reader",
		OrgID:     1,
		OrgRole:   identity.RoleViewer,
		Namespace: namespace,
	}
}

func accessPolicy(namespace string) *identity.StaticRequester {
	return &identity.StaticRequester{
		Type:      authlib.TypeAccessPolicy,
		UserID:    9,
		UserUID:   "connection-reader-policy",
		OrgID:     1,
		OrgRole:   identity.RoleNone,
		Namespace: namespace,
	}
}

func newAuthorizer(t *testing.T, client authlib.AccessChecker, token bool) *APIBuilder {
	t.Helper()
	var checker auth.AccessChecker
	if token {
		checker = auth.NewTokenAccessChecker(client)
	} else {
		checker = auth.NewSessionAccessChecker(client)
	}
	return &APIBuilder{
		gv:               provisioning.SchemeGroupVersion,
		accessWithAdmin:  checker.WithFallbackRole(identity.RoleAdmin),
		accessWithEditor: checker.WithFallbackRole(identity.RoleEditor),
		accessWithViewer: checker.WithFallbackRole(identity.RoleViewer),
	}
}

func statusAttributes(verb, name, namespace string) authorizer.AttributesRecord {
	return authorizer.AttributesRecord{
		User:            &user.DefaultInfo{Name: "caller"},
		Verb:            verb,
		APIGroup:        provisioning.GROUP,
		APIVersion:      provisioning.VERSION,
		Resource:        provisioning.ConnectionResourceInfo.GetName(),
		Subresource:     "status",
		Name:            name,
		Namespace:       namespace,
		ResourceRequest: true,
	}
}

func authorizerContext(principal identity.Requester) context.Context {
	return identity.WithRequester(context.Background(), principal)
}

type memStorage struct {
	codec runtime.Codec
	mu    sync.Mutex
	data  map[string]runtime.Object
}

func newMemStorage(codec runtime.Codec) *memStorage {
	return &memStorage{codec: codec, data: map[string]runtime.Object{}}
}

func (s *memStorage) Versioner() storage.Versioner { return storage.APIObjectVersioner{} }

func (s *memStorage) Create(context.Context, string, runtime.Object, runtime.Object, uint64) error {
	return nil
}

func (s *memStorage) Delete(context.Context, string, runtime.Object, *storage.Preconditions, storage.ValidateObjectFunc, runtime.Object, storage.DeleteOptions) error {
	return nil
}

func (s *memStorage) Watch(context.Context, string, storage.ListOptions) (watch.Interface, error) {
	return nil, nil
}

func (s *memStorage) Get(_ context.Context, key string, _ storage.GetOptions, objPtr runtime.Object) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.data[key]
	if !ok {
		return storage.NewKeyNotFoundError(key, 0)
	}
	return copyRuntimeObject(obj, objPtr)
}

func (s *memStorage) GetList(context.Context, string, storage.ListOptions, runtime.Object) error {
	return nil
}

// GuaranteedUpdate matches the etcd store's contract that matters here: load the
// current object, hand it to tryUpdate, and persist the object tryUpdate returns.
// Store.Update's callback is what runs the status strategy and admission.
func (s *memStorage) GuaranteedUpdate(_ context.Context, key string, destination runtime.Object, ignoreNotFound bool, preconditions *storage.Preconditions, tryUpdate storage.UpdateFunc, _ runtime.Object) error {
	s.mu.Lock()
	current, ok := s.data[key]
	s.mu.Unlock()
	if !ok {
		if !ignoreNotFound {
			return storage.NewKeyNotFoundError(key, 0)
		}
		current = destination.DeepCopyObject()
	} else {
		current = current.DeepCopyObject()
	}
	if err := preconditions.Check(key, current); err != nil {
		return err
	}
	updated, _, err := tryUpdate(current, storage.ResponseMeta{})
	if err != nil {
		return err
	}
	encoded, err := runtime.Encode(s.codec, updated)
	if err != nil {
		return err
	}
	if err := runtime.DecodeInto(s.codec, encoded, destination); err != nil {
		return err
	}
	s.mu.Lock()
	s.data[key] = destination.DeepCopyObject()
	s.mu.Unlock()
	return nil
}

func (s *memStorage) Stats(context.Context) (storage.Stats, error) { return storage.Stats{}, nil }
func (s *memStorage) ReadinessCheck() error                        { return nil }
func (s *memStorage) RequestWatchProgress(context.Context) error   { return nil }
func (s *memStorage) GetCurrentResourceVersion(context.Context) (uint64, error) {
	return 0, nil
}
func (s *memStorage) EnableResourceSizeEstimation(storage.KeysFunc) error { return nil }
func (s *memStorage) CompactRevision() int64                              { return 0 }

func copyRuntimeObject(from, to runtime.Object) error {
	dst := reflect.ValueOf(to)
	src := reflect.ValueOf(from)
	if dst.Kind() != reflect.Ptr || src.Kind() != reflect.Ptr || dst.IsNil() || src.IsNil() {
		return runtime.NewMissingKindErr("storage object")
	}
	dst.Elem().Set(src.Elem())
	return nil
}

func connectionScheme(t *testing.T) (*runtime.Scheme, runtime.Codec) {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(provisioning.AddToScheme(scheme))
	codecs := serializer.NewCodecFactory(scheme)
	jsonSerializer := jsonserializer.NewSerializerWithOptions(jsonserializer.DefaultMetaFactory, scheme, scheme, jsonserializer.SerializerOptions{})
	codec := codecs.CodecForVersions(jsonSerializer, jsonSerializer, provisioning.SchemeGroupVersion, provisioning.SchemeGroupVersion)
	return scheme, codec
}

func newTypedStore(t *testing.T, scheme *runtime.Scheme, codec runtime.Codec, info utils.ResourceInfo, mem *memStorage) *registry.Store {
	t.Helper()
	gv := info.GroupVersion()
	strategy := grafanaregistry.NewStrategy(scheme, gv)
	store := &registry.Store{
		NewFunc: func() runtime.Object {
			obj := info.NewFunc()
			obj.GetObjectKind().SetGroupVersionKind(info.GroupVersionKind())
			return obj
		},
		NewListFunc:               info.NewListFunc,
		KeyRootFunc:               grafanaregistry.KeyRootFunc(info.GroupResource()),
		KeyFunc:                   grafanaregistry.NamespaceKeyFunc(info.GroupResource()),
		DefaultQualifiedResource:  info.GroupResource(),
		SingularQualifiedResource: info.SingularGroupResource(),
		CreateStrategy:            strategy,
		UpdateStrategy:            strategy,
		DeleteStrategy:            strategy,
		Storage:                   registry.DryRunnableStorage{Storage: mem, Codec: codec},
	}
	return store
}

func seed(t *testing.T, store *registry.Store, mem *memStorage, namespace, name string, obj runtime.Object) {
	t.Helper()
	ctx := genericapirequest.WithNamespace(context.Background(), namespace)
	key, err := store.KeyFunc(ctx, name)
	require.NoError(t, err)
	mem.mu.Lock()
	mem.data[key] = obj.DeepCopyObject()
	mem.mu.Unlock()
}

func loadConnection(t *testing.T, store *registry.Store, mem *memStorage, namespace, name string) *provisioning.Connection {
	t.Helper()
	ctx := genericapirequest.WithNamespace(context.Background(), namespace)
	key, err := store.KeyFunc(ctx, name)
	require.NoError(t, err)
	mem.mu.Lock()
	obj := mem.data[key]
	mem.mu.Unlock()
	require.NotNil(t, obj)
	return obj.(*provisioning.Connection).DeepCopy()
}

func storedConnection(name string) *provisioning.Connection {
	obj := &provisioning.Connection{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       connectionStatusNamespace,
			UID:             types.UID("uid-" + name),
			ResourceVersion: "1",
			Generation:      1,
			Labels:          map[string]string{"keep": "yes"},
		},
		Spec: provisioning.ConnectionSpec{
			Title: "Git Sync",
			Type:  provisioning.GithubConnectionType,
			URL:   "https://github.com/settings/installations/" + storedInstallationID,
			GitHub: &provisioning.GitHubConnectionConfig{
				AppID:          storedAppID,
				InstallationID: storedInstallationID,
			},
			Webhook: &provisioning.ConnectionWebhookConfig{Disabled: false},
		},
		Secure: provisioning.ConnectionSecure{
			PrivateKey: common.InlineSecureValue{Name: storedPrivateKeyName},
			Token:      common.InlineSecureValue{Name: storedTokenName},
		},
		Status: provisioning.ConnectionStatus{ObservedGeneration: 1},
	}
	obj.SetGroupVersionKind(provisioning.ConnectionResourceInfo.GroupVersionKind())
	return obj
}

func connectionAdmission(t *testing.T, b *APIBuilder) admission.Interface {
	t.Helper()
	factory, err := connection.ProvideFactory(
		connection.ToConnectionTypes([]string{
			string(provisioning.GithubConnectionType),
			string(provisioning.GithubOAuthConnectionType),
		}),
		[]connection.Extra{
			ghconnection.Extra(storedSecrets, &ghconnection.Factory{}),
			githuboauth.Extra(storedSecrets, nil),
		},
		noop.NewTracerProvider().Tracer("connection-status-test"),
	)
	require.NoError(t, err)
	handler := appadmission.NewHandler()
	handler.RegisterMutator(provisioning.ConnectionResourceInfo.GetName(), connection.NewAdmissionMutator(factory))
	handler.RegisterValidator(provisioning.ConnectionResourceInfo.GetName(), connection.NewAdmissionValidator(factory))
	b.admissionHandler = handler
	gv := provisioning.SchemeGroupVersion
	return builder.NewAdmission(
		map[schema.GroupVersion]builder.APIGroupMutation{gv: b},
		map[schema.GroupVersion]builder.APIGroupValidation{gv: b},
	)
}

type storedSecretView struct {
	conn *provisioning.Connection
}

func storedSecrets(conn *provisioning.Connection) connection.SecureValues {
	return storedSecretView{conn: conn}
}

func (s storedSecretView) PrivateKey(context.Context) (common.RawSecureValue, error) {
	if s.conn == nil || s.conn.Secure.PrivateKey.Name == "" {
		return "", nil
	}
	return "placeholder-private-key", nil
}

func (s storedSecretView) ClientSecret(context.Context) (common.RawSecureValue, error) {
	return "", nil
}

func (s storedSecretView) Token(context.Context) (common.RawSecureValue, error) {
	if s.conn == nil || s.conn.Secure.Token.Name == "" {
		return "", nil
	}
	return "placeholder-token", nil
}

type capturedGitHubCall struct {
	host             string
	path             string
	hasAuthorization bool
}

type captureRoundTripper struct {
	mu   sync.Mutex
	call *capturedGitHubCall
}

func (c *captureRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.call = &capturedGitHubCall{
		host:             r.URL.Host,
		path:             r.URL.Path,
		hasAuthorization: r.Header.Get("Authorization") != "",
	}
	c.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusUnauthorized,
		Status:     "401 Unauthorized",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"message":"unauthorized"}`)),
		Request:    r,
	}, nil
}

func (c *captureRoundTripper) got() *capturedGitHubCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.call
}

func applyConnectionStatus(ctx context.Context, status rest.Updater, admit admission.Interface, codec runtime.Codec, name, namespace, verb string, body []byte, put *provisioning.Connection) (*provisioning.Connection, error) {
	ctx = genericapirequest.WithNamespace(ctx, namespace)
	gvr := provisioning.ConnectionResourceInfo.GroupVersionResource()
	gvk := provisioning.ConnectionResourceInfo.GroupVersionKind()
	static := admission.NewAttributesRecord(nil, nil, gvk, namespace, name, gvr, "status", admission.Update, &metav1.UpdateOptions{}, false, &user.DefaultInfo{Name: "caller"})
	validate := rest.AdmissionToValidateObjectUpdateFunc(admit, static, nil)
	mutate := func(ctx context.Context, patched, current runtime.Object) (runtime.Object, error) {
		if admit == nil || !admit.Handles(admission.Update) {
			return patched, nil
		}
		attrs := admission.NewAttributesRecord(patched, current, gvk, namespace, name, gvr, "status", admission.Update, &metav1.UpdateOptions{}, false, &user.DefaultInfo{Name: "caller"})
		return patched, admit.(admission.MutationInterface).Admit(ctx, attrs, nil)
	}
	var info rest.UpdatedObjectInfo
	switch verb {
	case utils.VerbUpdate:
		info = rest.DefaultUpdatedObjectInfo(put, mutate)
	case utils.VerbPatch:
		info = rest.DefaultUpdatedObjectInfo(nil, func(_ context.Context, _, current runtime.Object) (runtime.Object, error) {
			currentJS, err := runtime.Encode(codec, current)
			if err != nil {
				return nil, err
			}
			var patchedJS []byte
			if len(body) > 0 && body[0] == '[' {
				patch, err := jsonpatch.DecodePatch(body)
				if err != nil {
					return nil, err
				}
				patchedJS, err = patch.Apply(currentJS)
				if err != nil {
					return nil, err
				}
			} else {
				var err error
				patchedJS, err = jsonpatch.MergePatch(currentJS, body)
				if err != nil {
					return nil, err
				}
			}
			obj, _, err := codec.Decode(patchedJS, nil, nil)
			return obj, err
		}, mutate)
	default:
		return nil, nil
	}
	updated, _, err := status.Update(ctx, name, info, nil, validate, false, &metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	return updated.(*provisioning.Connection), nil
}

func assertSpecAndSecretsUnchanged(t *testing.T, got *provisioning.Connection) {
	t.Helper()
	require.Equal(t, storedAppID, got.Spec.GitHub.AppID)
	require.Equal(t, storedInstallationID, got.Spec.GitHub.InstallationID)
	require.Equal(t, provisioning.GithubConnectionType, got.Spec.Type)
	require.NotNil(t, got.Spec.Webhook)
	require.False(t, got.Spec.Webhook.Disabled)
	require.Nil(t, got.Spec.OAuth)
	require.Nil(t, got.Spec.GitHubEnterprise)
	require.Equal(t, "https://github.com/settings/installations/"+storedInstallationID, got.Spec.URL)
	require.Equal(t, storedPrivateKeyName, got.Secure.PrivateKey.Name)
	require.False(t, got.Secure.PrivateKey.Remove)
	require.Equal(t, storedTokenName, got.Secure.Token.Name)
	require.False(t, got.Secure.Token.Remove)
	require.Equal(t, map[string]string{"keep": "yes"}, got.Labels)
}

func assertTokenMintUsesStoredSpec(t *testing.T, ctx context.Context, got *provisioning.Connection) {
	t.Helper()
	transport := &captureRoundTripper{}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: transport})
	extra := ghconnection.Extra(storedSecrets, &ghconnection.Factory{})
	built, err := extra.Build(ctx, got)
	require.NoError(t, err)
	repo := &provisioning.Repository{}
	repo.Spec.Type = provisioning.GitHubRepositoryType
	repo.Spec.GitHub = &provisioning.GitHubRepositoryConfig{URL: "https://github.com/acme/widgets", Branch: "main"}
	_, _ = built.GenerateRepositoryToken(ctx, repo)
	call := transport.got()
	require.NotNil(t, call, "generating a repository token did not call GitHub")
	require.Equal(t, "api.github.com", call.host)
	require.Contains(t, call.path, "/app/installations/"+storedInstallationID+"/access_tokens")
	require.True(t, call.hasAuthorization)
}

func TestConnectionStatus_ReadPermissionCannotChangeSpec(t *testing.T) {
	scheme, codec := connectionScheme(t)
	cases := []struct {
		name  string
		token bool
		verb  string
		body  []byte
		put   func(current *provisioning.Connection) *provisioning.Connection
	}{
		{
			name: "session user merge patch",
			verb: utils.VerbPatch,
			body: specMergePatch(),
		},
		{
			name: "session user json patch",
			verb: utils.VerbPatch,
			body: specJSONPatch(),
		},
		{
			name: "session user put",
			verb: utils.VerbUpdate,
			put:  specReplacement,
		},
		{
			name:  "access token merge patch",
			token: true,
			verb:  utils.VerbPatch,
			body:  specMergePatch(),
		},
		{
			name:  "access token json patch",
			token: true,
			verb:  utils.VerbPatch,
			body:  specJSONPatch(),
		},
		{
			name:  "access token put",
			token: true,
			verb:  utils.VerbUpdate,
			put:   specReplacement,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			mem := newMemStorage(codec)
			specStore := newTypedStore(t, scheme, codec, provisioning.ConnectionResourceInfo, mem)
			statusStore := grafanaregistry.NewRegistryStatusStore(scheme, specStore)
			seed(t, specStore, mem, connectionStatusNamespace, "victim", storedConnection("victim"))
			seed(t, specStore, mem, connectionStatusNamespace, "other", storedConnection("other"))

			perms := &permissionClient{allowed: map[string]bool{
				"provisioning.connections:read": true,
			}}
			b := newAuthorizer(t, perms, tt.token)
			admit := connectionAdmission(t, b)
			principal := viewer(connectionStatusNamespace)
			if tt.token {
				principal = accessPolicy(connectionStatusNamespace)
			}
			ctx := authorizerContext(principal)

			getDecision, _, err := b.GetAuthorizer().Authorize(ctx, statusAttributes(utils.VerbGet, "victim", connectionStatusNamespace))
			require.NoError(t, err)
			require.Equal(t, authorizer.DecisionAllow, getDecision)
			require.Equal(t, "victim", perms.last().Name)
			require.Equal(t, connectionStatusNamespace, perms.last().Namespace)
			require.Equal(t, utils.VerbGet, perms.last().Verb)
			require.Equal(t, provisioning.ConnectionResourceInfo.GetName(), perms.last().Resource)

			decision, _, err := b.GetAuthorizer().Authorize(ctx, statusAttributes(tt.verb, "victim", connectionStatusNamespace))
			require.NoError(t, err)
			var updated *provisioning.Connection
			if decision == authorizer.DecisionAllow {
				var put *provisioning.Connection
				if tt.put != nil {
					put = tt.put(loadConnection(t, specStore, mem, connectionStatusNamespace, "victim"))
				}
				updated, err = applyConnectionStatus(ctx, statusStore, admit, codec, "victim", connectionStatusNamespace, tt.verb, tt.body, put)
				require.NoError(t, err)
			}

			got := loadConnection(t, specStore, mem, connectionStatusNamespace, "victim")
			assertSpecAndSecretsUnchanged(t, got)
			require.Equal(t, int64(1), got.Status.ObservedGeneration)
			require.Equal(t, authorizer.DecisionDeny, decision)
			require.Equal(t, "victim", perms.last().Name)
			require.Equal(t, connectionStatusNamespace, perms.last().Namespace)
			require.Equal(t, provisioning.GROUP, perms.last().Group)
			require.Equal(t, provisioning.ConnectionResourceInfo.GetName(), perms.last().Resource)
			require.Equal(t, tt.verb, perms.last().Verb)
			other := loadConnection(t, specStore, mem, connectionStatusNamespace, "other")
			assertSpecAndSecretsUnchanged(t, other)
			if updated != nil {
				assertSpecAndSecretsUnchanged(t, updated)
			}
		})
	}
}

func TestConnectionStatus_WritePermissionKeepsSpecAndMintsStoredInstallation(t *testing.T) {
	scheme, codec := connectionScheme(t)
	cases := []struct {
		name string
		verb string
		body []byte
		put  func(current *provisioning.Connection) *provisioning.Connection
	}{
		{name: "merge patch", verb: utils.VerbPatch, body: specMergePatch()},
		{name: "json patch", verb: utils.VerbPatch, body: specJSONPatch()},
		{name: "put", verb: utils.VerbUpdate, put: specReplacement},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			mem := newMemStorage(codec)
			specStore := newTypedStore(t, scheme, codec, provisioning.ConnectionResourceInfo, mem)
			statusStore := grafanaregistry.NewRegistryStatusStore(scheme, specStore)
			seed(t, specStore, mem, connectionStatusNamespace, "victim", storedConnection("victim"))
			seed(t, specStore, mem, connectionStatusNamespace, "other", storedConnection("other"))

			perms := &permissionClient{allowed: map[string]bool{
				"provisioning.connections:read":  true,
				"provisioning.connections:write": true,
			}}
			b := newAuthorizer(t, perms, false)
			admit := connectionAdmission(t, b)
			ctx := authorizerContext(viewer(connectionStatusNamespace))

			decision, _, err := b.GetAuthorizer().Authorize(ctx, statusAttributes(tt.verb, "victim", connectionStatusNamespace))
			require.NoError(t, err)
			require.Equal(t, authorizer.DecisionAllow, decision)
			check := perms.last()
			require.Equal(t, "victim", check.Name)
			require.Equal(t, connectionStatusNamespace, check.Namespace)
			require.Equal(t, provisioning.GROUP, check.Group)
			require.Equal(t, provisioning.ConnectionResourceInfo.GetName(), check.Resource)
			require.Equal(t, tt.verb, check.Verb)

			var put *provisioning.Connection
			if tt.put != nil {
				put = tt.put(loadConnection(t, specStore, mem, connectionStatusNamespace, "victim"))
			}
			updated, err := applyConnectionStatus(ctx, statusStore, admit, codec, check.Name, check.Namespace, tt.verb, tt.body, put)
			require.NoError(t, err)
			assertSpecAndSecretsUnchanged(t, updated)
			require.Equal(t, int64(7), updated.Status.ObservedGeneration)

			got := loadConnection(t, specStore, mem, connectionStatusNamespace, "victim")
			assertSpecAndSecretsUnchanged(t, got)
			require.Equal(t, int64(7), got.Status.ObservedGeneration)
			other := loadConnection(t, specStore, mem, connectionStatusNamespace, "other")
			assertSpecAndSecretsUnchanged(t, other)
			require.Equal(t, int64(1), other.Status.ObservedGeneration)
			assertTokenMintUsesStoredSpec(t, ctx, got)
		})
	}
}

func TestRepositoryStatusUpdateKeepsSpec(t *testing.T) {
	scheme, codec := connectionScheme(t)
	mem := newMemStorage(codec)
	specStore := newTypedStore(t, scheme, codec, provisioning.RepositoryResourceInfo, mem)
	statusStore := grafanaregistry.NewRegistryStatusStore(scheme, specStore)
	original := &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "repo",
			Namespace:       connectionStatusNamespace,
			UID:             "uid-repo",
			ResourceVersion: "1",
			Labels:          map[string]string{"keep": "yes"},
		},
		Spec: provisioning.RepositorySpec{
			Title: "original",
			Type:  provisioning.LocalRepositoryType,
		},
		Status: provisioning.RepositoryStatus{ObservedGeneration: 1},
	}
	original.SetGroupVersionKind(provisioning.RepositoryResourceInfo.GroupVersionKind())
	seed(t, specStore, mem, connectionStatusNamespace, "repo", original)

	replacement := original.DeepCopy()
	replacement.Spec.Title = "rewritten"
	replacement.Labels = map[string]string{"sneaky": "yes"}
	replacement.Status.ObservedGeneration = 7

	ctx := genericapirequest.WithNamespace(context.Background(), connectionStatusNamespace)
	updated, _, err := statusStore.Update(ctx, "repo", rest.DefaultUpdatedObjectInfo(replacement), nil, nil, false, &metav1.UpdateOptions{})
	require.NoError(t, err)
	got := updated.(*provisioning.Repository)
	require.Equal(t, "original", got.Spec.Title)
	require.Equal(t, provisioning.LocalRepositoryType, got.Spec.Type)
	require.Equal(t, map[string]string{"keep": "yes"}, got.Labels)
	require.Equal(t, int64(7), got.Status.ObservedGeneration)
}

func specMergePatch() []byte {
	return []byte(`{
		"metadata": {"labels": {"sneaky": "yes"}},
		"spec": {
			"type": "github",
			"title": "rewritten",
			"url": "https://attacker.example/git",
			"github": {"appID": "` + replacedAppID + `", "installationID": "` + replacedInstallationID + `"},
			"githubEnterprise": {"appID": "` + replacedAppID + `", "installationID": "` + replacedInstallationID + `", "serverUrl": "https://attacker.example"},
			"oauth": {"clientID": "attacker-client"},
			"webhook": {"disabled": true}
		},
		"secure": {"privateKey": {"name": "` + replacedPrivateKeyName + `"}, "token": {"remove": true}},
		"status": {"observedGeneration": 7}
	}`)
}

func specJSONPatch() []byte {
	return []byte(`[
		{"op":"replace","path":"/metadata/labels","value":{"sneaky":"yes"}},
		{"op":"replace","path":"/spec/github/appID","value":"` + replacedAppID + `"},
		{"op":"replace","path":"/spec/github/installationID","value":"` + replacedInstallationID + `"},
		{"op":"replace","path":"/spec/webhook/disabled","value":true},
		{"op":"add","path":"/spec/githubEnterprise","value":{"appID":"` + replacedAppID + `","installationID":"` + replacedInstallationID + `","serverUrl":"https://attacker.example"}},
		{"op":"add","path":"/spec/oauth","value":{"clientID":"attacker-client"}},
		{"op":"add","path":"/spec/url","value":"https://attacker.example/git"},
		{"op":"replace","path":"/secure/privateKey/name","value":"` + replacedPrivateKeyName + `"},
		{"op":"add","path":"/secure/token/remove","value":true},
		{"op":"replace","path":"/status/observedGeneration","value":7}
	]`)
}

func specReplacement(current *provisioning.Connection) *provisioning.Connection {
	put := current.DeepCopy()
	put.Labels = map[string]string{"sneaky": "yes"}
	put.Spec.Title = "rewritten"
	put.Spec.URL = "https://attacker.example/git"
	put.Spec.GitHub.AppID = replacedAppID
	put.Spec.GitHub.InstallationID = replacedInstallationID
	put.Spec.Webhook = &provisioning.ConnectionWebhookConfig{Disabled: true}
	put.Spec.GitHubEnterprise = &provisioning.GitHubEnterpriseConnectionConfig{
		AppID:          replacedAppID,
		InstallationID: replacedInstallationID,
		ServerURL:      "https://attacker.example",
	}
	put.Spec.OAuth = &provisioning.ConnectionOAuthConfig{ClientID: "attacker-client"}
	put.Secure.PrivateKey = common.InlineSecureValue{Name: replacedPrivateKeyName}
	put.Secure.Token = common.InlineSecureValue{Remove: true}
	put.Status.ObservedGeneration = 7
	return put
}
