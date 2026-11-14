package appinstaller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	appsdkapiserver "github.com/grafana/grafana-app-sdk/k8s/apiserver"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/handlers"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	k8srest "k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage"

	claims "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/apps/logsdrilldown/pkg/apis/logsdrilldown/v1alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	grafanaregistry "github.com/grafana/grafana/pkg/apiserver/registry/generic"
	"github.com/grafana/grafana/pkg/registry/apps/logsdrilldown"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	grafanaauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/datasources"
)

const (
	logsDrilldownOrgID      int64 = 1
	logsDrilldownNamespace        = "default"
	logsDrilldownCollection       = "/apis/" + v1alpha1.APIGroup + "/" + v1alpha1.APIVersion + "/namespaces/" + logsDrilldownNamespace + "/logsdrilldowns"
	victimUID                     = "uid-a"
	callerUID                     = "uid-b"
	victimName                    = "loki:" + victimUID
	callerName                    = "loki:" + callerUID
	victimPinnedField             = "pinned-field-user-a"
	callerPinnedField             = "pinned-field-user-b"
)

// TestLogsDrilldownCrossUserRead follows the apiserver read path for LogsDrilldown:
// the same request attributes the authorization filter builds, the authorizer chain
// registered for the app, then the namespaced store configureStorage installs.
// Another user's saved display settings must not come back. The caller's own object must.
func TestLogsDrilldownCrossUserRead(t *testing.T) {
	backend := newLogsDrilldownMemory()
	seedLogsDrilldown(t, backend, victimName, victimPinnedField)
	seedLogsDrilldown(t, backend, callerName, callerPinnedField)

	getter, lister, watcher, statusGetter := logsDrilldownStorage(t, backend)
	authz := logsDrilldownAuthorizer()

	editor := logsDrilldownUser(identity.RoleEditor, callerUID, map[string][]string{
		accesscontrol.ActionDatasourcesExplore: {""},
		datasources.ActionRead:                 {datasources.ScopeAll},
	})
	// A viewer does not get datasources:explore (viewers_can_edit is false). The map is
	// non-empty because the datasources reader role is granted to Viewer in OSS, so the
	// logsdrilldown authorizer falls through instead of denying an empty permission set.
	viewer := logsDrilldownUser(identity.RoleViewer, callerUID, map[string][]string{
		datasources.ActionRead: {datasources.ScopeAll},
	})

	t.Run("editor get returns another user's settings", func(t *testing.T) {
		obj := readObject(t, authz, editor, http.MethodGet, logsDrilldownCollection+"/"+victimName, getter)
		require.False(t, objectDiscloses(obj, victimPinnedField))
	})

	t.Run("editor get of status returns another user's settings", func(t *testing.T) {
		obj := readObject(t, authz, editor, http.MethodGet, logsDrilldownCollection+"/"+victimName+"/status", statusGetter)
		require.False(t, objectDiscloses(obj, victimPinnedField))
	})

	t.Run("editor list returns another user's settings", func(t *testing.T) {
		obj := readList(t, authz, editor, lister)
		require.False(t, objectDiscloses(obj, victimPinnedField))
	})

	t.Run("editor get returns the caller's own settings", func(t *testing.T) {
		obj := readObject(t, authz, editor, http.MethodGet, logsDrilldownCollection+"/"+callerName, getter)
		require.True(t, objectDiscloses(obj, callerPinnedField))
		require.False(t, objectDiscloses(obj, victimPinnedField))
	})

	t.Run("editor list returns the caller's own settings", func(t *testing.T) {
		obj := readList(t, authz, editor, lister)
		require.True(t, objectDiscloses(obj, callerPinnedField))
		require.False(t, objectDiscloses(obj, victimPinnedField))
	})

	t.Run("viewer get returns another user's settings", func(t *testing.T) {
		obj := readObject(t, authz, viewer, http.MethodGet, logsDrilldownCollection+"/"+victimName, getter)
		require.False(t, objectDiscloses(obj, victimPinnedField))
	})

	t.Run("viewer list returns another user's settings", func(t *testing.T) {
		obj := readList(t, authz, viewer, lister)
		require.False(t, objectDiscloses(obj, victimPinnedField))
	})

	t.Run("viewer watch streams another user's settings", func(t *testing.T) {
		obj := readWatch(t, authz, viewer, watcher)
		require.False(t, objectDiscloses(obj, victimPinnedField))
	})

	t.Run("editor watch does not stream another user's settings", func(t *testing.T) {
		obj := readWatch(t, authz, editor, watcher)
		require.False(t, objectDiscloses(obj, victimPinnedField))
	})

	for _, verb := range []struct {
		name   string
		method string
	}{
		{name: "update", method: http.MethodPut},
		{name: "patch", method: http.MethodPatch},
		{name: "delete", method: http.MethodDelete},
	} {
		t.Run("editor "+verb.name+" of another user stays denied", func(t *testing.T) {
			decision := authorizeLogsDrilldown(t, authz, editor, verb.method, logsDrilldownCollection+"/"+victimName)
			require.NotEqual(t, authorizer.DecisionAllow, decision)
		})
		t.Run("editor "+verb.name+" of the caller stays allowed", func(t *testing.T) {
			decision := authorizeLogsDrilldown(t, authz, editor, verb.method, logsDrilldownCollection+"/"+callerName)
			require.Equal(t, authorizer.DecisionAllow, decision)
		})
	}
}

func logsDrilldownAuthorizer() authorizer.Authorizer {
	chain := grafanaauthorizer.NewGrafanaBuiltInSTAuthorizer()
	// RegisterAuthorizers stores the installer's GetAuthorizer on each group version.
	chain.Register(v1alpha1.GroupVersion, (&logsdrilldown.LogsDrilldownAppInstaller{}).GetAuthorizer())
	return chain
}

func logsDrilldownUser(role identity.RoleType, uid string, permissions map[string][]string) *identity.StaticRequester {
	return &identity.StaticRequester{
		Type:      claims.TypeUser,
		UserID:    20,
		UserUID:   uid,
		OrgID:     logsDrilldownOrgID,
		OrgRole:   role,
		Namespace: logsDrilldownNamespace,
		Permissions: map[int64]map[string][]string{
			logsDrilldownOrgID: permissions,
		},
	}
}

func logsDrilldownStorage(t *testing.T, backend storage.Interface) (k8srest.Getter, k8srest.Lister, k8srest.Watcher, k8srest.Getter) {
	t.Helper()
	gr := schema.GroupResource{Group: v1alpha1.APIGroup, Resource: "logsdrilldowns"}
	store := &genericregistry.Store{
		NewFunc:                  func() runtime.Object { return &v1alpha1.LogsDrilldown{} },
		NewListFunc:              func() runtime.Object { return &v1alpha1.LogsDrilldownList{} },
		CreateStrategy:           namespaceScopedLogsStrategy{},
		PredicateFunc:            logsDrilldownPredicate,
		Storage:                  genericregistry.DryRunnableStorage{Storage: backend},
		DefaultQualifiedResource: gr,
	}
	server := &serverWrapper{
		ctx:       context.Background(),
		installer: &logsdrilldown.LogsDrilldownAppInstaller{},
	}
	// Same wiring InstallAPIGroup uses for a namespaced resource and its status subresource.
	main := server.configureStorage(gr, false, store)
	status := server.configureStorage(gr, false, &appsdkapiserver.StatusREST{Store: store})

	getter, ok := main.(k8srest.Getter)
	require.True(t, ok)
	lister, ok := main.(k8srest.Lister)
	require.True(t, ok)
	watcher, ok := main.(k8srest.Watcher)
	require.True(t, ok)
	statusGetter, ok := status.(k8srest.Getter)
	require.True(t, ok)
	return getter, lister, watcher, statusGetter
}

func logsDrilldownPredicate(label labels.Selector, field fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    field,
		GetAttrs: storage.DefaultNamespaceScopedAttr,
	}
}

func seedLogsDrilldown(t *testing.T, backend *logsDrilldownMemory, name, pinnedField string) {
	t.Helper()
	gr := schema.GroupResource{Group: v1alpha1.APIGroup, Resource: "logsdrilldowns"}
	ctx := request.WithNamespace(context.Background(), logsDrilldownNamespace)
	key, err := grafanaregistry.NamespaceKeyFunc(gr)(ctx, name)
	require.NoError(t, err)
	backend.items[key] = &v1alpha1.LogsDrilldown{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: logsDrilldownNamespace},
		Spec: v1alpha1.LogsDrilldownSpec{
			DefaultFields:      []string{pinnedField},
			PrettifyJSON:       true,
			WrapLogMessage:     true,
			InterceptDismissed: true,
		},
	}
}

func authorizeLogsDrilldown(t *testing.T, authz authorizer.Authorizer, caller identity.Requester, method, rawURL string) authorizer.Decision {
	t.Helper()
	ctx, attrs := logsDrilldownAttributes(t, caller, method, rawURL)
	decision, _, err := authz.Authorize(ctx, attrs)
	require.NoError(t, err)
	return decision
}

func readObject(t *testing.T, authz authorizer.Authorizer, caller identity.Requester, method, rawURL string, getter k8srest.Getter) runtime.Object {
	t.Helper()
	ctx, attrs := logsDrilldownAttributes(t, caller, method, rawURL)
	decision, _, err := authz.Authorize(ctx, attrs)
	require.NoError(t, err)
	if decision != authorizer.DecisionAllow {
		return nil
	}

	name := logsDrilldownHandlerName(t, ctx)
	// The authorization filter and the get handler both take the name from this request.
	require.Equal(t, attrs.GetName(), name)
	obj, err := getter.Get(logsDrilldownStorageContext(t, ctx), name, &metav1.GetOptions{})
	if err != nil {
		return nil
	}
	return obj
}

func readList(t *testing.T, authz authorizer.Authorizer, caller identity.Requester, lister k8srest.Lister) runtime.Object {
	t.Helper()
	ctx, attrs := logsDrilldownAttributes(t, caller, http.MethodGet, logsDrilldownCollection)
	require.Empty(t, attrs.GetName())
	require.Equal(t, "list", attrs.GetVerb())
	decision, _, err := authz.Authorize(ctx, attrs)
	require.NoError(t, err)
	if decision != authorizer.DecisionAllow {
		return nil
	}
	obj, err := lister.List(logsDrilldownStorageContext(t, ctx), &metainternalversion.ListOptions{})
	if err != nil {
		return nil
	}
	return obj
}

func readWatch(t *testing.T, authz authorizer.Authorizer, caller identity.Requester, watcher k8srest.Watcher) runtime.Object {
	t.Helper()
	ctx, attrs := logsDrilldownAttributes(t, caller, http.MethodGet, logsDrilldownCollection+"?watch=true")
	require.Equal(t, "watch", attrs.GetVerb())
	decision, _, err := authz.Authorize(ctx, attrs)
	require.NoError(t, err)
	if decision != authorizer.DecisionAllow {
		return nil
	}
	stream, err := watcher.Watch(logsDrilldownStorageContext(t, ctx), &metainternalversion.ListOptions{})
	if err != nil {
		return nil
	}
	defer stream.Stop()
	list := &v1alpha1.LogsDrilldownList{}
	for event := range stream.ResultChan() {
		if event.Type != watch.Added || event.Object == nil {
			continue
		}
		item, ok := event.Object.(*v1alpha1.LogsDrilldown)
		if !ok {
			raw, marshalErr := json.Marshal(event.Object)
			require.NoError(t, marshalErr)
			require.NotContains(t, string(raw), victimPinnedField)
			continue
		}
		list.Items = append(list.Items, *item)
	}
	return list
}

func logsDrilldownAttributes(t *testing.T, caller identity.Requester, method, rawURL string) (context.Context, authorizer.Attributes) {
	t.Helper()
	factory := &request.RequestInfoFactory{
		APIPrefixes:          sets.NewString("apis"),
		GrouplessAPIPrefixes: sets.NewString(),
	}
	req, err := http.NewRequest(method, rawURL, nil)
	require.NoError(t, err)
	info, err := factory.NewRequestInfo(req)
	require.NoError(t, err)
	require.True(t, info.IsResourceRequest)
	ctx := identity.WithRequester(request.WithRequestInfo(context.Background(), info), caller)
	attrs, err := filters.GetAuthorizerAttributes(ctx)
	require.NoError(t, err)
	return ctx, attrs
}

func logsDrilldownHandlerName(t *testing.T, ctx context.Context) string {
	t.Helper()
	req := (&http.Request{}).WithContext(ctx)
	_, name, err := (handlers.ContextBasedNaming{}).Name(req)
	require.NoError(t, err)
	return name
}

func logsDrilldownStorageContext(t *testing.T, ctx context.Context) context.Context {
	t.Helper()
	req := (&http.Request{}).WithContext(ctx)
	namespace, err := (handlers.ContextBasedNaming{}).Namespace(req)
	require.NoError(t, err)
	return request.WithNamespace(ctx, namespace)
}

func objectDiscloses(obj runtime.Object, marker string) bool {
	if obj == nil {
		return false
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return strings.Contains(obj.GetObjectKind().GroupVersionKind().String(), marker)
	}
	return strings.Contains(string(raw), marker)
}

type namespaceScopedLogsStrategy struct{}

func (namespaceScopedLogsStrategy) NamespaceScoped() bool { return true }
func (namespaceScopedLogsStrategy) PrepareForCreate(context.Context, runtime.Object) {
}
func (namespaceScopedLogsStrategy) Validate(context.Context, runtime.Object) field.ErrorList {
	return nil
}
func (namespaceScopedLogsStrategy) WarningsOnCreate(context.Context, runtime.Object) []string {
	return nil
}
func (namespaceScopedLogsStrategy) Canonicalize(runtime.Object) {}
func (namespaceScopedLogsStrategy) GenerateName(base string) string {
	return base
}
func (namespaceScopedLogsStrategy) ObjectKinds(runtime.Object) ([]schema.GroupVersionKind, bool, error) {
	return nil, false, nil
}
func (namespaceScopedLogsStrategy) Recognizes(gvk schema.GroupVersionKind) bool {
	return gvk.Kind == "LogsDrilldown"
}

// logsDrilldownMemory is the storage backend behind genericregistry.Store.
// Get and GetList follow storage.Interface: exact key, or a prefix for a recursive list.
type logsDrilldownMemory struct {
	items map[string]*v1alpha1.LogsDrilldown
}

func newLogsDrilldownMemory() *logsDrilldownMemory {
	return &logsDrilldownMemory{items: map[string]*v1alpha1.LogsDrilldown{}}
}

func (m *logsDrilldownMemory) Versioner() storage.Versioner { return nil }
func (m *logsDrilldownMemory) Create(context.Context, string, runtime.Object, runtime.Object, uint64) error {
	return errLogsDrilldownMemory
}
func (m *logsDrilldownMemory) Delete(context.Context, string, runtime.Object, *storage.Preconditions, storage.ValidateObjectFunc, runtime.Object, storage.DeleteOptions) error {
	return errLogsDrilldownMemory
}
func (m *logsDrilldownMemory) GuaranteedUpdate(context.Context, string, runtime.Object, bool, *storage.Preconditions, storage.UpdateFunc, runtime.Object) error {
	return errLogsDrilldownMemory
}
func (m *logsDrilldownMemory) Stats(context.Context) (storage.Stats, error) {
	return storage.Stats{}, nil
}
func (m *logsDrilldownMemory) ReadinessCheck() error                      { return nil }
func (m *logsDrilldownMemory) RequestWatchProgress(context.Context) error { return nil }
func (m *logsDrilldownMemory) GetCurrentResourceVersion(context.Context) (uint64, error) {
	return 0, nil
}
func (m *logsDrilldownMemory) EnableResourceSizeEstimation(storage.KeysFunc) error { return nil }
func (m *logsDrilldownMemory) CompactRevision() int64                              { return 0 }

func (m *logsDrilldownMemory) Get(_ context.Context, key string, _ storage.GetOptions, objPtr runtime.Object) error {
	item, ok := m.items[key]
	if !ok {
		return storage.NewKeyNotFoundError(key, 0)
	}
	dst, ok := objPtr.(*v1alpha1.LogsDrilldown)
	if !ok {
		return apierrors.NewInternalError(errLogsDrilldownMemory)
	}
	*dst = *item.DeepCopy()
	return nil
}

func (m *logsDrilldownMemory) GetList(_ context.Context, key string, opts storage.ListOptions, listObj runtime.Object) error {
	list, ok := listObj.(*v1alpha1.LogsDrilldownList)
	if !ok {
		return apierrors.NewInternalError(errLogsDrilldownMemory)
	}
	matched, err := m.match(key, opts)
	if err != nil {
		return err
	}
	list.Items = matched
	return nil
}

func (m *logsDrilldownMemory) Watch(_ context.Context, key string, opts storage.ListOptions) (watch.Interface, error) {
	matched, err := m.match(key, opts)
	if err != nil {
		return nil, err
	}
	events := make(chan watch.Event, len(matched))
	for i := range matched {
		events <- watch.Event{Type: watch.Added, Object: matched[i].DeepCopy()}
	}
	close(events)
	return &logsDrilldownWatch{events: events}, nil
}

func (m *logsDrilldownMemory) match(key string, opts storage.ListOptions) ([]v1alpha1.LogsDrilldown, error) {
	prefix := key
	if opts.Recursive && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	var matched []v1alpha1.LogsDrilldown
	for storedKey, item := range m.items {
		if opts.Recursive {
			if !strings.HasPrefix(storedKey, prefix) {
				continue
			}
		} else if storedKey != key {
			continue
		}
		ok, err := opts.Predicate.Matches(item)
		if err != nil {
			return nil, err
		}
		if ok {
			matched = append(matched, *item.DeepCopy())
		}
	}
	return matched, nil
}

type logsDrilldownWatch struct {
	events chan watch.Event
}

func (w *logsDrilldownWatch) Stop() {}
func (w *logsDrilldownWatch) ResultChan() <-chan watch.Event {
	return w.events
}

var errLogsDrilldownMemory = errors.New("not implemented")
