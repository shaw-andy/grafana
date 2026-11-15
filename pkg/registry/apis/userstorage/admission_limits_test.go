package userstorage

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	k8sstorage "k8s.io/apiserver/pkg/storage"

	"github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	userstorage "github.com/grafana/grafana/pkg/apis/userstorage/v0alpha1"
	grafanaregistry "github.com/grafana/grafana/pkg/apiserver/registry/generic"
	grafanaauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
)

// maxUserStorageObjectBytes is the size target documented on userstorageSize
// ("Target for user storage size < 3MB"). Objects larger than this must be
// rejected before they are stored and before a histogram sample is recorded.
const maxUserStorageObjectBytes = 3 * 1024 * 1024

// builtInUserStorageService is a service the Grafana UI already writes.
// A limit has to keep that write working for a normal Viewer.
const builtInUserStorageService = "grafana-splash-screen"

// TestViewerCannotStoreUnboundedUserStorage is the spec for the User Storage
// create/update admission hole. It fails while a Viewer can persist a new
// object for every attacker-chosen service name.
func TestViewerCannotStoreUnboundedUserStorage(t *testing.T) {
	const uid = "viewerbounded"
	ctx := viewerContext(uid)
	requireViewerVerb(t, ctx, "create", "")

	store := newUserStorageStore(t)
	splash := builtInUserStorageService + ":" + uid
	requireViewerVerb(t, ctx, "update", splash)

	created, err := store.Create(ctx, smallObject(splash), nil, &metav1.CreateOptions{})
	require.NoError(t, err)
	requireStoredData(t, store, ctx, splash, dataOf(created.(*userstorage.UserStorage)))

	// A new service prefix is a new object and a new histogram label. One
	// caller must not be able to keep doing that. POST create and PUT
	// create-on-update (AllowCreateOnUpdate) are both write paths. PATCH is
	// the same Store.Update admission as PUT.
	for i, verb := range []string{"create", "update"} {
		t.Run(verb, func(t *testing.T) {
			service := "attacker-svc-" + string(rune('a'+i))
			name := service + ":" + uid
			before := histogramSamples(service)
			obj := smallObject(name)
			var err error
			if verb == "create" {
				requireViewerVerb(t, ctx, "create", "")
				_, err = store.Create(ctx, obj, nil, &metav1.CreateOptions{})
			} else {
				requireViewerVerb(t, ctx, "update", name)
				_, _, err = store.Update(ctx, name, rest.DefaultUpdatedObjectInfo(obj), nil, nil, false, &metav1.UpdateOptions{})
			}
			require.Error(t, err, "viewer %s of %s must be rejected", verb, name)
			requireAbsent(t, store, ctx, name)
			require.Equal(t, before, histogramSamples(service), "rejected %s recorded a histogram sample for %s", verb, service)
		})
	}
}

// TestViewerUserStorageRejectsObjectsAboveDocumentedSize fails while create
// and update accept an object larger than the documented 3MB target. The
// apiserver body limit is 16MB, so a payload just over 3MB is still legal HTTP.
func TestViewerUserStorageRejectsObjectsAboveDocumentedSize(t *testing.T) {
	oversized := strings.Repeat("x", maxUserStorageObjectBytes+1)

	t.Run("create", func(t *testing.T) {
		const uid = "viewersize"
		ctx := viewerContext(uid)
		name := builtInUserStorageService + ":" + uid
		requireViewerVerb(t, ctx, "create", "")
		store := newUserStorageStore(t)
		before := histogramSamples(builtInUserStorageService)

		_, err := store.Create(ctx, objectWithData(name, oversized), nil, &metav1.CreateOptions{})
		require.Error(t, err)
		requireAbsent(t, store, ctx, name)
		require.Equal(t, before, histogramSamples(builtInUserStorageService))
	})

	t.Run("update existing", func(t *testing.T) {
		const uid = "viewersizeupd"
		ctx := viewerContext(uid)
		name := builtInUserStorageService + ":" + uid
		requireViewerVerb(t, ctx, "update", name)
		store := newUserStorageStore(t)

		created, err := store.Create(ctx, smallObject(name), nil, &metav1.CreateOptions{})
		require.NoError(t, err)
		original := dataOf(created.(*userstorage.UserStorage))
		before := histogramSamples(builtInUserStorageService)

		_, _, err = store.Update(ctx, name, rest.DefaultUpdatedObjectInfo(objectWithData(name, oversized)), nil, nil, false, &metav1.UpdateOptions{})
		require.Error(t, err)
		requireStoredData(t, store, ctx, name, original)
		require.Equal(t, before, histogramSamples(builtInUserStorageService))
	})

	t.Run("create on update", func(t *testing.T) {
		const uid = "viewersizeput"
		ctx := viewerContext(uid)
		name := builtInUserStorageService + ":" + uid
		requireViewerVerb(t, ctx, "update", name)
		store := newUserStorageStore(t)
		before := histogramSamples(builtInUserStorageService)

		_, _, err := store.Update(ctx, name, rest.DefaultUpdatedObjectInfo(objectWithData(name, oversized)), nil, nil, false, &metav1.UpdateOptions{})
		require.Error(t, err)
		requireAbsent(t, store, ctx, name)
		require.Equal(t, before, histogramSamples(builtInUserStorageService))
	})
}

func viewerContext(uid string) context.Context {
	requester := &identity.StaticRequester{
		Type:      types.TypeUser,
		UserUID:   uid,
		UserID:    7,
		OrgID:     1,
		Namespace: "default",
		OrgRole:   identity.RoleViewer,
	}
	ctx := identity.WithRequester(context.Background(), requester)
	return genericapirequest.WithNamespace(ctx, "default")
}

func requireViewerVerb(t *testing.T, ctx context.Context, verb, name string) {
	t.Helper()
	authz := grafanaauthorizer.NewGrafanaBuiltInSTAuthorizer()
	authz.Register(userstorage.SchemeGroupVersion, (&UserStorageAPIBuilder{}).GetAuthorizer())
	decision, reason, err := authz.Authorize(ctx, authorizer.AttributesRecord{
		User:            &user.DefaultInfo{Name: "viewer"},
		ResourceRequest: true,
		Verb:            verb,
		Namespace:       "default",
		APIGroup:        userstorage.GROUP,
		APIVersion:      userstorage.VERSION,
		Resource:        userstorage.UserStorageResourceInfo.GroupResource().Resource,
		Name:            name,
	})
	require.NoError(t, err)
	require.Equalf(t, authorizer.DecisionAllow, decision, "viewer %s %q reached the authorizer with reason %q; admission is what has to enforce the limit", verb, name, reason)
}

func newUserStorageStore(t *testing.T) *genericregistry.Store {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, userstorage.AddToScheme(scheme))
	info := userstorage.UserStorageResourceInfo
	storageStrategy := newStrategy(scheme, info.GroupVersion(), prometheus.NewRegistry())
	store := &genericregistry.Store{
		NewFunc:                   info.NewFunc,
		NewListFunc:               info.NewListFunc,
		KeyRootFunc:               grafanaregistry.KeyRootFunc(info.GroupResource()),
		KeyFunc:                   grafanaregistry.NamespaceKeyFunc(info.GroupResource()),
		PredicateFunc:             grafanaregistry.Matcher,
		DefaultQualifiedResource:  info.GroupResource(),
		SingularQualifiedResource: info.SingularGroupResource(),
		TableConvertor:            info.TableConverter(),
		CreateStrategy:            storageStrategy,
		UpdateStrategy:            storageStrategy,
		DeleteStrategy:            grafanaregistry.NewStrategy(scheme, info.GroupVersion()),
	}
	store.Storage.Storage = newMemStorage()
	require.NoError(t, store.CompleteWithOptions(&generic.StoreOptions{
		RESTOptions: generic.RESTOptions{ResourcePrefix: "/user-storage"},
		AttrFunc:    grafanaregistry.GetAttrs,
	}))
	return store
}

func smallObject(name string) runtime.Object {
	return objectWithData(name, "ok")
}

func objectWithData(name, payload string) runtime.Object {
	return &userstorage.UserStorage{
		TypeMeta: metav1.TypeMeta{
			APIVersion: userstorage.SchemeGroupVersion.String(),
			Kind:       "UserStorage",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: userstorage.UserStorageSpec{
			Data: map[string]string{"blob": payload},
		},
	}
}

func dataOf(obj *userstorage.UserStorage) map[string]string {
	out := make(map[string]string, len(obj.Spec.Data))
	for k, v := range obj.Spec.Data {
		out[k] = v
	}
	return out
}

func requireStoredData(t *testing.T, store *genericregistry.Store, ctx context.Context, name string, want map[string]string) {
	t.Helper()
	obj, err := store.Get(ctx, name, &metav1.GetOptions{})
	require.NoError(t, err)
	got := obj.(*userstorage.UserStorage)
	require.Equal(t, want, got.Spec.Data)
}

func requireAbsent(t *testing.T, store *genericregistry.Store, ctx context.Context, name string) {
	t.Helper()
	_, err := store.Get(ctx, name, &metav1.GetOptions{})
	require.Error(t, err, "rejected write of %s was still stored", name)
}

func histogramSamples(service string) uint64 {
	ch := make(chan prometheus.Metric)
	go func() {
		userstorageSize.Collect(ch)
		close(ch)
	}()
	var samples uint64
	for metric := range ch {
		var parsed dto.Metric
		if err := metric.Write(&parsed); err != nil {
			continue
		}
		matched := false
		for _, label := range parsed.GetLabel() {
			if label.GetName() == "service" && label.GetValue() == service {
				matched = true
				break
			}
		}
		if matched && parsed.GetHistogram() != nil {
			samples += parsed.GetHistogram().GetSampleCount()
		}
	}
	return samples
}

// memStorage is the k8sstorage.Interface genericregistry.Store writes after
// admission. It keeps the object Store.Create/Store.Update passed through
// rest.BeforeCreate/rest.BeforeUpdate, which is the object the unified SQL
// backend inserts as resource.value.
type memStorage struct {
	versioner k8sstorage.Versioner
	items     map[string]runtime.Object
	next      uint64
}

func newMemStorage() *memStorage {
	return &memStorage{
		versioner: k8sstorage.APIObjectVersioner{},
		items:     map[string]runtime.Object{},
	}
}

func (m *memStorage) Versioner() k8sstorage.Versioner { return m.versioner }

func (m *memStorage) Create(_ context.Context, key string, obj, out runtime.Object, _ uint64) error {
	if _, ok := m.items[key]; ok {
		return k8sstorage.NewKeyExistsError(key, 0)
	}
	stored := obj.DeepCopyObject()
	m.next++
	if err := m.versioner.UpdateObject(stored, m.next); err != nil {
		return err
	}
	m.items[key] = stored
	return copyUserStorage(stored, out)
}

func (m *memStorage) Get(_ context.Context, key string, _ k8sstorage.GetOptions, objPtr runtime.Object) error {
	stored, ok := m.items[key]
	if !ok {
		return k8sstorage.NewKeyNotFoundError(key, 0)
	}
	return copyUserStorage(stored, objPtr)
}

func (m *memStorage) GuaranteedUpdate(_ context.Context, key string, destination runtime.Object, ignoreNotFound bool, preconditions *k8sstorage.Preconditions, tryUpdate k8sstorage.UpdateFunc, _ runtime.Object) error {
	existing, ok := m.items[key]
	if !ok {
		if !ignoreNotFound {
			return k8sstorage.NewKeyNotFoundError(key, 0)
		}
		existing = destination.DeepCopyObject()
	} else {
		existing = existing.DeepCopyObject()
	}
	if err := preconditions.Check(key, existing); err != nil && ok {
		return err
	}
	rv, err := m.versioner.ObjectResourceVersion(existing)
	if err != nil {
		return err
	}
	updated, _, err := tryUpdate(existing, k8sstorage.ResponseMeta{ResourceVersion: rv})
	if err != nil {
		return err
	}
	stored := updated.DeepCopyObject()
	m.next++
	if err := m.versioner.UpdateObject(stored, m.next); err != nil {
		return err
	}
	m.items[key] = stored
	return copyUserStorage(stored, destination)
}

func (m *memStorage) Delete(context.Context, string, runtime.Object, *k8sstorage.Preconditions, k8sstorage.ValidateObjectFunc, runtime.Object, k8sstorage.DeleteOptions) error {
	return nil
}

func (m *memStorage) Watch(context.Context, string, k8sstorage.ListOptions) (watch.Interface, error) {
	return nil, nil
}

func (m *memStorage) GetList(context.Context, string, k8sstorage.ListOptions, runtime.Object) error {
	return nil
}

func (m *memStorage) Stats(context.Context) (k8sstorage.Stats, error) { return k8sstorage.Stats{}, nil }

func (m *memStorage) ReadinessCheck() error { return nil }

func (m *memStorage) RequestWatchProgress(context.Context) error { return nil }

func (m *memStorage) GetCurrentResourceVersion(context.Context) (uint64, error) { return m.next, nil }

func (m *memStorage) EnableResourceSizeEstimation(k8sstorage.KeysFunc) error { return nil }

func (m *memStorage) CompactRevision() int64 { return 0 }

func copyUserStorage(from, to runtime.Object) error {
	src, ok := from.(*userstorage.UserStorage)
	if !ok {
		return k8sstorage.NewInternalError(fmt.Errorf("stored object is %T", from))
	}
	dst, ok := to.(*userstorage.UserStorage)
	if !ok {
		return k8sstorage.NewInternalError(fmt.Errorf("output object is %T", to))
	}
	cloned := src.DeepCopy()
	*dst = *cloned
	return nil
}
