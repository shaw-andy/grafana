package dashboard

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/rest"
	k8sstorage "k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"
	"k8s.io/client-go/tools/cache"

	authnlib "github.com/grafana/authlib/authn"
	authlib "github.com/grafana/authlib/types"
	data "github.com/grafana/grafana-plugin-sdk-go/experimental/apis/datasource/v0alpha1"

	internal "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard"
	dashv0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	"github.com/grafana/grafana/apps/dashboard/pkg/migration"
	"github.com/grafana/grafana/apps/dashboard/pkg/migration/testutil"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	grafanarest "github.com/grafana/grafana/pkg/apiserver/rest"
	grafanaauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/apiserver/builder"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
)

const (
	libraryPanelNamespace   = "stacks-1"
	teamFolderUID           = "team-folder"
	restrictedFolderUID     = "restricted-folder"
	visiblePanelName        = "visible-panel"
	restrictedPanelName     = "restricted-panel"
	visiblePanelQuery       = "visible-query-expr"
	restrictedPanelQuery    = "restricted-query-expr"
	libraryPanelReadTimeout = 2 * time.Second
)

// folderScopedAccessClient is the library-panel access decision the product
// applies to writes: a panel is readable only when it lives in a folder the
// caller can open. The check is keyed by the folder on the object passed in,
// so authorizing a different object does not permit this one.
type folderScopedAccessClient struct {
	mu      sync.Mutex
	folders []string
	names   []string
	verbs   []string
}

func (c *folderScopedAccessClient) Check(_ context.Context, _ authlib.AuthInfo, req authlib.CheckRequest, folder string) (authlib.CheckResponse, error) {
	c.mu.Lock()
	c.folders = append(c.folders, folder)
	c.names = append(c.names, req.Name)
	c.verbs = append(c.verbs, req.Verb)
	c.mu.Unlock()
	return authlib.CheckResponse{Allowed: folder == teamFolderUID, Zookie: authlib.NoopZookie{}}, nil
}

func (c *folderScopedAccessClient) Compile(context.Context, authlib.AuthInfo, authlib.ListRequest) (authlib.ItemChecker, authlib.Zookie, error) {
	return func(_, folder string) bool { return folder == teamFolderUID }, authlib.NoopZookie{}, nil
}

func (c *folderScopedAccessClient) BatchCheck(context.Context, authlib.AuthInfo, authlib.BatchCheckRequest) (authlib.BatchCheckResponse, error) {
	return authlib.BatchCheckResponse{}, nil
}

func (c *folderScopedAccessClient) saw(verb, name, folder string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.verbs {
		if c.verbs[i] == verb && c.names[i] == name && c.folders[i] == folder {
			return true
		}
	}
	return false
}

type authorizedPanel struct {
	verb    string
	obj     runtime.Object
	allowed bool
}

func libraryPanelViewer() *identity.StaticRequester {
	// Same delegated grants AccessClaimsHook attaches to a session that has no
	// upstream access token. They satisfy the service authorizer and say
	// nothing about which folders this user can open.
	return &identity.StaticRequester{
		Type:      authlib.TypeUser,
		UserID:    7,
		UserUID:   "folder-limited-viewer",
		OrgID:     1,
		Namespace: libraryPanelNamespace,
		AccessTokenClaims: &authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{
				DelegatedPermissions: identity.ServiceIdentityClaims.Rest.DelegatedPermissions,
			},
		},
	}
}

func viewerContext() context.Context {
	ctx := identity.WithRequester(context.Background(), libraryPanelViewer())
	return request.WithNamespace(ctx, libraryPanelNamespace)
}

func libraryPanel(name, folder, query string) *dashv0.LibraryPanel {
	target := data.DataQuery{CommonQueryProperties: data.CommonQueryProperties{RefID: "A"}}
	target.Set("expr", query)
	return &dashv0.LibraryPanel{
		TypeMeta: metav1.TypeMeta{APIVersion: dashv0.APIVERSION, Kind: "LibraryPanel"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   libraryPanelNamespace,
			Annotations: map[string]string{utils.AnnoKeyFolder: folder},
		},
		Spec: dashv0.LibraryPanelSpec{
			Type:        "timeseries",
			Title:       name,
			Description: query,
			Options:     common.Unstructured{Object: map[string]any{}},
			FieldConfig: common.Unstructured{Object: map[string]any{}},
			Targets:     []data.DataQuery{target},
		},
	}
}

func libraryPanelAttributes(verb, name string) authorizer.Attributes {
	gv := dashv0.LibraryPanelResourceInfo.GroupVersion()
	return authorizer.AttributesRecord{
		User:            libraryPanelViewer(),
		Verb:            verb,
		Namespace:       libraryPanelNamespace,
		APIGroup:        gv.Group,
		APIVersion:      gv.Version,
		Resource:        dashv0.LibraryPanelResourceInfo.GetName(),
		Name:            name,
		ResourceRequest: true,
	}
}

func containsQuery(obj runtime.Object, query string) bool {
	if obj == nil {
		return false
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return true
	}
	return strings.Contains(string(raw), query)
}

func requireNoRestrictedQuery(t *testing.T, obj runtime.Object) {
	t.Helper()
	require.Falsef(t, containsQuery(obj, restrictedPanelQuery), "response included the library panel query from %s", restrictedFolderUID)
}

type readResult struct {
	obj runtime.Object
	err error
}

// servedGet is the apiserver path for one panel: the group authorizer runs,
// and only an allow continues into storage. A denial never returns a body.
func servedGet(t *testing.T, auth authorizer.Authorizer, getter rest.Getter, ctx context.Context, name string) readResult {
	t.Helper()
	decision, _, err := auth.Authorize(ctx, libraryPanelAttributes("get", name))
	require.NoError(t, err)
	if decision != authorizer.DecisionAllow {
		return readResult{err: apierrors.NewForbidden(dashv0.LibraryPanelResourceInfo.GroupResource(), name, err)}
	}
	obj, getErr := getter.Get(ctx, name, &metav1.GetOptions{})
	return readResult{obj: obj, err: getErr}
}

func servedList(t *testing.T, auth authorizer.Authorizer, lister rest.Lister, ctx context.Context) readResult {
	t.Helper()
	// List authorization carries no panel name and no folder. An allow here
	// still has to be narrowed to the panels the caller can open.
	decision, reason, err := auth.Authorize(ctx, libraryPanelAttributes("list", ""))
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision, "list reaches storage: %s", reason)
	obj, listErr := lister.List(ctx, &metainternalversion.ListOptions{})
	return readResult{obj: obj, err: listErr}
}

func servedWatch(t *testing.T, auth authorizer.Authorizer, watcher rest.Watcher, ctx context.Context) []runtime.Object {
	t.Helper()
	decision, reason, err := auth.Authorize(ctx, libraryPanelAttributes("watch", ""))
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision, "watch reaches storage: %s", reason)
	stream, watchErr := watcher.Watch(ctx, &metainternalversion.ListOptions{})
	require.NoError(t, watchErr)
	require.NotNil(t, stream)
	defer stream.Stop()

	var seen []runtime.Object
	timeout := time.After(libraryPanelReadTimeout)
	for {
		select {
		case ev, ok := <-stream.ResultChan():
			if !ok {
				return seen
			}
			if ev.Object == nil {
				continue
			}
			if ev.Type == watch.Error {
				continue
			}
			seen = append(seen, ev.Object)
		case <-timeout:
			t.Fatal("watch did not finish")
		}
	}
}

func requireVisibleAndOnlyVisible(t *testing.T, objects []runtime.Object, records []authorizedPanel) {
	t.Helper()
	for _, obj := range objects {
		requireNoRestrictedQuery(t, obj)
	}
	var visible int
	for _, obj := range objects {
		require.Truef(t, matchesAllowedRecord(obj, records), "returned library panel was not the object authorization allowed: %#v", obj)
		if containsQuery(obj, visiblePanelQuery) {
			visible++
		}
	}
	require.Equal(t, 1, visible, "the panel in the folder the caller can open must still be returned")
}

func matchesAllowedRecord(obj runtime.Object, records []authorizedPanel) bool {
	for _, rec := range records {
		if rec.allowed && rec.obj != nil && equality.Semantic.DeepEqual(obj, rec.obj) {
			return true
		}
	}
	return false
}

func panelsOf(obj runtime.Object) []runtime.Object {
	list, ok := obj.(*dashv0.LibraryPanelList)
	if !ok || list == nil {
		return nil
	}
	out := make([]runtime.Object, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, list.Items[i].DeepCopyObject())
	}
	return out
}

func TestLibraryPanelReadsEnforceFolderAuthorization(t *testing.T) {
	access := &folderScopedAccessClient{}
	builder := &DashboardsAPIBuilder{accessClient: access}
	authz := grafanaauthorizer.NewGrafanaBuiltInSTAuthorizer()
	authz.Register(dashv0.LibraryPanelResourceInfo.GroupVersion(), builder.GetAuthorizer())

	var records []authorizedPanel
	record := func(ctx context.Context, obj runtime.Object, verb, namespace string) error {
		err := builder.authorizeLibraryPanel(ctx, obj, verb, namespace)
		copied := runtime.Object(nil)
		if obj != nil {
			copied = obj.DeepCopyObject()
		}
		records = append(records, authorizedPanel{verb: verb, obj: copied, allowed: err == nil})
		return err
	}

	store := newPanelStore(
		libraryPanel(visiblePanelName, teamFolderUID, visiblePanelQuery),
		libraryPanel(restrictedPanelName, restrictedFolderUID, restrictedPanelQuery),
	)
	// A second read of the restricted panel returns the same saved query under a
	// folder the caller can open. Authorization has to stick to the object that
	// is returned; checking the first body and serving the second leaks the query.
	store.swapAfterFirstRead = func(panel *dashv0.LibraryPanel) *dashv0.LibraryPanel {
		if panel.Name != restrictedPanelName {
			return panel
		}
		swapped := panel.DeepCopy()
		swapped.Annotations = map[string]string{utils.AnnoKeyFolder: teamFolderUID}
		return swapped
	}
	wrapped := newLibraryPanelAccessStorage(
		store,
		record,
		func(ctx context.Context, oldObj, newObj runtime.Object, namespace string) error {
			if err := record(ctx, oldObj, utils.VerbUpdate, namespace); err != nil {
				return err
			}
			return record(ctx, newObj, utils.VerbCreate, namespace)
		},
		func(context.Context, string, string) error { return nil },
		func(context.Context, runtime.Object) error { return nil },
	)

	ctx := viewerContext()

	t.Run("get", func(t *testing.T) {
		records = nil
		restricted := servedGet(t, authz, wrapped, ctx, restrictedPanelName)
		if restricted.err == nil {
			requireNoRestrictedQuery(t, restricted.obj)
			require.True(t, matchesAllowedRecord(restricted.obj, records))
		}

		records = nil
		visible := servedGet(t, authz, wrapped, ctx, visiblePanelName)
		require.NoError(t, visible.err)
		requireVisibleAndOnlyVisible(t, []runtime.Object{visible.obj}, records)
		require.Zero(t, store.writes, "a refused read must not write")
	})

	t.Run("list", func(t *testing.T) {
		records = nil
		listed := servedList(t, authz, wrapped, ctx)
		require.NoError(t, listed.err)
		requireVisibleAndOnlyVisible(t, panelsOf(listed.obj), records)
	})

	t.Run("watch", func(t *testing.T) {
		records = nil
		events := servedWatch(t, authz, wrapped, ctx)
		requireVisibleAndOnlyVisible(t, events, records)
	})

	t.Run("writes stay forbidden and do not reach storage", func(t *testing.T) {
		store.mu.Lock()
		store.writes = 0
		store.reads = map[string]int{}
		store.mu.Unlock()
		_, err := wrapped.Create(ctx, libraryPanel(restrictedPanelName, restrictedFolderUID, restrictedPanelQuery), rest.ValidateAllObjectFunc, &metav1.CreateOptions{})
		require.True(t, apierrors.IsForbidden(err))
		_, _, err = wrapped.Delete(ctx, restrictedPanelName, rest.ValidateAllObjectFunc, &metav1.DeleteOptions{})
		require.True(t, apierrors.IsForbidden(err))
		require.Zero(t, store.writes)
	})
}

func TestInstalledLibraryPanelStorageEnforcesFolderAuthorization(t *testing.T) {
	panels := []*dashv0.LibraryPanel{
		libraryPanel(visiblePanelName, teamFolderUID, visiblePanelQuery),
		libraryPanel(restrictedPanelName, restrictedFolderUID, restrictedPanelQuery),
	}

	t.Run("standalone", func(t *testing.T) {
		storage := installLibraryPanelStorage(t, panels, true)
		assertInstalledReads(t, storage.auth, storage.store, storage.access)
	})

	t.Run("all-in-one unified reads", func(t *testing.T) {
		// Dual-write mode unified returns the unified store. Legacy mode keeps
		// the SQL store, which evaluates library.panels:read per panel.
		storage := installLibraryPanelStorage(t, panels, false)
		assertInstalledReads(t, storage.auth, storage.store, storage.access)
	})
}

type installedLibraryPanels struct {
	auth   authorizer.Authorizer
	store  rest.StandardStorage
	access *folderScopedAccessClient
}

func installLibraryPanelStorage(t *testing.T, panels []*dashv0.LibraryPanel, standalone bool) installedLibraryPanels {
	t.Helper()
	access := &folderScopedAccessClient{}
	apiBuilder := &DashboardsAPIBuilder{
		accessClient: access,
		isStandalone: standalone,
	}
	if !standalone {
		apiBuilder.features = featuremgmt.WithFeatures(featuremgmt.FlagKubernetesAuthzResourcePermissionApis)
	}
	migration.ResetForTesting()
	migration.Initialize(testutil.NewDataSourceProvider(testutil.StandardTestConfig), testutil.NewLibraryElementProvider(), migration.DefaultCacheTTL)
	scheme := runtime.NewScheme()
	require.NoError(t, apiBuilder.InstallSchema(scheme))

	groupInfo := &genericapiserver.APIGroupInfo{
		VersionedResourcesStorageMap: map[string]map[string]rest.Storage{},
	}
	opts := builder.APIGroupOptions{
		Scheme:     scheme,
		OptsGetter: &libraryPanelOptions{panels: panels},
		DualWriteBuilder: func(gr schema.GroupResource, legacy, unified grafanarest.Storage) (grafanarest.Storage, error) {
			// storageService.NewStorage returns the unified store when the
			// resource's storage mode is unified.
			require.Equal(t, dashv0.LibraryPanelResourceInfo.GroupResource(), gr)
			return unified, nil
		},
	}
	require.NoError(t, apiBuilder.storageForVersion(groupInfo, opts, dashv0.DashboardResourceInfo, &dashv0.LibraryPanelResourceInfo, nil,
		func(runtime.Object, *internal.DashboardAccess) (runtime.Object, error) {
			return &dashv0.DashboardWithAccessInfo{}, nil
		},
	))

	stored := groupInfo.VersionedResourcesStorageMap[dashv0.VERSION][dashv0.LibraryPanelResourceInfo.StoragePath()]
	standard, ok := stored.(rest.StandardStorage)
	require.True(t, ok)

	authz := grafanaauthorizer.NewGrafanaBuiltInSTAuthorizer()
	authz.Register(dashv0.LibraryPanelResourceInfo.GroupVersion(), apiBuilder.GetAuthorizer())
	return installedLibraryPanels{auth: authz, store: standard, access: access}
}

func assertInstalledReads(t *testing.T, auth authorizer.Authorizer, store rest.StandardStorage, access *folderScopedAccessClient) {
	t.Helper()
	ctx := viewerContext()

	restricted := servedGet(t, auth, store, ctx, restrictedPanelName)
	if restricted.err == nil {
		requireNoRestrictedQuery(t, restricted.obj)
	}
	require.True(t, access.saw(utils.VerbGet, restrictedPanelName, restrictedFolderUID), "get must authorize the restricted panel that is stored, not a substitute")

	visible := servedGet(t, auth, store, ctx, visiblePanelName)
	require.NoError(t, visible.err)
	require.True(t, containsQuery(visible.obj, visiblePanelQuery))
	requireNoRestrictedQuery(t, visible.obj)
	require.True(t, access.saw(utils.VerbGet, visiblePanelName, teamFolderUID), "get must authorize the stored panel and its folder")

	listed := servedList(t, auth, store, ctx)
	require.NoError(t, listed.err)
	require.True(t, containsQuery(listed.obj, visiblePanelQuery))
	requireNoRestrictedQuery(t, listed.obj)
	require.True(t, access.saw(utils.VerbGet, visiblePanelName, teamFolderUID) || access.saw(utils.VerbList, visiblePanelName, teamFolderUID))
	require.True(t, access.saw(utils.VerbGet, restrictedPanelName, restrictedFolderUID) || access.saw(utils.VerbList, restrictedPanelName, restrictedFolderUID))

	events := servedWatch(t, auth, store, ctx)
	var visibleEvents int
	for _, ev := range events {
		requireNoRestrictedQuery(t, ev)
		if containsQuery(ev, visiblePanelQuery) {
			visibleEvents++
		}
	}
	require.Equal(t, 1, visibleEvents)
	require.True(t, access.saw(utils.VerbGet, restrictedPanelName, restrictedFolderUID) || access.saw(utils.VerbWatch, restrictedPanelName, restrictedFolderUID) || access.saw(utils.VerbList, restrictedPanelName, restrictedFolderUID))
}

// panelStore is the unified store behind the access wrapper. Reads of the
// restricted panel change folders after the first load so a check of one
// object cannot authorize a later one.
type panelStore struct {
	mu                 sync.Mutex
	panels             map[string]*dashv0.LibraryPanel
	reads              map[string]int
	writes             int
	swapAfterFirstRead func(*dashv0.LibraryPanel) *dashv0.LibraryPanel
}

func newPanelStore(panels ...*dashv0.LibraryPanel) *panelStore {
	stored := make(map[string]*dashv0.LibraryPanel, len(panels))
	for _, panel := range panels {
		stored[panel.Name] = panel.DeepCopy()
	}
	return &panelStore{panels: stored, reads: map[string]int{}}
}

func (s *panelStore) New() runtime.Object     { return &dashv0.LibraryPanel{} }
func (s *panelStore) NewList() runtime.Object { return &dashv0.LibraryPanelList{} }
func (s *panelStore) Destroy()                {}
func (s *panelStore) NamespaceScoped() bool   { return true }
func (s *panelStore) GetSingularName() string { return "librarypanel" }
func (s *panelStore) ConvertToTable(context.Context, runtime.Object, runtime.Object) (*metav1.Table, error) {
	return &metav1.Table{}, nil
}

func (s *panelStore) Get(_ context.Context, name string, _ *metav1.GetOptions) (runtime.Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	panel, ok := s.panels[name]
	if !ok {
		return nil, apierrors.NewNotFound(dashv0.LibraryPanelResourceInfo.GroupResource(), name)
	}
	s.reads[name]++
	out := panel.DeepCopy()
	if s.reads[name] > 1 && s.swapAfterFirstRead != nil {
		out = s.swapAfterFirstRead(panel)
	}
	return out, nil
}

func (s *panelStore) List(context.Context, *metainternalversion.ListOptions) (runtime.Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := &dashv0.LibraryPanelList{}
	for _, name := range []string{visiblePanelName, restrictedPanelName} {
		list.Items = append(list.Items, *s.panels[name].DeepCopy())
	}
	return list, nil
}

func (s *panelStore) Watch(context.Context, *metainternalversion.ListOptions) (watch.Interface, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := make(chan watch.Event, len(s.panels))
	for _, name := range []string{visiblePanelName, restrictedPanelName} {
		ch <- watch.Event{Type: watch.Added, Object: s.panels[name].DeepCopy()}
	}
	close(ch)
	return &closedWatch{ch: ch}, nil
}

func (s *panelStore) Create(_ context.Context, obj runtime.Object, _ rest.ValidateObjectFunc, _ *metav1.CreateOptions) (runtime.Object, error) {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()
	return obj, nil
}

func (s *panelStore) Update(_ context.Context, _ string, _ rest.UpdatedObjectInfo, _ rest.ValidateObjectFunc, _ rest.ValidateObjectUpdateFunc, _ bool, _ *metav1.UpdateOptions) (runtime.Object, bool, error) {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()
	return nil, false, nil
}

func (s *panelStore) Delete(context.Context, string, rest.ValidateObjectFunc, *metav1.DeleteOptions) (runtime.Object, bool, error) {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()
	return nil, true, nil
}

func (s *panelStore) DeleteCollection(context.Context, rest.ValidateObjectFunc, *metav1.DeleteOptions, *metainternalversion.ListOptions) (runtime.Object, error) {
	return nil, apierrors.NewMethodNotSupported(dashv0.LibraryPanelResourceInfo.GroupResource(), "deletecollection")
}

type closedWatch struct{ ch chan watch.Event }

func (w *closedWatch) Stop()                      {}
func (w *closedWatch) ResultChan() <-chan watch.Event { return w.ch }

// libraryPanelOptions serves library panels from memory so storageForVersion
// installs the same stores the API server installs, without a database.
type libraryPanelOptions struct {
	panels []*dashv0.LibraryPanel
}

func (o *libraryPanelOptions) GetRESTOptions(resource schema.GroupResource, _ runtime.Object) (generic.RESTOptions, error) {
	return generic.RESTOptions{
		StorageConfig:  &storagebackend.ConfigForResource{GroupResource: resource},
		ResourcePrefix: "/" + resource.Resource,
		Decorator: func(
			*storagebackend.ConfigForResource,
			string,
			func(runtime.Object) (string, error),
			func() runtime.Object,
			func() runtime.Object,
			k8sstorage.AttrFunc,
			k8sstorage.IndexerFuncs,
			*cache.Indexers,
		) (k8sstorage.Interface, factory.DestroyFunc, error) {
			return &memoryPanels{resource: resource.Resource, panels: o.panels}, func() {}, nil
		},
	}, nil
}

type memoryPanels struct {
	resource string
	panels   []*dashv0.LibraryPanel
}

func (m *memoryPanels) Versioner() k8sstorage.Versioner { return k8sstorage.APIObjectVersioner{} }
func (m *memoryPanels) Create(context.Context, string, runtime.Object, runtime.Object, uint64) error {
	return k8sstorage.NewInvalidObjError("", "create is not used")
}
func (m *memoryPanels) Delete(context.Context, string, runtime.Object, *k8sstorage.Preconditions, k8sstorage.ValidateObjectFunc, runtime.Object, k8sstorage.DeleteOptions) error {
	return k8sstorage.NewKeyNotFoundError("", 0)
}
func (m *memoryPanels) Watch(_ context.Context, key string, _ k8sstorage.ListOptions) (watch.Interface, error) {
	ch := make(chan watch.Event, len(m.panels))
	if m.resource == "librarypanels" {
		for _, panel := range m.panels {
			if panelMatchesKey(key, panel.Name) {
				ch <- watch.Event{Type: watch.Added, Object: panel.DeepCopy()}
			}
		}
	}
	close(ch)
	return &closedWatch{ch: ch}, nil
}
func (m *memoryPanels) Get(_ context.Context, key string, _ k8sstorage.GetOptions, objPtr runtime.Object) error {
	if m.resource != "librarypanels" {
		return k8sstorage.NewKeyNotFoundError(key, 0)
	}
	for _, panel := range m.panels {
		if panelMatchesKey(key, panel.Name) {
			return copyRuntimeObject(objPtr, panel.DeepCopy())
		}
	}
	return k8sstorage.NewKeyNotFoundError(key, 0)
}
func (m *memoryPanels) GetList(_ context.Context, key string, _ k8sstorage.ListOptions, listObj runtime.Object) error {
	if m.resource != "librarypanels" {
		return nil
	}
	list := &dashv0.LibraryPanelList{}
	for _, panel := range m.panels {
		if panelMatchesKey(key, panel.Name) {
			list.Items = append(list.Items, *panel.DeepCopy())
		}
	}
	return copyRuntimeObject(listObj, list)
}
func (m *memoryPanels) GuaranteedUpdate(context.Context, string, runtime.Object, bool, *k8sstorage.Preconditions, k8sstorage.UpdateFunc, runtime.Object) error {
	return k8sstorage.NewInvalidObjError("", "update is not used")
}
func (m *memoryPanels) Stats(context.Context) (k8sstorage.Stats, error) { return k8sstorage.Stats{}, nil }
func (m *memoryPanels) ReadinessCheck() error                           { return nil }
func (m *memoryPanels) RequestWatchProgress(context.Context) error      { return nil }
func (m *memoryPanels) GetCurrentResourceVersion(context.Context) (uint64, error) {
	return 1, nil
}
func (m *memoryPanels) EnableResourceSizeEstimation(k8sstorage.KeysFunc) error { return nil }
func (m *memoryPanels) CompactRevision() int64                                 { return 0 }

func panelMatchesKey(key, name string) bool {
	if strings.HasSuffix(key, "/"+name) {
		return true
	}
	// A collection key names the resource, not one panel.
	return !strings.HasSuffix(key, "/"+visiblePanelName) && !strings.HasSuffix(key, "/"+restrictedPanelName)
}

func copyRuntimeObject(dst, src runtime.Object) error {
	raw, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dst)
}
