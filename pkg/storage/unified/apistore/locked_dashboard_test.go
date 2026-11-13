package apistore

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage"
	clientrest "k8s.io/client-go/rest"

	authtypes "github.com/grafana/authlib/types"

	dashv1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// Locked file-provisioned dashboards are stored with manager kind classic-file-provisioning
// and without grafana.app/managerAllowsEdits (AllowUIUpdates left unset). The same storage
// check also admits plugin, classic API, converted Prometheus, Terraform, and kubectl
// managers while that flag is false. These tests drive Storage.GuaranteedUpdate, Create,
// and Delete — the writes the dashboard API reaches after admission — and require the
// stored object to be left untouched for every caller except the in-process service
// identities that file provisioning and git sync already use.

func TestLockedManagedDashboardWrites(t *testing.T) {
	kinds := []struct {
		name     string
		kind     utils.ManagerKind
		identity string
	}{
		{name: "classic file provisioning", kind: utils.ManagerKindClassicFP, identity: "dash-files"}, //nolint:staticcheck
		{name: "classic file provisioning without identity", kind: utils.ManagerKindClassicFP},        //nolint:staticcheck
		{name: "plugin", kind: utils.ManagerKindPlugin, identity: "plugin-1"},
		{name: "classic api provisioning", kind: utils.ManagerKindClassicAPI, identity: "api"},                           //nolint:staticcheck
		{name: "classic converted prometheus", kind: utils.ManagerKindClassicConvertedPrometheus, identity: "converted"}, //nolint:staticcheck
		{name: "terraform", kind: utils.ManagerKindTerraform, identity: "grafana-terraform-provider"},
		{name: "kubectl", kind: utils.ManagerKindKubectl, identity: "kubectl-context"},
	}

	editors := []struct {
		name string
		user identity.Requester
	}{
		{name: "editor", user: humanRequester(authtypes.TypeUser, "editor-uid", identity.RoleEditor, false)},
		{name: "org admin", user: humanRequester(authtypes.TypeUser, "org-admin-uid", identity.RoleAdmin, false)},
		{name: "grafana admin", user: humanRequester(authtypes.TypeUser, "grafana-admin-uid", identity.RoleAdmin, true)},
	}

	for _, kind := range kinds {
		t.Run(kind.name, func(t *testing.T) {
			for _, who := range editors {
				t.Run(who.name+" spec update keeps the stored dashboard", func(t *testing.T) {
					store, s := newLockedDashboardStorage(t, kind.kind, kind.identity, false)
					err := s.GuaranteedUpdate(identity.WithRequester(context.Background(), who.user), lockedDashboardName, &unstructured.Unstructured{}, false, &storage.Preconditions{}, func(runtime.Object, storage.ResponseMeta) (runtime.Object, *uint64, error) {
						return mutateLockedDashboard(kind.kind, kind.identity, "rewritten_query", false), nil, nil
					}, nil)
					assertLockedDashboardUntouched(t, store, err)
				})

				t.Run(who.name+" cannot clear the lock by setting allows-edits on the request", func(t *testing.T) {
					store, s := newLockedDashboardStorage(t, kind.kind, kind.identity, false)
					err := s.GuaranteedUpdate(identity.WithRequester(context.Background(), who.user), lockedDashboardName, &unstructured.Unstructured{}, false, &storage.Preconditions{}, func(runtime.Object, storage.ResponseMeta) (runtime.Object, *uint64, error) {
						return mutateLockedDashboard(kind.kind, kind.identity, "rewritten_query", true), nil, nil
					}, nil)
					assertLockedDashboardUntouched(t, store, err)
				})

				t.Run(who.name+" cannot remove the manager", func(t *testing.T) {
					store, s := newLockedDashboardStorage(t, kind.kind, kind.identity, false)
					err := s.GuaranteedUpdate(identity.WithRequester(context.Background(), who.user), lockedDashboardName, &unstructured.Unstructured{}, false, &storage.Preconditions{}, func(runtime.Object, storage.ResponseMeta) (runtime.Object, *uint64, error) {
						updated := mutateLockedDashboard(kind.kind, kind.identity, "rewritten_query", false)
						meta, merr := utils.MetaAccessor(updated)
						require.NoError(t, merr)
						meta.SetManagerProperties(utils.ManagerProperties{})
						return updated, nil, nil
					}, nil)
					assertLockedDashboardUntouched(t, store, err)
				})

				t.Run(who.name+" delete is rejected", func(t *testing.T) {
					store, s := newLockedDashboardStorage(t, kind.kind, kind.identity, false)
					err := s.Delete(identity.WithRequester(context.Background(), who.user), lockedDashboardName, &unstructured.Unstructured{}, &storage.Preconditions{}, func(context.Context, runtime.Object) error {
						return nil
					}, nil, storage.DeleteOptions{})
					assertLockedDashboardUntouched(t, store, err)
				})

				t.Run(who.name+" create is rejected", func(t *testing.T) {
					store, s := newLockedDashboardStorage(t, kind.kind, kind.identity, false)
					obj := mutateLockedDashboard(kind.kind, kind.identity, "created_query", false)
					obj.SetName("new-locked")
					err := s.Create(identity.WithRequester(context.Background(), who.user), "new-locked", obj, &unstructured.Unstructured{}, 0)
					require.Error(t, err)
					require.Zero(t, store.creates)
					require.Zero(t, store.updates)
					require.Zero(t, store.deletes)
					require.Zero(t, store.routes.calls)
					require.NotContains(t, store.objects, "new-locked")
					require.Equal(t, store.original[lockedDashboardName], store.objects[lockedDashboardName])
					require.Equal(t, store.original[openDashboardName], store.objects[openDashboardName])
				})
			}
		})
	}

	t.Run("service identity can overwrite a locked file-provisioned dashboard", func(t *testing.T) {
		store, s := newLockedDashboardStorage(t, utils.ManagerKindClassicFP, "dash-files", false) //nolint:staticcheck
		ctx, _ := identity.WithServiceIdentity(context.Background(), 1)
		err := s.GuaranteedUpdate(ctx, lockedDashboardName, &unstructured.Unstructured{}, false, &storage.Preconditions{}, func(runtime.Object, storage.ResponseMeta) (runtime.Object, *uint64, error) {
			return mutateLockedDashboard(utils.ManagerKindClassicFP, "dash-files", "provisioned_query", false), nil, nil //nolint:staticcheck
		}, nil)
		require.NoError(t, err)
		require.Equal(t, 1, store.updates)
		require.Zero(t, store.routes.calls)
		require.Contains(t, string(store.objects[lockedDashboardName]), "provisioned_query")
		require.Contains(t, string(store.objects[lockedDashboardName]), string(utils.ManagerKindClassicFP)) //nolint:staticcheck
		require.NotContains(t, string(store.objects[lockedDashboardName]), utils.AnnoKeyManagerAllowsEdits)
	})

	t.Run("provisioning identity can overwrite a locked file-provisioned dashboard", func(t *testing.T) {
		store, s := newLockedDashboardStorage(t, utils.ManagerKindClassicFP, "dash-files", false) //nolint:staticcheck
		ctx, _, err := identity.WithProvisioningIdentity(context.Background(), "stacks-123")
		require.NoError(t, err)
		err = s.GuaranteedUpdate(ctx, lockedDashboardName, &unstructured.Unstructured{}, false, &storage.Preconditions{}, func(runtime.Object, storage.ResponseMeta) (runtime.Object, *uint64, error) {
			return mutateLockedDashboard(utils.ManagerKindClassicFP, "dash-files", "provisioned_query", false), nil, nil //nolint:staticcheck
		}, nil)
		require.NoError(t, err)
		require.Equal(t, 1, store.updates)
		require.Zero(t, store.routes.calls)
		require.Contains(t, string(store.objects[lockedDashboardName]), "provisioned_query")
	})

	t.Run("service identity can delete and create a locked dashboard", func(t *testing.T) {
		store, s := newLockedDashboardStorage(t, utils.ManagerKindClassicFP, "dash-files", false) //nolint:staticcheck
		ctx, _ := identity.WithServiceIdentity(context.Background(), 1)
		err := s.Delete(ctx, lockedDashboardName, &unstructured.Unstructured{}, &storage.Preconditions{}, func(context.Context, runtime.Object) error {
			return nil
		}, nil, storage.DeleteOptions{})
		require.NoError(t, err)
		require.Equal(t, 1, store.deletes)

		obj := mutateLockedDashboard(utils.ManagerKindClassicFP, "dash-files", "created_query", false) //nolint:staticcheck
		obj.SetName("new-locked")
		err = s.Create(ctx, "new-locked", obj, &unstructured.Unstructured{}, 0)
		require.NoError(t, err)
		require.Equal(t, 1, store.creates)
		require.Zero(t, store.routes.calls)
	})

	t.Run("editor can update when the stored dashboard allows edits", func(t *testing.T) {
		store, s := newLockedDashboardStorage(t, utils.ManagerKindClassicFP, "dash-files", true) //nolint:staticcheck
		editor := humanRequester(authtypes.TypeUser, "editor-uid", identity.RoleEditor, false)
		err := s.GuaranteedUpdate(identity.WithRequester(context.Background(), editor), lockedDashboardName, &unstructured.Unstructured{}, false, &storage.Preconditions{}, func(runtime.Object, storage.ResponseMeta) (runtime.Object, *uint64, error) {
			return mutateLockedDashboard(utils.ManagerKindClassicFP, "dash-files", "allowed_query", true), nil, nil //nolint:staticcheck
		}, nil)
		require.NoError(t, err)
		require.Equal(t, 1, store.updates)
		require.Contains(t, string(store.objects[lockedDashboardName]), "allowed_query")
		require.Equal(t, store.original[openDashboardName], store.objects[openDashboardName])
	})
}

const (
	lockedDashboardName = "locked-dash"
	openDashboardName   = "open-dash"
)

func humanRequester(idType authtypes.IdentityType, uid string, role identity.RoleType, grafanaAdmin bool) identity.Requester {
	return &identity.StaticRequester{
		Type:           idType,
		UserUID:        uid,
		UserID:         42,
		OrgID:          1,
		OrgRole:        role,
		IsGrafanaAdmin: grafanaAdmin,
	}
}

func dashboardSpec(expr string) map[string]any {
	return map[string]any{
		"title": "Locked",
		"panels": []any{
			map[string]any{
				"targets": []any{map[string]any{"expr": expr}},
				"links":   []any{map[string]any{"url": "https://example.test/d/" + expr}},
			},
		},
	}
}

func dashboardObject(name string, kind utils.ManagerKind, managerID string, allowsEdits bool, expr string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "dashboard.grafana.app/v1",
		"kind":       "Dashboard",
		"metadata": map[string]any{
			"name":      name,
			"namespace": "stacks-123",
			"uid":       "uid-" + name,
		},
		"spec": dashboardSpec(expr),
	}}
	meta, err := utils.MetaAccessor(obj)
	if err != nil {
		panic(err)
	}
	meta.SetManagerProperties(utils.ManagerProperties{
		Kind:        kind,
		Identity:    managerID,
		AllowsEdits: allowsEdits,
	})
	return obj
}

func mutateLockedDashboard(kind utils.ManagerKind, managerID string, expr string, allowsEdits bool) *unstructured.Unstructured {
	return dashboardObject(lockedDashboardName, kind, managerID, allowsEdits, expr)
}

func mustEncode(t *testing.T, obj runtime.Object) []byte {
	t.Helper()
	raw, err := (&jsonSerializer{}).Encode(context.Background(), obj)
	require.NoError(t, err)
	return raw
}

type recordingRoutes struct {
	calls int
}

func (r *recordingRoutes) GetRestConfig(context.Context) (*clientrest.Config, error) {
	r.calls++
	return nil, http.ErrNotSupported
}

// lockedWriteStore is the unified storage client GuaranteedUpdate talks to.
// The first read of a locked dashboard returns the stored bytes. A later read of
// that same key returns a copy with allows-edits set, so a check that looks the
// dashboard up again and trusts the second result would accept the write.
type lockedWriteStore struct {
	resource.ResourceClient
	objects  map[string][]byte
	original map[string][]byte
	second   map[string][]byte
	reads    map[string]int
	updates  int
	creates  int
	deletes  int
	routes   *recordingRoutes
}

func (s *lockedWriteStore) Read(_ context.Context, req *resourcepb.ReadRequest, _ ...grpc.CallOption) (*resourcepb.ReadResponse, error) {
	name := req.GetKey().GetName()
	s.reads[name]++
	body, ok := s.objects[name]
	if !ok {
		return &resourcepb.ReadResponse{Error: &resourcepb.ErrorResult{Code: http.StatusNotFound, Message: "not found"}}, nil
	}
	if s.reads[name] > 1 {
		if alt, ok := s.second[name]; ok {
			body = alt
		}
	}
	return &resourcepb.ReadResponse{Value: append([]byte(nil), body...), ResourceVersion: 7}, nil
}

func (s *lockedWriteStore) Update(_ context.Context, req *resourcepb.UpdateRequest, _ ...grpc.CallOption) (*resourcepb.UpdateResponse, error) {
	s.updates++
	name := req.GetKey().GetName()
	s.objects[name] = append([]byte(nil), req.GetValue()...)
	return &resourcepb.UpdateResponse{ResourceVersion: 8}, nil
}

func (s *lockedWriteStore) Create(_ context.Context, req *resourcepb.CreateRequest, _ ...grpc.CallOption) (*resourcepb.CreateResponse, error) {
	s.creates++
	name := req.GetKey().GetName()
	s.objects[name] = append([]byte(nil), req.GetValue()...)
	return &resourcepb.CreateResponse{ResourceVersion: 1}, nil
}

func (s *lockedWriteStore) Delete(_ context.Context, req *resourcepb.DeleteRequest, _ ...grpc.CallOption) (*resourcepb.DeleteResponse, error) {
	s.deletes++
	delete(s.objects, req.GetKey().GetName())
	return &resourcepb.DeleteResponse{ResourceVersion: 9}, nil
}

func newLockedDashboardStorage(t *testing.T, kind utils.ManagerKind, managerID string, allowsEdits bool) (*lockedWriteStore, *Storage) {
	t.Helper()
	locked := dashboardObject(lockedDashboardName, kind, managerID, allowsEdits, "original_query")
	// A different editable dashboard sits beside the locked one. Authorizing this
	// object must not permit a write of the locked dashboard.
	open := dashboardObject(openDashboardName, utils.ManagerKindClassicFP, "other-reader", true, "open_query") //nolint:staticcheck
	editableCopy := dashboardObject(lockedDashboardName, kind, managerID, true, "original_query")
	store := &lockedWriteStore{
		objects: map[string][]byte{
			lockedDashboardName: mustEncode(t, locked),
			openDashboardName:   mustEncode(t, open),
		},
		second: map[string][]byte{
			lockedDashboardName: mustEncode(t, editableCopy),
		},
		reads:  map[string]int{},
		routes: &recordingRoutes{},
	}
	store.original = map[string][]byte{
		lockedDashboardName: append([]byte(nil), store.objects[lockedDashboardName]...),
		openDashboardName:   append([]byte(nil), store.objects[openDashboardName]...),
	}
	s := &Storage{
		gr:             dashv1.DashboardResourceInfo.GroupResource(),
		serializer:     &jsonSerializer{},
		newFunc:        func() runtime.Object { return &unstructured.Unstructured{} },
		versioner:      &storage.APIObjectVersioner{},
		store:          store,
		configProvider: store.routes,
		getKey: func(key string) (*resourcepb.ResourceKey, error) {
			return &resourcepb.ResourceKey{
				Namespace: "stacks-123",
				Group:     dashv1.DashboardResourceInfo.GroupResource().Group,
				Resource:  dashv1.DashboardResourceInfo.GroupResource().Resource,
				Name:      key,
			}, nil
		},
		opts: StorageOptions{GVK: dashv1.DashboardResourceInfo.GroupVersionKind()},
	}
	return store, s
}

func assertLockedDashboardUntouched(t *testing.T, store *lockedWriteStore, err error) {
	t.Helper()
	require.Error(t, err)
	require.Zero(t, store.updates)
	require.Zero(t, store.creates)
	require.Zero(t, store.deletes)
	require.Zero(t, store.routes.calls)
	require.Equal(t, store.original[lockedDashboardName], store.objects[lockedDashboardName])
	require.Equal(t, store.original[openDashboardName], store.objects[openDashboardName])
}
