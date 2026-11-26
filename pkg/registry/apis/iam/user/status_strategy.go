package user

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"

	iamv0alpha1 "github.com/grafana/grafana/apps/iam/pkg/apis/iam/v0alpha1"
	grafanaregistry "github.com/grafana/grafana/pkg/apiserver/registry/generic"
)

// NewStatusStore serves users/status over the unified user store.
//
// It is not grafanaregistry.NewRegistryStatusStore: that strategy keeps the spec
// the request carried, and user admission validation does not run for status
// writes, so callers allowed to write status could change any spec field.
func NewStatusStore(scheme *runtime.Scheme, store *registry.Store) *grafanaregistry.StatusREST {
	gv := store.New().GetObjectKind().GroupVersionKind().GroupVersion()
	return grafanaregistry.NewStatusREST(store, &statusStrategy{
		UpdateResetFieldsStrategy: grafanaregistry.NewStatusStrategy(scheme, gv),
	})
}

// statusStrategy restricts a write to users/status to the status field.
type statusStrategy struct {
	rest.UpdateResetFieldsStrategy
}

// PrepareForUpdate starts from the stored user and keeps only the incoming
// status and the managed fields computed for this request.
func (s *statusStrategy) PrepareForUpdate(_ context.Context, obj, old runtime.Object) {
	newUser, ok := obj.(*iamv0alpha1.User)
	if !ok {
		return
	}
	oldUser, ok := old.(*iamv0alpha1.User)
	if !ok {
		return
	}
	status := newUser.Status
	managedFields := newUser.ManagedFields
	*newUser = *oldUser.DeepCopy()
	newUser.Status = status
	newUser.ManagedFields = managedFields
}

// ValidateUpdate rejects objects PrepareForUpdate could not restrict.
func (s *statusStrategy) ValidateUpdate(_ context.Context, obj, old runtime.Object) field.ErrorList {
	if _, ok := obj.(*iamv0alpha1.User); !ok {
		return field.ErrorList{field.InternalError(nil, fmt.Errorf("expected User but got %T", obj))}
	}
	if _, ok := old.(*iamv0alpha1.User); !ok {
		return field.ErrorList{field.InternalError(nil, fmt.Errorf("expected stored User but got %T", old))}
	}
	return nil
}
