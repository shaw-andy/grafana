package logsdrilldown

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/grafana/grafana/apps/logsdrilldown/pkg/apis/logsdrilldown/v1alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer/storewrapper"
)

var logsDrilldownResource = schema.GroupResource{
	Group:    v1alpha1.APIGroup,
	Resource: v1alpha1.LogsDrilldownKind().Plural(),
}

// ownerStorageAuthorizer limits every LogsDrilldown storage operation to the
// object named after the caller (<service>:<user_uid>). The check is made on the
// object the store returned or is about to write, not on the request name.
type ownerStorageAuthorizer struct{}

var _ storewrapper.ResourceStorageAuthorizer = (*ownerStorageAuthorizer)(nil)

func (a *ownerStorageAuthorizer) BeforeCreate(ctx context.Context, obj runtime.Object) error {
	return requireOwner(ctx, obj)
}

func (a *ownerStorageAuthorizer) BeforeUpdate(ctx context.Context, oldObj, obj runtime.Object) error {
	if oldObj != nil {
		if meta, err := utils.MetaAccessor(oldObj); err == nil && meta.GetName() != "" {
			if err := requireOwner(ctx, oldObj); err != nil {
				return err
			}
		}
	}
	return requireOwner(ctx, obj)
}

func (a *ownerStorageAuthorizer) BeforeDelete(ctx context.Context, obj runtime.Object) error {
	return requireOwner(ctx, obj)
}

func (a *ownerStorageAuthorizer) AfterGet(ctx context.Context, obj runtime.Object) error {
	return requireOwner(ctx, obj)
}

func (a *ownerStorageAuthorizer) FilterList(ctx context.Context, list runtime.Object) (runtime.Object, error) {
	u, err := identity.GetRequester(ctx)
	if err != nil {
		return nil, storewrapper.ErrUnauthenticated
	}

	l, ok := list.(*v1alpha1.LogsDrilldownList)
	if !ok {
		return nil, apierrors.NewInternalError(fmt.Errorf("expected LogsDrilldownList, got %T: %w", list, storewrapper.ErrUnexpectedType))
	}

	if u.GetIsGrafanaAdmin() {
		return l, nil
	}

	filtered := make([]v1alpha1.LogsDrilldown, 0, 1)
	for _, item := range l.Items {
		if compareResourceNameAndUserUID(item.GetName(), u) {
			filtered = append(filtered, item)
		}
	}
	l.Items = filtered
	return l, nil
}

func (a *ownerStorageAuthorizer) WatchFilter(ctx context.Context) (storewrapper.WatchEventFilter, error) {
	u, err := identity.GetRequester(ctx)
	if err != nil {
		return nil, storewrapper.ErrUnauthenticated
	}

	return func(events []watch.Event) ([]bool, error) {
		allowed := make([]bool, len(events))
		for i, event := range events {
			allowed[i] = isOwner(u, event.Object)
		}
		return allowed, nil
	}, nil
}

func requireOwner(ctx context.Context, obj runtime.Object) error {
	u, err := identity.GetRequester(ctx)
	if err != nil {
		return storewrapper.ErrUnauthenticated
	}

	if !isOwner(u, obj) {
		name := ""
		if meta, err := utils.MetaAccessor(obj); err == nil {
			name = meta.GetName()
		}
		return apierrors.NewForbidden(logsDrilldownResource, name, fmt.Errorf("only the owner can access this resource"))
	}
	return nil
}

func isOwner(u identity.Requester, obj runtime.Object) bool {
	if u.GetIsGrafanaAdmin() {
		return true
	}
	if obj == nil {
		return false
	}
	meta, err := utils.MetaAccessor(obj)
	if err != nil {
		return false
	}
	return compareResourceNameAndUserUID(meta.GetName(), u)
}
