package snapshot

import (
	"context"
	"crypto/subtle"
	"errors"
	"slices"
	"strconv"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/rest"

	authlib "github.com/grafana/authlib/types"
	dashv0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/components/simplejson"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/dashboards"
)

// AccessOption configures how snapshot storage decides delete access.
type AccessOption func(*accessOptions)

type accessOptions struct {
	accessControl ac.AccessControl
}

// WithAccessControl evaluates dashboard permissions through accessControl so
// scope resolvers (for example folder inheritance) apply. Without it, the
// caller's own permissions are evaluated without scope resolution.
func WithAccessControl(accessControl ac.AccessControl) AccessOption {
	return func(o *accessOptions) {
		o.accessControl = accessControl
	}
}

func newAccessOptions(opts []AccessOption) accessOptions {
	var o accessOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

type deleteKeyGrantKey struct{}

// withDeleteKeyGrant marks ctx as coming from a caller that presented deleteKey.
// Holding the delete key is sufficient to delete the snapshot that carries it.
func withDeleteKeyGrant(ctx context.Context, deleteKey string) context.Context {
	return context.WithValue(ctx, deleteKeyGrantKey{}, deleteKey)
}

func snapshotNotFound(name string) error {
	return apierrors.NewNotFound(dashv0.SnapshotResourceInfo.GroupResource(), name)
}

func deleteKeyEquals(snap *dashv0.Snapshot, deleteKey string) bool {
	return deleteKey != "" && snap.Spec.DeleteKey != nil &&
		subtle.ConstantTimeCompare([]byte(*snap.Spec.DeleteKey), []byte(deleteKey)) == 1
}

// checkSnapshotDeleteAccess decides whether the caller may delete snap or read its
// delete key. snap must be the object the caller is about to act on. The caller
// must have created the snapshot, be able to write its source dashboard, or be an
// org admin. Denials return NotFound so the endpoint does not reveal which keys exist.
func checkSnapshotDeleteAccess(ctx context.Context, accessControl ac.AccessControl, snap *dashv0.Snapshot) error {
	if grant, ok := ctx.Value(deleteKeyGrantKey{}).(string); ok && deleteKeyEquals(snap, grant) {
		return nil
	}

	requester, err := identity.GetRequester(ctx)
	if err != nil {
		return err
	}

	if isSnapshotCreator(requester, snap) || requester.GetOrgRole() == identity.RoleAdmin {
		return nil
	}

	canWrite, err := canWriteSourceDashboard(ctx, accessControl, requester, snap.Spec.Dashboard)
	if err != nil {
		return err
	}
	if canWrite {
		return nil
	}
	return snapshotNotFound(snap.Name)
}

func isSnapshotCreator(requester identity.Requester, snap *dashv0.Snapshot) bool {
	meta, err := utils.MetaAccessor(snap)
	if err != nil {
		return false
	}
	creators := []string{meta.GetCreatedBy()}
	// The snapshot migrator records the creator through the generated accessor,
	// which uses a different annotation key than unified storage.
	if snap.Annotations != nil {
		creators = append(creators, snap.GetCreatedBy())
	}

	callerIDs := []string{requester.GetUID(), requester.GetID()}
	// Legacy rows and migrated objects record the creator as user:<internal id>,
	// also for service accounts, which share the user id space.
	if requester.IsIdentityType(authlib.TypeUser, authlib.TypeServiceAccount) {
		if id, err := requester.GetInternalID(); err == nil && id > 0 {
			callerIDs = append(callerIDs, authlib.NewTypeID(authlib.TypeUser, strconv.FormatInt(id, 10)))
		}
	}

	for _, createdBy := range creators {
		if createdBy != "" && slices.Contains(callerIDs, createdBy) {
			return true
		}
	}
	return false
}

func canWriteSourceDashboard(ctx context.Context, accessControl ac.AccessControl, requester identity.Requester, dashboard map[string]any) (bool, error) {
	if len(dashboard) == 0 {
		return false, nil
	}
	dash := simplejson.NewFromAny(dashboard)
	dashboardID := dash.Get("id").MustInt64()
	dashboardUID := dash.Get("uid").MustString()

	var evaluators []ac.Evaluator
	if dashboardID != 0 {
		evaluators = append(evaluators, ac.EvalPermission(dashboards.ActionDashboardsWrite,
			dashboards.ScopeDashboardsProvider.GetResourceScope(strconv.FormatInt(dashboardID, 10))))
	}
	if dashboardUID != "" {
		evaluators = append(evaluators, ac.EvalPermission(dashboards.ActionDashboardsWrite,
			dashboards.ScopeDashboardsProvider.GetResourceScopeUID(dashboardUID)))
	}
	if len(evaluators) == 0 {
		return false, nil
	}
	evaluator := ac.EvalAny(evaluators...)

	if accessControl == nil {
		return evaluator.Evaluate(requester.GetPermissions()), nil
	}
	ok, err := accessControl.Evaluate(ctx, requester, evaluator)
	if err != nil {
		if errors.Is(err, dashboards.ErrDashboardNotFound) {
			return false, nil
		}
		return false, err
	}
	return ok, nil
}

// requireSameSnapshot refuses a delete when the object the store is about to
// delete is not the one that was authorized, then runs next.
func requireSameSnapshot(authorized *dashv0.Snapshot, next rest.ValidateObjectFunc) rest.ValidateObjectFunc {
	return func(ctx context.Context, obj runtime.Object) error {
		snap, ok := obj.(*dashv0.Snapshot)
		if !ok || snap.Name != authorized.Name ||
			(authorized.UID != "" && snap.UID != "" && snap.UID != authorized.UID) ||
			deref(snap.Spec.DeleteKey) != deref(authorized.Spec.DeleteKey) {
			return snapshotNotFound(authorized.Name)
		}
		if next != nil {
			return next(ctx, obj)
		}
		return nil
	}
}

// requireDeleteKey refuses a delete when the object the store is about to delete
// does not carry deleteKey.
func requireDeleteKey(deleteKey string) rest.ValidateObjectFunc {
	return func(ctx context.Context, obj runtime.Object) error {
		snap, ok := obj.(*dashv0.Snapshot)
		if !ok || !deleteKeyEquals(snap, deleteKey) {
			return snapshotNotFound("")
		}
		return nil
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
