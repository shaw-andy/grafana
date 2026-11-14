package snapshot

import (
	"context"
	"errors"
	"strconv"

	"github.com/open-feature/go-sdk/openfeature"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	claims "github.com/grafana/authlib/types"
	dashv0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
)

// NewSnapshotAuthorizer returns an authorizer that maps k8s verbs to snapshot RBAC actions.
// The snapshots resource is gated on kubernetesSnapshots, evaluated per request: the storage
// is always registered, so enablement is enforced here. When the feature is disabled, snapshots
// are served exclusively by the legacy /api routes and the /apis endpoints are denied.
// When enabled, anonymous GET requests for snapshots and the dashboard subresource are allowed
// without RBAC checks (mirroring legacy SnapshotPublicMode behavior).
func NewSnapshotAuthorizer(accessControl ac.AccessControl) authorizer.Authorizer {
	return authorizer.AuthorizerFunc(
		func(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
			if !attr.IsResourceRequest() {
				return authorizer.DecisionNoOpinion, "", nil
			}

			if !openfeature.NewDefaultClient().Boolean(ctx, featuremgmt.FlagSnapshotsKubernetesSnapshots, false, openfeature.TransactionContext(ctx)) {
				return authorizer.DecisionDeny, "kubernetes snapshots feature is not enabled", nil
			}

			// Allow anonymous GET on snapshots and the dashboard subresource (public viewing).
			verb := attr.GetVerb()
			sub := attr.GetSubresource()
			if verb == "get" && (sub == "" || sub == "dashboard") {
				return authorizer.DecisionAllow, "", nil
			}

			user, err := identity.GetRequester(ctx)
			if err != nil {
				return authorizer.DecisionDeny, "valid user is required", err
			}

			// Custom routes: snapshots/create, snapshots/delete/{deleteKey}, snapshots/settings
			// K8s parses these as name="create"|"delete"|"settings" with the path param as subresource.
			name := attr.GetName()
			if name == "create" || name == "delete" || name == "settings" {
				var action string
				switch name {
				case "create":
					action = dashboards.ActionSnapshotsCreate
				case "delete":
					action = dashboards.ActionSnapshotsDelete
				case "settings":
					action = dashboards.ActionSnapshotsRead
				}
				ok, err := accessControl.Evaluate(ctx, user, ac.EvalPermission(action))
				if !ok || err != nil {
					return authorizer.DecisionDeny, "access denied", err
				}
				return authorizer.DecisionAllow, "", nil
			}

			// Handle subresources
			if attr.GetSubresource() != "" {
				var action string
				switch attr.GetSubresource() {
				case "dashboard":
					action = dashboards.ActionSnapshotsRead
				case "deletekey":
					action = dashboards.ActionSnapshotsDelete
				case "delete":
					action = dashboards.ActionSnapshotsDelete
				case "create":
					action = dashboards.ActionSnapshotsCreate
				case "settings":
					action = dashboards.ActionSnapshotsRead
				default:
					return authorizer.DecisionDeny, "unsupported subresource", nil
				}
				ok, err := accessControl.Evaluate(ctx, user, ac.EvalPermission(action))
				if !ok || err != nil {
					return authorizer.DecisionDeny, "access denied", err
				}
				return authorizer.DecisionAllow, "", nil
			}

			// Map k8s verbs to snapshot RBAC actions
			var action string
			switch attr.GetVerb() {
			case "get", "list":
				action = dashboards.ActionSnapshotsRead
			case "create":
				action = dashboards.ActionSnapshotsCreate
			case "delete":
				action = dashboards.ActionSnapshotsDelete
			default:
				return authorizer.DecisionDeny, "unsupported verb", nil
			}

			ok, err := accessControl.Evaluate(ctx, user, ac.EvalPermission(action))
			if !ok || err != nil {
				return authorizer.DecisionDeny, "access denied", err
			}
			return authorizer.DecisionAllow, "", nil
		})
}

// authorizeSnapshotOwner allows the snapshot's creator or an admin of the org that owns it.
// The snapshot key is public and snapshots:delete is not scoped to a snapshot, so the
// authorizer above cannot tell whose snapshot is being deleted or whose delete key is read.
func authorizeSnapshotOwner(ctx context.Context, snap *dashv0.Snapshot) error {
	gr := dashv0.SnapshotResourceInfo.GroupResource()
	requester, err := identity.GetRequester(ctx)
	if err != nil {
		return apierrors.NewUnauthorized("valid user is required")
	}
	ns, err := claims.ParseNamespace(snap.Namespace)
	if err != nil || ns.OrgID != requester.GetOrgID() {
		return apierrors.NewNotFound(gr, snap.Name)
	}
	if requester.HasRole(identity.RoleAdmin) || isSnapshotCreator(requester, snapshotCreatedBy(snap)) {
		return nil
	}
	return apierrors.NewForbidden(gr, snap.Name, errors.New("only the snapshot creator or an org admin can do this"))
}

// snapshotCreatedBy reads grafana.app/createdBy, which unified storage sets on create, and
// falls back to the generated grafana.com/createdBy accessor used by the snapshot migrator.
func snapshotCreatedBy(snap *dashv0.Snapshot) string {
	if meta, err := utils.MetaAccessor(snap); err == nil {
		if createdBy := meta.GetCreatedBy(); createdBy != "" {
			return createdBy
		}
	}
	return snap.GetCreatedBy()
}

// isSnapshotCreator accepts both createdBy forms: the requester UID written by unified
// storage, and user:<internal id> written for legacy SQL rows, which only store user_id.
func isSnapshotCreator(requester identity.Requester, createdBy string) bool {
	if createdBy == "" {
		return false
	}
	if createdBy == requester.GetUID() {
		return true
	}
	if !requester.IsIdentityType(claims.TypeUser, claims.TypeServiceAccount) {
		return false
	}
	id, err := requester.GetInternalID()
	if err != nil || id <= 0 {
		return false
	}
	return createdBy == claims.NewTypeID(claims.TypeUser, strconv.FormatInt(id, 10))
}
