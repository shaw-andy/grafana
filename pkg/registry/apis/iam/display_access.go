package iam

import (
	"context"
	"strconv"

	authlib "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/registry/apis/iam/display"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/services/serviceaccounts"
	"github.com/grafana/grafana/pkg/setting"
)

// newDisplayAccessPolicy limits the display API to the identities the caller
// could already read: users returned by GET /api/org/users/lookup, and service
// accounts the caller has serviceaccounts:read on.
func newDisplayAccessPolicy(ac accesscontrol.AccessControl, license licensing.Licensing, cfg *setting.Cfg) display.AccessPolicy {
	return func(ctx context.Context, ns authlib.NamespaceInfo) (display.MemberFilter, error) {
		if identity.IsServiceIdentity(ctx) {
			return func(display.Member) bool { return true }, nil
		}

		requester, err := identity.GetRequester(ctx)
		if err != nil {
			return nil, err
		}
		// Permissions are evaluated in the requester's signed-in organization, so
		// they only say something about members of that organization.
		if requester.GetOrgID() != ns.OrgID {
			return nil, nil
		}

		enforceUserScope := license != nil && license.FeatureEnabled("accesscontrol.enforcement")
		canLookupUsers, err := ac.Evaluate(ctx, requester, orgUserLookupEvaluator(enforceUserScope))
		if err != nil {
			return nil, err
		}

		var hiddenUsers map[string]struct{}
		if cfg != nil && !requester.GetIsGrafanaAdmin() {
			hiddenUsers = cfg.HiddenUsers
		}

		evaluate := func(action, scope string) bool {
			ok, err := ac.Evaluate(ctx, requester, accesscontrol.EvalPermission(action, scope))
			return err == nil && ok
		}

		return func(m display.Member) bool {
			switch m.Type {
			case authlib.TypeUser:
				if !canLookupUsers {
					return false
				}
				if _, hidden := hiddenUsers[m.Login]; hidden {
					return false
				}
				if enforceUserScope {
					return evaluate(accesscontrol.ActionOrgUsersRead, accesscontrol.Scope("users", "id", strconv.FormatInt(m.ID, 10)))
				}
				return true
			case authlib.TypeServiceAccount:
				return evaluate(serviceaccounts.ActionRead, accesscontrol.Scope("serviceaccounts", "id", strconv.FormatInt(m.ID, 10)))
			default:
				return false
			}
		}, nil
	}
}

// orgUserLookupEvaluator mirrors the evaluator guarding GET /api/org/users/lookup.
func orgUserLookupEvaluator(enforceUserScope bool) accesscontrol.Evaluator {
	if enforceUserScope {
		return accesscontrol.EvalPermission(accesscontrol.ActionOrgUsersRead)
	}
	return accesscontrol.EvalAny(
		accesscontrol.EvalPermission(accesscontrol.ActionOrgUsersRead),
		accesscontrol.EvalPermission(accesscontrol.ActionTeamsPermissionsWrite),
		accesscontrol.EvalPermission(folder.ActionFoldersPermissionsWrite),
		accesscontrol.EvalPermission(dashboards.ActionDashboardsPermissionsWrite),
	)
}
