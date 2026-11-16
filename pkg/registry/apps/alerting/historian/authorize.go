package historian

import (
	"context"

	authtypes "github.com/grafana/authlib/types"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
)

// Kubernetes parses the namespaced custom routes as {resource}/{name}.
type historyRoute struct {
	resource string
	name     string
	verb     string
}

var historyRoutes = map[historyRoute]struct{}{
	{resource: "alertstate", name: "history", verb: "get"}:           {},
	{resource: "notification", name: "query", verb: "create"}:        {},
	{resource: "notifications", name: "queryalerts", verb: "create"}: {},
}

var historyResources = map[string]struct{}{
	"alertstate":    {},
	"notification":  {},
	"notifications": {},
}

// newAuthorizer must not return allow for anything other than the history
// routes: an allow short-circuits the org role authorizer, which is what keeps
// Viewers and None-role users from writing the Dummy kind.
func newAuthorizer(ac accesscontrol.AccessControl) authorizer.Authorizer {
	return authorizer.AuthorizerFunc(func(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
		if !attr.IsResourceRequest() {
			return authorizer.DecisionNoOpinion, "", nil
		}

		user, err := identity.GetRequester(ctx)
		if err != nil {
			return authorizer.DecisionDeny, "valid user is required", nil
		}

		// The shared namespace authorizer does not bind anonymous callers to an
		// organization, so do it here.
		if authtypes.IsIdentityType(user.GetIdentityType(), authtypes.TypeAnonymous) && attr.GetNamespace() != "" {
			ns, err := authtypes.ParseNamespace(attr.GetNamespace())
			if err != nil || ns.OrgID != user.GetOrgID() {
				return authorizer.DecisionDeny, "invalid org", nil
			}
		}

		if _, ok := historyResources[attr.GetResource()]; !ok {
			return authorizer.DecisionNoOpinion, "", nil
		}

		route := historyRoute{resource: attr.GetResource(), name: attr.GetName(), verb: attr.GetVerb()}
		if _, ok := historyRoutes[route]; !ok || attr.GetSubresource() != "" {
			return authorizer.DecisionDeny, "unsupported history request", nil
		}

		if ac == nil {
			return authorizer.DecisionDeny, "access control is not configured", nil
		}

		ok, err := ac.Evaluate(ctx, user, accesscontrol.EvalPermission(accesscontrol.ActionAlertingRuleRead))
		if ok {
			return authorizer.DecisionAllow, "", nil
		}
		if err != nil {
			return authorizer.DecisionDeny, err.Error(), nil
		}
		return authorizer.DecisionDeny, "", nil
	})
}
