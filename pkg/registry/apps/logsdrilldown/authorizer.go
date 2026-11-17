package logsdrilldown

import (
	"context"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginaccesscontrol"

	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// The default columns and default labels objects are shared by the whole organization,
// so a plugins:write grant scoped to individual plugins must not be enough to change them.
var orgDefaultsWriteEvaluator = accesscontrol.EvalPermission(
	pluginaccesscontrol.ActionWrite,
	pluginaccesscontrol.ScopeProvider.GetResourceAllScope(),
)

func canManageOrgDefaults(u identity.Requester) bool {
	return u.GetOrgRole() == identity.RoleAdmin && orgDefaultsWriteEvaluator.Evaluate(u.GetPermissions())
}

func orgDefaultsDecision(u identity.Requester) (authorizer.Decision, string, error) {
	if canManageOrgDefaults(u) {
		return authorizer.DecisionAllow, "org admin with plugins:write on all plugins", nil
	}
	return authorizer.DecisionDeny, "org admin with plugins:write on all plugins required", nil
}

// GetAuthorizer returns an authorizer for all kinds managed by the logsdrilldown app.
func GetAuthorizer() authorizer.Authorizer {
	return authorizer.AuthorizerFunc(func(
		ctx context.Context, attr authorizer.Attributes,
	) (authorized authorizer.Decision, reason string, err error) {
		if !attr.IsResourceRequest() {
			return authorizer.DecisionNoOpinion, "", nil
		}

		// require a user
		u, err := identity.GetRequester(ctx)
		if err != nil {
			return authorizer.DecisionDeny, "valid user is required", err
		}

		// check if is admin
		if u.GetIsGrafanaAdmin() {
			return authorizer.DecisionAllow, "isGrafanaAdmin", nil
		}

		// Auth handling for LogsDrilldownDefaults resource
		if attr.GetResource() == "logsdrilldowndefaults" {
			// Allow list and get for everyone
			if attr.GetVerb() == "list" || attr.GetVerb() == "get" {
				return authorizer.DecisionAllow, "", nil
			}
			// Deny all other operations for non-admins
			return authorizer.DecisionDeny, "admin access required", nil
		}

		// Auth handling for Logs Drilldown default columns
		if attr.GetResource() == "logsdrilldowndefaultcolumns" {
			// Allow get for all users
			if attr.GetVerb() == "get" {
				return authorizer.DecisionAllow, "", nil
			}
			return orgDefaultsDecision(u)
		}

		// Auth handling for Logs Drilldown default labels
		if attr.GetResource() == "logsdrilldowndefaultlabels" {
			// Allow list and get for all users
			if attr.GetVerb() == "list" || attr.GetVerb() == "get" {
				return authorizer.DecisionAllow, "", nil
			}
			return orgDefaultsDecision(u)
		}

		p := u.GetPermissions()
		if len(p) == 0 {
			return authorizer.DecisionDeny, "no permissions", nil
		}

		_, ok := p[accesscontrol.ActionDatasourcesExplore]
		if !ok {
			// defer to the default authorizer if datasources:explore is not present
			return authorizer.DecisionNoOpinion, "", nil
		}

		switch attr.GetVerb() {
		case "list":
			// Allow everyone to list logsdrilldowns
			return authorizer.DecisionAllow, "", nil
		case "get":
			// Allow everyone to get individual logsdrilldowns
			return authorizer.DecisionAllow, "", nil
		case "create":
			// Create requests are validated later since we don't have access to the resource name
			return authorizer.DecisionAllow, "", nil
		case "delete", "patch", "update":
			// Only allow the user to access their own settings
			if !compareResourceNameAndUserUID(attr.GetName(), u) {
				return authorizer.DecisionDeny, "forbidden", nil
			}
			return authorizer.DecisionAllow, "", nil
		default:
			// Forbid the rest
			return authorizer.DecisionDeny, "forbidden", nil
		}
	})
}
