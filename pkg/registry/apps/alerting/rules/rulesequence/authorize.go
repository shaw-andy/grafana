package rulesequence

import (
	"context"

	"k8s.io/apiserver/pkg/authorization/authorizer"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/folder"
)

// Authorize is a coarse, unscoped pre-check: it passes when the caller holds the
// action on any folder. The folder scope is enforced on the stored object by
// StorageAuthorizer, which subresources such as status do not go through, so
// those require the action on every folder.
func Authorize(ctx context.Context, ac accesscontrol.AccessControl, attr authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	if attr.GetResource() != ResourceInfo.GroupResource().Resource {
		return authorizer.DecisionNoOpinion, "", nil
	}
	user, err := identity.GetRequester(ctx)
	if err != nil {
		return authorizer.DecisionDeny, "valid user is required", err
	}

	var actions []string
	switch attr.GetVerb() {
	case "get", "list", "watch":
	case "create":
		actions = []string{accesscontrol.ActionAlertingRuleCreate}
	case "patch", "update":
		actions = []string{accesscontrol.ActionAlertingRuleUpdate}
	case "delete", "deletecollection":
		actions = []string{accesscontrol.ActionAlertingRuleDelete}
	default:
		return authorizer.DecisionNoOpinion, "unsupported verb", nil
	}

	var action accesscontrol.Evaluator
	if attr.GetSubresource() != "" {
		action = allFoldersEvaluator(actions...)
	} else {
		evals := []accesscontrol.Evaluator{accesscontrol.EvalPermission(accesscontrol.ActionAlertingRuleRead)}
		for _, a := range actions {
			evals = append(evals, accesscontrol.EvalPermission(a))
		}
		action = accesscontrol.EvalAll(evals...)
	}

	ok, err := ac.Evaluate(ctx, user, action)
	if ok {
		return authorizer.DecisionAllow, "", nil
	}
	return authorizer.DecisionDeny, "", err
}

func allFoldersEvaluator(actions ...string) accesscontrol.Evaluator {
	scope := folder.ScopeFoldersProvider.GetResourceAllScope()
	evals := []accesscontrol.Evaluator{
		accesscontrol.EvalPermission(folder.ActionFoldersRead, scope),
		accesscontrol.EvalPermission(accesscontrol.ActionAlertingRuleRead, scope),
	}
	for _, a := range actions {
		evals = append(evals, accesscontrol.EvalPermission(a, scope))
	}
	return accesscontrol.EvalAll(evals...)
}
