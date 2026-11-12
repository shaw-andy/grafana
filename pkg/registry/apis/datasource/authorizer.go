package datasource

import (
	"context"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	authn "github.com/grafana/authlib/authn"
	authlib "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
)

func (b *DataSourceAPIBuilder) GetAuthorizer() authorizer.Authorizer {
	group := b.GetGroupVersion().Group
	return authorizer.AuthorizerFunc(
		func(ctx context.Context, attr authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
			if !attr.IsResourceRequest() {
				return authorizer.DecisionNoOpinion, "", nil
			}

			sub := attr.GetSubresource()

			var svcIdentity []string
			if authInfo, ok := authlib.AuthInfoFrom(ctx); ok {
				svcIdentity = authInfo.GetExtra()[authn.ServiceIdentityKey]
			}

			// Observe svc_identity state for future enforcement.
			caller := "empty"
			if len(svcIdentity) > 0 {
				caller = svcIdentity[0]
			}

			verb := attr.GetVerb()

			user, err := identity.GetRequester(ctx)
			if err != nil {
				recordAuthzDecision(group, sub, verb, caller, "deny", "no_user")
				return authorizer.DecisionDeny, "valid user is required", err
			}

			req := authlib.CheckRequest{
				Group:     group,
				Resource:  "datasources",
				Namespace: attr.GetNamespace(),
				Name:      attr.GetName(),
				Verb:      verb,
			}

			if sub != "" {
				req.Verb = utils.VerbCreate
				req.Subresource = "query"
			}

			rsp, err := b.accessClient.Check(ctx, user, req, "")
			if err != nil {
				recordAuthzDecision(group, sub, verb, caller, "deny", "error")
				return authorizer.DecisionDeny, "failed to check permissions", err
			}
			if rsp.Allowed {
				recordAuthzDecision(group, sub, verb, caller, "allow", "")
				return authorizer.DecisionAllow, "", nil
			}
			if req.Subresource != "" {
				recordAuthzDecision(group, sub, verb, caller, "deny", "missing_permissions")
				return authorizer.DecisionDeny, "missing `query` subresource permission", nil
			}

			recordAuthzDecision(group, sub, verb, caller, "deny", "access_denied")
			return authorizer.DecisionDeny, "access denied", nil
		})
}

// authorizeEdit returns nil only when the requester in ctx may update the
// datasource with the given UID.
func (b *DataSourceAPIBuilder) authorizeEdit(ctx context.Context, namespace, uid string) error {
	gr := b.datasourceResourceInfo.GroupResource()
	if b.accessClient == nil || uid == "" {
		return apierrors.NewForbidden(gr, uid, errors.New("datasource edit permission is required"))
	}

	user, err := identity.GetRequester(ctx)
	if err != nil {
		return apierrors.NewUnauthorized("valid user is required")
	}

	rsp, err := b.accessClient.Check(ctx, user, authlib.CheckRequest{
		Group:     b.GetGroupVersion().Group,
		Resource:  "datasources",
		Namespace: namespace,
		Name:      uid,
		Verb:      utils.VerbUpdate,
	}, "")
	if err != nil {
		return apierrors.NewInternalError(fmt.Errorf("failed to check permissions: %w", err))
	}
	if !rsp.Allowed {
		return apierrors.NewForbidden(gr, uid, errors.New("datasource edit permission is required"))
	}
	return nil
}
