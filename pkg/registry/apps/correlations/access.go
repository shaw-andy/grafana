package correlations

import (
	"context"
	"fmt"
	"io"

	"github.com/grafana/authlib/types"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	correlationsV0 "github.com/grafana/grafana/apps/correlations/pkg/apis/correlation/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/datasources"
)

var correlationsGR = schema.GroupResource{
	Group:    correlationsV0.CorrelationKind().Group(),
	Resource: correlationsV0.CorrelationKind().Plural(),
}

// correlationAccess mirrors the legacy /api/datasources/uid/:uid/correlations routes:
// writes need datasources:write on the correlation's source datasource and reads need
// datasources:read on it.
type correlationAccess struct {
	ac accesscontrol.AccessControl
}

// authorize is the coarse request-level gate. It can only see the verb, so the
// per-source checks happen in storage (legacy) and admission (unified).
// It must never return NoOpinion for resource requests: the org role authorizer
// that runs after it would allow Editors to write.
func (c *correlationAccess) authorize(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
	if !attr.IsResourceRequest() {
		return authorizer.DecisionNoOpinion, "", nil
	}
	if identity.IsServiceIdentity(ctx) {
		return authorizer.DecisionAllow, "", nil
	}
	user, err := identity.GetRequester(ctx)
	if err != nil {
		return authorizer.DecisionDeny, "valid user is required", nil
	}

	var eval accesscontrol.Evaluator
	switch attr.GetVerb() {
	case "get", "list", "watch":
		eval = accesscontrol.EvalPermission(datasources.ActionRead)
	case "create", "update", "patch", "delete":
		eval = accesscontrol.EvalPermission(datasources.ActionWrite)
	case "deletecollection":
		eval = accesscontrol.EvalAny(
			accesscontrol.EvalPermission(datasources.ActionWrite),
			accesscontrol.EvalPermission(datasources.ActionDelete),
		)
	default:
		return authorizer.DecisionDeny, fmt.Sprintf("verb %q is not supported for correlations", attr.GetVerb()), nil
	}

	ok, err := c.ac.Evaluate(ctx, user, eval)
	if err != nil {
		return authorizer.DecisionDeny, "failed to evaluate permissions", nil
	}
	if !ok {
		return authorizer.DecisionDeny, "missing datasource permissions for correlations", nil
	}
	return authorizer.DecisionAllow, "", nil
}

func (c *correlationAccess) check(ctx context.Context, orgID int64, name, sourceUID string, eval func(scope string) accesscontrol.Evaluator) error {
	if sourceUID == "" {
		return apierrors.NewBadRequest("spec.source.name is required")
	}
	if identity.IsServiceIdentity(ctx) {
		return nil
	}
	user, err := identity.GetRequester(ctx)
	if err != nil {
		return apierrors.NewUnauthorized("valid user is required")
	}
	if user.GetOrgID() != orgID {
		return apierrors.NewForbidden(correlationsGR, name, fmt.Errorf("correlations can only be accessed in the caller's organization"))
	}
	ok, err := c.ac.Evaluate(ctx, user, eval(datasources.ScopeProvider.GetResourceScopeUID(sourceUID)))
	if err != nil {
		return apierrors.NewInternalError(err)
	}
	if !ok {
		return apierrors.NewForbidden(correlationsGR, name, fmt.Errorf("missing permissions on source datasource %q", sourceUID))
	}
	return nil
}

func (c *correlationAccess) checkWrite(ctx context.Context, orgID int64, name, sourceUID string) error {
	return c.check(ctx, orgID, name, sourceUID, func(scope string) accesscontrol.Evaluator {
		return accesscontrol.EvalPermission(datasources.ActionWrite, scope)
	})
}

// checkCollectionDelete also accepts datasources:delete, since deleting the datasource
// removes the same correlations.
func (c *correlationAccess) checkCollectionDelete(ctx context.Context, orgID int64, datasourceUID string, bySource bool) error {
	return c.check(ctx, orgID, "", datasourceUID, func(scope string) accesscontrol.Evaluator {
		if !bySource {
			return accesscontrol.EvalPermission(datasources.ActionDelete, scope)
		}
		return accesscontrol.EvalAny(
			accesscontrol.EvalPermission(datasources.ActionWrite, scope),
			accesscontrol.EvalPermission(datasources.ActionDelete, scope),
		)
	})
}

func (c *correlationAccess) checkRead(ctx context.Context, orgID int64, name, sourceUID string) error {
	return c.check(ctx, orgID, name, sourceUID, func(scope string) accesscontrol.Evaluator {
		return accesscontrol.EvalPermission(datasources.ActionRead, scope)
	})
}

// admissionValidator enforces the per-source write checks for storage backends that
// run admission (unified storage). Legacy storage enforces them itself.
type admissionValidator struct {
	*admission.Handler
	access *correlationAccess
}

var _ admission.ValidationInterface = (*admissionValidator)(nil)

func newAdmissionValidator(access *correlationAccess) *admissionValidator {
	return &admissionValidator{
		Handler: admission.NewHandler(admission.Create, admission.Update, admission.Delete),
		access:  access,
	}
}

func (v *admissionValidator) Validate(ctx context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	if a.GetResource().GroupResource() != correlationsGR || a.GetSubresource() != "" {
		return nil
	}
	ns, err := types.ParseNamespace(a.GetNamespace())
	if err != nil {
		return apierrors.NewBadRequest("invalid namespace")
	}

	switch a.GetOperation() {
	case admission.Create:
		obj, ok := a.GetObject().(*correlationsV0.Correlation)
		if !ok {
			return apierrors.NewBadRequest("expected correlation")
		}
		return v.access.checkWrite(ctx, ns.OrgID, a.GetName(), obj.Spec.Source.Name)
	case admission.Update:
		obj, ok := a.GetObject().(*correlationsV0.Correlation)
		if !ok {
			return apierrors.NewBadRequest("expected correlation")
		}
		old, ok := a.GetOldObject().(*correlationsV0.Correlation)
		if !ok {
			return apierrors.NewBadRequest("expected correlation")
		}
		if err := v.access.checkWrite(ctx, ns.OrgID, a.GetName(), old.Spec.Source.Name); err != nil {
			return err
		}
		if obj.Spec.Source.Name != old.Spec.Source.Name {
			return apierrors.NewBadRequest("spec.source cannot be changed")
		}
		return nil
	case admission.Delete:
		old, ok := a.GetOldObject().(*correlationsV0.Correlation)
		if !ok {
			return apierrors.NewBadRequest("expected correlation")
		}
		// Collection deletes are validated item by item without a name.
		if a.GetName() == "" {
			return v.access.checkCollectionDelete(ctx, ns.OrgID, old.Spec.Source.Name, true)
		}
		return v.access.checkWrite(ctx, ns.OrgID, a.GetName(), old.Spec.Source.Name)
	}
	return nil
}

func chainAdmission(base admission.Factory, validator *admissionValidator) admission.Factory {
	return func(cfg io.Reader) (admission.Interface, error) {
		if base == nil {
			return validator, nil
		}
		baseAdmission, err := base(cfg)
		if err != nil {
			return nil, err
		}
		return admission.NewChainHandler(baseAdmission, validator), nil
	}
}
