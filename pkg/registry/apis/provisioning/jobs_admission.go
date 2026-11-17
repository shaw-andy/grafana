package provisioning

import (
	"context"
	"errors"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/admission"

	authlib "github.com/grafana/authlib/types"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
)

// jobAuthorizationValidator authorizes Job objects at admission. Editors hold
// jobs:create and jobs:write on the jobs resource itself, so the checks made by
// the jobs subresource must also hold for a Job created there directly, and a
// queued Job's spec must not change after it was authorized.
//
// Jobs queued through the jobs subresource are inserted with the requesting
// user's identity and are checked here as well. Jobs queued by background
// components (controller, webhooks, workers) use the provisioning identity,
// which is trusted.
type jobAuthorizationValidator struct {
	connector *jobsConnector
}

func newJobAuthorizationValidator(connector *jobsConnector) *jobAuthorizationValidator {
	return &jobAuthorizationValidator{connector: connector}
}

func (v *jobAuthorizationValidator) Validate(ctx context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	job, ok := a.GetObject().(*provisioning.Job)
	if !ok {
		return nil
	}

	if info, ok := authlib.AuthInfoFrom(ctx); ok && identity.IsProvisioningServiceIdentity(info) {
		return nil
	}

	switch a.GetOperation() {
	case admission.Create:
		return v.connector.authorizeJobObject(ctx, a.GetNamespace(), job.Spec)
	case admission.Update:
		old, ok := a.GetOldObject().(*provisioning.Job)
		if !ok {
			return apierrors.NewBadRequest("expected the existing job")
		}
		if !apiequality.Semantic.DeepEqual(old.Spec, job.Spec) {
			return apierrors.NewForbidden(
				provisioning.JobResourceInfo.GroupResource(),
				job.GetName(),
				errors.New("the spec of a queued job cannot be changed"),
			)
		}
	case admission.Delete, admission.Connect:
	}
	return nil
}
