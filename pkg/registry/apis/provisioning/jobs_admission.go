package provisioning

import (
	"context"
	"fmt"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/admission"

	authlib "github.com/grafana/authlib/types"

	appadmission "github.com/grafana/grafana/apps/provisioning/pkg/apis/admission"
	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	appjobs "github.com/grafana/grafana/apps/provisioning/pkg/jobs"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs"
)

// jobAuthorizationAdmission authorizes Job objects against the job creator. Jobs run
// later as the provisioning service, and the jobs resource can be written directly as
// well as through the repository jobs subresource, so the checks the subresource
// applies are enforced here for every create, and a created job cannot be changed.
type jobAuthorizationAdmission struct {
	mutator            appadmission.Mutator
	validator          appadmission.Validator
	connector          *jobsConnector
	supportedResources []provisioning.SupportedResource
}

func newJobAuthorizationAdmission(mutator appadmission.Mutator, validator appadmission.Validator, connector *jobsConnector, supportedResources []provisioning.SupportedResource) *jobAuthorizationAdmission {
	return &jobAuthorizationAdmission{
		mutator:            mutator,
		validator:          validator,
		connector:          connector,
		supportedResources: supportedResources,
	}
}

// Mutate authorizes a new job and records the directory contents it was authorized
// to delete, replacing anything the creator supplied.
func (j *jobAuthorizationAdmission) Mutate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	if err := j.mutator.Mutate(ctx, a, o); err != nil {
		return err
	}
	if a.GetOperation() != admission.Create || isServiceJobWriter(ctx) {
		return nil
	}

	job, ok := a.GetObject().(*provisioning.Job)
	if !ok {
		return fmt.Errorf("expected job, got %T", a.GetObject())
	}
	delete(job.Annotations, jobs.AnnoAuthorizedDirectories)

	// Validation rejects an invalid job; its paths must not be resolved before that.
	if appjobs.ValidateJob(job, j.supportedResources) != nil {
		return nil
	}

	directories, err := j.connector.authorizeJobAdmission(ctx, a.GetNamespace(), job.Spec)
	if err != nil {
		return err
	}
	return jobs.SetAuthorizedDirectories(job, directories)
}

// Validate refuses changes to what an existing job does unless they come from a
// service, since the job was authorized for its original spec only.
func (j *jobAuthorizationAdmission) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	if err := j.validator.Validate(ctx, a, o); err != nil {
		return err
	}
	if a.GetOperation() != admission.Update || isServiceJobWriter(ctx) {
		return nil
	}

	job, ok := a.GetObject().(*provisioning.Job)
	if !ok {
		return nil
	}
	old, ok := a.GetOldObject().(*provisioning.Job)
	if !ok {
		return nil
	}

	if !apiequality.Semantic.DeepEqual(old.Spec, job.Spec) {
		return apierrors.NewForbidden(provisioning.JobResourceInfo.GroupResource(), job.Name,
			fmt.Errorf("the spec of an existing job cannot be changed; create a new job instead"))
	}
	if old.Annotations[jobs.AnnoAuthorizedDirectories] != job.Annotations[jobs.AnnoAuthorizedDirectories] {
		return apierrors.NewForbidden(provisioning.JobResourceInfo.GroupResource(), job.Name,
			fmt.Errorf("annotation %s is immutable", jobs.AnnoAuthorizedDirectories))
	}
	return nil
}

// isServiceJobWriter reports whether the request comes from Grafana or the
// provisioning service rather than from a user, service account or token.
func isServiceJobWriter(ctx context.Context) bool {
	if info, ok := authlib.AuthInfoFrom(ctx); ok && identity.IsProvisioningServiceIdentity(info) {
		return true
	}
	return identity.IsServiceIdentity(ctx)
}
