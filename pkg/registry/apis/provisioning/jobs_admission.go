package provisioning

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/admission"

	authlib "github.com/grafana/authlib/types"
	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs"
)

// jobAdmissionValidator applies the jobs connector's authorization to the Job
// object as it is stored. Jobs run as the provisioning service identity and
// trust their spec, so a Job written directly to the jobs resource, or one
// whose spec changes after creation, must not skip the checks made for the
// repository jobs subresource.
type jobAdmissionValidator struct {
	connector *jobsConnector
}

func (v *jobAdmissionValidator) Validate(ctx context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	if isProvisioningService(ctx) {
		return nil
	}

	switch a.GetOperation() {
	case admission.Create:
		job, ok := a.GetObject().(*provisioning.Job)
		if !ok {
			return fmt.Errorf("expected job, got %T", a.GetObject())
		}
		if jobs.IsOrphanCleanupAction(job.Spec.Action) {
			return v.connector.authorizeOrphanCleanupJob(ctx, a.GetNamespace(), job.Spec.Repository)
		}
		_, err := v.connector.authorizeCreateJob(ctx, job.Spec.Repository, job.Spec)
		return err
	case admission.Update:
		job, ok := a.GetObject().(*provisioning.Job)
		if !ok {
			return fmt.Errorf("expected job, got %T", a.GetObject())
		}
		old, ok := a.GetOldObject().(*provisioning.Job)
		if !ok {
			return fmt.Errorf("expected job, got %T", a.GetOldObject())
		}
		if !equality.Semantic.DeepEqual(job.Spec, old.Spec) {
			return apierrors.NewForbidden(provisioning.JobResourceInfo.GroupResource(), job.Name,
				fmt.Errorf("the job spec cannot be changed after the job is created"))
		}
	case admission.Delete, admission.Connect:
	}

	return nil
}

func isProvisioningService(ctx context.Context) bool {
	if identity.IsServiceIdentity(ctx) {
		return true
	}
	info, ok := authlib.AuthInfoFrom(ctx)
	return ok && identity.IsProvisioningServiceIdentity(info)
}
