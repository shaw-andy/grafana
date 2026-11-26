package provisioning

import (
	"context"
	"fmt"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/endpoints/request"

	authlib "github.com/grafana/authlib/types"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs"
)

// jobAdmissionValidator authorizes every Job written to the jobs resource
// against the identity writing it.
//
// Queued jobs run later as the provisioning service identity, so the checks the
// repositories/{name}/jobs subresource makes before queuing are the only thing
// limiting what a job may read or change. The jobs resource accepts creates and
// updates from anyone holding jobs:create or jobs:write, so the same checks have
// to run here, on the job as it is stored, or writing a Job directly would skip
// them. Only the provisioning service may change the spec of a stored job, so a
// job keeps the spec it was authorized with until it runs.
type jobAdmissionValidator struct {
	connector *jobsConnector
}

func newJobAdmissionValidator(connector *jobsConnector) *jobAdmissionValidator {
	return &jobAdmissionValidator{connector: connector}
}

func (v *jobAdmissionValidator) Validate(ctx context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	job, ok := a.GetObject().(*provisioning.Job)
	if !ok || job == nil {
		return nil
	}
	if job.GetDeletionTimestamp() != nil {
		return nil
	}
	if info, ok := authlib.AuthInfoFrom(ctx); ok && identity.IsProvisioningServiceIdentity(info) {
		return nil
	}

	switch a.GetOperation() {
	case admission.Create:
		ctx = request.WithNamespace(ctx, a.GetNamespace())
		return v.connector.authorizeStoredJob(ctx, a.GetNamespace(), job.Spec)
	case admission.Update:
		old, ok := a.GetOldObject().(*provisioning.Job)
		if !ok {
			return fmt.Errorf("expected job, got %T", a.GetOldObject())
		}
		if !apiequality.Semantic.DeepEqual(old.Spec, job.Spec) {
			return apierrors.NewForbidden(provisioning.JobResourceInfo.GroupResource(), job.Name,
				fmt.Errorf("the spec of a job can only be changed by the provisioning service"))
		}
	case admission.Delete, admission.Connect:
	}
	return nil
}

// authorizeStoredJob runs the checks a caller must pass to queue a job with the
// given spec, for a job written to the jobs resource rather than through the
// repositories/{name}/jobs subresource.
func (c *jobsConnector) authorizeStoredJob(ctx context.Context, namespace string, spec provisioning.JobSpec) error {
	namespaceOnly := &provisioning.Repository{ObjectMeta: metav1.ObjectMeta{Namespace: namespace}}
	if jobs.IsOrphanCleanupAction(spec.Action) {
		return c.authorizeAdminJob(ctx, namespaceOnly)
	}

	repo, err := c.repoGetter.GetRepository(ctx, spec.Repository)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// A job for a repository that does not exist fails when it runs.
			return c.authorizeAdminJob(ctx, namespaceOnly)
		}
		return err
	}
	cfg := repo.Config()

	if spec.Action == provisioning.JobActionPull || spec.Action == provisioning.JobActionTest {
		if err := c.authorizeAdminJob(ctx, cfg); err != nil {
			return err
		}
	}
	if err := c.validateWriteAccess(cfg, spec); err != nil {
		return err
	}
	return c.authorizeJob(ctx, repo, cfg, spec)
}
