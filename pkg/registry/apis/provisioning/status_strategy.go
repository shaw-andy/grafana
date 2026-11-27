package provisioning

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	grafanaregistry "github.com/grafana/grafana/pkg/apiserver/registry/generic"
)

// newStatusStore serves the status subresource of a repository or connection.
func newStatusStore(scheme *runtime.Scheme, store *registry.Store) *statusREST {
	gv := store.New().GetObjectKind().GroupVersionKind().GroupVersion()
	return &statusREST{StatusREST: grafanaregistry.NewStatusREST(store, &statusStrategy{
		UpdateResetFieldsStrategy: grafanaregistry.NewStatusStrategy(scheme, gv),
	})}
}

type statusREST struct {
	*grafanaregistry.StatusREST
}

// Update validates the object the request asked for before the status strategy
// discards everything but status, so a status write bundling an invalid spec
// change is rejected as a whole instead of landing its status half.
func (r *statusREST) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc, updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	if updateValidation != nil {
		objInfo = &validatedObjectInfo{UpdatedObjectInfo: objInfo, validate: updateValidation}
	}
	return r.StatusREST.Update(ctx, name, objInfo, createValidation, updateValidation, forceAllowCreate, options)
}

type validatedObjectInfo struct {
	rest.UpdatedObjectInfo
	validate rest.ValidateObjectUpdateFunc
}

func (i *validatedObjectInfo) UpdatedObject(ctx context.Context, oldObj runtime.Object) (runtime.Object, error) {
	obj, err := i.UpdatedObjectInfo.UpdatedObject(ctx, oldObj)
	if err != nil {
		return nil, err
	}
	if err := i.validate(ctx, obj.DeepCopyObject(), oldObj.DeepCopyObject()); err != nil {
		return nil, err
	}
	return obj, nil
}

// statusStrategy only lets a status write change status, plus what the
// controllers and the authorize flow write together with their status:
//   - the connection token, and the repository token and webhook secret. A
//     rotation can only create a new value; it cannot point at another secret
//     or remove one.
//   - the repository branch and GitLab repository ID, only while unset, so the
//     controller can fill in the default branch and backfill the resolved ID.
type statusStrategy struct {
	rest.UpdateResetFieldsStrategy
}

func (s *statusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	switch o := obj.(type) {
	case *provisioning.Connection:
		token := o.Secure.Token
		s.UpdateResetFieldsStrategy.PrepareForUpdate(ctx, obj, old)
		keepRotatedSecret(&o.Secure.Token, token)
	case *provisioning.Repository:
		incoming := o.DeepCopy()
		s.UpdateResetFieldsStrategy.PrepareForUpdate(ctx, obj, old)
		keepRotatedSecret(&o.Secure.Token, incoming.Secure.Token)
		keepRotatedSecret(&o.Secure.WebhookSecret, incoming.Secure.WebhookSecret)
		if incoming.Spec.Type == o.Spec.Type {
			fillUnset(repositoryBranch(&o.Spec), repositoryBranch(&incoming.Spec))
			if o.Spec.GitLab != nil && incoming.Spec.GitLab != nil {
				fillUnset(&o.Spec.GitLab.RepoID, &incoming.Spec.GitLab.RepoID)
			}
		}
	default:
		s.UpdateResetFieldsStrategy.PrepareForUpdate(ctx, obj, old)
	}
}

func keepRotatedSecret(dst *common.InlineSecureValue, incoming common.InlineSecureValue) {
	if incoming.Create.IsZero() {
		return
	}
	*dst = common.InlineSecureValue{Create: incoming.Create}
}

func fillUnset(dst, incoming *string) {
	if dst != nil && incoming != nil && *dst == "" {
		*dst = *incoming
	}
}

func repositoryBranch(spec *provisioning.RepositorySpec) *string {
	switch spec.Type {
	case provisioning.GitHubRepositoryType:
		if spec.GitHub != nil {
			return &spec.GitHub.Branch
		}
	case provisioning.GitHubEnterpriseRepositoryType:
		if spec.GitHubEnterprise != nil {
			return &spec.GitHubEnterprise.Branch
		}
	case provisioning.GitRepositoryType:
		if spec.Git != nil {
			return &spec.Git.Branch
		}
	case provisioning.BitbucketRepositoryType:
		if spec.Bitbucket != nil {
			return &spec.Bitbucket.Branch
		}
	case provisioning.GitLabRepositoryType:
		if spec.GitLab != nil {
			return &spec.GitLab.Branch
		}
	}
	return nil
}
