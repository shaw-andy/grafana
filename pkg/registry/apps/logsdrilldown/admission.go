package logsdrilldown

import (
	"context"
	"errors"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"

	logsdrilldownv1alpha1 "github.com/grafana/grafana/apps/logsdrilldown/pkg/apis/logsdrilldown/v1alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
)

var logsDrilldownResource = schema.GroupResource{
	Group:    logsdrilldownv1alpha1.APIGroup,
	Resource: logsdrilldownv1alpha1.LogsDrilldownKind().Plural(),
}

// ownerAdmission enforces on create the same name ownership the authorizer
// enforces on other verbs, since the name of a created object is only known
// once the request body has been decoded.
type ownerAdmission struct {
	*admission.Handler
}

var _ admission.ValidationInterface = (*ownerAdmission)(nil)

func newOwnerAdmission() *ownerAdmission {
	return &ownerAdmission{Handler: admission.NewHandler(admission.Create)}
}

func (o *ownerAdmission) Validate(ctx context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	if a.GetOperation() != admission.Create || a.GetResource().GroupResource() != logsDrilldownResource {
		return nil
	}

	u, err := identity.GetRequester(ctx)
	if err != nil {
		return admission.NewForbidden(a, errors.New("valid user is required"))
	}
	if u.GetIsGrafanaAdmin() {
		return nil
	}

	// Check the name on the object that will be stored. An empty name would be
	// generated later by storage, so it cannot be tied to the caller here.
	obj, err := meta.Accessor(a.GetObject())
	if err != nil {
		return admission.NewForbidden(a, err)
	}
	if !compareResourceNameAndUserUID(obj.GetName(), u) {
		return admission.NewForbidden(a, errors.New("name must be in the format <service>:<user_uid> for the current user"))
	}
	return nil
}
