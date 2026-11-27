package datasource

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/admission"

	datasourceV0 "github.com/grafana/grafana/pkg/apis/datasource/v0alpha1"
	"github.com/grafana/grafana/pkg/services/apiserver/builder"
	"github.com/grafana/grafana/pkg/services/datasources"
)

var _ builder.APIGroupValidation = (*DataSourceAPIBuilder)(nil)

// Validate keeps read-only (provisioned) datasources locked when writes go to unified storage,
// which bypasses the legacy store. Unified storage runs this against the stored object it is
// about to replace or remove, under the same resource version check as the write.
func (b *DataSourceAPIBuilder) Validate(_ context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	gr := b.datasourceResourceInfo.GroupResource()
	if a.GetSubresource() != "" || a.GetResource().Resource != gr.Resource {
		return nil
	}
	switch a.GetOperation() {
	case admission.Update, admission.Delete:
	default:
		return nil
	}
	old, ok := a.GetOldObject().(*datasourceV0.DataSource)
	if !ok || !old.Spec.ReadOnly() {
		return nil
	}
	return apierrors.NewForbidden(gr, a.GetName(), datasources.ErrDatasourceIsReadOnly)
}
