package datasource

import (
	"context"
	"maps"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	datasourceV0 "github.com/grafana/grafana/pkg/apis/datasource/v0alpha1"
	"github.com/grafana/grafana/pkg/services/datasources"
)

// withoutTeamHTTPHeaders omits the label-based access rules from the jsonData returned to a requester
// that cannot read them. The datasource is never modified, because its jsonData map may be shared
// with the datasource cache.
func withoutTeamHTTPHeaders(ctx context.Context, ds *datasourceV0.DataSource) *datasourceV0.DataSource {
	if ds == nil {
		return nil
	}
	jsonData, ok := ds.Spec.JSONData().(map[string]any)
	if !ok {
		return ds
	}
	if _, ok := jsonData["teamHttpHeaders"]; !ok {
		return ds
	}
	if requester, err := identity.GetRequester(ctx); err == nil && datasources.CanReadTeamHTTPHeaders(requester.GetPermissions(), ds.Name) {
		return ds
	}

	filtered := maps.Clone(jsonData)
	delete(filtered, "teamHttpHeaders")
	out := *ds
	out.Spec.Object = maps.Clone(ds.Spec.Object)
	out.Spec.SetJSONData(filtered)
	return &out
}

func listWithoutTeamHTTPHeaders(ctx context.Context, list *datasourceV0.DataSourceList) *datasourceV0.DataSourceList {
	if list == nil {
		return nil
	}
	for i := range list.Items {
		list.Items[i] = *withoutTeamHTTPHeaders(ctx, &list.Items[i])
	}
	return list
}
