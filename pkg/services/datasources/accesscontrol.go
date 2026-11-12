package datasources

import (
	"net/url"
	"path"
	"strings"

	"github.com/grafana/grafana/pkg/services/accesscontrol"
)

const (
	ScopeRoot   = "datasources"
	ScopePrefix = ScopeRoot + ":uid:"

	ActionRead             = "datasources:read"
	ActionQuery            = "datasources:query"
	ActionCreate           = "datasources:create"
	ActionWrite            = "datasources:write"
	ActionDelete           = "datasources:delete"
	ActionIDRead           = "datasources.id:read"
	ActionPermissionsRead  = "datasources.permissions:read"
	ActionPermissionsWrite = "datasources.permissions:write"
)

var (
	ScopeID       = accesscontrol.Scope("datasources", "id", accesscontrol.Parameter(":datasourceId"))
	ScopeAll      = accesscontrol.GetResourceAllScope(ScopeRoot)
	ScopeProvider = accesscontrol.NewScopeProvider(ScopeRoot)
)

var (
	// ConfigurationPageAccess is used to protect the "Configure > Data sources" tab access
	ConfigurationPageAccess = accesscontrol.EvalAny(
		accesscontrol.EvalPermission(ActionCreate),
		accesscontrol.EvalAll(
			accesscontrol.EvalPermission(ActionRead),
			accesscontrol.EvalAny(
				accesscontrol.EvalPermission(ActionDelete),
				accesscontrol.EvalPermission(ActionWrite),
			),
		),
	)

	// NewPageAccess is used to protect the "Configure > Data sources > New" page access
	NewPageAccess = accesscontrol.EvalAll(
		accesscontrol.EvalPermission(ActionRead),
		accesscontrol.EvalPermission(ActionCreate),
	)

	// EditPageAccess is used to protect the "Configure > Data sources > Edit" page access
	EditPageAccess = accesscontrol.EvalAll(
		accesscontrol.EvalPermission(ActionRead),
		accesscontrol.EvalPermission(ActionWrite),
	)
)

// writeProtectedResources lists plugin resource paths that return datasource
// configuration only the datasource's editors may read, keyed by plugin ID.
var writeProtectedResources = map[string][]string{
	// Returns the instance AWS external ID that IAM trust policies rely on.
	"cloudwatch": {"/external-id"},
}

// ResourceCallRequiresWrite reports whether a datasource resource call to the
// given plugin must be authorized with ActionWrite on that datasource rather
// than ActionQuery. resourcePath is the CallResourceRequest path.
func ResourceCallRequiresWrite(pluginID, resourcePath string) bool {
	protected, ok := writeProtectedResources[pluginID]
	if !ok {
		return false
	}

	// Mirror how the plugin SDK HTTP adapter rebuilds the request so that
	// encoded, host-prefixed, or unclean forms of a protected path still match.
	p := resourcePath
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u, err := url.Parse(p)
	if err != nil {
		return true
	}
	cleaned := path.Clean("/" + u.Path)
	for _, pp := range protected {
		if strings.EqualFold(cleaned, pp) {
			return true
		}
	}
	return false
}
