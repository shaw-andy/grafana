package accesscontrol

// AccessResources contains resources that are used to filter annotations based on RBAC.
type AccessResources struct {
	// Dashboards is a map of dashboard UIDs to IDs
	Dashboards map[string]int64
	// CanAccessOrgAnnotations true if the user is allowed to access organization annotations
	CanAccessOrgAnnotations bool
	// Skip filtering
	SkipAccessControlFilter bool
	// HasMoreDashboards is true if the dashboard search page was full, so later pages may hold more dashboards.
	// Dashboards can be smaller than the search page because it only keeps dashboards whose annotations the user can read.
	HasMoreDashboards bool
}
