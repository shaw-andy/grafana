package accesscontrol

// AccessResources contains resources that are used to filter annotations based on RBAC.
type AccessResources struct {
	// Dashboards is a map of dashboard UIDs to IDs
	Dashboards map[string]int64
	// HasMoreDashboards is true when the dashboard search page was full, so the next page may hold
	// more dashboards. Dashboards can be smaller than the page because it only keeps dashboards
	// whose annotations the user can read.
	HasMoreDashboards bool
	// CanAccessOrgAnnotations true if the user is allowed to access organization annotations
	CanAccessOrgAnnotations bool
	// Skip filtering
	SkipAccessControlFilter bool
}
