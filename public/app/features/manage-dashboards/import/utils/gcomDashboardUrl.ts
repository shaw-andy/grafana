const GCOM_DASHBOARD_ID = /^\d+$/;

function isGcomDashboardId(id: unknown): id is string | number {
  return (typeof id === 'string' || typeof id === 'number') && GCOM_DASHBOARD_ID.test(String(id));
}

// The id often comes from the page URL and the request carries the session cookie,
// so anything but a plain numeric id could retarget it at another Grafana endpoint.
export function getGcomDashboardUrl(id: unknown): string {
  if (!isGcomDashboardId(id)) {
    throw new Error('Invalid Grafana.com dashboard ID');
  }
  return `/api/gnet/dashboards/${encodeURIComponent(String(id))}`;
}
