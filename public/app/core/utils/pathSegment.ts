// Grafana UIDs, numeric ids and Kubernetes-style names. Dots are only allowed between other
// characters so that "." and ".." can never reach the browser as dot-segments.
const SAFE_ID_PATH_SEGMENT = /^[A-Za-z0-9_~-]+(\.[A-Za-z0-9_~-]+)*$/;

/**
 * Returns true when an id taken from the URL (for example a route parameter) can be
 * interpolated into a backend request path as exactly one path segment.
 */
export function isSafeIdPathSegment(id: string | undefined | null): id is string {
  return typeof id === 'string' && SAFE_ID_PATH_SEGMENT.test(id);
}
