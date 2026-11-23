import { PathValidationError } from '@grafana/data';

// The backend only accepts access tokens that parse as a UUID, so any other character means the token
// did not come from Grafana and could otherwise change the path or query string of the request.
const ACCESS_TOKEN_PATTERN = /^[0-9A-Za-z{}:-]+$/;

/**
 * Builds the API path for a public dashboard access token, rejecting tokens that are not UUID-shaped.
 * Pass `validatePath: true` to the request using the returned path.
 */
export function getPublicDashboardApiPath(accessToken: string | undefined, subPath = ''): string {
  if (!accessToken || !ACCESS_TOKEN_PATTERN.test(accessToken)) {
    throw new PathValidationError('Invalid public dashboard access token');
  }

  return `/api/public/dashboards/${encodeURIComponent(accessToken)}${subPath}`;
}
