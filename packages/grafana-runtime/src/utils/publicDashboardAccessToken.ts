import { validatePath } from '@grafana/data';

// The token comes from the page URL and is interpolated into same-origin request paths,
// so dots, slashes, backslashes, `?`, `#` and `%` must never be accepted.
const ACCESS_TOKEN_PATTERN = /^[A-Za-z0-9_-]+$/;

export function isValidPublicDashboardAccessToken(token: unknown): token is string {
  return typeof token === 'string' && ACCESS_TOKEN_PATTERN.test(token);
}

/**
 * Builds a `/api/public/dashboards/{accessToken}{subPath}` URL.
 * Throws if the access token is not a valid public dashboard access token.
 */
export function getPublicDashboardApiUrl(accessToken: string | undefined, subPath = ''): string {
  if (!isValidPublicDashboardAccessToken(accessToken)) {
    throw new Error('Invalid public dashboard access token');
  }

  return validatePath(`/api/public/dashboards/${encodeURIComponent(accessToken)}${subPath}`);
}
