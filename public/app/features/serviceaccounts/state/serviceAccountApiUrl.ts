const BASE_URL = '/api/serviceaccounts';

/**
 * Builds the API path for a single service account. The uid can come from the page address, so it is
 * encoded as one path segment; "." and ".." are left as-is by encodeURIComponent and would still be
 * resolved as dot segments by the browser, so they are rejected.
 */
export function serviceAccountApiUrl(uid: string, subPath?: string): string {
  if (uid === '.' || uid === '..') {
    throw new Error('Invalid service account id');
  }
  const url = `${BASE_URL}/${encodeURIComponent(uid)}`;
  return subPath ? `${url}/${subPath}` : url;
}
