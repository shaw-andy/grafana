import { config } from '@grafana/runtime';

// Encoded dots and slashes, or an empty segment, can be normalised by the server into a
// path outside the public folder.
const UNSAFE_PATH = /\/\/|%2e|%2f|%5c/i;

function parseUrl(raw: string): URL | undefined {
  try {
    return new URL(raw, document.baseURI);
  } catch {
    return undefined;
  }
}

function hostWithoutTrailingDot(hostname: string): string {
  return hostname.endsWith('.') ? hostname.slice(0, -1) : hostname;
}

function isInFolder(url: URL, folderPath: string | undefined): boolean {
  const folder = folderPath ? parseUrl(folderPath) : undefined;
  if (!folder || folder.protocol !== url.protocol || folder.host !== url.host) {
    return false;
  }
  const prefix = folder.pathname.endsWith('/') ? folder.pathname : `${folder.pathname}/`;
  return url.pathname.startsWith(prefix);
}

/**
 * Geomap loads addresses from saved panel options as images, fetch and XHR requests. On the
 * Grafana host those requests carry the viewer's session cookie, so they are only allowed
 * for static files in the public folder. Any other http(s) host is allowed.
 */
export function isAllowedResourceUrl(raw: string | undefined): boolean {
  const url = raw ? parseUrl(raw) : undefined;
  if (!url || (url.protocol !== 'https:' && url.protocol !== 'http:')) {
    return false;
  }

  // Cookies are scoped to the host name, not the origin, so another scheme or port on the
  // same host still sends the session.
  if (hostWithoutTrailingDot(url.hostname) !== hostWithoutTrailingDot(window.location.hostname)) {
    return true;
  }

  if (UNSAFE_PATH.test(url.pathname)) {
    return false;
  }

  return isInFolder(url, window.__grafana_public_path__) || isInFolder(url, `${config.appSubUrl ?? ''}/public/`);
}
