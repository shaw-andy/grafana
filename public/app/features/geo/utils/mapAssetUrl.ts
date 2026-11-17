import { config } from '@grafana/runtime';

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:', 'data:']);

// Encoded dots, slashes and backslashes survive browser normalization and can be decoded into
// a path outside the static directory by the server.
const ENCODED_PATH_SEPARATOR = /%(2e|2f|5c)/i;

function normalizeHostname(hostname: string): string {
  return hostname.toLowerCase().replace(/\.+$/, '');
}

function getGrafanaHostnames(): Set<string> {
  const hostnames = new Set([normalizeHostname(window.location.hostname)]);
  try {
    if (config.appUrl) {
      hostnames.add(normalizeHostname(new URL(config.appUrl).hostname));
    }
  } catch {
    // An unparsable appUrl adds no hostname.
  }
  return hostnames;
}

function getStaticPathPrefix(): string {
  return `${(config.appSubUrl ?? '').replace(/\/+$/, '')}/public/`;
}

/**
 * Resolves an address that the map will request from saved panel options or query data.
 *
 * Cookies are scoped by hostname regardless of scheme or port, so any request to the Grafana
 * hostname carries the viewer's session. Those requests are only allowed for static assets.
 * Callers must request the returned URL rather than the original value so the checked address
 * is the one loaded.
 */
export function getMapAssetUrl(value: unknown): string | undefined {
  if (typeof value !== 'string' || !value.trim()) {
    return undefined;
  }

  let url: URL;
  try {
    url = new URL(value.trim(), document.baseURI);
  } catch {
    return undefined;
  }

  if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
    return undefined;
  }

  if (url.protocol === 'data:') {
    return url.href;
  }

  if (getGrafanaHostnames().has(normalizeHostname(url.hostname))) {
    if (!url.pathname.startsWith(getStaticPathPrefix()) || ENCODED_PATH_SEPARATOR.test(url.pathname)) {
      return undefined;
    }
  }

  return url.href;
}
