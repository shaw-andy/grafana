import { config } from '@grafana/runtime';

export type RelativeUrl = `/${string}`;

export function isRelativeUrl(url: string): url is RelativeUrl {
  return url.startsWith('/') && !url.startsWith('//');
}

interface CreateRelativeUrlOptions {
  /**
   * If true, the sub path will not be added to the URL
   * If the URL will be used by react-router or history (e.g. locationService.push), you should set this to true because react-router adds the sub path by itself
   */
  skipSubPath?: boolean;
}

export function createRelativeUrl(
  path: RelativeUrl,
  queryParams?: string[][] | Record<string, string> | string | URLSearchParams,
  options: CreateRelativeUrlOptions = { skipSubPath: false }
) {
  const searchParams = new URLSearchParams(queryParams);
  const searchParamsString = searchParams.toString();

  const subPath = options.skipSubPath ? '' : config.appSubUrl;
  return `${subPath}${path}${searchParamsString ? `?${searchParamsString}` : ''}`;
}

/**
 * Returns the URL a browser would navigate to for a user-authored link (such as an annotation value),
 * or undefined unless it is an http(s) URL on a host other than this Grafana server.
 *
 * Every request to this server's host carries the viewer's session cookie (cookies ignore port and scheme),
 * and several GET routes change session state: /logout, /profile/switch-org/:id and any page with ?orgId=.
 * A link authored by one user and rendered for another must therefore never point back at this host.
 * Callers must render the returned href, not the original value, so the link is the URL that was checked.
 */
export function getExternalLinkHref(value: string): string | undefined {
  const url = parseUrl(value, window.location.href);
  if (!url || (url.protocol !== 'http:' && url.protocol !== 'https:')) {
    return undefined;
  }

  const grafanaHostnames = [window.location.hostname, parseUrl(config.appUrl)?.hostname].filter(
    (hostname): hostname is string => Boolean(hostname)
  );
  const hostname = normalizeHostname(url.hostname);
  if (grafanaHostnames.some((grafanaHostname) => normalizeHostname(grafanaHostname) === hostname)) {
    return undefined;
  }

  return url.href;
}

function parseUrl(value: string, base?: string): URL | undefined {
  try {
    return new URL(value, base);
  } catch {
    return undefined;
  }
}

function normalizeHostname(hostname: string): string {
  return hostname.toLowerCase().replace(/\.+$/, '');
}

export function createAbsoluteUrl(
  path: RelativeUrl,
  queryParams?: string[][] | Record<string, string> | string | URLSearchParams
) {
  const searchParams = new URLSearchParams(queryParams);
  const searchParamsString = searchParams.toString();

  try {
    const baseUrl = new URL(config.appSubUrl + path, config.appUrl);
    return `${baseUrl.href}${searchParamsString ? `?${searchParamsString}` : ''}`;
  } catch (err) {
    return createRelativeUrl(path, queryParams);
  }
}
