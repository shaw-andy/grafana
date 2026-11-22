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
 * Returns the canonical form of `value` when it is an absolute http(s) URL on a host other than this
 * Grafana server, and undefined otherwise. Use the returned value, not `value`, as the link href.
 *
 * Links built from user-provided values must not point back at Grafana: following one sends the
 * viewer's session cookie with a GET request. Hosts are compared without scheme or port because
 * cookies are scoped to the host only.
 */
export function getExternalLinkUrl(value: string): string | undefined {
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    return undefined;
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return undefined;
  }

  const host = normalizeHost(url.hostname);
  if (!host || getOwnHosts().includes(host)) {
    return undefined;
  }

  return url.href;
}

function getOwnHosts(): string[] {
  const hosts = [window.location.hostname];
  try {
    hosts.push(new URL(config.appUrl).hostname);
  } catch {
    // appUrl is not an absolute URL, so only the page's own host is known
  }
  return hosts.map(normalizeHost).filter(Boolean);
}

function normalizeHost(hostname: string): string {
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
