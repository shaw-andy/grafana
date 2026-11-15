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
 * Parses a URL taken from an alert of an external Alertmanager, such as its generator URL or an annotation value.
 * Anyone who can post alerts to that Alertmanager controls these URLs, so only absolute http(s) URLs outside of
 * Grafana are returned: a link back into Grafana would run a request with the viewer's session.
 */
export function parseExternalAlertmanagerUrl(raw: string): URL | undefined {
  const url = tryParseUrl(raw);
  if (!url || (url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password) {
    return undefined;
  }

  const grafanaOrigins = [window.location.origin, tryParseUrl(config.appUrl)?.origin];
  return grafanaOrigins.includes(url.origin) ? undefined : url;
}

function tryParseUrl(raw: string): URL | undefined {
  try {
    return new URL(raw);
  } catch {
    return undefined;
  }
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
