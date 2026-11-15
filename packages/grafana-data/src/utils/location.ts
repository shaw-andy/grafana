import { type Location } from 'history';

import { textUtil } from '../text/sanitize';
import { type ScopedVars } from '../types/ScopedVars';
import { type GrafanaConfig } from '../types/config';
import { type RawTimeRange } from '../types/time';

import { type UrlQueryMap, urlUtil } from './url';

interface MinimalGrafanaConfig {
  appSubUrl: string;
  disableSanitizeHtml?: boolean;
}

let grafanaConfig: MinimalGrafanaConfig = { appSubUrl: '' };
let getTimeRangeUrlParams: () => RawTimeRange;
let getVariablesUrlParams: (scopedVars?: ScopedVars) => UrlQueryMap;
let getCurrentOrgId: (() => number | undefined) | undefined;

const maybeParseUrl = (input: string): URL | undefined => {
  try {
    return new URL(input);
  } catch {
    return undefined;
  }
};

/**
 *
 * @param url
 * @internal
 */
const stripBaseFromUrl = (urlOrPath: string): string => {
  // Will only return a URL object if the input is actually a valid URL
  const parsedUrl = maybeParseUrl(urlOrPath);
  if (parsedUrl) {
    // If the input is a URL, and for a different origin that we're on, just bail
    // and return it. There's no need to strip anything from it
    if (parsedUrl.origin !== window.location.origin) {
      return urlOrPath;
    }
  }

  const appSubUrl = grafanaConfig.appSubUrl ?? '';
  const stripExtraChars = appSubUrl.endsWith('/') ? 1 : 0;
  const isAbsoluteUrl = urlOrPath.startsWith('http');

  let segmentToStrip = appSubUrl;

  if (!urlOrPath.startsWith('/') || isAbsoluteUrl) {
    segmentToStrip = `${window.location.origin}${appSubUrl}`;
  }

  // Check if the segment is either exactly the same as the url
  // or followed by a '/' so it does not replace incorrect similarly named segments
  // i.e. /grafana should not replace /grafanadashboards
  return urlOrPath.length > 0 && (urlOrPath.indexOf(segmentToStrip + '/') === 0 || urlOrPath === segmentToStrip)
    ? urlOrPath.slice(segmentToStrip.length - stripExtraChars)
    : urlOrPath;
};

/**
 *
 * @param url
 * @internal
 */
const assureBaseUrl = (url: string): string => {
  if (url.startsWith('/')) {
    return `${grafanaConfig.appSubUrl}${stripBaseFromUrl(url)}`;
  }
  return url;
};

/**
 *
 * @param location
 * @param searchParamsToUpdate
 * @returns
 */
const getUrlForPartial = (location: Location, searchParamsToUpdate: UrlQueryMap) => {
  const searchParams = urlUtil.parseKeyValue(
    location.search.startsWith('?') ? location.search.substring(1) : location.search
  );
  for (const key in searchParamsToUpdate) {
    // removing params with null | undefined
    if (searchParamsToUpdate[key] === null || searchParamsToUpdate[key] === undefined) {
      delete searchParams[key];
    } else {
      searchParams[key] = searchParamsToUpdate[key];
    }
  }
  return assureBaseUrl(urlUtil.renderUrl(location.pathname, searchParams));
};

/**
 * @deprecated use `getUrlForPartial` instead
 * Update URL or search param string `init` with new params `partial`.
 */
const updateSearchParams = (init: string, partial: string) => {
  const urlSearchParams = new URLSearchParams(partial);

  // Check if full URL
  try {
    const curURL = new URL(init);
    urlSearchParams.forEach((val, key) => curURL.searchParams.set(key, val));
    return curURL.href;
  } catch {
    // assume search params
    const newSearchParams = new URLSearchParams(init);
    urlSearchParams.forEach((v, k) => {
      newSearchParams.set(k, v);
    });
    return '?' + newSearchParams.toString();
  }
};

// One-click links navigate without showing the destination, so same-origin targets are limited to
// routes the backend only answers with the app shell. Anything else (logout, org switching, shortlink
// redirects, OAuth and invite endpoints, snapshot deletion) can act on the viewer's session.
const oneClickSameOriginPathRes = [
  /^\/(?:d|d-solo)\/[^/]+(?:\/[^/]+)?\/?$/,
  /^\/dashboards(?:\/.*)?$/,
  /^\/explore\/?$/,
];

// Query parameters that backend middleware acts on for any route.
const oneClickBlockedQueryParams = ['auth_token', 'forceLogin'];

const isSafeOneClickPath = (path: string): boolean => {
  if (!oneClickSameOriginPathRes.some((re) => re.test(path))) {
    return false;
  }

  for (const segment of path.split('/')) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      return false;
    }
    if (decoded === '.' || decoded === '..' || decoded.includes('/') || decoded.includes('\\')) {
      return false;
    }
  }

  return true;
};

const isSafeOneClickQuery = (params: URLSearchParams): boolean => {
  if (oneClickBlockedQueryParams.some((name) => params.has(name))) {
    return false;
  }

  // The org redirect middleware switches the active org whenever orgId differs from it.
  const orgIds = params.getAll('orgId');
  if (orgIds.length > 0) {
    const currentOrgId = getCurrentOrgId?.();
    if (currentOrgId == null || orgIds.some((orgId) => orgId !== String(currentOrgId))) {
      return false;
    }
  }

  return true;
};

/**
 * Resolves the href of a one-click data link to the absolute URL that may be opened without the
 * viewer first seeing it. Returns undefined when the link must not be followed on a single click.
 * Callers must open the returned URL rather than the original href.
 *
 * @internal
 */
const getOneClickUrl = (href: string | undefined): string | undefined => {
  if (!href) {
    return undefined;
  }

  let url: URL;
  try {
    url = new URL(href, document.baseURI);
  } catch {
    return undefined;
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return undefined;
  }

  if (url.origin !== window.location.origin) {
    return url.href;
  }

  const appSubUrl = (grafanaConfig.appSubUrl ?? '').replace(/\/+$/, '');
  let path = url.pathname;
  if (appSubUrl !== '') {
    if (path !== appSubUrl && !path.startsWith(`${appSubUrl}/`)) {
      return undefined;
    }
    path = path.slice(appSubUrl.length) || '/';
  }

  if (!isSafeOneClickPath(path) || !isSafeOneClickQuery(url.searchParams)) {
    return undefined;
  }

  return url.href;
};

interface LocationUtilDependencies {
  config: GrafanaConfig;
  getTimeRangeForUrl: () => RawTimeRange;
  getVariablesUrlParams: (scopedVars?: ScopedVars) => UrlQueryMap;
  getCurrentOrgId?: () => number | undefined;
}

export const locationUtil = {
  /**
   *
   * @param getConfig
   * @param getAllVariableValuesForUrl
   * @param getTimeRangeForUrl
   * @internal
   */
  initialize: (dependencies: LocationUtilDependencies) => {
    grafanaConfig = dependencies.config;
    getTimeRangeUrlParams = dependencies.getTimeRangeForUrl;
    getVariablesUrlParams = dependencies.getVariablesUrlParams;
    getCurrentOrgId = dependencies.getCurrentOrgId;
  },
  stripBaseFromUrl,
  getOneClickUrl,
  assureBaseUrl,
  updateSearchParams,
  getTimeRangeUrlParams: () => {
    if (!getTimeRangeUrlParams) {
      return null;
    }
    return urlUtil.toUrlParams(getTimeRangeUrlParams());
  },
  getVariablesUrlParams: (scopedVars?: ScopedVars) => {
    if (!getVariablesUrlParams) {
      return null;
    }
    const params = getVariablesUrlParams(scopedVars);
    return urlUtil.toUrlParams(params);
  },
  getUrlForPartial,
  processUrl: (url: string) => {
    return grafanaConfig.disableSanitizeHtml ? url : textUtil.sanitizeUrl(url);
  },
  /**
   * Process a redirect URI by merging its query parameters with current location's query parameters.
   * Current query params are preserved, but redirect URI params take precedence.
   *
   * @param redirectUri - The redirect URI from the backend (may contain query params)
   * @param currentLocation - Current location object to preserve query params
   * @returns Final URL with merged query parameters
   * @internal
   */
  processRedirectUri: (redirectUri: string, currentLocation: Location): string => {
    try {
      const redirectUrl = new URL(redirectUri, window.location.origin);
      const redirectParams = new Set(redirectUrl.searchParams.keys());

      const currentParams = new URLSearchParams(currentLocation.search);
      currentParams.forEach((value, key) => {
        if (!redirectParams.has(key)) {
          redirectUrl.searchParams.append(key, value);
        }
      });

      // For relative paths, use pathname+search rather than href. new URL(relativePath, origin)
      // produces an absolute URL without the appSubUrl prefix, which stripBaseFromUrl cannot strip,
      // causing the router to treat the full URL string as a literal path.
      const isAbsoluteUri = redirectUri.startsWith('http');
      return stripBaseFromUrl(isAbsoluteUri ? redirectUrl.href : redirectUrl.pathname + redirectUrl.search);
    } catch {
      return stripBaseFromUrl(redirectUri);
    }
  },
};
