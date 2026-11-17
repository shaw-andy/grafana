import { locationUtil } from '@grafana/data';
import { locationService } from '@grafana/runtime';

import { contextSrv, RedirectToUrlKey } from '../services/context_srv';

import { isShortUrlPath } from './shortUrlPath';

const redirectToParamKey = 'redirectTo';

export function handleRedirectTo(): void {
  const queryParams = locationService.getSearch();

  if (queryParams.has('auth_token')) {
    // URL Login should not be redirected
    window.sessionStorage.removeItem(RedirectToUrlKey);
    return;
  }

  if (queryParams.has(redirectToParamKey) && window.location.pathname !== '/') {
    const rawRedirectTo = queryParams.get(redirectToParamKey)!;
    window.sessionStorage.setItem(RedirectToUrlKey, encodeURIComponent(rawRedirectTo));
    queryParams.delete(redirectToParamKey);
    window.history.replaceState({}, '', `${window.location.pathname}${queryParams.size > 0 ? `?${queryParams}` : ''}`);
    return;
  }

  if (!contextSrv.user.isSignedIn) {
    return;
  }

  const redirectTo = window.sessionStorage.getItem(RedirectToUrlKey);
  if (!redirectTo) {
    return;
  }

  window.sessionStorage.removeItem(RedirectToUrlKey);
  let decodedRedirectTo: string;
  try {
    decodedRedirectTo = decodeURIComponent(redirectTo);
  } catch {
    return;
  }

  const appRelativeRedirectTo = locationUtil.stripBaseFromUrl(decodedRedirectTo);
  if (appRelativeRedirectTo.startsWith('/goto/')) {
    // In this case there should be a request to the backend
    if (isShortUrlPath(appRelativeRedirectTo.split(/[?#]/, 1)[0])) {
      window.location.replace(locationUtil.assureBaseUrl(appRelativeRedirectTo));
    }
    return;
  }

  const appBase = locationUtil.assureBaseUrl('/');
  let redirectUrl: URL | undefined;

  try {
    redirectUrl = new URL(locationUtil.assureBaseUrl(decodedRedirectTo), `${window.location.origin}${appBase}`);
  } catch {}

  // Only allow same-origin redirects to avoid an open redirect via the redirectTo query param.
  // Note that the base is only used in `new URL()` if the first param isn't an absolute URL.
  if (redirectUrl?.origin === window.location.origin) {
    // Navigate to the URL as the browser resolves it, so the checked path is the path that is requested.
    const resolvedRedirectTo = `${redirectUrl.pathname}${redirectUrl.search}${redirectUrl.hash}`;

    if (!isFrontendAppPath(redirectUrl.pathname, appBase)) {
      return;
    }

    const redirectOrgId = redirectUrl.searchParams.get('orgId');

    if (redirectOrgId) {
      const targetOrgId = Number(redirectOrgId);

      if (Number.isFinite(targetOrgId) && targetOrgId !== contextSrv.user.orgId) {
        window.location.replace(resolvedRedirectTo);
        return;
      }
    }

    locationService.replace(locationUtil.stripBaseFromUrl(resolvedRedirectTo));
    return;
  }

  // Ensure that the appSubUrl is stripped from the redirect to in case of a frontend redirect
  const stripped = locationUtil.stripBaseFromUrl(decodedRedirectTo);
  locationService.replace(stripped);
}

// GET routes served by the backend instead of the frontend app. Several of them change the session or the
// active org, so a redirect must never send the browser there with the viewer's session cookie.
const backendRoutesRe =
  /^\/(?:logout|login|profile\/switch-org|user\/auth-tokens|user\/email|api|avatar|render|public|bootdata|goto)(?:\/|$)/i;

// `pathname` must come from a parsed URL so dot segments and backslashes are already resolved the way the
// browser resolves them. The backend decodes the path once more before routing, so check the decoded form.
function isFrontendAppPath(pathname: string, appBase: string): boolean {
  let decodedPath: string;
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch {
    return false;
  }

  if (/\\|\/\/|\/\.\.?(?:\/|$)|%(?:2e|2f|5c)/i.test(decodedPath)) {
    return false;
  }

  const appRoot = appBase.slice(0, -1);
  if (decodedPath !== appRoot && !decodedPath.startsWith(appBase)) {
    return false;
  }

  return !backendRoutesRe.test(`/${decodedPath.slice(appBase.length)}`);
}
