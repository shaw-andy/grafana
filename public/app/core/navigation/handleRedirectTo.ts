import { locationUtil } from '@grafana/data';
import { locationService } from '@grafana/runtime';

import { contextSrv, RedirectToUrlKey } from '../services/context_srv';

const redirectToParamKey = 'redirectTo';

// GET routes that change state. The stored redirect is followed right after
// login, so landing on one of these would act on the user's behalf.
const actionPaths = ['/logout', '/profile/switch-org'];

function isActionPath(url: URL): boolean {
  let pathname: string;
  try {
    // The backend routes on the decoded path, so "/%6cogout" reaches /logout.
    pathname = decodeURIComponent(url.pathname);
  } catch {
    return true;
  }

  const segments: string[] = [];
  for (const segment of pathname.split('/')) {
    if (segment === '..') {
      segments.pop();
    } else if (segment !== '' && segment !== '.') {
      segments.push(segment);
    }
  }

  const path = locationUtil.stripBaseFromUrl(`/${segments.join('/')}`).toLowerCase();
  return actionPaths.some((action) => path === action || path.startsWith(`${action}/`));
}

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
  const decodedRedirectTo = decodeURIComponent(redirectTo);

  let redirectUrl: URL | undefined;

  try {
    redirectUrl = new URL(decodedRedirectTo, window.location.origin);
  } catch {}

  if (redirectUrl && isActionPath(redirectUrl)) {
    return;
  }

  if (decodedRedirectTo.startsWith('/goto/')) {
    // In this case there should be a request to the backend
    const urlToRedirectTo = locationUtil.assureBaseUrl(decodedRedirectTo);
    window.location.replace(urlToRedirectTo);
    return;
  }

  // Only allow same-origin redirects to avoid an open redirect via the redirectTo query param.
  // Note that `window.location.origin` is only used in `new URL()` if the first param isn't
  // an absolute URL.
  if (redirectUrl?.origin === window.location.origin) {
    const redirectOrgId = redirectUrl.searchParams.get('orgId');

    if (redirectOrgId) {
      const targetOrgId = Number(redirectOrgId);

      if (Number.isFinite(targetOrgId) && targetOrgId !== contextSrv.user.orgId) {
        const urlToRedirectTo = locationUtil.assureBaseUrl(decodedRedirectTo);
        window.location.replace(urlToRedirectTo);
        return;
      }
    }
  }

  // Ensure that the appSubUrl is stripped from the redirect to in case of a frontend redirect
  const stripped = locationUtil.stripBaseFromUrl(decodedRedirectTo);
  locationService.replace(stripped);
}
