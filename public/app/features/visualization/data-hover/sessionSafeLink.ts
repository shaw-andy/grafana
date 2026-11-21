import { type LinkModel } from '@grafana/data';
import { config } from '@grafana/runtime';

// GET routes on this server that act on the viewer's session: signing out, signing in, switching the
// active organization, rotating the session token, confirming an email change, or redirecting to a
// stored target (short URLs) that cannot be inspected here.
const SESSION_ACTION_SEGMENTS = new Set(['logout', 'login', 'switch-org', 'auth-tokens', 'goto']);
const SESSION_ACTION_PATHS = ['/email/update'];

const ORG_ID_PARAM = 'orgid';

function isThisServer(url: URL): boolean {
  // Cookies are scoped to the host regardless of scheme or port, so compare hostnames rather than origins.
  const hosts = new Set([window.location.hostname.toLowerCase()]);
  if (config.appUrl) {
    try {
      hosts.add(new URL(config.appUrl).hostname.toLowerCase());
    } catch {}
  }
  return hosts.has(url.hostname.toLowerCase());
}

function isSessionActionPath(pathname: string): boolean {
  let decoded: string;
  try {
    // The backend router matches on the percent-decoded path.
    decoded = decodeURIComponent(pathname).toLowerCase();
  } catch {
    return true;
  }

  const segments = decoded.split('/').filter((segment) => segment !== '' && segment !== '.');
  if (segments.some((segment) => segment === '..' || SESSION_ACTION_SEGMENTS.has(segment))) {
    return true;
  }

  const normalized = `/${segments.join('/')}`;
  return SESSION_ACTION_PATHS.some((path) => normalized.includes(path));
}

/**
 * Removes the orgId query parameter when it names the active organization. Returns false when any orgId
 * value names another organization, because the backend switches the viewer's active organization on load.
 * The parameter is removed rather than kept so the request cannot switch organizations even if the
 * active organization changed after this page loaded.
 */
function stripActiveOrgId(url: URL): boolean {
  const activeOrgId = config.bootData?.user?.orgId;
  const keys = Array.from(new Set(url.searchParams.keys())).filter((key) => key.toLowerCase() === ORG_ID_PARAM);

  for (const key of keys) {
    const allActive = url.searchParams
      .getAll(key)
      .every((value) => /^\d+$/.test(value) && activeOrgId != null && Number(value) === activeOrgId);
    if (!allActive) {
      return false;
    }
    url.searchParams.delete(key);
  }

  return true;
}

function isRootRelative(href: string): boolean {
  return href.startsWith('/') && !href.startsWith('//') && !href.startsWith('/\\');
}

/**
 * Returns a link that is safe to follow from a tooltip, or undefined when following it would act on the
 * viewer's session on this server. Same-server links that only carry the active organization are returned
 * without the orgId parameter.
 */
export function getSessionSafeLink<T>(link: LinkModel<T>): LinkModel<T> | undefined {
  let url: URL;
  try {
    url = new URL(link.href, window.location.href);
  } catch {
    return undefined;
  }

  if ((url.protocol !== 'http:' && url.protocol !== 'https:') || !isThisServer(url)) {
    return link;
  }

  if (isSessionActionPath(url.pathname)) {
    return undefined;
  }

  const search = url.search;
  if (!stripActiveOrgId(url)) {
    return undefined;
  }

  if (url.search === search) {
    return link;
  }

  const href = isRootRelative(link.href) ? `${url.pathname}${url.search}${url.hash}` : url.toString();
  return { ...link, href };
}
