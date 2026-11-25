import { config } from '@grafana/runtime';

const int64Min = BigInt('-9223372036854775808');
const int64Max = BigInt('9223372036854775807');

/**
 * Whether a browser would request this Grafana origin on a path that
 * pkg/web routes to GET /logout or GET /profile/switch-org/:id.
 *
 * The path is normalized the way the server matches it: the configured
 * subpath is stripped (pkg/web/macaron.go ServeHTTP), slashes are trimmed,
 * and each segment is decoded once (pkg/web/tree.go Match). An organization
 * id counts only when strconv.ParseInt would accept it.
 */
export function hrefTargetsSessionAction(href: string, base: string = window.location.href): boolean {
  let url: URL;
  try {
    url = new URL(href, base);
  } catch {
    return false;
  }

  if (url.origin !== window.location.origin) {
    return false;
  }

  let path = url.pathname;
  const subUrl = (config.appSubUrl || '').replace(/\/$/, '');
  if (subUrl && (path === subUrl || path.startsWith(`${subUrl}/`))) {
    path = path.slice(subUrl.length) || '/';
  }

  path = path.replace(/^\/+/, '').replace(/\/+$/, '');
  const rawSegments = path === '' ? [] : path.split('/');
  const segments: string[] = [];
  for (const segment of rawSegments) {
    try {
      segments.push(decodeURIComponent(segment));
    } catch {
      return false;
    }
  }

  if (segments.length === 1 && segments[0] === 'logout') {
    return true;
  }

  if (
    segments.length === 3 &&
    segments[0] === 'profile' &&
    segments[1] === 'switch-org' &&
    isParseableOrgID(segments[2])
  ) {
    return true;
  }

  return false;
}

function isParseableOrgID(value: string): boolean {
  if (!/^[+-]?\d+$/.test(value)) {
    return false;
  }
  const parsed = BigInt(value);
  return parsed >= int64Min && parsed <= int64Max;
}

export function sessionActionHrefs(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll('a[href]'))
    .map((anchor) => anchor.getAttribute('href') ?? '')
    .filter((href) => hrefTargetsSessionAction(href));
}
