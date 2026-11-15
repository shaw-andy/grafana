const GNET_PROXY_PREFIX = '/api/gnet';
const URL_SCHEME = /^[a-z][a-z\d+.-]*:/i;
// Browsers drop tabs and newlines anywhere in a URL and treat backslashes as path separators,
// so any of these could turn an innocent-looking segment into a dot segment after parsing.
const UNSAFE_CHARACTERS = /[\\\u0000-\u001f\u007f]/;

/**
 * Builds a same-origin address on the Grafana.com proxy for a Grafana.com API path, such as a
 * screenshot href returned by the catalog. The browser resolves dot segments (including
 * percent-encoded ones) before sending the request, so a path that is not strictly confined to
 * the proxy could reach any Grafana endpoint with the user's session.
 *
 * Returns an empty string when the path has a scheme, an empty segment (`//`), a `..` segment,
 * an encoded slash, a backslash or a control character. Each segment is re-encoded and the
 * fragment is dropped.
 */
export function getGnetProxyUrl(gcomPath: string | null | undefined): string {
  if (typeof gcomPath !== 'string' || gcomPath === '') {
    return '';
  }

  if (URL_SCHEME.test(gcomPath) || UNSAFE_CHARACTERS.test(gcomPath)) {
    return '';
  }

  const hashIndex = gcomPath.indexOf('#');
  const withoutHash = hashIndex === -1 ? gcomPath : gcomPath.slice(0, hashIndex);
  const queryIndex = withoutHash.indexOf('?');
  const path = queryIndex === -1 ? withoutHash : withoutHash.slice(0, queryIndex);
  const query = queryIndex === -1 ? '' : withoutHash.slice(queryIndex + 1);

  const rawSegments = (path.startsWith('/') ? path.slice(1) : path).split('/');
  const segments: string[] = [];
  for (const rawSegment of rawSegments) {
    let segment: string;
    try {
      segment = decodeURIComponent(rawSegment);
    } catch {
      return '';
    }

    if (segment === '.') {
      continue;
    }
    if (segment === '' || segment === '..' || segment.includes('/') || UNSAFE_CHARACTERS.test(segment)) {
      return '';
    }
    segments.push(encodeURIComponent(segment));
  }

  if (segments.length === 0) {
    return '';
  }

  const search = query ? new URLSearchParams(query).toString() : '';
  return `${GNET_PROXY_PREFIX}/${segments.join('/')}${search ? `?${search}` : ''}`;
}
