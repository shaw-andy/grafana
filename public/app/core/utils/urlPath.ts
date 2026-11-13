/**
 * Browsers resolve dot segments (including percent-encoded ones) and treat backslashes as separators before they
 * send a request. A value from an external source that is copied into a same-origin URL can therefore address any
 * route of this Grafana server unless every segment is encoded and checked.
 */

/**
 * Encodes a value as a single URL path segment. Returns undefined when the value would still be read as an
 * empty or dot segment.
 */
export function encodeUrlPathSegment(value: string | undefined): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }

  let encoded: string;
  try {
    encoded = encodeURIComponent(value);
  } catch {
    return undefined;
  }

  if (encoded === '' || encoded === '.' || encoded === '..') {
    return undefined;
  }
  return encoded;
}

/**
 * Encodes a relative `/`-separated path so that it stays below the prefix it is appended to. Returns undefined for
 * absolute URLs, backslashes, malformed escapes, and empty or dot segments, whether literal or percent-encoded.
 */
export function encodeRelativeUrlPath(path: string | undefined): string | undefined {
  if (typeof path !== 'string' || path.includes('\\') || /^[a-z][a-z\d+.-]*:/i.test(path)) {
    return undefined;
  }

  const encodedSegments: string[] = [];
  for (const segment of path.split('/')) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      return undefined;
    }

    if (decoded.includes('\\')) {
      return undefined;
    }

    const encoded = encodeUrlPathSegment(decoded);
    if (!encoded) {
      return undefined;
    }
    encodedSegments.push(encoded);
  }

  return encodedSegments.join('/');
}
