const APP_ORIGIN = 'http://grafana.local';

/**
 * Why this image address is not a safe catalog thumbnail, or null when it is.
 * Resolution matches Chrome's WHATWG URL parser, which is what turns
 * `/api/gnet/../../../logout` into a request for `/logout`.
 * Omitting the image is safe.
 */
export function catalogThumbnailViolation(src: string | null | undefined): string | null {
  if (!src) {
    return null;
  }

  const url = new URL(src, APP_ORIGIN);
  if (url.origin !== APP_ORIGIN) {
    return `left the app origin: ${url.href}`;
  }
  if (url.pathname === '/logout') {
    return `resolves to /logout from ${src}`;
  }
  if (!url.pathname.startsWith('/api/gnet/')) {
    return `leaves the gnet proxy: ${url.pathname}`;
  }

  const segments = url.pathname
    .split('/')
    .slice(1)
    .map((segment) => {
      try {
        return decodeURIComponent(segment);
      } catch {
        return segment;
      }
    });
  if (segments.includes('..') || segments.includes('.') || segments.includes('')) {
    return `dot or empty segment in ${url.pathname}`;
  }
  return null;
}
