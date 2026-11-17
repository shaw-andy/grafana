const shortUrlPathRe = /^\/goto\/[A-Za-z0-9_-]+$/;

// The backend resolves short URLs at /goto/:uid. Any other path under /goto/ (extra segments, dot segments,
// encoded or backslash separators) can be resolved by the browser to a different backend route, so only a
// single short URL key may be sent to the backend with a full page load.
export function isShortUrlPath(path: string): boolean {
  return shortUrlPathRe.test(path);
}
