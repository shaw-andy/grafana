const URL_TOKEN_PARAM = 'auth_token';

let cachedToken = '';

export const loadUrlToken = (): string | null => {
  const params = new URLSearchParams(window.location.search);

  const token = params.get(URL_TOKEN_PARAM);
  if (token !== null && token !== '') {
    cachedToken = token;
    return token;
  }

  return cachedToken;
};

/**
 * The URL login token authenticates whoever opens the URL as the current user, so it must be
 * removed from any URL that is shown, copied, shortened or otherwise handed to someone else.
 * Accepts a full URL, a path with a query string, or a bare search string, and leaves every other
 * query parameter exactly as it was encoded.
 */
export function removeUrlToken(url: string): string {
  const hashStart = url.indexOf('#');
  const beforeHash = hashStart === -1 ? url : url.slice(0, hashStart);
  const hash = hashStart === -1 ? '' : url.slice(hashStart);

  const queryStart = beforeHash.indexOf('?');
  if (queryStart === -1) {
    return url;
  }

  const query = beforeHash
    .slice(queryStart + 1)
    .split('&')
    .filter((part) => !isUrlTokenParam(part))
    .join('&');

  return beforeHash.slice(0, queryStart) + (query ? `?${query}` : '') + hash;
}

// Keys are compared decoded because the backend decodes them before looking up the token.
function isUrlTokenParam(part: string): boolean {
  const key = part.split('=', 1)[0].replace(/\+/g, ' ');
  try {
    return decodeURIComponent(key) === URL_TOKEN_PARAM;
  } catch {
    return key === URL_TOKEN_PARAM;
  }
}
