import { locationService } from '@grafana/runtime';

const urlTokenParam = 'auth_token';

let cachedToken = '';

/**
 * Returns the JWT URL login token. The token is read from the address once and then removed from it,
 * so it does not stay visible, end up in the browser history, or get copied into shared links.
 */
export const loadUrlToken = (): string | null => {
  const token = new URLSearchParams(window.location.search).get(urlTokenParam);
  if (token !== null && token !== '') {
    cachedToken = token;
  }

  removeUrlTokenFromAddress();

  return cachedToken;
};

function removeUrlTokenFromAddress() {
  const params = new URLSearchParams(window.location.search);
  if (params.has(urlTokenParam)) {
    params.delete(urlTokenParam);
    const search = params.toString();
    window.history.replaceState(
      window.history.state,
      '',
      `${window.location.pathname}${search ? `?${search}` : ''}${window.location.hash}`
    );
  }

  // The location service caches the location it was created with, so it would put the token back
  // into the address on the next partial update unless it is cleaned as well.
  const location = locationService.getLocation();
  const appParams = new URLSearchParams(location.search);
  if (appParams.has(urlTokenParam)) {
    appParams.delete(urlTokenParam);
    const search = appParams.toString();
    locationService.replace({
      pathname: location.pathname,
      search: search ? `?${search}` : '',
      hash: location.hash,
      state: location.state,
    });
  }
}
