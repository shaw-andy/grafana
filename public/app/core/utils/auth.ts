import { config } from '@grafana/runtime';

/**
 * The server only ends the session on POST. A top-level form submission, unlike
 * fetch, lets the server redirect the browser to an identity provider's logout page.
 */
export function signOut() {
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = `${config.appSubUrl}/logout`;
  form.style.display = 'none';
  document.body.appendChild(form);
  form.submit();
}

export function getSessionExpiry() {
  const expiryCookie = document.cookie.split('; ').find((row) => row.startsWith('grafana_session_expiry='));
  if (!expiryCookie) {
    return 0;
  }

  let expiresStr = expiryCookie.split('=').at(1);
  if (!expiresStr) {
    return 0;
  }

  return parseInt(expiresStr, 10);
}

function hasSessionExpiry() {
  return document.cookie.split('; ').findIndex((row) => row.startsWith('grafana_session_expiry=')) > -1;
}

export function canRotateSessionToken(authenticatedBy?: string) {
  return authenticatedBy !== 'jwt' && authenticatedBy !== 'extendedjwt';
}

export function hasRotatableSession(authenticatedBy?: string) {
  return hasSessionExpiry() && canRotateSessionToken(authenticatedBy);
}
