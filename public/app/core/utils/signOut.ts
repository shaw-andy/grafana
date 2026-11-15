import { config } from '@grafana/runtime';

// Only POST /logout ends the session, so that a link or a background GET request cannot.
export function signOut() {
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = `${config.appSubUrl}/logout`;
  document.body.appendChild(form);
  form.submit();
}
