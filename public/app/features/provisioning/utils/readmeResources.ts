import { config } from '@grafana/runtime';

const URL_ATTRIBUTES = ['src', 'poster', 'background', 'data'];

/**
 * Drops everything in sanitized README HTML that makes the browser request a URL on
 * Grafana's own host when the page loads: that request carries the viewer's session,
 * so an address such as the logout page would act on it.
 *
 * CSS (style attributes and elements) and srcset are removed outright, since their
 * URLs can't be vetted reliably here.
 */
export function removeGrafanaHostResources(html: string): string {
  const grafanaHosts = getGrafanaHosts();
  const doc = new DOMParser().parseFromString(html, 'text/html');

  doc.querySelectorAll('style').forEach((style) => style.remove());
  doc.querySelectorAll('*').forEach((element) => {
    element.removeAttribute('style');
    element.removeAttribute('srcset');
    for (const name of URL_ATTRIBUTES) {
      const value = element.getAttribute(name);
      if (value !== null && !isOffHostResource(value, grafanaHosts)) {
        element.removeAttribute(name);
      }
    }
  });

  return doc.body.innerHTML;
}

function isOffHostResource(value: string, grafanaHosts: string[]): boolean {
  const url = parseUrl(value, document.baseURI);
  if (url?.protocol === 'data:') {
    return true;
  }
  // Cookies are scoped by host, not by scheme or port.
  return (
    (url?.protocol === 'http:' || url?.protocol === 'https:') && !grafanaHosts.includes(normalizeHost(url.hostname))
  );
}

function getGrafanaHosts(): string[] {
  const appUrl = parseUrl(config.appUrl);
  return [document.location.hostname, ...(appUrl ? [appUrl.hostname] : [])].map(normalizeHost);
}

function parseUrl(value: string, base?: string): URL | undefined {
  try {
    return new URL(value, base);
  } catch {
    return undefined;
  }
}

function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, '');
}
