import { textUtil } from '@grafana/data';
import { config } from '@grafana/runtime';

const HTTP_URL_PATTERN = /^https?:\/\//i;
const SESSION_ROUTE_PATTERN = /(^|\/)(logout|profile\/switch-org)(\/|$)/i;
const LINK_ATTRIBUTES = ['href', 'xlink:href'];

/**
 * Plugin metadata and catalog entries are written by plugin publishers. Following one of their links must never
 * send this Grafana server's session cookie, so only absolute http(s) URLs on another host are accepted.
 *
 * The returned string is a fixed point of `textUtil.sanitizeUrl`, so link components that sanitize their href
 * again render exactly the value that was checked here.
 */
export function getSafeExternalPluginUrl(url: unknown): string | undefined {
  if (typeof url !== 'string') {
    return undefined;
  }

  const sanitized = textUtil.sanitizeUrl(url);
  if (textUtil.sanitizeUrl(sanitized) !== sanitized || !HTTP_URL_PATTERN.test(sanitized)) {
    return undefined;
  }

  let parsed: URL;
  try {
    parsed = new URL(sanitized, window.location.href);
  } catch {
    return undefined;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return undefined;
  }

  if (getGrafanaHostnames().has(normalizeHostname(parsed.hostname))) {
    return undefined;
  }

  let pathname: string;
  try {
    pathname = decodeURIComponent(parsed.pathname);
  } catch {
    return undefined;
  }

  if (SESSION_ROUTE_PATTERN.test(pathname)) {
    return undefined;
  }

  return sanitized;
}

export function getSafeExternalPluginLinks<T extends { url: string }>(links: T[] | undefined): T[] {
  return (links ?? []).flatMap((link) => {
    const url = getSafeExternalPluginUrl(link.url);
    return url ? [{ ...link, url }] : [];
  });
}

/**
 * Applies `getSafeExternalPluginUrl` to every link in publisher-supplied HTML such as a plugin readme or changelog.
 * Same-document fragment links are kept; any other link that fails the check loses its href.
 */
export function removeUnsafePluginHtmlLinks(html: string): string {
  if (!html) {
    return html;
  }

  const template = document.createElement('template');
  template.innerHTML = html;

  template.content.querySelectorAll('a, area').forEach((element) => {
    for (const attribute of LINK_ATTRIBUTES) {
      const value = element.getAttribute(attribute);
      if (value === null || value.startsWith('#')) {
        continue;
      }

      const url = getSafeExternalPluginUrl(value);
      if (url) {
        element.setAttribute(attribute, url);
      } else {
        element.removeAttribute(attribute);
      }
    }
  });

  return template.innerHTML;
}

function getGrafanaHostnames(): Set<string> {
  const hostnames = new Set<string>();

  for (const url of [window.location.href, config.appUrl]) {
    try {
      hostnames.add(normalizeHostname(new URL(url).hostname));
    } catch {
      // An unset or relative address names no host to add.
    }
  }

  return hostnames;
}

function normalizeHostname(hostname: string): string {
  return hostname.toLowerCase().replace(/\.+$/, '');
}
