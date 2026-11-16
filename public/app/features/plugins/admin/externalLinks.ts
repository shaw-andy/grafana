import { textUtil } from '@grafana/data';
import { config } from '@grafana/runtime';

const HTTP_URL_PATTERN = /^https?:\/\//i;
const SESSION_ROUTE_PATTERN = /(^|\/)(logout|profile\/switch-org)(\/|$)/i;
const CSS_RESOURCE_PATTERN = /url\s*\(|image(-set)?\s*\(|src\s*\(|@import|\\/i;
const REQUESTING_ELEMENTS = 'audio, source, style, track, video';
const URL_ATTRIBUTES = new Set([
  'action',
  'background',
  'cite',
  'data',
  'formaction',
  'href',
  'poster',
  'src',
  'srcset',
  'xlink:href',
]);
export const EXTERNAL_PLUGIN_LINK_REL = 'noopener noreferrer';

/**
 * Plugin metadata and catalog entries are written by plugin publishers. Following one of their links must never
 * send this Grafana server's session cookie, so only absolute http(s) URLs on another host are accepted. Render
 * accepted URLs with `EXTERNAL_PLUGIN_LINK_REL` so the publisher's site cannot learn which Grafana opened it.
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

  const parsed = parseUrl(sanitized);
  if (!parsed || (parsed.protocol !== 'http:' && parsed.protocol !== 'https:')) {
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
 * Sanitizes publisher-supplied HTML such as a plugin readme, changelog or deprecation notice. Links and images are
 * kept only when `getSafeExternalPluginUrl` accepts them and are fetched without a referrer. Same-document fragment
 * links are kept. Every other way for the markup to make the browser request an address is removed.
 */
export function sanitizePluginHtml(html: string): string {
  if (!html) {
    return html;
  }

  const template = document.createElement('template');
  template.innerHTML = textUtil.sanitize(html);
  template.content.querySelectorAll(REQUESTING_ELEMENTS).forEach((element) => element.remove());

  template.content.querySelectorAll('*').forEach((element) => {
    const tag = element.localName;

    for (const { name, value } of Array.from(element.attributes)) {
      const attribute = name.toLowerCase();

      if (attribute === 'style') {
        if (CSS_RESOURCE_PATTERN.test(value)) {
          element.removeAttribute(name);
        }
        continue;
      }

      if (!URL_ATTRIBUTES.has(attribute)) {
        continue;
      }

      const url = getSafePluginHtmlUrl(tag, attribute, value);
      if (url) {
        element.setAttribute(name, url);
      } else {
        element.removeAttribute(name);
      }
    }

    const href = element.getAttribute('href');
    if ((tag === 'a' || tag === 'area') && href && !href.startsWith('#')) {
      element.setAttribute('target', '_blank');
      element.setAttribute('rel', EXTERNAL_PLUGIN_LINK_REL);
    }

    if (tag === 'img') {
      element.setAttribute('referrerpolicy', 'no-referrer');
    }
  });

  return template.innerHTML;
}

function getSafePluginHtmlUrl(tag: string, attribute: string, value: string): string | undefined {
  if (attribute === 'href' && (tag === 'a' || tag === 'area')) {
    return value.startsWith('#') ? value : getSafeExternalPluginUrl(value);
  }

  if (attribute === 'src' && tag === 'img') {
    return getSafeExternalPluginUrl(value);
  }

  return undefined;
}

/**
 * Whether an address built from catalog data, such as a screenshot path, still resolves inside this Grafana's
 * grafana.com plugin proxy once the browser normalizes it.
 */
export function isPluginCatalogProxyPath(path: string): boolean {
  const resolved = parseUrl(path);
  const root = parseUrl(`${config.appSubUrl}/api/gnet/plugins/`);

  return Boolean(resolved && root && resolved.origin === root.origin && resolved.pathname.startsWith(root.pathname));
}

function parseUrl(url: string): URL | undefined {
  try {
    return new URL(url, document.baseURI);
  } catch {
    return undefined;
  }
}

function getGrafanaHostnames(): Set<string> {
  const hostnames = new Set<string>();

  for (const url of [window.location.href, document.baseURI, config.appUrl]) {
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
