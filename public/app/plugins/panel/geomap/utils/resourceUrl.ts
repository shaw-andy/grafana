import { config } from '@grafana/runtime';

function hostnameOf(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  try {
    return new URL(value).hostname;
  } catch {
    return undefined;
  }
}

function sameHostname(a: string, b: string): boolean {
  return a.replace(/\.$/, '') === b.replace(/\.$/, '');
}

// Cookies are scoped by host, not by origin, so another port or scheme on this host still carries
// the viewer's Grafana session.
function isGrafanaHost(url: URL): boolean {
  const hosts = [window.location.hostname, hostnameOf(config.appUrl)];
  return hosts.some((host) => host && sameHostname(host, url.hostname));
}

function allowedPathPrefixes(publicSubdirectory: string): string[] {
  const prefixes = [`${config.appSubUrl ?? ''}/public/${publicSubdirectory}`];
  if (window.__grafana_public_path__) {
    try {
      const publicDir = new URL(`${window.__grafana_public_path__}${publicSubdirectory}`, document.baseURI);
      if (isGrafanaHost(publicDir)) {
        prefixes.push(publicDir.pathname);
      }
    } catch {
      // An unparseable public path adds no prefix.
    }
  }
  return prefixes;
}

/**
 * Resolves a URL saved in panel options before the map loads it.
 *
 * Grafana serves `public/` as static files that ignore the session. Any other path on this host can
 * be a route that acts on the viewer's session when requested, such as logout, so a URL that lands
 * on this host outside `public/<publicSubdirectory>` is refused and `undefined` is returned.
 */
export function resolveMapResourceUrl(value: string, base: string, publicSubdirectory: string): URL | undefined {
  let url: URL;
  try {
    url = new URL(value, base);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return undefined;
  }
  if (!isGrafanaHost(url)) {
    return url;
  }
  // The server decodes the path again, so an encoded dot or separator could still leave the directory.
  if (/%2e|%2f|%5c/i.test(url.pathname)) {
    return undefined;
  }
  return allowedPathPrefixes(publicSubdirectory).some((prefix) => url.pathname.startsWith(prefix)) ? url : undefined;
}

/** Request options for map resources: they never need the viewer's cookies. */
export const mapResourceFetchOptions: RequestInit = { credentials: 'omit' };
