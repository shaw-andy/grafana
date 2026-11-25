const APP_ORIGIN = 'https://grafana.example';

const AUTO_FETCH_ATTRS: Record<string, string[]> = {
  IMG: ['src', 'srcset'],
  AUDIO: ['src'],
  VIDEO: ['src', 'poster'],
  SOURCE: ['src', 'srcset'],
  TRACK: ['src'],
  IFRAME: ['src'],
  EMBED: ['src'],
  OBJECT: ['data'],
  LINK: ['href'],
  IMAGE: ['href'],
  USE: ['href'],
};

/**
 * URLs in rendered HTML that a browser loads with the viewer's cookies.
 * Anchors are omitted: they do not fetch until activated.
 * A sandboxed iframe without allow-same-origin is omitted: Chrome does not send the session cookie for it.
 */
export function credentialedResourceUrls(html: string): string[] {
  const doc = new DOMParser().parseFromString(`<div id="root">${html}</div>`, 'text/html');
  const urls: string[] = [];

  doc.body.querySelectorAll('*').forEach((el) => {
    const attrs = AUTO_FETCH_ATTRS[el.tagName];
    if (attrs && !isUncredentialedFrame(el)) {
      for (const attr of attrs) {
        collect(urls, el.getAttribute(attr));
        if (attr === 'href') {
          collect(urls, el.getAttribute('xlink:href'));
        }
      }
    }

    if (el.tagName === 'META' && /refresh/i.test(el.getAttribute('http-equiv') ?? '')) {
      const content = el.getAttribute('content') ?? '';
      const match = content.match(/url\s*=\s*(['"]?)([^'">]+)\1/i);
      collect(urls, match?.[2] ?? null);
    }

    collectCss(urls, el.getAttribute('style'));
    if (el.tagName === 'STYLE') {
      collectCss(urls, el.textContent);
    }
  });

  return urls;
}

function isUncredentialedFrame(el: Element): boolean {
  if (el.tagName !== 'IFRAME' || !el.hasAttribute('sandbox')) {
    return false;
  }
  return !el
    .getAttribute('sandbox')!
    .split(/\s+/)
    .includes('allow-same-origin');
}

function collectCss(urls: string[], css: string | null) {
  if (!css) {
    return;
  }
  const re = /url\(\s*(['"]?)(.*?)\1\s*\)/gi;
  for (const match of css.matchAll(re)) {
    collect(urls, match[2] ?? null);
  }
}

function collect(urls: string[], raw: string | null) {
  if (!raw) {
    return;
  }
  for (const candidate of raw.split(',')) {
    const token = candidate.trim().split(/\s+/)[0];
    if (token && resolvesToApp(token)) {
      urls.push(token);
    }
  }
}

function resolvesToApp(raw: string): boolean {
  const value = raw.trim();
  if (!value || /^(data|blob|mailto|tel):/i.test(value)) {
    return false;
  }
  try {
    return new URL(value, APP_ORIGIN).origin === APP_ORIGIN;
  } catch {
    return true;
  }
}
