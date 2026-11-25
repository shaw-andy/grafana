type UrlPredicate = (url: string) => boolean;

const URL_ATTRIBUTES = new Set([
  'src',
  'lowsrc',
  'dynsrc',
  'poster',
  'data',
  'background',
  'codebase',
  'manifest',
  'icon',
]);
const URL_LIST_ATTRIBUTES = new Set(['srcset', 'imagesrcset', 'archive']);
// href on these is only followed when the user activates the element.
const NAVIGATION_ELEMENTS = new Set(['a', 'area']);
// CSS contexts where a bare quoted string is loaded as a URL.
const CSS_STRING_URL_CONTEXT = /image-set\s*\(|image\s*\(|cross-fade\s*\(|src\s*\(|@import/i;

/**
 * Returns true when the browser would load `url` from the Grafana server itself, with the viewer's
 * session cookie, if it appeared as an image, media, frame, stylesheet or other subresource address.
 * Such loads must not come from content that dashboard editors or query results control, since GET
 * routes like logout or org switching act on the viewer's session. Static assets under `public/` are allowed.
 */
export function isUnsafeResourceUrl(url: string): boolean {
  const value = url.trim();
  if (!value || typeof document === 'undefined') {
    return false;
  }

  let parsed: URL;
  try {
    parsed = new URL(value, document.baseURI);
  } catch {
    return true;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false;
  }
  if (stripTrailingDots(parsed.hostname) !== stripTrailingDots(window.location.hostname)) {
    return false;
  }
  return !(parsed.origin === window.location.origin && isStaticAssetPath(parsed.pathname));
}

/**
 * Removes every attribute, inline style and style sheet from `html` that would make the browser load
 * a URL for which `isUnsafe` is true. Returns `html` unchanged when nothing had to be removed.
 */
export function removeUnsafeResourceUrls(html: string, isUnsafe: UrlPredicate = isUnsafeResourceUrl): string {
  if (typeof document === 'undefined' || !html.includes('<')) {
    return html;
  }

  // Template content is inert: parsing it here loads nothing and runs no scripts.
  const template = document.createElement('template');
  template.innerHTML = html;

  let changed = false;
  template.content.querySelectorAll('*').forEach((el) => {
    changed = removeUnsafeResourceUrlsFromElement(el, isUnsafe) || changed;
  });

  return changed ? template.innerHTML : html;
}

/**
 * Element-level step of `removeUnsafeResourceUrls`, also used as a DOMPurify hook.
 * Returns true if the element was modified.
 */
export function removeUnsafeResourceUrlsFromElement(
  el: Element,
  isUnsafe: UrlPredicate = isUnsafeResourceUrl
): boolean {
  const tag = el.localName.toLowerCase();
  let changed = false;

  if (tag === 'style' && cssReferencesUnsafeUrl(el.textContent ?? '', isUnsafe)) {
    el.textContent = '';
    changed = true;
  }

  if (tag === 'meta' && el.hasAttribute('http-equiv')) {
    el.removeAttribute('http-equiv');
    el.removeAttribute('content');
    changed = true;
  }

  for (const name of el.getAttributeNames()) {
    const lowerName = name.toLowerCase();
    const value = el.getAttribute(name) ?? '';

    if (lowerName === 'srcdoc') {
      const cleaned = removeUnsafeResourceUrls(value, isUnsafe);
      if (cleaned !== value) {
        el.setAttribute(name, cleaned);
        changed = true;
      }
    } else if (isUnsafeAttribute(tag, lowerName, value, isUnsafe)) {
      el.removeAttribute(name);
      changed = true;
    }
  }

  return changed;
}

function isUnsafeAttribute(tag: string, name: string, value: string, isUnsafe: UrlPredicate): boolean {
  if (URL_ATTRIBUTES.has(name)) {
    return isUnsafe(value);
  }
  if (URL_LIST_ATTRIBUTES.has(name)) {
    return urlListCandidates(value).some((url) => isUnsafe(url));
  }
  if ((name === 'href' || name.endsWith(':href')) && !NAVIGATION_ELEMENTS.has(tag)) {
    return isUnsafe(value);
  }
  if (name === 'style' || /url\s*\(/i.test(value)) {
    return cssReferencesUnsafeUrl(value, isUnsafe);
  }
  return false;
}

// Each comma-separated candidate starts with a URL, optionally followed by a descriptor such as `2x`.
function urlListCandidates(value: string): string[] {
  return value.split(',').map((candidate) => candidate.trim().split(/\s+/)[0] ?? '');
}

function cssReferencesUnsafeUrl(css: string, isUnsafe: UrlPredicate): boolean {
  // CSS escapes can spell `url(` or an address in ways the patterns below would not recognize.
  if (css.includes('\\')) {
    return true;
  }

  for (const match of css.matchAll(/url\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))/gi)) {
    if (isUnsafe(match[1] ?? match[2] ?? match[3] ?? '')) {
      return true;
    }
  }

  if (CSS_STRING_URL_CONTEXT.test(css)) {
    for (const match of css.matchAll(/"([^"]*)"|'([^']*)'/g)) {
      if (isUnsafe(match[1] ?? match[2] ?? '')) {
        return true;
      }
    }
  }

  return false;
}

function isStaticAssetPath(pathname: string): boolean {
  const staticPrefix = new URL('public/', document.baseURI).pathname;
  // Encoded dots and slashes may be decoded by a proxy or the server into a path outside `public/`.
  return pathname.startsWith(staticPrefix) && !/%2e|%2f|%5c/i.test(pathname);
}

function stripTrailingDots(hostname: string): string {
  return hostname.replace(/\.+$/, '');
}
