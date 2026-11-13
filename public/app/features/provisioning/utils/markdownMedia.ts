import { type RepositoryView } from 'app/api/clients/provisioning/v0alpha1';

// Attributes whose value the browser fetches as soon as the element is painted.
const FETCHED_URL_ATTRS = new Set(['src', 'poster', 'background', 'lowsrc', 'dynsrc', 'data']);
// Candidate lists are not parsed: dropping them is the only way to be sure no candidate is fetched.
const CANDIDATE_LIST_ATTRS = new Set(['srcset', 'imagesrcset']);
const REFERENCE_ATTRS = new Set(['href', 'xlink:href']);
// Elements whose href is followed only when the user clicks it.
const NAVIGATION_ELEMENTS = new Set(['a', 'area']);
// SVG elements that fetch their href as an image.
const IMAGE_REFERENCE_ELEMENTS = new Set(['image', 'feimage']);
// The URL parser strips only C0 controls and spaces, so a broader trim would misjudge the value.
const URL_FRAGMENT_ONLY = /^[\u0000-\u0020]*#/;

const CSS_WHITESPACE = '[ \\t\\n\\r\\f]*';
const CSS_URL_FUNCTION = /url\s*\(/gi;
const CSS_FRAGMENT_ONLY_URL_ARGUMENT = new RegExp(`^${CSS_WHITESPACE}(['"]?)${CSS_WHITESPACE}#`);
// Escapes could spell any of these, so a backslash is treated as unsafe on its own.
const CSS_OTHER_FETCHES = /\\|@import|(?:image-set|image|cross-fade|src|attr)\s*\(/i;

/**
 * The origin media in folder markdown may load from: the configured repository's
 * host. Undefined when the repository has no web host (e.g. local repositories)
 * or is served from this Grafana origin, in which case no media is loaded.
 */
export function getRepositoryMediaOrigin(repository: Pick<RepositoryView, 'url'>): string | undefined {
  if (!repository.url) {
    return undefined;
  }
  let url: URL;
  try {
    url = new URL(repository.url);
  } catch {
    return undefined;
  }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.origin === window.location.origin) {
    return undefined;
  }
  return url.origin;
}

/**
 * Removes every address the browser would fetch while painting `html` (images,
 * audio, video, CSS backgrounds, SVG resource references) unless it resolves to
 * `allowedOrigin`. Same-origin loads carry the viewer's Grafana session, so
 * repository content must not be able to make the viewer request this server
 * or any other host. Run this on already-sanitized HTML.
 */
export function restrictMarkdownMedia(html: string, allowedOrigin: string | undefined): string {
  const doc = new DOMParser().parseFromString(html, 'text/html');

  // Template content is not reached by querySelectorAll, so it can't be filtered.
  doc.body.querySelectorAll('template').forEach((template) => template.remove());

  doc.body.querySelectorAll('*').forEach((element) => {
    const tag = element.localName.toLowerCase();
    if (tag === 'style') {
      if (cssMayFetch(element.textContent ?? '')) {
        element.remove();
      }
      return;
    }

    for (const { name, value } of Array.from(element.attributes)) {
      const attr = name.toLowerCase();
      if (!isAllowedAttribute(tag, attr, value, allowedOrigin)) {
        element.removeAttribute(name);
      }
    }
  });

  return doc.body.innerHTML;
}

function isAllowedAttribute(tag: string, attr: string, value: string, allowedOrigin: string | undefined): boolean {
  if (CANDIDATE_LIST_ATTRS.has(attr)) {
    return false;
  }
  if (FETCHED_URL_ATTRS.has(attr)) {
    return isAllowedMediaUrl(value, allowedOrigin);
  }
  if (REFERENCE_ATTRS.has(attr)) {
    if (NAVIGATION_ELEMENTS.has(tag)) {
      return true;
    }
    if (IMAGE_REFERENCE_ELEMENTS.has(tag)) {
      return isAllowedMediaUrl(value, allowedOrigin);
    }
    return URL_FRAGMENT_ONLY.test(value) || isAllowedMediaUrl(value, allowedOrigin);
  }
  if (attr.startsWith('data-') || attr.startsWith('aria-') || attr === 'alt' || attr === 'title') {
    return true;
  }
  // `style` and SVG presentation attributes such as `fill`, `filter` or `mask` can load url() references.
  return !cssMayFetch(value);
}

function isAllowedMediaUrl(value: string, allowedOrigin: string | undefined): boolean {
  if (!allowedOrigin) {
    return false;
  }
  try {
    const url = new URL(value, document.baseURI);
    return (url.protocol === 'https:' || url.protocol === 'http:') && url.origin === allowedOrigin;
  } catch {
    return false;
  }
}

function cssMayFetch(css: string): boolean {
  if (CSS_OTHER_FETCHES.test(css)) {
    return true;
  }
  for (const match of css.matchAll(CSS_URL_FUNCTION)) {
    const argument = css.slice((match.index ?? 0) + match[0].length);
    if (!CSS_FRAGMENT_ONLY_URL_ARGUMENT.test(argument)) {
      return true;
    }
  }
  return false;
}
