import { sanitizeUrl as braintreeSanitizeUrl } from '@braintree/sanitize-url';
import DOMPurify from 'dompurify';
import * as xss from 'xss';

const XSSWL = Object.keys(xss.whiteList).reduce<xss.IWhiteList>((acc, element) => {
  acc[element] = xss.whiteList[element]?.concat(['class', 'style']);
  return acc;
}, {});

// Add iframe tags to XSSWL.
// We don't allow the sandbox attribute, since it can be overridden, instead we add it below.
XSSWL.iframe = ['src', 'width', 'height'];

// Allow button elements with safe presentational attributes.
// Event handlers (onclick etc.) are stripped by the xss library automatically.
XSSWL.button = ['class', 'style', 'type', 'disabled'];

// GET routes that end or change the viewer's session. Markup that makes the browser fetch one of them
// (a media source, a poster, a CSS url()) sends that request with the viewer's cookies as soon as it
// renders, and links are excluded because they only navigate when clicked. Matched as a suffix so a
// server under a sub path is covered too.
const SESSION_ROUTE = /(?:^|\/)(?:logout(?:\/[^/]*)?|profile\/switch-org(?:\/[^/]*)?|user\/auth-tokens\/rotate)$/;

const RESOURCE_URL_ATTRS = new Set([
  'src',
  'poster',
  'background',
  'data',
  'href',
  'xlink:href',
  'action',
  'formaction',
]);
const NAVIGATION_TAGS = new Set(['a', 'area']);

// The server percent-decodes the path before routing. Decoding fully and dropping empty and dot
// segments yields a path that matches whenever the server's would.
function normalizeRequestPath(pathname: string): string {
  let path = pathname;
  for (let i = 0; i < 10; i++) {
    const decoded = path.replace(/%([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    if (decoded === path) {
      break;
    }
    path = decoded;
  }
  const segments: string[] = [];
  for (const segment of path.replace(/\\/g, '/').toLowerCase().split('/')) {
    if (segment === '' || segment === '.') {
      continue;
    }
    if (segment === '..') {
      segments.pop();
      continue;
    }
    segments.push(segment);
  }
  return '/' + segments.join('/');
}

function requestBaseUrl(): string {
  if (typeof window !== 'undefined' && /^https?:$/.test(window.location?.protocol ?? '')) {
    return window.location.href;
  }
  return 'http://localhost/';
}

// The host is ignored: the same server can be reachable under several names, and a page served over
// https still upgrades an http media URL to the same origin.
function isSessionRouteUrl(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value.trim(), requestBaseUrl());
  } catch {
    return false;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return false;
  }
  return SESSION_ROUTE.test(normalizeRequestPath(url.pathname));
}

function isSessionRouteSrcset(value: string): boolean {
  const candidates = value.split(/\s+/).flatMap((token) => [token.replace(/^,+|,+$/g, ''), ...token.split(',')]);
  return candidates.some((candidate) => candidate !== '' && isSessionRouteUrl(candidate));
}

function unescapeCss(value: string): string {
  return value.replace(/\\(?:([0-9a-f]{1,6})[ \t\n\r\f]?|\r\n|[\n\r\f]|([\s\S]))/gi, (_, hex, char) => {
    if (hex === undefined) {
      return char ?? '';
    }
    const codePoint = parseInt(hex, 16);
    return codePoint > 0 && codePoint <= 0x10ffff ? String.fromCodePoint(codePoint) : '\ufffd';
  });
}

// CSS reaches a URL through url() and through the plain strings image-set() accepts.
function hasSessionRouteCssUrl(value: string): boolean {
  if (!/url|image-set|["'\\]/i.test(value)) {
    return false;
  }
  for (const css of [unescapeCss(value), unescapeCss(value.replace(/\/\*[\s\S]*?\*\//g, ''))]) {
    for (const match of css.matchAll(/url\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))|"([^"]*)"|'([^']*)'/gi)) {
      const url = match[1] ?? match[2] ?? match[3] ?? match[4] ?? match[5] ?? '';
      if (isSessionRouteUrl(url)) {
        return true;
      }
    }
  }
  return false;
}

/** Reports whether the browser would request a session route for this decoded attribute value. */
function requestsSessionRoute(tag: string, name: string, value: string): boolean {
  if (name === 'srcset' || name === 'imagesrcset') {
    if (isSessionRouteSrcset(value)) {
      return true;
    }
  } else if (RESOURCE_URL_ATTRS.has(name) && !(name === 'href' && NAVIGATION_TAGS.has(tag))) {
    if (isSessionRouteUrl(value)) {
      return true;
    }
  }
  return hasSessionRouteCssUrl(value);
}

// The browser decodes character references in an attribute before using it, so check the value the
// HTML parser produces from the escaped output rather than the escaped text.
function parsedAttributeValue(escaped: string): string {
  if (!escaped.includes('&') || typeof DOMParser === 'undefined') {
    return escaped;
  }
  const doc = new DOMParser().parseFromString(`<i title="${escaped}"></i>`, 'text/html');
  return doc.body.firstElementChild?.getAttribute('title') ?? escaped;
}

function dropSessionRequestAttributes(node: Element) {
  const tag = node.nodeName.toLowerCase();
  if (tag === 'style' && hasSessionRouteCssUrl(node.textContent ?? '')) {
    node.textContent = '';
  }
  for (const attr of Array.from(node.attributes)) {
    if (requestsSessionRoute(tag, attr.name.toLowerCase(), attr.value)) {
      node.removeAttribute(attr.name);
    }
  }
}

function withSessionRequestFilter<T>(run: () => T): T {
  DOMPurify.addHook('afterSanitizeAttributes', dropSessionRequestAttributes);
  try {
    return run();
  } finally {
    DOMPurify.removeHook('afterSanitizeAttributes', dropSessionRequestAttributes);
  }
}

const sanitizeTextPanelWhitelist = new xss.FilterXSS({
  // Add sandbox attribute to iframe tags if an attribute is allowed.
  onTagAttr(tag, name, value, isWhiteAttr) {
    if (tag === 'iframe') {
      if (!isWhiteAttr) {
        return '';
      }
      const escaped = xss.escapeAttrValue(sanitizeUrl(value));
      if (requestsSessionRoute(tag, name, parsedAttributeValue(escaped))) {
        return '';
      }
      return ` ${name}="${escaped}" sandbox credentialless referrerpolicy=no-referrer`;
    }
    return;
  },
  safeAttrValue(tag, name, value, cssFilter) {
    const escaped = xss.safeAttrValue(tag, name, value, cssFilter);
    return requestsSessionRoute(tag, name, parsedAttributeValue(escaped)) ? '' : escaped;
  },
  onTag(tag, html, options) {
    if (html === '<input disabled="" type="checkbox">' || html === '<input checked="" disabled="" type="checkbox">') {
      return html;
    }
    return;
  },
  whiteList: XSSWL,
  css: {
    whiteList: {
      ...xss.getDefaultCSSWhiteList(),
      'flex-direction': true,
      'flex-wrap': true,
      'flex-basis': true,
      'flex-grow': true,
      'flex-shrink': true,
      'flex-flow': true,
      gap: true,
      order: true,
      'justify-content': true,
      'justify-items': true,
      'justify-self': true,
      'align-items': true,
      'align-content': true,
      'align-self': true,
    },
  },
});

/**
 * Return a sanitized string that is going to be rendered in the browser to prevent XSS attacks.
 * Note that sanitized tags will be removed, such as "<script>".
 * We don't allow form or input elements.
 */
export function sanitize(unsanitizedString: string): string {
  const addNoopener = (node: Element) => {
    if (node.tagName === 'A' && node.getAttribute('target') === '_blank') {
      node.setAttribute('rel', 'noopener noreferrer');
    }
  };
  try {
    DOMPurify.addHook('afterSanitizeAttributes', addNoopener);

    return withSessionRequestFilter(() =>
      DOMPurify.sanitize(unsanitizedString, {
        USE_PROFILES: { html: true },
        FORBID_TAGS: ['form', 'input'],
        ADD_ATTR: ['target'],
      })
    );
  } catch (error) {
    console.error('String could not be sanitized', unsanitizedString);
    return escapeHtml(unsanitizedString);
  } finally {
    DOMPurify.removeHook('afterSanitizeAttributes', addNoopener);
  }
}

function sanitizeTrustedTypesRSS(unsanitizedString: string): TrustedHTML {
  return DOMPurify.sanitize(unsanitizedString, {
    RETURN_TRUSTED_TYPE: true,
    ADD_ATTR: ['xmlns:atom', 'version', 'property', 'content'],
    ADD_TAGS: ['rss', 'meta', 'channel', 'title', 'link', 'description', 'atom:link', 'item', 'pubDate', 'guid'],
    PARSER_MEDIA_TYPE: 'application/xhtml+xml',
  });
}

function sanitizeTrustedTypes(unsanitizedString: string): TrustedHTML {
  return withSessionRequestFilter(() => DOMPurify.sanitize(unsanitizedString, { RETURN_TRUSTED_TYPE: true }));
}

/**
 * Returns string safe from XSS attacks to be used in the Text panel plugin.
 *
 * Even though we allow the style-attribute, there's still default filtering applied to it
 * Info: https://github.com/leizongmin/js-xss#customize-css-filter
 * Whitelist: https://github.com/leizongmin/js-css-filter/blob/master/lib/default.js
 */
export function sanitizeTextPanelContent(unsanitizedString: string): string {
  try {
    return sanitizeTextPanelWhitelist.process(unsanitizedString);
  } catch (error) {
    console.error('String could not be sanitized', unsanitizedString);
    return 'Text string could not be sanitized';
  }
}

// Returns sanitized SVG, free from XSS attacks to be used when rendering SVG content.
function sanitizeSVGContent(unsanitizedString: string): string {
  return withSessionRequestFilter(() =>
    DOMPurify.sanitize(unsanitizedString, { USE_PROFILES: { svg: true, svgFilters: true } })
  );
}

// Return a sanitized URL, free from XSS attacks, such as javascript:alert(1)
export function sanitizeUrl(url: string): string {
  return braintreeSanitizeUrl(url);
}

// Returns true if the string contains ANSI color codes.
function hasAnsiCodes(input: string): boolean {
  return /\u001b\[\d{1,2}m/.test(input);
}

// Returns a string with HTML entities escaped.
function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/'/g, '&#39;')
    .replace(/"/g, '&quot;');
}

export class PathValidationError extends Error {
  constructor(message = 'Invalid request path') {
    super(message);
    this.name = 'PathValidationError';
    // Maintains proper stack trace for where error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, PathValidationError);
    }
  }
}

/**
 * Validates a path or URL, protecting against path traversal attacks.
 * Returns the original input if safe, or throw an error
 */
export function validatePath<OriginalPath extends string>(path: OriginalPath): OriginalPath {
  try {
    let decoded: string = path;
    while (true) {
      const nextDecode = decodeURIComponent(decoded);
      if (nextDecode === decoded) {
        break; // String is fully decoded.
      }
      decoded = nextDecode;
    }

    // Validate the entire decoded string for traversal attempts
    // This prevents attacks that use query separators to hide traversal payloads
    if (/\.\.|\/\\|[\t\n\r]/.test(decoded)) {
      throw new PathValidationError();
    }

    // Return the original path (not the decoded version) to preserve the full URL
    return path;
  } catch (err) {
    // Rethrow the original PathValidationError to preserve the stack trace
    if (err instanceof PathValidationError) {
      throw err;
    }

    // A decoding error can happen with malformed URIs (e.g., % not followed by hex).
    // These are suspicious, so we treat them as traversal attempts.
    throw new PathValidationError('Error validating request path');
  }
}

export const textUtil = {
  escapeHtml,
  hasAnsiCodes,
  sanitize,
  sanitizeTextPanelContent,
  sanitizeUrl,
  sanitizeSVGContent,
  sanitizeTrustedTypes,
  sanitizeTrustedTypesRSS,
};
