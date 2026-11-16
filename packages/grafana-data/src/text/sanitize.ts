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

// CSS that makes the browser fetch a resource. There is no leading boundary so that vendor-prefixed
// forms such as -webkit-image-set() and -webkit-cross-fade() match as well. @import takes a bare string.
const CSS_RESOURCE_LOAD = /@import|(?:url|src|image|image-set|cross-fade|attr)\s*\(/i;

// SVG presentation attributes that take a CSS url(), which Firefox fetches for external references.
const CSS_URL_ATTRIBUTES = new Set([
  'style',
  'fill',
  'stroke',
  'filter',
  'mask',
  'clip-path',
  'marker-start',
  'marker-mid',
  'marker-end',
  'cursor',
]);

function decodeCssEscapes(css: string): string {
  return css.replace(/\\([0-9a-fA-F]{1,6})[ \t\n\r\f]?|\\([\s\S])/g, (_, hex: string | undefined, char: string) => {
    if (hex === undefined) {
      return char;
    }
    const codePoint = parseInt(hex, 16);
    const isValid = codePoint > 0 && codePoint <= 0x10ffff && (codePoint < 0xd800 || codePoint > 0xdfff);
    return isValid ? String.fromCodePoint(codePoint) : '\uFFFD';
  });
}

/**
 * Whether the browser would fetch something while applying this CSS. It sends the viewer's session
 * with a same-origin fetch, so a style that names a Grafana route makes the viewer call that route.
 */
function cssLoadsResource(css: string): boolean {
  // A fragment-only url() such as an SVG gradient or marker reference points into the same document.
  // Only the literal form is skipped, before escapes are decoded, so an escaped quote or parenthesis
  // cannot turn a relative address into something that looks like a fragment.
  const withoutFragments = css.replace(/url\(\s*(['"]?)#[\w.:-]*\1\s*\)/gi, '');
  const normalized = decodeCssEscapes(withoutFragments).replace(/\/\*[\s\S]*?\*\//g, '');
  return CSS_RESOURCE_LOAD.test(normalized);
}

function dropResourceLoadingCSS(node: Element, data: { attrName: string; attrValue: string; keepAttr: boolean }) {
  // The HTML background attribute on body, table and td loads an image just like a CSS background.
  if (data.attrName === 'background' || (CSS_URL_ATTRIBUTES.has(data.attrName) && cssLoadsResource(data.attrValue))) {
    data.keepAttr = false;
  }
}

function emptyResourceLoadingStyleElement(node: Node, data: { tagName: string }) {
  if (data.tagName === 'style' && cssLoadsResource(node.textContent ?? '')) {
    node.textContent = '';
  }
}

function withoutResourceLoadingCSS<T>(purify: () => T): T {
  DOMPurify.addHook('uponSanitizeAttribute', dropResourceLoadingCSS);
  DOMPurify.addHook('uponSanitizeElement', emptyResourceLoadingStyleElement);
  try {
    return purify();
  } finally {
    DOMPurify.removeHook('uponSanitizeAttribute', dropResourceLoadingCSS);
    DOMPurify.removeHook('uponSanitizeElement', emptyResourceLoadingStyleElement);
  }
}

const sanitizeTextPanelWhitelist = new xss.FilterXSS({
  // Add sandbox attribute to iframe tags if an attribute is allowed.
  onTagAttr(tag, name, value, isWhiteAttr) {
    if (tag === 'iframe') {
      return isWhiteAttr
        ? ` ${name}="${xss.escapeAttrValue(sanitizeUrl(value))}" sandbox credentialless referrerpolicy=no-referrer`
        : '';
    }
    return;
  },
  onTag(tag, html, options) {
    if (html === '<input disabled="" type="checkbox">' || html === '<input checked="" disabled="" type="checkbox">') {
      return html;
    }
    return;
  },
  whiteList: XSSWL,
  css: {
    // The default only drops a url() with a script scheme. The xss library also leaves named character
    // references such as &lpar; undecoded here while the browser decodes them, so a value with one
    // cannot be checked and is dropped too.
    safeAttrValue(name: string, value: string) {
      return value.includes('&') || cssLoadsResource(value) ? '' : value;
    },
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
  try {
    DOMPurify.addHook('afterSanitizeAttributes', (node) => {
      if (node.tagName === 'A' && node.getAttribute('target') === '_blank') {
        node.setAttribute('rel', 'noopener noreferrer');
      }
    });

    return withoutResourceLoadingCSS(() =>
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
    DOMPurify.removeHook('afterSanitizeAttributes');
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
  return withoutResourceLoadingCSS(() => DOMPurify.sanitize(unsanitizedString, { RETURN_TRUSTED_TYPE: true }));
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
  return withoutResourceLoadingCSS(() =>
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
