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

// Attributes in XSSWL that the browser fetches as soon as the element renders.
const RESOURCE_ATTRIBUTES: Record<string, string[]> = {
  audio: ['src'],
  iframe: ['src'],
  img: ['src'],
  video: ['src', 'poster'],
};

const sanitizeTextPanelWhitelist = new xss.FilterXSS({
  // Add sandbox attribute to iframe tags if an attribute is allowed.
  onTagAttr(tag, name, value, isWhiteAttr) {
    if (tag === 'iframe') {
      if (!isWhiteAttr) {
        return '';
      }
      const safeValue = xss.escapeAttrValue(sanitizeUrl(value));
      if (isResourceAttribute(tag, name) && loadsFromCurrentHost(parseAttributeValue(safeValue))) {
        return '';
      }
      return ` ${name}="${safeValue}" sandbox credentialless referrerpolicy=no-referrer`;
    }
    if (
      isWhiteAttr &&
      isResourceAttribute(tag, name) &&
      loadsFromCurrentHost(parseAttributeValue(xss.safeAttrValue(tag, name, value, xss.cssFilter)))
    ) {
      return '';
    }
    return;
  },
  safeAttrValue(tag, name, value, cssFilter) {
    const safeValue = xss.safeAttrValue(tag, name, value, cssFilter);
    if (name === 'style' && cssLoadsFromCurrentHost(parseAttributeValue(safeValue))) {
      return '';
    }
    return safeValue;
  },
  onTag(tag, html, options) {
    if (html === '<input disabled="" type="checkbox">' || html === '<input checked="" disabled="" type="checkbox">') {
      return html;
    }
    if (tag === 'img' && !options.isClosing && imageTagLoadsFromCurrentHost(html)) {
      return '';
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
  try {
    DOMPurify.addHook('afterSanitizeAttributes', (node) => {
      if (node.tagName === 'A' && node.getAttribute('target') === '_blank') {
        node.setAttribute('rel', 'noopener noreferrer');
      }
    });

    return DOMPurify.sanitize(unsanitizedString, {
      USE_PROFILES: { html: true },
      FORBID_TAGS: ['form', 'input'],
      ADD_ATTR: ['target'],
    });
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
  return DOMPurify.sanitize(unsanitizedString, { RETURN_TRUSTED_TYPE: true });
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
  return DOMPurify.sanitize(unsanitizedString, { USE_PROFILES: { svg: true, svgFilters: true } });
}

// Return a sanitized URL, free from XSS attacks, such as javascript:alert(1)
export function sanitizeUrl(url: string): string {
  return braintreeSanitizeUrl(url);
}

/**
 * Returns the URL unchanged if an image element can load it without sending this Grafana server's session
 * cookie: an http(s) URL on another host, or a data URL. Returns an empty string for anything else, including
 * relative and protocol-relative paths and absolute URLs that resolve to this host.
 */
export function sanitizeImageUrl(url: string): string {
  const resolved = resolveUrl(url);
  if (!resolved) {
    return '';
  }
  if (resolved.protocol === 'data:') {
    return url;
  }
  if ((resolved.protocol === 'http:' || resolved.protocol === 'https:') && !isCurrentHost(resolved.hostname)) {
    return url;
  }
  return '';
}

function resolveUrl(url: string): URL | undefined {
  try {
    return new URL(url, document.baseURI);
  } catch {
    return undefined;
  }
}

// Session cookies are scoped to the host, not the port or scheme, so any URL on this host carries them.
function isCurrentHost(hostname: string): boolean {
  const withoutTrailingDot = (host: string) => host.replace(/\.$/, '');
  return withoutTrailingDot(hostname) === withoutTrailingDot(window.location.hostname);
}

function loadsFromCurrentHost(url: string): boolean {
  const resolved = resolveUrl(url);
  return resolved !== undefined && isCurrentHost(resolved.hostname);
}

function imageTagLoadsFromCurrentHost(html: string): boolean {
  const attributesStart = html.search(/\s/);
  if (attributesStart === -1) {
    return false;
  }
  let loads = false;
  xss.parseAttr(html.slice(attributesStart + 1, -1), (name, value) => {
    if (
      name === 'src' &&
      loadsFromCurrentHost(parseAttributeValue(xss.safeAttrValue('img', name, value, xss.cssFilter)))
    ) {
      loads = true;
    }
    return '';
  });
  return loads;
}

function isResourceAttribute(tag: string, name: string): boolean {
  return RESOURCE_ATTRIBUTES[tag]?.includes(name) ?? false;
}

// Returns the value the browser will see for an escaped attribute, after it decodes character references.
function parseAttributeValue(escapedValue: string): string {
  const template = document.createElement('template');
  template.innerHTML = `<i title="${escapedValue}"></i>`;
  return template.content.firstElementChild?.getAttribute('title') ?? '';
}

const CSS_URL = /url\(\s*(?:"([^"]*)"|'([^']*)'|([^)"'\s]*))\s*\)/gi;
const CSS_URL_START = /url\s*\(/gi;
const CSS_IMAGE_FUNCTION = /(?:image-set|image|cross-fade|element|src)\s*\(/i;

function cssLoadsFromCurrentHost(css: string): boolean {
  // Escapes can spell out url( or any part of the address, and the other image functions take bare strings.
  if (css.includes('\\') || CSS_IMAGE_FUNCTION.test(css)) {
    return true;
  }
  const urls = Array.from(css.matchAll(CSS_URL));
  if (urls.length !== (css.match(CSS_URL_START) ?? []).length) {
    return true;
  }
  return urls.some(([, doubleQuoted, singleQuoted, bare]) =>
    loadsFromCurrentHost(doubleQuoted ?? singleQuoted ?? bare)
  );
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
  sanitizeImageUrl,
  sanitizeSVGContent,
  sanitizeTrustedTypes,
  sanitizeTrustedTypesRSS,
};
