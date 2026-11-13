import DOMPurify from 'dompurify';

// With the HTML profile and the forbidden tags and attributes below, these are the only attributes left that make
// the browser fetch a URL without a click.
const resourceAttributes = ['src', 'poster', 'background', 'data'];
const srcsetDescriptor = /^\d*\.?\d+(?:e[+-]?\d+)?[wxh]$/i;

function isSameOrigin(url: string): boolean {
  try {
    return new URL(url, document.baseURI).origin === window.location.origin;
  } catch {
    return true;
  }
}

function hasSameOriginCandidate(srcset: string): boolean {
  return srcset
    .split(/[\s,]+/)
    .filter((token) => token !== '' && !srcsetDescriptor.test(token))
    .some(isSameOrigin);
}

function removeSameOriginResources(node: Element) {
  for (const name of resourceAttributes) {
    const value = node.getAttribute(name);
    if (value !== null && isSameOrigin(value)) {
      node.removeAttribute(name);
    }
  }

  const srcset = node.getAttribute('srcset');
  if (srcset !== null && hasSameOriginCandidate(srcset)) {
    node.removeAttribute('srcset');
  }

  if (node.tagName === 'A' && node.getAttribute('target') === '_blank') {
    node.setAttribute('rel', 'noopener noreferrer');
  }
}

/**
 * Sanitizes plugin-authored HTML (catalog or installed plugin readme, changelog, and notes). Besides removing
 * scripts, it drops every resource the page would load from this Grafana server, because those requests carry the
 * viewer's session.
 */
export function sanitizeCatalogHtml(html: string): string {
  DOMPurify.addHook('afterSanitizeAttributes', removeSameOriginResources);
  try {
    return DOMPurify.sanitize(html, {
      USE_PROFILES: { html: true },
      FORBID_TAGS: ['style', 'form', 'input'],
      FORBID_ATTR: ['style'],
      ADD_ATTR: ['target'],
    });
  } finally {
    DOMPurify.removeHook('afterSanitizeAttributes', removeSameOriginResources);
  }
}
