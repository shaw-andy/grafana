import { type RepositoryView } from 'app/api/clients/provisioning/v0alpha1';

import { isMarkdownFile } from './folderDocConventions';
import { buildCleanBaseUrl, getRepoFileUrl, getRepoRawFileUrl } from './git';

interface RewriteOptions {
  repository: RepositoryView;
  /** Repo-relative directory containing the README (e.g. "ops/resources/RnD"). */
  baseDirInRepo: string;
}

const SCHEME_RE = /^[a-z][a-z0-9+\-.]*:/i;

/**
 * Attribute stamped on links whose target could be viewed in-app: a Grafana
 * resource (JSON/YAML files or folder directories) or a `.md` doc (which opens
 * as a tab on its containing folder's page). It carries the resolved repo path;
 * the README click handler reads it to lazily resolve the link to the in-app page
 * — untagged links (images, other files, external) always open the host URL.
 */
export const RESOURCE_PATH_ATTR = 'data-provisioning-repo-path';

/**
 * Walk the rendered Markdown HTML and rewrite relative URLs (`<a href>` and
 * `<img src>`) to absolute URLs that point back to the host repository.
 * Same-page anchors (`#…`) and already-absolute URLs are left untouched.
 *
 * Links go to the host's web view (blob/tree). Images go to the host's raw
 * file URL so they actually render inline.
 *
 * Best-effort: if the host doesn't have a known URL pattern (e.g. local
 * repos), the broken relative attribute is removed so it doesn't render as
 * a clickable but non-functional link or a broken image with the relative
 * path leaking into the page.
 */
export function rewriteRelativeMarkdownLinks(html: string, options: RewriteOptions): string {
  if (typeof DOMParser === 'undefined') {
    return html;
  }

  const doc = new DOMParser().parseFromString(html, 'text/html');

  // Only this rewriter decides which links resolve in-app; never trust the tag from the markdown itself.
  doc.querySelectorAll(`[${RESOURCE_PATH_ATTR}]`).forEach((el) => el.removeAttribute(RESOURCE_PATH_ATTR));

  doc.querySelectorAll('a[href]').forEach((anchor) => {
    const href = anchor.getAttribute('href');
    if (!href || isAbsoluteUrl(href) || href.startsWith('#')) {
      return;
    }

    const result = resolveRepoRelativePath(options.baseDirInRepo, href);
    if (!result) {
      return;
    }

    const absolute = getRepoFileUrl({
      repoType: options.repository.type,
      url: options.repository.url,
      branch: options.repository.branch,
      filePath: result.path,
    });

    if (absolute) {
      anchor.setAttribute('href', absolute + result.suffix);
      anchor.setAttribute('target', '_blank');
      anchor.setAttribute('rel', 'noopener noreferrer');
    } else {
      // No host link pattern (e.g. local repo) — strip the broken relative
      // href so it doesn't render as a clickable but non-functional link.
      anchor.removeAttribute('href');
    }

    // Tag JSON/YAML/folder/markdown links so the README click handler can resolve
    // them to the in-app Grafana page. Done regardless of the host URL so links in
    // repos without one (local/git) still resolve via the resource listing.
    if (isResourceLinkCandidate(result.path)) {
      anchor.setAttribute(RESOURCE_PATH_ATTR, result.path);
    }
  });

  doc.querySelectorAll('img[src]').forEach((img) => {
    const src = img.getAttribute('src');
    if (!src || isAbsoluteUrl(src)) {
      return;
    }

    const result = resolveRepoRelativePath(options.baseDirInRepo, src);
    if (!result) {
      return;
    }

    const absolute = getRepoRawFileUrl({
      repoType: options.repository.type,
      url: options.repository.url,
      branch: options.repository.branch,
      filePath: result.path,
    });

    if (absolute) {
      img.setAttribute('src', absolute + result.suffix);
    } else {
      // Strip a broken relative src so the alt text takes over instead of a
      // broken-image icon pointing at the Grafana app's own URL space.
      img.removeAttribute('src');
    }
  });

  return doc.body.innerHTML;
}

export const XLINK_NS = 'http://www.w3.org/1999/xlink';
const RESOURCE_URL_ATTRS = new Set(['src', 'poster', 'background']);
// Anything that can make CSS fetch a resource, other than a same-document `url(#id)`.
// Escapes are refused outright since they can spell any of these.
const CSS_RESOURCE_RE = /\\|@import|image-set|image\(|src\(|url\(\s*(?!['"]?#)/i;

/**
 * Final pass over rendered README HTML (or a diagram's SVG). The markdown comes
 * from anyone who can commit to the repository, and any request it makes to
 * Grafana carries the viewer's session — `/logout` signs them out, `?orgId=N`
 * switches their organization. So:
 *
 * - links keep their href only when it is an http(s) URL on the repository's git
 *   host, and always open in a new tab; every other link (Grafana URLs, other
 *   schemes, protocol-relative, query-only, fragments) loses its href.
 * - embedded resources (images, media, SVG references, CSS) are dropped when they
 *   would load from Grafana's own host or over a non-http(s) scheme.
 *
 * Fails closed: without a DOM parser nothing is rendered.
 */
export function restrictReadmeUrls(html: string, repositoryUrl: string | undefined): string {
  if (typeof DOMParser === 'undefined') {
    return '';
  }

  const doc = new DOMParser().parseFromString(html, 'text/html');

  doc.body.querySelectorAll('*').forEach((el) => {
    const tag = el.localName.toLowerCase();
    if (tag === 'style') {
      if (CSS_RESOURCE_RE.test(el.textContent ?? '')) {
        el.remove();
      }
      return;
    }

    const isLink = tag === 'a' || tag === 'area';
    if (isLink) {
      restrictLink(el, repositoryUrl);
    }

    for (const attr of Array.from(el.attributes)) {
      const name = attr.localName.toLowerCase();
      if (name === 'srcset') {
        el.removeAttributeNode(attr);
      } else if (name === 'style') {
        if (CSS_RESOURCE_RE.test(attr.value)) {
          el.removeAttributeNode(attr);
        }
      } else if (RESOURCE_URL_ATTRS.has(name) || (name === 'href' && !isLink)) {
        // SVG elements reference their own definitions with `href="#id"`.
        const internalRef = name === 'href' && attr.value.trim().startsWith('#');
        if (!internalRef && !isExternalResourceUrl(attr.value)) {
          el.removeAttributeNode(attr);
        }
      }
    }
  });

  return doc.body.innerHTML;
}

/**
 * The normalized href when it may stay on a README link: an absolute http(s) URL
 * on the repository's git host. Anything else returns undefined.
 */
export function getAllowedReadmeLink(href: string | null, repositoryUrl: string | undefined): string | undefined {
  const gitHostOrigin = getGitHostOrigin(repositoryUrl);
  if (!href || !gitHostOrigin) {
    return undefined;
  }
  let url: URL;
  try {
    // No base: relative, query-only and protocol-relative addresses are refused.
    url = new URL(href);
  } catch {
    return undefined;
  }
  if (url.origin !== gitHostOrigin || isGrafanaHost(url)) {
    return undefined;
  }
  return url.href;
}

function restrictLink(link: Element, repositoryUrl: string | undefined) {
  const allowed = getAllowedReadmeLink(
    link.getAttribute('href') ?? link.getAttributeNS(XLINK_NS, 'href'),
    repositoryUrl
  );
  link.removeAttribute('href');
  link.removeAttributeNS(XLINK_NS, 'href');
  if (allowed) {
    link.setAttribute('href', allowed);
    link.setAttribute('target', '_blank');
    link.setAttribute('rel', 'noopener noreferrer');
  } else {
    link.removeAttribute('target');
  }
}

function getGitHostOrigin(repositoryUrl: string | undefined): string | undefined {
  if (!repositoryUrl) {
    return undefined;
  }
  try {
    const url = new URL(buildCleanBaseUrl(repositoryUrl));
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.origin : undefined;
  } catch {
    return undefined;
  }
}

function isExternalResourceUrl(value: string): boolean {
  try {
    const url = new URL(value, window.location.href);
    return (url.protocol === 'https:' || url.protocol === 'http:') && !isGrafanaHost(url);
  } catch {
    return false;
  }
}

// Cookies are scoped to the host, not the port, so any port on Grafana's host counts.
function isGrafanaHost(url: URL): boolean {
  return url.hostname === window.location.hostname;
}

function isAbsoluteUrl(url: string): boolean {
  return SCHEME_RE.test(url) || url.startsWith('//');
}

/**
 * Resolve a relative path against the README's directory inside the repo.
 * `/foo` is treated as repo-root-relative. Trailing slashes are preserved so
 * directories produce a tree URL upstream.
 */
function resolveRepoRelativePath(baseDir: string, relPath: string): { path: string; suffix: string } | undefined {
  // Split off query/fragment suffix while preserving it for later reattachment.
  const suffixIdx = relPath.search(/[?#]/);
  const pathPart = suffixIdx === -1 ? relPath : relPath.slice(0, suffixIdx);
  const suffix = suffixIdx === -1 ? '' : relPath.slice(suffixIdx);

  if (!pathPart) {
    return undefined;
  }

  // Decode percent-escapes so downstream encodeURIComponent doesn't double-encode.
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathPart);
  } catch {
    decoded = pathPart;
  }

  const trailingSlash = decoded.endsWith('/') ? '/' : '';

  if (decoded.startsWith('/')) {
    return { path: stripLeadingSlashes(decoded), suffix };
  }

  const baseParts = baseDir.split('/').filter(Boolean);
  const relParts = decoded.split('/');
  const stack = [...baseParts];

  for (const part of relParts) {
    if (part === '..') {
      stack.pop();
    } else if (part !== '.' && part !== '') {
      stack.push(part);
    }
  }

  if (stack.length === 0) {
    return trailingSlash ? { path: trailingSlash, suffix } : undefined;
  }
  return { path: stack.join('/') + trailingSlash, suffix };
}
function stripLeadingSlashes(s: string): string {
  return s.replace(/^\/+/, '');
}

/**
 * Whether a resolved repo path could be viewed in-app: a JSON/YAML file
 * (dashboard, playlist, folder metadata, ...), a folder directory, or a `.md`
 * doc (which opens as a tab on its containing folder's page). Folders are matched
 * by their trailing slash — which the resolver preserves for directory links —
 * rather than by "no extension", so extensionless files (README, LICENSE,
 * Makefile) aren't tagged and never trigger a lookup. Links that fail this
 * (images, arbitrary files) are left as plain host links.
 */
export function isResourceLinkCandidate(path: string): boolean {
  if (path.endsWith('/')) {
    return true;
  }
  const lastSegment = path.slice(path.lastIndexOf('/') + 1);
  return /\.(json|ya?ml)$/i.test(lastSegment) || isMarkdownFile(lastSegment);
}
