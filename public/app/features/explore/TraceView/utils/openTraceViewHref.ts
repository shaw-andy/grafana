import { locationUtil, textUtil } from '@grafana/data';
import { locationService } from '@grafana/runtime';

type ResolvedTraceViewHref = {
  href: string;
  sameTab: boolean;
};

export type TraceViewLinkAttrs = {
  href: string;
  target: '_self' | '_blank';
  rel?: 'noopener noreferrer';
};

/** Same-tab Grafana routes via the router; other http(s) origins in a new tab. */
export function openTraceViewHref(href: string): void {
  const resolved = resolveTraceViewHref(href);
  if (!resolved) {
    return;
  }
  if (resolved.sameTab) {
    locationService.push(locationUtil.stripBaseFromUrl(resolved.href));
    return;
  }
  window.open(resolved.href, '_blank', 'noopener,noreferrer');
}

/** Sanitized href/target for anchors (cmd-click / middle-click). */
export function getTraceViewLinkAttrs(href: string): TraceViewLinkAttrs | undefined {
  const resolved = resolveTraceViewHref(href);
  if (!resolved) {
    return undefined;
  }
  if (resolved.sameTab) {
    return { href: resolved.href, target: '_self' };
  }
  return { href: resolved.href, target: '_blank', rel: 'noopener noreferrer' };
}

function resolveTraceViewHref(href: string): ResolvedTraceViewHref | undefined {
  const sanitized = textUtil.sanitizeUrl(href).trim();
  if (!sanitized || sanitized === 'about:blank') {
    return undefined;
  }

  // Resolve exactly as the anchor would, so `/\host`, `\\host` and stripped tabs/newlines cannot
  // reach another host while looking like a Grafana path.
  let url: URL;
  try {
    url = new URL(sanitized, document.baseURI);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return undefined;
  }
  if (url.origin !== window.location.origin) {
    return { href: url.href, sameTab: false };
  }

  // A same-origin URL whose path starts with `//` or `/\` is protocol-relative once the origin is dropped.
  const path = `${url.pathname}${url.search}${url.hash}`;
  if (!isSingleSlashPath(path)) {
    return undefined;
  }
  return { href: path, sameTab: true };
}

function isSingleSlashPath(path: string): boolean {
  return path.startsWith('/') && path[1] !== '/' && path[1] !== '\\';
}
