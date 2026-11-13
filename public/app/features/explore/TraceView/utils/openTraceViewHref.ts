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
  // The sanitizer blanks protocol-relative URLs (`//…`), so give them this page's protocol and open them in a new tab.
  const trimmed = href.trim();
  const withProtocol = trimmed.startsWith('//') ? `${window.location.protocol}${trimmed}` : trimmed;
  const sanitized = textUtil.sanitizeUrl(withProtocol).trim();
  if (!sanitized || sanitized === 'about:blank') {
    return undefined;
  }

  // Same-tab only for Grafana paths.
  if (sanitized.startsWith('/')) {
    return { href: sanitized, sameTab: true };
  }

  try {
    const url = new URL(sanitized);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return undefined;
    }
    if (url.origin === window.location.origin) {
      return { href: `${url.pathname}${url.search}${url.hash}`, sameTab: true };
    }
    return { href: url.href, sameTab: false };
  } catch {
    // Schemeless leftovers such as "explore" stay same-tab; anything with a colon is rejected.
    if (!sanitized.includes(':')) {
      return { href: sanitized, sameTab: true };
    }
    return undefined;
  }
}
