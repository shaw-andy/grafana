import { useMemo } from 'react';

import { config } from '@grafana/runtime';
import { type Annotations } from 'app/types/unified-alerting-dto';

import { Annotation } from './constants';
import { makeDashboardLink, makePanelLink } from './misc';

function normalizeHostname(hostname: string): string {
  return hostname.toLowerCase().replace(/\.+$/, '');
}

function grafanaHostnames(): Set<string> {
  const hostnames = new Set<string>();
  for (const candidate of [window.location.href, document.baseURI, config.appUrl]) {
    try {
      hostnames.add(normalizeHostname(new URL(candidate).hostname));
    } catch {
      // appUrl can be empty or relative; the other candidates still cover the current host
    }
  }
  return hostnames;
}

/**
 * Returns the href to use when rendering an annotation value as a link, or undefined if it must be rendered as text.
 *
 * Annotation values are authored by anyone who can edit the rule, so only absolute http(s) URLs pointing at another
 * host are linked. A link to this Grafana host carries the viewer's (host-only) session cookie, and several GET routes
 * on it change session state (`/logout`, `/profile/switch-org/:id`, or any page with `?orgId=`), so no path-based
 * filter can make such a link safe. The returned href is the normalized URL that was checked, so callers must use it
 * instead of the raw value.
 */
export function getAnnotationLinkHref(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return undefined;
  }

  if (grafanaHostnames().has(normalizeHostname(url.hostname))) {
    return undefined;
  }

  return url.href;
}

// Restricting the uid to these characters keeps it a single, non-dot path segment even when a proxy in front of
// Grafana decodes and normalizes the path, so `/d/<uid>` cannot be turned into another route.
const SAFE_DASHBOARD_UID = /^(?!\.+$)[A-Za-z0-9._-]+$/;

export function isLinkableDashboardUID(uid: string | undefined): uid is string {
  return Boolean(uid && SAFE_DASHBOARD_UID.test(uid));
}

function usePanelAndDashboardIds(annotations: Array<[string, string]>): {
  dashboardUID?: string;
  panelId?: string;
} {
  const dashboardUID = annotations.find(([key]) => key === Annotation.dashboardUID)?.[1];
  return {
    dashboardUID: isLinkableDashboardUID(dashboardUID) ? dashboardUID : undefined,
    panelId: annotations.find(([key]) => key === Annotation.panelID)?.[1],
  };
}

/**
 * Removes annotations with empty or whitespace values
 */
export function useCleanAnnotations(annotations: Annotations): Array<[string, string]> {
  return useMemo(() => {
    return Object.entries(annotations || {}).filter(([_, value]) => !!value.trim());
  }, [annotations]);
}

export function useAnnotationLinks(annotations: Array<[string, string]>): Map<string, string> {
  const links = new Map<string, string>();

  const { panelId, dashboardUID } = usePanelAndDashboardIds(annotations);

  if (dashboardUID) {
    links.set(Annotation.dashboardUID, makeDashboardLink(dashboardUID));
  }
  if (dashboardUID && panelId) {
    links.set(Annotation.panelID, makePanelLink(dashboardUID, panelId));
  }

  return links;
}
