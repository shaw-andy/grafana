import { locationUtil, urlUtil } from '@grafana/data';
import { locationService, navigationLogger } from '@grafana/runtime';

import { contextSrv } from '../../services/context_srv';

export function interceptLinkClicks(e: MouseEvent) {
  const anchor = e.target instanceof Element && getParentAnchor(e.target);

  // Ignore if opening new tab or already default prevented
  if (e.ctrlKey || e.metaKey || e.defaultPrevented) {
    return;
  }

  if (anchor) {
    let href = anchor.getAttribute('href');
    const target = anchor.getAttribute('target');

    if (href && !target) {
      const params = urlUtil.parseKeyValue(href.split('?')[1]);
      const orgIdChange = params.orgId && Number(params.orgId) !== contextSrv.user.orgId;
      navigationLogger('utils', false, 'intercepting link click', e);
      e.preventDefault();

      href = locationUtil.stripBaseFromUrl(href);

      // Ensure old angular urls with no starting '/' are handled the same as before
      // Make sure external links are handled correctly
      // That is they where seen as being absolute from app root
      if (href[0] !== '/' || orgIdChange) {
        // if it has its own protocol or is a mailto link, it's an absolute link to another domain or web application
        if (isExplicitExternalLink(href)) {
          window.location.href = href;
          return;
        } else if (orgIdChange) {
          // Switching organization needs a full page load, which must stay on this server
          const destination = pathOnThisServer(href);
          if (destination) {
            window.location.href = destination;
          } else {
            navigationLogger('utils', false, 'ignoring link that leaves this server', href);
          }
          return;
        } else if (href.indexOf('#') === 0) {
          // If it is a hash click, update the hash instead of trying to update the history
          window.location.hash = href;
          return;
        } else {
          href = `/${href}`;
        }
      }

      if (!pathOnThisServer(href)) {
        navigationLogger('utils', false, 'ignoring link that leaves this server', href);
        return;
      }
      locationService.push(href);
    }
  }
}

function isExplicitExternalLink(href: string): boolean {
  if (href.indexOf('://') <= 0 && href.indexOf('mailto:') !== 0) {
    return false;
  }
  // "//host/?next=https://..." contains "://" but has no scheme of its own
  try {
    new URL(href);
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolves href the way the browser does and returns it as a path on this server,
 * or undefined when it resolves to another origin (for example //host, \\host or /\host).
 */
function pathOnThisServer(href: string): string | undefined {
  let destination: URL;
  try {
    destination = new URL(href, document.baseURI);
  } catch {
    return undefined;
  }

  // A path starting with "//" would itself be read as another host
  if (destination.origin !== window.location.origin || destination.pathname.startsWith('//')) {
    return undefined;
  }

  return `${destination.pathname}${destination.search}${destination.hash}`;
}

function getParentAnchor(element: Element | null): Element | null {
  while (element !== null && element.tagName) {
    if (element.tagName.toUpperCase() === 'A') {
      return element;
    }
    element = element.parentElement;
  }

  return null;
}
