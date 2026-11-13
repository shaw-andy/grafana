import { renderMarkdown, renderTextPanelMarkdown } from './markdown';
import { sanitize, sanitizeTextPanelContent } from './sanitize';

/**
 * Spec for the text-panel media request bug. These assertions fail while img, audio,
 * video, poster, and CSS url() values can still make the browser GET a same-origin
 * Grafana route with the viewer's session cookie.
 *
 * A URL is blocked when resolving it against the page and percent-decoding the path
 * once (the same decoding net/http applies to URL.Path before the static router
 * lookup) lands on logout, organization switch, or session-token rotation.
 */

const PAGE = 'http://localhost/';

const BLOCKED_PATH = /^\/(?:logout|profile\/switch-org\/[0-9]+|user\/auth-tokens\/rotate)$/;

function decodedPathname(pathname: string): string {
  try {
    return decodeURIComponent(pathname);
  } catch {
    return pathname;
  }
}

function consider(raw: string | null | undefined, found: string[]) {
  if (!raw) {
    return;
  }
  let url: URL;
  try {
    url = new URL(raw, PAGE);
  } catch {
    return;
  }
  if (url.origin !== new URL(PAGE).origin) {
    return;
  }
  const path = decodedPathname(url.pathname);
  if (BLOCKED_PATH.test(path)) {
    found.push(path);
  }
}

/** Resource URLs the browser would request after parsing the sanitized markup. */
function sessionSubresourcePaths(html: string): string[] {
  const doc = new DOMParser().parseFromString(`<div id="root">${html}</div>`, 'text/html');
  const found: string[] = [];
  doc.querySelectorAll('*').forEach((el) => {
    if (el.hasAttribute('src')) {
      consider(el.getAttribute('src'), found);
    }
    if (el.hasAttribute('poster')) {
      consider(el.getAttribute('poster'), found);
    }
    const srcset = el.getAttribute('srcset');
    if (srcset) {
      for (const part of srcset.split(',')) {
        consider(part.trim().split(/\s+/)[0], found);
      }
    }
    const style = el.getAttribute('style');
    if (style) {
      for (const match of style.matchAll(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi)) {
        consider(match[2], found);
      }
    }
  });
  return found;
}

const DIRECT_MARKUP = [
  '<img src="/logout">',
  '<img src="/profile/switch-org/2">',
  '<img src="/user/auth-tokens/rotate">',
  '<img src="/%6Cogout">',
  '<img src="//localhost/logout">',
  '<img src="http://localhost/logout">',
  '<img src="/logout?continue=/">',
  '<audio src="/logout"></audio>',
  '<video src="/profile/switch-org/2"></video>',
  '<video poster="/logout"></video>',
  '<audio><source src="/logout"></audio>',
  '<img srcset="/logout 1x">',
  '<div style="background-image:url(/logout)"></div>',
  '<div style="list-style-image:url(/profile/switch-org/2)"></div>',
  '<div style="border-image-source:url(/user/auth-tokens/rotate)"></div>',
];

describe('text panel media must not request session routes', () => {
  it.each(DIRECT_MARKUP)('sanitizeTextPanelContent drops a session request from %s', (html) => {
    expect(sessionSubresourcePaths(sanitizeTextPanelContent(html))).toEqual([]);
  });

  it.each(DIRECT_MARKUP)('DOMPurify sanitize drops a session request from %s', (html) => {
    expect(sessionSubresourcePaths(sanitize(html))).toEqual([]);
  });

  it.each([
    '![x](/logout)',
    '![x](/profile/switch-org/2)',
    '<img src="/logout">',
    '<video poster="/user/auth-tokens/rotate"></video>',
    '<div style="background-image:url(/logout)"></div>',
  ])('renderTextPanelMarkdown drops a session request from %s', (markdown) => {
    expect(sessionSubresourcePaths(renderTextPanelMarkdown(markdown))).toEqual([]);
  });

  it.each(['![x](/logout)', '<audio src="/profile/switch-org/2"></audio>'])(
    'renderMarkdown drops a session request from %s',
    (markdown) => {
      expect(sessionSubresourcePaths(renderMarkdown(markdown))).toEqual([]);
    }
  );
});
