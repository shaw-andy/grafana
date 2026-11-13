import { URL as NodeURL } from 'node:url';
import { initTemplateSrv } from 'test/helpers/initTemplateSrv';

import { type GrafanaConfig, locationUtil, textUtil } from '@grafana/data';
import { sanitizeUrl } from '@grafana/data/internal';
import { getTemplateSrv, setTemplateSrv } from '@grafana/runtime';
import { type DashboardLink, type DataLink } from '@grafana/schema';
import { updateConfig } from 'app/core/config';
import { contextSrv } from 'app/core/services/context_srv';
import { LinkSrv } from 'app/features/panel/panellinks/link_srv';

import { interceptLinkClicks } from './interceptLinkClicks';

/**
 * Page the link is opened from. Jest's jsdom document is http://localhost/, and
 * the destination check below resolves against this same absolute URL.
 */
const PAGE_HREF = 'http://localhost/d/abc';
const SIGNED_IN_ORG_ID = 1;
const OTHER_ORG_ID = 2;

/**
 * Addresses that do not contain "://" (so the click handler does not treat them
 * as explicit external links) but that the URL parser resolves to another host
 * when the base is this page. Confirmed with Node's URL parser and with
 * whatwg-url 11.0.0, the parser jsdom 20.0.2 uses for location assignment.
 */
const OFF_ORIGIN_APP_URLS = [
  `//attacker.example/capture?orgId=${OTHER_ORG_ID}`,
  `//attacker.example/capture?redirect=1&orgId=${OTHER_ORG_ID}`,
  `///attacker.example/capture?orgId=${OTHER_ORG_ID}`,
  `/\\attacker.example/capture?orgId=${OTHER_ORG_ID}`,
  `\\\\attacker.example/capture?orgId=${OTHER_ORG_ID}`,
  `//attacker.example\\@localhost/capture?orgId=${OTHER_ORG_ID}`,
  `//localhost.attacker.example/capture?orgId=${OTHER_ORG_ID}`,
];

function destinationOrigin(href: string): string {
  return new NodeURL(href, PAGE_HREF).origin;
}

/** True when following href from this page would load a different origin. about:blank is the sanitizer's inert result. */
function leavesThisServer(href: string): boolean {
  const destination = new NodeURL(href, PAGE_HREF);
  if (destination.origin === destinationOrigin(PAGE_HREF)) {
    return false;
  }
  return !(destination.protocol === 'about:' && destination.pathname === 'blank');
}

function dashboardLink(url: string, targetBlank = false): DashboardLink {
  return {
    type: 'link',
    title: 'Documentation',
    url,
    icon: 'doc',
    tooltip: '',
    targetBlank,
    asDropdown: false,
    keepTime: false,
    includeVars: false,
    tags: [],
  };
}

/**
 * DashboardLinkRenderer puts sanitizeUrl(getAnchorInfo().href) on an anchor and
 * leaves the target unset when "open in new tab" is off.
 */
function hrefOnDashboardLink(linkSrv: LinkSrv, url: string, targetBlank = false): string {
  return sanitizeUrl(linkSrv.getAnchorInfo(dashboardLink(url, targetBlank)).href);
}

function installLocationRecorder() {
  const page = new NodeURL(PAGE_HREF);
  const assigned: string[] = [];
  const win = window as unknown as { location: Location };
  const previous = win.location;
  // jsdom's Location href setter parses the URL and then refuses to navigate, so the
  // document URL would not change. Record the string the handler assigns; the assertion
  // resolves that string with the URL parser the browser uses to choose the host.
  // @ts-expect-error jsdom tests replace Location with a recorder. See GoToSnapshotOriginButton.test.tsx.
  delete win.location;
  let current = PAGE_HREF;
  win.location = {
    assign(value: string) {
      this.href = value;
    },
    replace(value: string) {
      this.href = value;
    },
    reload() {},
    ancestorOrigins: previous.ancestorOrigins,
    origin: page.origin,
    protocol: page.protocol,
    host: page.host,
    hostname: page.hostname,
    port: page.port,
    pathname: page.pathname,
    search: page.search,
    hash: page.hash,
    toString() {
      return current;
    },
  } as Location;
  Object.defineProperty(win.location, 'href', {
    configurable: true,
    get() {
      return current;
    },
    set(value: string) {
      assigned.push(String(value));
      current = String(value);
    },
  });

  return {
    assigned,
    restore() {
      win.location = previous;
    },
  };
}

function clickLink(href: string, target?: string) {
  const anchor = document.createElement('a');
  anchor.setAttribute('href', href);
  if (target) {
    anchor.setAttribute('target', target);
  }
  const label = document.createElement('span');
  label.textContent = 'Documentation';
  anchor.appendChild(label);
  document.body.appendChild(anchor);
  document.addEventListener('click', interceptLinkClicks);
  label.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
  document.removeEventListener('click', interceptLinkClicks);
}

describe('protocol-relative dashboard links with another org id', () => {
  let linkSrv: LinkSrv;
  let recorder: ReturnType<typeof installLocationRecorder>;

  beforeEach(() => {
    document.body.innerHTML = '';
    recorder = installLocationRecorder();
    contextSrv.user.orgId = SIGNED_IN_ORG_ID;
    updateConfig({ disableSanitizeHtml: false, appSubUrl: '' });
    locationUtil.initialize({
      config: { appSubUrl: '', disableSanitizeHtml: false } as GrafanaConfig,
      getTimeRangeForUrl: () => ({ from: 'now-1h', to: 'now' }),
      getVariablesUrlParams: () => ({}),
    });
    setTemplateSrv(initTemplateSrv('dash', []));
    linkSrv = new LinkSrv();
  });

  afterEach(() => {
    recorder.restore();
    document.body.innerHTML = '';
  });

  describe('URL sanitizer used for dashboard and panel links', () => {
    it.each(OFF_ORIGIN_APP_URLS)('sanitizeUrl does not leave %s as an address that loads another host', (url) => {
      expect(leavesThisServer(sanitizeUrl(url))).toBe(false);
      expect(leavesThisServer(textUtil.sanitizeUrl(url))).toBe(false);
    });

    it.each(OFF_ORIGIN_APP_URLS)('getLinkUrl does not return %s as an address that loads another host', (url) => {
      expect(leavesThisServer(linkSrv.getLinkUrl(dashboardLink(url)))).toBe(false);
      expect(leavesThisServer(hrefOnDashboardLink(linkSrv, url))).toBe(false);
      expect(leavesThisServer(hrefOnDashboardLink(linkSrv, url, true))).toBe(false);
    });

    it.each(OFF_ORIGIN_APP_URLS)(
      'getDataLinkUIModel does not return %s as an address that loads another host',
      (url) => {
        const link: DataLink = { title: 'Documentation', url };
        const href = linkSrv.getDataLinkUIModel(
          link,
          (value, scopedVars, format) => getTemplateSrv().replace(value, scopedVars, format),
          {}
        ).href;
        expect(leavesThisServer(href)).toBe(false);
      }
    );

    it('still returns an explicit external url unchanged', () => {
      const url = 'https://docs.example/guide';
      expect(sanitizeUrl(url)).toBe(url);
      expect(linkSrv.getLinkUrl(dashboardLink(url))).toBe(url);
    });
  });

  describe('click handler', () => {
    it.each(OFF_ORIGIN_APP_URLS)(
      'does not navigate away when a link to %s names another org and has no target',
      (url) => {
        clickLink(url);
        const departed = recorder.assigned.filter((href) => leavesThisServer(href));
        expect(departed).toEqual([]);
      }
    );

    it.each(OFF_ORIGIN_APP_URLS)(
      'does not navigate away when the clicked href is the one a dashboard link renders for %s',
      (url) => {
        clickLink(hrefOnDashboardLink(linkSrv, url));
        const departed = recorder.assigned.filter((href) => leavesThisServer(href));
        expect(departed).toEqual([]);
      }
    );

    it('still performs a same-origin organization switch', () => {
      const href = `/d/other?orgId=${OTHER_ORG_ID}`;
      clickLink(href);
      expect(recorder.assigned).toEqual([href]);
      expect(leavesThisServer(recorder.assigned[0])).toBe(false);
    });

    it('still follows an explicit external url', () => {
      const href = 'https://docs.example/guide';
      clickLink(href);
      expect(recorder.assigned).toEqual([href]);
    });

    it('still follows an explicit external url that also names another org', () => {
      const href = `https://docs.example/guide?orgId=${OTHER_ORG_ID}`;
      clickLink(href);
      expect(recorder.assigned).toEqual([href]);
    });
  });
});
