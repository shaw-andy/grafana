/**
 * @jest-environment jsdom
 * @jest-environment-options {"url": "http://127.0.0.1:39221/dashboard/import", "customExportConditions": ["@grafana-app/source", "browser"]}
 */
import http from 'node:http';
import { type AddressInfo } from 'node:net';

import { act, cleanup } from '@testing-library/react';
import { render } from 'test/test-utils';

import { locationSearchToObject, locationService, setBackendSrv } from '@grafana/runtime';
import { getRouteComponentProps } from 'app/core/navigation/mocks/routeProps';
import { BackendSrv } from 'app/core/services/backend_srv';
import { DashboardScenePageStateManager } from 'app/features/dashboard-scene/pages/DashboardScenePageStateManager';
import { DashboardRoutes } from 'app/types/dashboard';

import { DashboardImportK8s } from './DashboardImportK8s';

jest.mock('./ImportOverview', () => ({
  ImportOverview: () => null,
}));

const ORIGIN = 'http://127.0.0.1:39221';
const SESSION_COOKIE = 'grafana_session=placeholder-session';

type Hit = { method: string; path: string; cookie: string; origin: string };

const hits: Hit[] = [];
const inflight = new Set<XMLHttpRequest>();
let server: http.Server;

const originalOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function (
  method: string,
  url: string | URL,
  async?: boolean,
  username?: string | null,
  password?: string | null
) {
  inflight.add(this);
  this.addEventListener('loadend', () => inflight.delete(this));
  return originalOpen.call(this, method, url, async ?? true, username, password);
};

const stateChanging = (path: string) => path === '/logout' || path === '/grafana/logout' || /^\/(?:grafana\/)?profile\/switch-org\/\d+$/.test(path);

function installBase(href: string) {
  document.head.querySelectorAll('base').forEach((node) => node.remove());
  const base = document.createElement('base');
  base.href = href;
  document.head.appendChild(base);
}

function renderImport(gcomDashboardId: string) {
  render(
    <DashboardImportK8s
      {...getRouteComponentProps({
        queryParams: { gcomDashboardId },
        location: {
          pathname: '/dashboard/import',
          search: `?gcomDashboardId=${encodeURIComponent(gcomDashboardId)}`,
          hash: '',
          state: null,
        },
      })}
    />
  );
}

async function renderAndSettle(gcomDashboardId: string) {
  const mark = hits.length;
  await act(async () => {
    renderImport(gcomDashboardId);
    let lastCount = hits.length;
    let quietFor = 0;
    const started = Date.now();
    while (Date.now() - started < 2000) {
      await new Promise((resolve) => setTimeout(resolve, 30));
      if (hits.length > mark && hits.length === lastCount) {
        quietFor += 30;
        if (quietFor >= 150) {
          return;
        }
      } else {
        quietFor = 0;
        lastCount = hits.length;
      }
    }
  });
}

describe('dashboard gcom id request target', () => {
  beforeAll(async () => {
    server = http.createServer((req, res) => {
      hits.push({
        method: req.method ?? '',
        path: (req.url ?? '/').split('?')[0],
        cookie: req.headers.cookie ?? '',
        origin: typeof req.headers.origin === 'string' ? req.headers.origin : '',
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ json: { title: 'Example', schemaVersion: 40, panels: [] } }));
    });
    await new Promise<void>((resolve) => {
      server.listen(39221, '127.0.0.1', () => resolve());
    });
    const address = server.address() as AddressInfo;
    if (address.port !== 39221) {
      throw new Error(`expected the probe to listen on 39221, got ${address.port}`);
    }
    setBackendSrv(new BackendSrv());
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  beforeEach(async () => {
    for (const xhr of inflight) {
      xhr.abort();
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
    hits.length = 0;
    installBase('/');
    document.cookie = `${SESSION_COOKIE}; Path=/`;
  });

  afterEach(() => {
    cleanup();
  });

  it.each([
    ['parent-directory segments followed by logout', '../../../logout'],
    ['parent-directory segments followed by an organization switch', '../../../profile/switch-org/2'],
    ['backslashes that the URL parser treats as separators', '..\\..\\..\\logout'],
  ])('does not send a signed-in import of %s to a state-changing path', async (_label, gcomDashboardId) => {
    await renderAndSettle(gcomDashboardId);

    expect(hits.filter((hit) => stateChanging(hit.path))).toEqual([]);
  });

  it.each([
    ['?gcomDashboardId=..%2F..%2F..%2Flogout', '../../../logout'],
    ['?gcomDashboardId=%2e%2e%2f%2e%2e%2f%2e%2e%2flogout', '../../../logout'],
    ['?gcomDashboardId=%2e%2e/%2e%2e/%2e%2e/logout', '../../../logout'],
    ['?gcomDashboardId=..%5C..%5C..%5Clogout', '..\\..\\..\\logout'],
  ])('decodes %s to the traversal the import page requests', (search, decoded) => {
    expect(locationSearchToObject(search).gcomDashboardId).toBe(decoded);
  });

  it('does not follow a query value that was percent-encoded before it was decoded', async () => {
    const gcomDashboardId = locationSearchToObject('?gcomDashboardId=..%2F..%2F..%2Fprofile%2Fswitch-org%2F2')
      .gcomDashboardId;
    expect(gcomDashboardId).toBe('../../../profile/switch-org/2');

    await renderAndSettle(String(gcomDashboardId));

    expect(hits.filter((hit) => stateChanging(hit.path))).toEqual([]);
  });

  it('does not retarget the request when the page base URL is an application subpath', async () => {
    installBase('/grafana/');
    await renderAndSettle('../../../logout');

    expect(hits.map((hit) => hit.path)).not.toContain('/grafana/logout');
    expect(hits.filter((hit) => stateChanging(hit.path))).toEqual([]);
  });

  it('still loads a numeric Grafana.com id and sends the session cookie', async () => {
    await renderAndSettle('1860');

    const dashboardRequests = hits.filter((hit) => hit.path === '/api/gnet/dashboards/1860');
    expect(hits.map((hit) => hit.path)).toEqual(['/api/gnet/dashboards/1860']);
    expect(dashboardRequests.map((hit) => hit.method)).toEqual(['GET']);
    expect(dashboardRequests[0].cookie).toContain(SESSION_COOKIE);
    expect(hits.filter((hit) => stateChanging(hit.path))).toEqual([]);
  });

  it('does not let a template gnetId walk to logout or switch organization', async () => {
    const payloads = ['../../../logout', '../../../profile/switch-org/2', '..\\..\\..\\logout'];

    for (const gnetId of payloads) {
      hits.length = 0;
      const search = `?gnetId=${encodeURIComponent(gnetId)}&datasource=prom&pluginId=prometheus`;
      window.history.replaceState(null, '', `/dashboard/template${search}`);
      locationService.push({ pathname: '/dashboard/template', search });

      const manager = new DashboardScenePageStateManager({});
      await manager.fetchDashboard({ uid: '', route: DashboardRoutes.Template }).catch(() => undefined);

      expect(hits.filter((hit) => stateChanging(hit.path))).toEqual([]);
    }
  });

  it('does not let a community template gnetId walk to logout', async () => {
    hits.length = 0;
    const search = `?gnetId=${encodeURIComponent('../../../logout')}&mappings=${encodeURIComponent('[]')}`;
    window.history.replaceState(null, '', `/dashboard/template${search}`);
    locationService.push({ pathname: '/dashboard/template', search });

    const manager = new DashboardScenePageStateManager({});
    await manager.fetchDashboard({ uid: '', route: DashboardRoutes.Template }).catch(() => undefined);

    expect(hits.filter((hit) => stateChanging(hit.path))).toEqual([]);
  });
});
