import { act } from '@testing-library/react';
import { fromFetch } from 'rxjs/fetch';
import { render, waitFor } from 'test/test-utils';

import { locationSearchToObject, locationService, setBackendSrv } from '@grafana/runtime';
import { appEvents } from 'app/core/app_events';
import { getRouteComponentProps } from 'app/core/navigation/mocks/routeProps';
import { BackendSrv } from 'app/core/services/backend_srv';
import { contextSrv } from 'app/core/services/context_srv';
import { fetchCommunityDashboard } from 'app/features/dashboard/dashgrid/DashboardLibrary/api/dashboardLibraryApi';
import { DashboardImportK8s } from 'app/features/manage-dashboards/import/components/DashboardImportK8s';
import { DashboardRoutes } from 'app/types/dashboard';

import { DashboardScenePageStateManager } from './DashboardScenePageStateManager';

jest.mock('@fingerprintjs/fingerprintjs', () => ({
  load: () => Promise.resolve({ get: () => Promise.resolve({ visitorId: 'visitor' }) }),
}));

/**
 * Document base URL used by Grafana's index page when AppSubUrl is empty.
 * Relative fetch URLs are resolved against this, not against /dashboard/template.
 */
const APP_ROOT = 'http://localhost/';

type IssuedRequest = {
  pathname: string;
  method: string;
  credentials: string;
};

type CapturedFetch = {
  url: string;
  method: string;
  credentials: string;
};

const captured: CapturedFetch[] = [];

function installFetchCapture() {
  captured.length = 0;
  window.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    captured.push({
      url,
      method: init?.method ?? (typeof input === 'object' && 'method' in input ? input.method : 'GET'),
      credentials: init?.credentials ?? 'same-origin',
    });
    return new Response(
      JSON.stringify({
        json: { title: 'Template', schemaVersion: 40, panels: [], uid: '' },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    );
  }) as typeof window.fetch;
}

function issuedRequests(): IssuedRequest[] {
  return captured.map((call) => ({
    pathname: new URL(call.url, document.baseURI).pathname,
    method: call.method,
    credentials: call.credentials,
  }));
}

const NUMERIC_GNET_DASHBOARD = /^\/api\/gnet\/dashboards\/\d+$/;

function sessionChangingRequests(): IssuedRequest[] {
  return issuedRequests().filter((request) => {
    if (NUMERIC_GNET_DASHBOARD.test(request.pathname)) {
      return false;
    }
    return (
      request.pathname === '/logout' ||
      request.pathname.startsWith('/profile/switch-org/') ||
      request.pathname.startsWith('/api/gnet/') ||
      request.pathname.endsWith('/logout') ||
      request.pathname.includes('/switch-org/')
    );
  });
}

function setTemplateQuery(search: string) {
  const query = search.startsWith('?') ? search : `?${search}`;
  window.history.replaceState(null, '', `/dashboard/template${query}`);
  locationService.push({ pathname: '/dashboard/template', search: query });
}

async function loadTemplate(search: string) {
  setTemplateQuery(search);
  const manager = new DashboardScenePageStateManager({});
  try {
    await manager.fetchDashboard({ uid: '', route: DashboardRoutes.Template });
  } catch {
    // Refusal, or a response that is not a dashboard, is safe when no session-changing request was sent.
  }
}

describe('Grafana.com dashboard id requests', () => {
  beforeEach(() => {
    document.head.querySelector('base')?.remove();
    const base = document.createElement('base');
    base.href = '/';
    document.head.appendChild(base);

    installFetchCapture();
    setBackendSrv(
      new BackendSrv({
        fromFetch,
        appEvents,
        contextSrv,
        logout: () => undefined,
      })
    );
  });

  describe('template route', () => {
    it.each([
      ['parent segments and logout', '?gnetId=../../../logout&mappings=%5B%5D'],
      ['parent segments and organization switch', '?gnetId=../../../profile/switch-org/2&mappings=%5B%5D'],
      ['a numeric prefix before parent segments', '?gnetId=969/../../../logout&mappings=%5B%5D'],
      ['percent-encoded parent segments', '?gnetId=%2e%2e%2f%2e%2e%2f%2e%2e%2flogout&mappings=%5B%5D'],
      ['twice-encoded parent segments', '?gnetId=%252e%252e%252f%252e%252e%252f%252e%252e%252flogout&mappings=%5B%5D'],
    ])('does not request a community dashboard when gnetId is %s', async (_label, search) => {
      expect(document.baseURI).toBe(APP_ROOT);

      await loadTemplate(search);

      expect(sessionChangingRequests()).toEqual([]);
    });

    it.each([
      ['parent segments and logout', '?gnetId=../../../logout&datasource=prom&pluginId=prometheus'],
      [
        'parent segments and organization switch',
        '?gnetId=../../../profile/switch-org/2&datasource=prom&pluginId=prometheus',
      ],
      [
        'percent-encoded parent segments',
        '?gnetId=%2e%2e%2f%2e%2e%2f%2e%2e%2flogout&datasource=prom&pluginId=prometheus',
      ],
    ])('does not request a Grafana dashboard template when gnetId is %s', async (_label, search) => {
      await loadTemplate(search);

      expect(sessionChangingRequests()).toEqual([]);
    });

    it('requests a decimal community dashboard id with the session cookie', async () => {
      await loadTemplate('?gnetId=969&mappings=%5B%5D');

      expect(issuedRequests().filter((request) => NUMERIC_GNET_DASHBOARD.test(request.pathname))).toEqual([
        { pathname: '/api/gnet/dashboards/969', method: 'GET', credentials: 'same-origin' },
      ]);
    });

    it('requests a decimal Grafana dashboard template id with the session cookie', async () => {
      await loadTemplate('?gnetId=969&datasource=prom&pluginId=prometheus');

      expect(issuedRequests().filter((request) => NUMERIC_GNET_DASHBOARD.test(request.pathname))).toEqual([
        { pathname: '/api/gnet/dashboards/969', method: 'GET', credentials: 'same-origin' },
      ]);
    });
  });

  describe('dashboard import', () => {
    async function openImport(search: string) {
      const parsed = locationSearchToObject(search);
      const gcomDashboardId = parsed.gcomDashboardId;
      const props = getRouteComponentProps({
        queryParams: { gcomDashboardId: typeof gcomDashboardId === 'string' ? gcomDashboardId : undefined },
        route: { path: '/dashboard/import', component: () => null },
      });

      render(<DashboardImportK8s {...props} />);
      await waitFor(() => {
        expect(issuedRequests().some((request) => NUMERIC_GNET_DASHBOARD.test(request.pathname))).toBe(true);
      });
    }

    it.each([
      ['parent segments and logout', '?gcomDashboardId=../../../logout'],
      ['parent segments and organization switch', '?gcomDashboardId=../../../profile/switch-org/2'],
      ['percent-encoded parent segments', '?gcomDashboardId=%2e%2e%2f%2e%2e%2f%2e%2e%2flogout'],
    ])('does not request a dashboard when gcomDashboardId is %s', async (_label, search) => {
      const parsed = locationSearchToObject(search);
      const props = getRouteComponentProps({
        queryParams: {
          gcomDashboardId: typeof parsed.gcomDashboardId === 'string' ? parsed.gcomDashboardId : undefined,
        },
        route: { path: '/dashboard/import', component: () => null },
      });

      render(<DashboardImportK8s {...props} />);
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 20));
      });

      expect(sessionChangingRequests()).toEqual([]);
    });

    it('requests a decimal gcom dashboard id with the session cookie', async () => {
      await openImport('?gcomDashboardId=969');

      expect(issuedRequests().filter((request) => NUMERIC_GNET_DASHBOARD.test(request.pathname))).toEqual([
        { pathname: '/api/gnet/dashboards/969', method: 'GET', credentials: 'same-origin' },
      ]);
    });
  });

  describe('community dashboard fetch', () => {
    it('does not request a dashboard when the id is not a decimal integer', async () => {
      try {
        await fetchCommunityDashboard('../../../logout' as unknown as number);
      } catch {
        // Refusal is safe when no session-changing request was sent.
      }

      expect(sessionChangingRequests()).toEqual([]);
    });

    it('requests a decimal dashboard id with the session cookie', async () => {
      try {
        await fetchCommunityDashboard(969);
      } catch {
        // Interpolation is not under test. The request is.
      }

      expect(issuedRequests().filter((request) => NUMERIC_GNET_DASHBOARD.test(request.pathname))).toEqual([
        { pathname: '/api/gnet/dashboards/969', method: 'GET', credentials: 'same-origin' },
      ]);
    });
  });
});
