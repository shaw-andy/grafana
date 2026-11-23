import { screen, waitFor } from '@testing-library/react';
import { Route, Routes, useParams } from 'react-router-dom-v5-compat';
import { lastValueFrom } from 'rxjs';

import { type DataQueryRequest, getDefaultTimeRange } from '@grafana/data';
import { config, setBackendSrv } from '@grafana/runtime';
import { getRouteComponentProps } from 'app/core/navigation/mocks/routeProps';
import { backendSrv } from 'app/core/services/backend_srv';
import { getDashboardScenePageStateManager } from 'app/features/dashboard-scene/pages/DashboardScenePageStateManager';
import { PublicDashboardScenePage } from 'app/features/dashboard-scene/pages/PublicDashboardScenePage';
import { GRAFANA_DATASOURCE_NAME } from 'app/features/alerting/unified/utils/constants';
import { PublicAnnotationsDataSource } from 'app/features/query/state/DashboardQueryRunner/PublicAnnotationsDataSource';
import { publicDashboardQueryHandler } from '../../../../../packages/grafana-runtime/src/utils/publicDashboardQueryHandler';
import { GrafanaQueryType } from 'app/plugins/datasource/grafana/types';
import { render } from 'test/test-utils';
import { DashboardRoutes } from 'app/types/dashboard';

import { DashboardLoaderSrv, DashboardLoaderSrvV2, setDashboardLoaderSrv } from './DashboardLoaderSrv';

// Same origin the browser uses when <base href="/"> is the site root.
const APP_ORIGIN = 'http://grafana.example';
const SAFE_TOKEN = '11111111-1111-4111-8111-111111111111';
// One path segment, as Chrome reports location.pathname for this link.
const LOGOUT_SEGMENT = '..%2F..%2F..%2Flogout%3F.';
const ORG_SEGMENT = '..%2F..%2F..%2F%3ForgId%3D2';
const QUERY_ORG_SEGMENT = `${SAFE_TOKEN}%3ForgId%3D2`;

interface CapturedRequest {
  pathname: string;
  search: string;
  credentials: RequestCredentials | undefined;
}

function installFetchCapture() {
  const captured: CapturedRequest[] = [];
  const previous = global.fetch;
  global.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const raw = input instanceof Request ? input.url : input instanceof URL ? input.href : String(input);
    const resolved = new URL(raw, `${APP_ORIGIN}/`);
    captured.push({
      pathname: resolved.pathname,
      search: resolved.search,
      credentials: init?.credentials ?? (input instanceof Request ? input.credentials : undefined),
    });
    return new Response(JSON.stringify({ message: 'rejected' }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;

  return {
    captured,
    restore() {
      global.fetch = previous;
    },
  };
}

function assertNoSessionChangingRequest(captured: CapturedRequest[]) {
  const escaped = captured.filter(
    (request) =>
      request.pathname === '/logout' || request.pathname === '/' || new URLSearchParams(request.search).has('orgId')
  );
  expect(escaped).toEqual([]);
}

function ignoreUnhandledRejections() {
  // Jest installs its own unhandledRejection listener after beforeEach. The dashboard
  // loader keeps a floating follow-up on the same request, so a refused load rejects
  // that follow-up. The spec is the request that was issued, not that follow-up.
  process.removeAllListeners('unhandledRejection');
  process.on('unhandledRejection', () => {});
}

async function settle(work: Promise<unknown>) {
  ignoreUnhandledRejections();
  try {
    await work;
  } catch {
    // A rejected load is a valid outcome when the token is refused before the browser is asked to fetch.
  }
}

describe('public dashboard access token requests', () => {
  let capture: ReturnType<typeof installFetchCapture>;
  const previousToken = config.publicDashboardAccessToken;
  let unhandledRejectionListeners: Array<(...args: unknown[]) => void> = [];

  beforeEach(() => {
    capture = installFetchCapture();
    setBackendSrv(backendSrv);
    setDashboardLoaderSrv(new DashboardLoaderSrv());
    config.publicDashboardsEnabled = true;
    config.publicDashboardAccessToken = '';
    getDashboardScenePageStateManager().clearState();
    getDashboardScenePageStateManager().clearDashboardCache();
    jest.spyOn(console, 'error').mockImplementation(() => {});
    unhandledRejectionListeners = process.listeners('unhandledRejection') as Array<(...args: unknown[]) => void>;
  });

  afterEach(() => {
    capture.restore();
    config.publicDashboardAccessToken = previousToken;
    getDashboardScenePageStateManager().clearState();
    jest.restoreAllMocks();
    process.removeAllListeners('unhandledRejection');
    for (const listener of unhandledRejectionListeners) {
      process.on('unhandledRejection', listener);
    }
  });

  it('loads a normal access token from the public dashboard API', async () => {
    await settle(backendSrv.getPublicDashboardByUid(SAFE_TOKEN));

    expect(capture.captured).toEqual([
      {
        pathname: `/api/public/dashboards/${SAFE_TOKEN}`,
        search: '',
        credentials: 'same-origin',
      },
    ]);
  });

  it.each([
    ['logout traversal', '../../../logout?.'],
    ['home org switch', '../../../?orgId=2'],
    ['query org switch', `${SAFE_TOKEN}?orgId=2`],
  ])('does not let getPublicDashboardByUid turn %s into a session request', async (_label, token) => {
    await settle(backendSrv.getPublicDashboardByUid(token));
    assertNoSessionChangingRequest(capture.captured);
  });

  it.each([
    ['v1 loader', () => new DashboardLoaderSrv().loadDashboard('public', '', '../../../logout?.')],
    ['v2 loader', () => new DashboardLoaderSrvV2().loadDashboard('public', '', '../../../logout?.')],
    ['v1 org switch', () => new DashboardLoaderSrv().loadDashboard('public', '', '../../../?orgId=2')],
    ['v2 org switch', () => new DashboardLoaderSrvV2().loadDashboard('public', '', '../../../?orgId=2')],
  ])('does not let the %s issue a session-changing request', async (_label, load) => {
    await settle(load());
    assertNoSessionChangingRequest(capture.captured);
  });

  it('does not let a public dashboard panel query escape the API path', async () => {
    config.publicDashboardAccessToken = '../../../logout?.';
    const request = {
      targets: [{ refId: 'A' }],
      range: getDefaultTimeRange(),
      requestId: 'req-1',
      intervalMs: 1000,
      maxDataPoints: 100,
      panelId: 7,
    } as DataQueryRequest;

    await settle(lastValueFrom(publicDashboardQueryHandler(request)));
    assertNoSessionChangingRequest(capture.captured);

    capture.captured.length = 0;
    config.publicDashboardAccessToken = `${SAFE_TOKEN}?orgId=2`;
    await settle(lastValueFrom(publicDashboardQueryHandler(request)));
    assertNoSessionChangingRequest(capture.captured);
  });

  it('does not let public dashboard annotations escape the API path', async () => {
    config.publicDashboardAccessToken = '../../../logout?.';
    const ds = new PublicAnnotationsDataSource();
    await settle(
      ds.query({
        targets: [
          {
            refId: 'A',
            datasource: { uid: GRAFANA_DATASOURCE_NAME, type: 'grafana' },
            queryType: GrafanaQueryType.Annotations,
          },
        ],
        range: getDefaultTimeRange(),
        intervalMs: 1000,
        maxDataPoints: 100,
      } as DataQueryRequest)
    );
    assertNoSessionChangingRequest(capture.captured);

    capture.captured.length = 0;
    config.publicDashboardAccessToken = '../../../?orgId=2';
    await settle(
      ds.query({
        targets: [
          {
            refId: 'A',
            datasource: { uid: GRAFANA_DATASOURCE_NAME, type: 'grafana' },
            queryType: GrafanaQueryType.Annotations,
          },
        ],
        range: getDefaultTimeRange(),
        intervalMs: 1000,
        maxDataPoints: 100,
      } as DataQueryRequest)
    );
    assertNoSessionChangingRequest(capture.captured);
  });

  it.each([
    ['logout', LOGOUT_SEGMENT, '../../../logout?.'],
    ['active organization', ORG_SEGMENT, '../../../?orgId=2'],
    ['organization on the API path', QUERY_ORG_SEGMENT, `${SAFE_TOKEN}?orgId=2`],
  ])(
    'does not change the viewer session when the public dashboard route token is a %s payload',
    async (_label, segment, decoded) => {
      ignoreUnhandledRejections();
      function TokenProbe() {
        const { accessToken = '' } = useParams();
        return <div data-testid="token-probe">{accessToken}</div>;
      }

      render(
        <Routes>
          <Route
            path="/public-dashboards/:accessToken"
            element={
              <>
                <TokenProbe />
                <PublicDashboardScenePage
                  {...getRouteComponentProps({
                    route: {
                      routeName: DashboardRoutes.Public,
                      path: '/public-dashboards/:accessToken',
                      component: () => null,
                    },
                  })}
                />
              </>
            }
          />
        </Routes>,
        { historyOptions: { initialEntries: [`/public-dashboards/${segment}`] } }
      );

      expect(await screen.findByTestId('token-probe')).toHaveTextContent(decoded);

      await waitFor(() => {
        expect(getDashboardScenePageStateManager().state.isLoading).toBe(false);
      });

      assertNoSessionChangingRequest(capture.captured);
    }
  );
});

describe('public dashboard boot data token', () => {
  afterEach(() => {
    delete window.__grafanaPublicDashboardAccessToken;
    jest.resetModules();
    jest.restoreAllMocks();
  });

  it.each([
    ['logout', '../../../logout?.'],
    ['active organization', '../../../?orgId=2'],
  ])('does not request %s when the injected access token contains that path', async (_label, token) => {
    ignoreUnhandledRejections();
    jest.spyOn(console, 'error').mockImplementation(() => {});
    window.grafanaBootData = {
      ...window.grafanaBootData,
      settings: { ...window.grafanaBootData.settings, loginError: '' },
      user: { ...window.grafanaBootData.user, lightTheme: false, theme: 'dark' },
      assets: { dark: '/public/build/dark.css', light: '/public/build/light.css' },
      navTree: window.grafanaBootData.navTree ?? [],
    };
    window.__grafanaPublicDashboardAccessToken = token;
    const seen: Array<{ pathname: string; search: string }> = [];
    global.fetch = jest.fn(async (input: RequestInfo | URL) => {
      const raw = input instanceof Request ? input.url : input instanceof URL ? input.href : String(input);
      const resolved = new URL(raw, `${APP_ORIGIN}/`);
      seen.push({ pathname: resolved.pathname, search: resolved.search });
      return new Response(JSON.stringify({ settings: { loginError: '' }, user: {}, navTree: [], assets: {} }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;

    jest.resetModules();
    await import('../../../../boot/index');
    await Promise.race([
      window.__grafana_boot_data_promise,
      new Promise((resolve) => setTimeout(resolve, 1000)),
    ]).catch(() => undefined);

    const escaped = seen.filter(
      (request) =>
        request.pathname === '/logout' || request.pathname === '/' || new URLSearchParams(request.search).has('orgId')
    );
    expect(escaped).toEqual([]);
  });
});
