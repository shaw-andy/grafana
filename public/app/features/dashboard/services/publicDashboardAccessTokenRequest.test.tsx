import { Route, Routes, useParams } from 'react-router-dom-v5-compat';
import { lastValueFrom } from 'rxjs';
import { render, screen, waitFor } from 'test/test-utils';

import { type DataQueryRequest } from '@grafana/data';
import { config, setBackendSrv } from '@grafana/runtime';
import { getRouteComponentProps } from 'app/core/navigation/mocks/routeProps';
import { backendSrv } from 'app/core/services/backend_srv';
import { GRAFANA_DATASOURCE_NAME } from 'app/features/alerting/unified/utils/datasource';
import { getDashboardScenePageStateManager } from 'app/features/dashboard-scene/pages/DashboardScenePageStateManager';
import { PublicDashboardScenePage } from 'app/features/dashboard-scene/pages/PublicDashboardScenePage';
import { PublicAnnotationsDataSource } from 'app/features/query/state/DashboardQueryRunner/PublicAnnotationsDataSource';
import { DashboardRoutes } from 'app/types/dashboard';

import { publicDashboardQueryHandler } from '../../../../../packages/grafana-runtime/src/utils/publicDashboardQueryHandler';

/**
 * These tests are the spec for a path-traversal bug in public dashboard URLs.
 * They fail while the bug is present and pass once a public-dashboard access
 * token can no longer be turned into a request for /logout or /profile/switch-org/:id.
 */

const ROOT_BASE = 'http://grafana.example/';
const SUBPATH_BASE = 'http://grafana.example/grafana/';
const BENIGN_TOKEN = '00000000-0000-4000-8000-000000000001';

type CapturedRequest = {
  input: string;
  credentials?: RequestCredentials;
  method?: string;
};

const captured: CapturedRequest[] = [];
const originalFetch = global.fetch;

function browserPaths(input: string): { atRoot: string; underSubpath: string } {
  const atRoot = new URL(input, ROOT_BASE).pathname;
  const resolved = new URL(input, SUBPATH_BASE).pathname;
  const underSubpath = resolved.startsWith('/grafana/') ? resolved.slice('/grafana'.length) : resolved;
  return { atRoot, underSubpath };
}

function isPublicDashboardApi(pathname: string): boolean {
  return pathname.startsWith('/api/public/dashboards/');
}

function isBootData(pathname: string): boolean {
  return /^\/bootdata\/[^/]+$/.test(pathname);
}

function assertConfinedTo(input: string, accepts: (pathname: string) => boolean) {
  const { atRoot, underSubpath } = browserPaths(input);
  expect({
    input,
    atRoot,
    underSubpath,
    atRootAllowed: accepts(atRoot),
    underSubpathAllowed: accepts(underSubpath),
    atRootIsLogout: atRoot === '/logout',
    underSubpathIsLogout: underSubpath === '/logout',
    atRootSwitchesOrg: atRoot.startsWith('/profile/switch-org/'),
    underSubpathSwitchesOrg: underSubpath.startsWith('/profile/switch-org/'),
  }).toEqual({
    input,
    atRoot,
    underSubpath,
    atRootAllowed: true,
    underSubpathAllowed: true,
    atRootIsLogout: false,
    underSubpathIsLogout: false,
    atRootSwitchesOrg: false,
    underSubpathSwitchesOrg: false,
  });
}

function accessTokenFromLink(pathname: string): string {
  let token = '';
  render(
    <Routes>
      <Route path="/public-dashboards/:accessToken" element={<TokenProbe onToken={(value) => (token = value)} />} />
    </Routes>,
    { historyOptions: { initialEntries: [pathname] } }
  );
  return token;
}

function TokenProbe({ onToken }: { onToken: (token: string) => void }) {
  const { accessToken = '' } = useParams();
  onToken(accessToken);
  return null;
}

async function runConfined(prefix: 'api' | 'boot', operation: () => Promise<unknown>) {
  const start = captured.length;
  let thrown: unknown;
  try {
    await operation();
  } catch (error) {
    thrown = error;
  }

  const calls = captured.slice(start).filter((call) => {
    const { atRoot } = browserPaths(call.input);
    return (
      call.input.includes('public/dashboards') ||
      call.input.includes('bootdata') ||
      atRoot === '/logout' ||
      atRoot.startsWith('/profile/switch-org/') ||
      atRoot.startsWith('/logout/')
    );
  });

  const accepts = prefix === 'api' ? isPublicDashboardApi : isBootData;
  for (const call of calls) {
    assertConfinedTo(call.input, accepts);
    expect(call.credentials ?? 'same-origin').toBe('same-origin');
  }

  // A fix may refuse before fetch. A missing call with no error means the operation never ran.
  if (calls.length === 0) {
    expect(thrown).toBeTruthy();
  }
}

beforeAll(() => {
  setBackendSrv(backendSrv);
});

beforeEach(() => {
  captured.length = 0;
  global.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' || input instanceof URL ? String(input) : input.url;
    captured.push({
      input: url,
      credentials: init?.credentials,
      method: init?.method,
    });
    const body = url.includes('/annotations')
      ? []
      : {
          dashboard: { uid: 'dash', title: 'Dash', schemaVersion: 39, panels: [] },
          meta: {},
        };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
});

afterEach(() => {
  jest.restoreAllMocks();
  global.fetch = originalFetch;
  config.publicDashboardAccessToken = '';
});

describe('public dashboard access token requests', () => {
  it('loads a normal access token from the public dashboard API', async () => {
    const token = accessTokenFromLink(`/public-dashboards/${BENIGN_TOKEN}`);
    expect(token).toBe(BENIGN_TOKEN);

    await runConfined('api', () => backendSrv.getPublicDashboardByUid(token));

    const call = captured.find((entry) => entry.input.includes(BENIGN_TOKEN));
    expect(call).toBeDefined();
    expect(browserPaths(call!.input).atRoot).toBe(`/api/public/dashboards/${BENIGN_TOKEN}`);
    expect(call!.credentials).toBe('same-origin');
    expect(call!.method ?? 'GET').toBe('GET');
  });

  it('does not let an encoded parent-directory access token request logout', async () => {
    const token = accessTokenFromLink('/public-dashboards/..%2F..%2F..%2Flogout');
    expect(token).toBe('../../../logout');
    config.publicDashboardAccessToken = token;

    await runConfined('api', () => backendSrv.getPublicDashboardByUid(token));
  });

  it('does not let an encoded parent-directory access token switch organization', async () => {
    const token = accessTokenFromLink('/public-dashboards/..%2F..%2F..%2Fprofile%2Fswitch-org%2F2');
    expect(token).toBe('../../../profile/switch-org/2');

    await runConfined('api', () => backendSrv.getPublicDashboardByUid(token));
  });

  it('does not let an encoded backslash access token request logout', async () => {
    const token = accessTokenFromLink('/public-dashboards/..%5C..%5C..%5Clogout');
    expect(token).toBe('..\\..\\..\\logout');

    await runConfined('api', () => backendSrv.getPublicDashboardByUid(token));
  });

  it('does not let the public dashboard page issue that logout request', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    const tokenPath = '/public-dashboards/..%2F..%2F..%2Flogout';
    render(
      <Routes>
        <Route
          path="/public-dashboards/:accessToken"
          element={
            <PublicDashboardScenePage
              {...getRouteComponentProps({
                route: {
                  routeName: DashboardRoutes.Public,
                  path: '/public-dashboards/:accessToken',
                  component: () => null,
                },
              })}
            />
          }
        />
      </Routes>,
      { historyOptions: { initialEntries: [tokenPath] } }
    );

    await waitFor(() => {
      const requested = captured.some(
        (call) => call.input.includes('public/dashboards') || browserPaths(call.input).atRoot === '/logout'
      );
      const failedClosed = screen.queryByRole('alert') !== null;
      expect(requested || failedClosed).toBe(true);
    });

    const calls = captured.filter(
      (call) => call.input.includes('public/dashboards') || browserPaths(call.input).atRoot === '/logout'
    );
    for (const call of calls) {
      assertConfinedTo(call.input, isPublicDashboardApi);
      expect(call.credentials ?? 'same-origin').toBe('same-origin');
    }
  });

  it('does not let a panel query built from the access token leave the public dashboard API', async () => {
    const token = accessTokenFromLink('/public-dashboards/..%2F..%2F..%2Flogout%3F');
    expect(token).toBe('../../../logout?');
    config.publicDashboardAccessToken = token;

    await runConfined('api', () =>
      lastValueFrom(
        publicDashboardQueryHandler({
          targets: [{ refId: 'A' }],
          requestId: 'panel-query',
          panelId: 1,
          intervalMs: 1000,
          maxDataPoints: 100,
          range: {
            from: { valueOf: () => 1 },
            to: { valueOf: () => 2 },
            raw: { from: 'now-1h', to: 'now' },
          },
        } as unknown as DataQueryRequest)
      )
    );
  });

  it('does not let an annotation query built from the access token leave the public dashboard API', async () => {
    const token = accessTokenFromLink('/public-dashboards/..%2F..%2F..%2Flogout%3F');
    expect(token).toBe('../../../logout?');
    config.publicDashboardAccessToken = token;

    const datasource = new PublicAnnotationsDataSource();
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    await runConfined('api', () =>
      lastValueFrom(
        datasource.query({
          targets: [
            {
              refId: 'A',
              datasource: { uid: GRAFANA_DATASOURCE_NAME, type: 'datasource' },
            },
          ],
          requestId: 'annotations',
          intervalMs: 1000,
          maxDataPoints: 100,
          range: {
            from: { valueOf: () => 1 },
            to: { valueOf: () => 2 },
            raw: { from: 'now-1h', to: 'now' },
          },
        } as unknown as DataQueryRequest)
      )
    );
  });

  it('does not let boot data append the access token in a way that requests logout', async () => {
    const token = accessTokenFromLink('/public-dashboards/..%2F..%2F..%2Flogout');
    expect(token).toBe('../../../logout');
    jest.spyOn(console, 'error').mockImplementation(() => {});

    await runConfined('boot', async () => {
      window.__grafanaPublicDashboardAccessToken = token;
      let bootPromise: Promise<unknown> | undefined;
      jest.isolateModules(() => {
        require('../../../../boot/index');
        bootPromise = window.__grafana_boot_data_promise;
      });
      await bootPromise;
    });
  });
});

afterAll(() => {
  getDashboardScenePageStateManager().clearState();
});
