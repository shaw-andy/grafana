import { matchRoutes } from 'react-router-dom-v5-compat';
import { of } from 'rxjs';

import { setBackendSrv } from '@grafana/runtime';
import { type Dashboard } from '@grafana/schema';
import { BackendSrv, type BackendSrvDependencies } from 'app/core/services/backend_srv';
import { type ContextSrv } from 'app/core/services/context_srv';
import { K8sDashboardAPI } from 'app/features/dashboard/api/v1';
import { K8sDashboardV2API } from 'app/features/dashboard/api/v2';

import { ScopedResourceClient } from './client';
import { type GroupVersionResource } from './types';

// `<base href="/">` in public/views/index.html makes the document base the Grafana root.
// fetch() resolves a relative URL against that base, so parent-directory segments leave the API path.
const PAGE_BASE = 'http://grafana.example/';

const LOGOUT_NAME = '../../../../../../../../logout?';
const SWITCH_ORG_NAME = '../../../../../../../../profile/switch-org/2?';
const BACKSLASH_NAME = '..\\..\\..\\..\\..\\..\\..\\..\\logout?';

interface CapturedCall {
  url: string;
  init?: { method?: string; credentials?: RequestCredentials };
}

const captured: CapturedCall[] = [];

function percentEncodePathSegment(value: string): string {
  return value.replaceAll('.', '%2e').replaceAll('/', '%2f').replaceAll('\\', '%5c').replaceAll('?', '%3f');
}

function dashboardPath(name: string): string {
  return `/d/${percentEncodePathSegment(name)}`;
}

function uidFromDashboardPath(pathname: string): string {
  const matches = matchRoutes([{ path: '/d/:uid/:slug?' }], pathname);
  const uid = matches?.[0]?.params.uid;
  if (!uid) {
    throw new Error(`dashboard route did not match ${pathname}`);
  }
  return uid;
}

function summarize() {
  return captured.map(({ url, init }) => {
    const resolved = new URL(url, PAGE_BASE);
    return {
      path: resolved.pathname,
      search: resolved.search,
      method: init?.method,
      credentials: init?.credentials,
    };
  });
}

async function expectNoRequest(action: () => Promise<unknown>) {
  captured.length = 0;
  await action().catch(() => undefined);
  expect(summarize()).toEqual([]);
}

describe('dashboard resource names', () => {
  let backendSrv: BackendSrv;
  let client: ScopedResourceClient;

  beforeEach(() => {
    captured.length = 0;
    const fromFetch = jest.fn().mockImplementation((url: string, init?: CapturedCall['init']) => {
      captured.push({ url: String(url), init });
      return of({
        ok: false,
        status: 500,
        statusText: 'Error',
        headers: new Map(),
        text: () => Promise.resolve(''),
        redirected: false,
        type: 'basic',
        url,
      });
    });

    const dependencies: BackendSrvDependencies = {
      fromFetch,
      appEvents: { emit: jest.fn(), publish: jest.fn() } as BackendSrvDependencies['appEvents'],
      contextSrv: { user: { orgId: 1 } } as ContextSrv,
      logout: jest.fn(),
    };
    backendSrv = new BackendSrv(dependencies);
    setBackendSrv(backendSrv);
    client = new ScopedResourceClient({
      group: 'dashboard.grafana.app',
      version: 'v1beta1',
      resource: 'dashboards',
    } satisfies GroupVersionResource);
  });

  it('requests a normal dashboard under the dashboards API and sends the session cookie', async () => {
    const api = new K8sDashboardAPI();
    await api.getDashboardDTO('abc123').catch(() => undefined);

    expect(summarize()).toEqual([
      {
        path: '/apis/dashboard.grafana.app/v1beta1/namespaces/default/dashboards/abc123/dto',
        search: '',
        method: 'GET',
        credentials: 'same-origin',
      },
    ]);
  });

  it('requests a normal v2 dashboard under the dashboards API', async () => {
    const api = new K8sDashboardV2API();
    await api.getDashboardDTO('abc123').catch(() => undefined);

    expect(summarize()).toEqual([
      {
        path: '/apis/dashboard.grafana.app/v2beta1/namespaces/default/dashboards/abc123/dto',
        search: '',
        method: 'GET',
        credentials: 'same-origin',
      },
    ]);
  });

  it.each([
    ['logout', LOGOUT_NAME],
    ['organization switch', SWITCH_ORG_NAME],
    ['backslash traversal', BACKSLASH_NAME],
    ['parent directory', '..'],
    ['slash', 'foo/bar'],
    ['question mark', 'foo?'],
    ['backslash', 'foo\\bar'],
  ])('does not request %s when get, update, delete, or subresource is given that name', async (_label, name) => {
    const resource = {
      metadata: { name, resourceVersion: '1' },
      spec: {},
    };
    const calls = [
      () => client.get(name),
      () => client.subresource(name, 'dto'),
      () => client.update(resource),
      () => client.delete(name, false),
    ];
    const requests = [];
    for (const call of calls) {
      captured.length = 0;
      await call().catch(() => undefined);
      requests.push(summarize());
    }

    expect(requests).toEqual([[], [], [], []]);
  });

  it('does not request logout when the dashboard route uid is a percent-encoded traversal', async () => {
    const uid = uidFromDashboardPath(dashboardPath(LOGOUT_NAME));
    expect(uid).toBe(LOGOUT_NAME);

    const calls = [
      () => new K8sDashboardAPI().getDashboardDTO(uid),
      () => new K8sDashboardV2API().getDashboardDTO(uid),
      () => new K8sDashboardAPI().getDashboard(uid),
      () => new K8sDashboardV2API().getDashboard(uid),
      () => new K8sDashboardAPI().deleteDashboard(uid, false),
      () => new K8sDashboardV2API().deleteDashboard(uid, false),
      () =>
        new K8sDashboardAPI().saveDashboard({
          dashboard: { uid, title: 'Example' } as Dashboard,
        }),
    ];
    const requests = [];
    for (const call of calls) {
      captured.length = 0;
      await call().catch(() => undefined);
      requests.push(summarize());
    }

    expect(requests).toEqual([[], [], [], [], [], [], []]);
  });

  it('does not switch organization when the dashboard route uid is a percent-encoded traversal', async () => {
    const uid = uidFromDashboardPath(dashboardPath(SWITCH_ORG_NAME));
    expect(uid).toBe(SWITCH_ORG_NAME);

    const calls = [
      () => new K8sDashboardAPI().getDashboardDTO(uid),
      () => new K8sDashboardV2API().getDashboardDTO(uid),
    ];
    const requests = [];
    for (const call of calls) {
      captured.length = 0;
      await call().catch(() => undefined);
      requests.push(summarize());
    }

    expect(requests).toEqual([[], []]);
  });

  it('does not request logout when a public dashboard token is a percent-encoded traversal', async () => {
    const token = '../../../logout?';
    const pathname = `/public-dashboards/${percentEncodePathSegment(token)}`;
    const matches = matchRoutes([{ path: '/public-dashboards/:accessToken' }], pathname);
    expect(matches?.[0]?.params.accessToken).toBe(token);

    await expectNoRequest(() => backendSrv.getPublicDashboardByUid(matches![0]!.params.accessToken!));
  });
});
