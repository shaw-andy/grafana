import { lastValueFrom, of } from 'rxjs';

import { CoreApp, dateTime, type DataQueryRequest, type DataSourceInstanceSettings } from '@grafana/data';
import { config, setBackendSrv } from '@grafana/runtime';
import { PanelModel } from 'app/features/dashboard/state/PanelModel';
import { TemplateSrv } from 'app/features/templating/template_srv';

import { type TestDataDataQuery } from './dataquery';
import { TestDataDataSource } from './datasource';
import { appEvents } from 'app/core/app_events';
import { BackendSrv, type BackendSrvDependencies } from 'app/core/services/backend_srv';
import { type ContextSrv } from 'app/core/services/context_srv';

interface IssuedRequest {
  pathname: string;
  search: string;
  method: string;
  credentials: RequestCredentials | undefined;
}

const sessionCookieCredentials = new Set<RequestCredentials | undefined>([undefined, 'same-origin', 'include']);

/**
 * Grafana's index document sets the base URL from the server subpath.
 * Relative fetches resolve against that base, which is what lets a saved
 * `api/../logout` climb out of `/api/`.
 */
function installDocumentBase(baseHref: string, pagePath: string) {
  window.history.pushState({}, '', pagePath);
  document.head.querySelectorAll('base').forEach((node) => node.remove());
  const base = document.createElement('base');
  base.setAttribute('href', baseHref);
  document.head.appendChild(base);
}

function documentBaseURL(): string {
  const href = document.querySelector('base')?.getAttribute('href');
  if (!href) {
    throw new Error('missing base href');
  }
  return new URL(href, window.location.href).href;
}

function isSessionRoute(pathname: string): boolean {
  return (
    pathname === '/logout' ||
    pathname.endsWith('/logout') ||
    /\/profile\/switch-org\/[^/]+$/.test(pathname) ||
    pathname.endsWith('/user/auth-tokens/rotate')
  );
}

function savedPanel(stringInput: string): PanelModel {
  return new PanelModel({
    id: 1,
    type: 'timeseries',
    datasource: { type: 'grafana-testdata-datasource', uid: 'testdata' },
    targets: [
      {
        refId: 'A',
        datasource: { type: 'grafana-testdata-datasource', uid: 'testdata' },
        scenarioId: 'grafana_api',
        stringInput,
      },
    ],
  });
}

describe('TestData grafana_api saved paths', () => {
  const issued: IssuedRequest[] = [];

  beforeAll(() => {
    config.bootData.user = {
      ...config.bootData.user,
      id: 42,
      uid: 'viewer',
      isSignedIn: true,
    };

    const backendSrv = new BackendSrv({
      fromFetch: (input, init) => {
        const raw = typeof input === 'string' ? input : input.url;
        const resolved = new URL(raw, documentBaseURL());
        issued.push({
          pathname: resolved.pathname,
          search: resolved.search,
          method: init?.method ?? 'GET',
          credentials: init?.credentials,
        });
        return of(new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } }));
      },
      appEvents,
      contextSrv: { user: { orgId: 1, isSignedIn: true } } as ContextSrv,
      logout: jest.fn(),
    } satisfies BackendSrvDependencies);
    setBackendSrv(backendSrv);
  });

  beforeEach(() => {
    issued.length = 0;
    installDocumentBase('/', '/d/uid/slug');
  });

  function requestFor(panel: PanelModel, scopedVars: DataQueryRequest<TestDataDataQuery>['scopedVars'] = {}) {
    const request: DataQueryRequest<TestDataDataQuery> = {
      app: CoreApp.Dashboard,
      requestId: 'req',
      timezone: 'utc',
      panelId: panel.id,
      dashboardUID: 'uid',
      range: { from: dateTime(0), to: dateTime(1), raw: { from: 'now-1h', to: 'now' } },
      interval: '1s',
      intervalMs: 1000,
      scopedVars,
      targets: panel.targets as TestDataDataQuery[],
      startTime: 0,
      maxDataPoints: 100,
    };
    return request;
  }

  async function runSavedQuery(stringInput: string, scopedVars?: DataQueryRequest<TestDataDataQuery>['scopedVars']) {
    const panel = savedPanel(stringInput);
    const ds = new TestDataDataSource(
      {
        id: 1,
        uid: 'testdata',
        type: 'grafana-testdata-datasource',
        name: 'TestData',
        jsonData: {},
        meta: {} as DataSourceInstanceSettings['meta'],
        access: 'proxy',
        readOnly: false,
      },
      new TemplateSrv()
    );
    await lastValueFrom(ds.query(requestFor(panel, scopedVars)));
  }

  function credentialedSessionRoutes() {
    return issued.filter(
      (request) => isSessionRoute(request.pathname) && sessionCookieCredentials.has(request.credentials)
    );
  }

  it('resolves a relative api path against the document base the way the browser does', () => {
    installDocumentBase('/', '/d/abc/my-dashboard');
    expect(documentBaseURL()).toBe(new URL('/', window.location.href).href);
    expect(new URL('api/../logout', documentBaseURL()).pathname).toBe('/logout');
    expect(new URL('api/../logout', window.location.href).pathname).toBe('/d/abc/logout');
  });

  it.each([
    ['../logout', '/logout'],
    ['../profile/switch-org/2', '/profile/switch-org/2'],
    ['../user/auth-tokens/rotate', '/user/auth-tokens/rotate'],
    ['%2e%2e/logout', '/logout'],
    ['datasources/../../logout', '/logout'],
    ['..\\logout', '/logout'],
    ['../logout?x=1', '/logout'],
  ])('does not send the viewer session to %s', async (stringInput) => {
    await runSavedQuery(stringInput);
    expect(credentialedSessionRoutes()).toEqual([]);
  });

  it('does not send the viewer session when the saved path is produced by template interpolation', async () => {
    await runSavedQuery('${path}', { path: { text: '../logout', value: '../logout' } });
    expect(credentialedSessionRoutes()).toEqual([]);
  });

  it('does not climb out of a subpath base url', async () => {
    installDocumentBase('/grafana/', '/grafana/d/uid/slug');
    await runSavedQuery('../logout');
    expect(credentialedSessionRoutes()).toEqual([]);
    expect(new URL('api/../logout', documentBaseURL()).pathname).toBe('/grafana/logout');
  });
});
