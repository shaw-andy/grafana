import { CoreApp, dateTime, type DataQueryRequest, type DataSourceInstanceSettings } from '@grafana/data';
import { config } from '@grafana/runtime';

import { type TestDataDataQuery } from './dataquery';
import { TestDataDataSource } from './datasource';
import { TemplateSrv } from 'app/features/templating/template_srv';

interface IssuedRequest {
  pathname: string;
  method: string;
  credentials: RequestCredentials;
}

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

describe('TestData streaming fetch saved urls', () => {
  const issued: IssuedRequest[] = [];
  const originalFetch = global.fetch;
  const originalRequest = global.Request;

  beforeAll(() => {
    config.bootData.user = {
      ...config.bootData.user,
      id: 42,
      uid: 'viewer',
      isSignedIn: true,
    };

    class DocumentBaseRequest {
      readonly url: string;
      readonly method: string;
      readonly credentials: RequestCredentials;

      constructor(input: string, init?: RequestInit) {
        const resolved = new URL(input, documentBaseURL());
        this.url = resolved.href;
        this.method = init?.method ?? 'GET';
        this.credentials = init?.credentials ?? 'same-origin';
      }
    }

    global.Request = DocumentBaseRequest as unknown as typeof Request;
    global.fetch = ((input: Request | string, init?: RequestInit) => {
      const request =
        typeof input === 'string' || !(input instanceof DocumentBaseRequest)
          ? new DocumentBaseRequest(typeof input === 'string' ? input : input.url, init)
          : input;
      const resolved = new URL(request.url);
      issued.push({ pathname: resolved.pathname, method: request.method, credentials: request.credentials });
      return Promise.resolve(new Response('', { status: 200 }));
    }) as typeof fetch;
  });

  afterAll(() => {
    global.fetch = originalFetch;
    global.Request = originalRequest;
  });

  beforeEach(() => {
    issued.length = 0;
    installDocumentBase('/', '/d/uid/slug');
  });

  function run(url: string) {
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
    const request: DataQueryRequest<TestDataDataQuery> = {
      app: CoreApp.Dashboard,
      requestId: 'req',
      timezone: 'utc',
      panelId: 1,
      dashboardUID: 'uid',
      range: { from: dateTime(0), to: dateTime(1), raw: { from: 'now-1h', to: 'now' } },
      interval: '1s',
      intervalMs: 1000,
      scopedVars: {},
      maxDataPoints: 100,
      startTime: 0,
      targets: [
        {
          refId: 'A',
          scenarioId: 'streaming_client',
          stream: { type: 'fetch', url, noise: 0, speed: 250, spread: 0 },
        },
      ],
    };
    ds.query(request).subscribe();
  }

  it.each(['/logout', '../logout', '../profile/switch-org/2', '../user/auth-tokens/rotate'])(
    'does not fetch %s with the viewer session',
    (url) => {
      run(url);
      const hits = issued.filter(
        (request) => isSessionRoute(request.pathname) && request.credentials !== 'omit'
      );
      expect(hits).toEqual([]);
    }
  );

  it('keeps the subscription from issuing a request before the url is rejected', () => {
    run('../logout');
    expect(issued).toEqual([]);
  });
});
