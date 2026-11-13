/**
 * @jest-environment-options {"url": "http://127.0.0.1:18765/d/uid/panel", "customExportConditions": ["@grafana-app/source", "browser"]}
 *
 * A saved TestData streaming_client fetch query must not make the viewer's
 * browser request a dashboard-supplied URL. These tests fail while that
 * request is still issued.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { fetch as whatwgFetch, Request as WhatwgRequest } from 'whatwg-fetch';

import {
  CoreApp,
  dateTime,
  type DataQueryRequest,
  type DataSourceInstanceSettings,
} from '@grafana/data';
import type { TemplateSrv } from '@grafana/runtime';

import { type TestDataDataQuery, TestDataQueryType } from './dataquery';
import { TestDataDataSource } from './datasource';

const PAGE_ORIGIN = 'http://127.0.0.1:18765';
const OTHER_ORIGIN = 'http://127.0.0.1:18766';
const SESSION_COOKIE = 'grafana_session=placeholder';

type FetchCall = {
  url: string;
  credentials: RequestCredentials;
  method: string;
};

type SeenRequest = {
  server: 'page' | 'other';
  method: string;
  path: string;
  cookie: 'present' | 'absent';
};

const seen: SeenRequest[] = [];
const fetchCalls: FetchCall[] = [];
let originalFetch: typeof fetch;
let originalRequest: typeof Request;
let pageServer: http.Server;
let otherServer: http.Server;

function record(server: SeenRequest['server']) {
  return (req: http.IncomingMessage, res: http.ServerResponse) => {
    const path = req.url ?? '';
    seen.push({
      server,
      method: req.method ?? '',
      path,
      cookie: req.headers.cookie ? 'present' : 'absent',
    });

    if (server === 'other' && path === '/bounce') {
      res.writeHead(302, { Location: `${PAGE_ORIGIN}/logout` });
      res.end();
      return;
    }

    res.writeHead(204);
    res.end();
  };
}

function listen(server: http.Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      const address = server.address() as AddressInfo;
      if (address.port !== port) {
        reject(new Error(`expected port ${port} but bound ${address.port}`));
        return;
      }
      resolve();
    });
  });
}

function close(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

beforeAll(async () => {
  pageServer = http.createServer(record('page'));
  otherServer = http.createServer(record('other'));
  await listen(pageServer, 18765);
  await listen(otherServer, 18766);
});

afterAll(async () => {
  await Promise.all([close(pageServer), close(otherServer)]);
});

beforeEach(() => {
  seen.length = 0;
  fetchCalls.length = 0;
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
  jest.spyOn(console, 'info').mockImplementation(() => undefined);
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
  document.cookie = `${SESSION_COOKIE}; Path=/`;
  originalFetch = globalThis.fetch;
  originalRequest = globalThis.Request;
  // whatwg-fetch resolves the saved URL through XMLHttpRequest against the document base
  // and applies the document cookie jar for same-origin requests. Node's Request rejects
  // a relative URL, which is not how the browser hosting this panel behaves.
  globalThis.Request = WhatwgRequest as unknown as typeof Request;
  globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    if (input instanceof Request) {
      fetchCalls.push({ url: input.url, credentials: input.credentials, method: input.method });
    } else {
      const request = new Request(input, init);
      fetchCalls.push({ url: request.url, credentials: request.credentials, method: request.method });
    }
    const pending = whatwgFetch(input as RequestInfo, init);
    pending.catch(() => undefined);
    return pending;
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  globalThis.Request = originalRequest;
  jest.restoreAllMocks();
});

function datasource(): TestDataDataSource {
  const settings = {
    uid: 'testdata',
    type: 'grafana-testdata-datasource',
    name: 'TestData',
    access: 'proxy',
    readOnly: true,
    jsonData: {},
    meta: { id: 'grafana-testdata-datasource', name: 'TestData', type: 'datasource', info: { author: { name: '' }, version: '1', links: [] } },
  } as DataSourceInstanceSettings;
  const templateSrv = {
    replace: (target?: string) => target ?? '',
  } as TemplateSrv;
  return new TestDataDataSource(settings, templateSrv);
}

function requestFor(target: TestDataDataQuery): DataQueryRequest<TestDataDataQuery> {
  const now = dateTime('2026-01-01T00:00:00.000Z');
  return {
    requestId: 'req',
    interval: '1s',
    intervalMs: 1000,
    maxDataPoints: 10,
    range: { from: now, to: now, raw: { from: 'now-1h', to: 'now' } },
    scopedVars: {},
    targets: [target],
    timezone: 'utc',
    app: CoreApp.Dashboard,
    startTime: now.valueOf(),
    panelId: 7,
  };
}

async function openPanel(target: TestDataDataQuery) {
  const subscription = datasource()
    .query(requestFor(target))
    .subscribe({ error: () => undefined });
  await new Promise((resolve) => setTimeout(resolve, 300));
  subscription.unsubscribe();
}

function fetchQuery(url: string): TestDataDataQuery {
  return {
    refId: 'A',
    scenarioId: TestDataQueryType.StreamingClient,
    stream: { type: 'fetch', url, speed: 250, spread: 3.5, noise: 2.2, bands: 1 },
  };
}

const attackerUrls: Array<[string, string]> = [
  ['relative logout path', '/logout'],
  ['relative organization-switch path', '/profile/switch-org/2'],
  ['relative session-rotation path', '/user/auth-tokens/rotate'],
  ['absolute logout URL on the page origin', `${PAGE_ORIGIN}/logout`],
  ['absolute organization-switch URL on the page origin', `${PAGE_ORIGIN}/profile/switch-org/2`],
  ['absolute session-rotation URL on the page origin', `${PAGE_ORIGIN}/user/auth-tokens/rotate`],
  ['logout path with a leading space', ' /logout'],
  ['logout path with a trailing space', '/logout '],
  ['session-rotation path with a leading tab', '\t/user/auth-tokens/rotate'],
  ['organization-switch path with a leading newline', '\n/profile/switch-org/2'],
  ['uppercase-scheme logout URL', 'HTTP://127.0.0.1:18765/logout'],
  ['logout URL with a query string', `${PAGE_ORIGIN}/logout?next=/`],
  ['protocol-relative URL on another host', '//127.0.0.1:18766/collect'],
  ['absolute URL on another host', `${OTHER_ORIGIN}/collect`],
  ['slash-prefixed URL that parses as another host', '///logout'],
  ['other host that redirects to the page logout path', `${OTHER_ORIGIN}/bounce`],
];

describe('TestData streaming_client fetch', () => {
  it.each(attackerUrls)('does not request a saved %s', async (_name, url) => {
    await openPanel(fetchQuery(url));

    expect({ fetchCalls, requests: seen.slice() }).toEqual({ fetchCalls: [], requests: [] });
  });

  it('does not request a URL when the panel query is a signal stream', async () => {
    await openPanel({
      refId: 'A',
      scenarioId: TestDataQueryType.StreamingClient,
      stream: { type: 'signal', speed: 250, spread: 3.5, noise: 2.2, bands: 1 },
    });

    expect({ fetchCalls, requests: seen.slice() }).toEqual({ fetchCalls: [], requests: [] });
  });
});
