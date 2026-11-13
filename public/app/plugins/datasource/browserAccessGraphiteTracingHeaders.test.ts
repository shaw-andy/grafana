// Root Jest ignores every path under public/app/plugins/datasource/graphite, and that
// plugin's own Jest config cannot load the application BackendSrv that sends the request.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { lastValueFrom } from 'rxjs';
import { fromFetch } from 'rxjs/fetch';

import { CoreApp, dateTime, type DataQueryRequest } from '@grafana/data';
import { config, getBackendSrv, setBackendSrv, type TemplateSrv } from '@grafana/runtime';

import { BackendSrv } from 'app/core/services/backend_srv';

import { GraphiteDatasource } from './graphite/datasource';
import { type GraphiteQuery } from './graphite/types';

const DASHBOARD_UID = 'dash-private-uid';
const PANEL_ID = 42;
const PANEL_PLUGIN_ID = 'timeseries';
const METRIC = 'collected.private.metric';

type Captured = {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
};

const templateSrv = {
  replace: (target?: string) => target ?? '',
} as unknown as TemplateSrv;

function panelQuery(): DataQueryRequest<GraphiteQuery> {
  return {
    app: CoreApp.Dashboard,
    requestId: 'browser-access-tracing',
    timezone: 'utc',
    panelId: PANEL_ID,
    panelPluginId: PANEL_PLUGIN_ID,
    dashboardUID: DASHBOARD_UID,
    range: {
      from: dateTime('2022-04-01T00:00:00Z'),
      to: dateTime('2022-04-01T01:00:00Z'),
      raw: { from: 'now-1h', to: 'now' },
    },
    targets: [{ refId: 'A', target: METRIC }],
    maxDataPoints: 100,
    interval: '1m',
    intervalMs: 60000,
    scopedVars: {},
    startTime: 0,
  };
}

function datasource(url: string) {
  return new GraphiteDatasource({ url, name: 'graphite-browser', jsonData: {} }, templateSrv);
}

function collect(bucket: Captured[]) {
  return (req: http.IncomingMessage, res: http.ServerResponse) => {
    if (req.method === 'OPTIONS') {
      bucket.push({ method: 'OPTIONS', url: req.url ?? '', headers: req.headers, body: '' });
      res.writeHead(204, {
        'access-control-allow-origin': '*',
        'access-control-allow-headers': '*',
        'access-control-allow-methods': 'POST, OPTIONS',
      });
      res.end();
      return;
    }

    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => {
      chunks.push(Buffer.from(chunk));
    });
    req.on('end', () => {
      bucket.push({
        method: req.method ?? '',
        url: req.url ?? '',
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      });
      const body = Buffer.from('[]');
      res.writeHead(200, {
        'content-type': 'application/json',
        'content-length': String(body.length),
        'access-control-allow-origin': '*',
        'access-control-allow-headers': '*',
      });
      res.end(body);
    });
  };
}

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('collector did not bind a TCP port'));
        return;
      }
      resolve(address.port);
    });
  });
}

function expectNoDashboardHeaders(seen: Captured[], pathname: string, bodyIncludes: string) {
  const posts = seen.filter((entry) => entry.method === 'POST' && entry.url === pathname);
  expect(posts).toHaveLength(1);
  expect(posts[0].body).toContain(bodyIncludes);
  expect(String(posts[0].headers.host)).toMatch(/^127\.0\.0\.1:/);
  expect({
    dashboard: posts[0].headers['x-dashboard-id'],
    panel: posts[0].headers['x-panel-id'],
    plugin: posts[0].headers['x-panel-plugin-id'],
  }).toEqual({
    dashboard: undefined,
    panel: undefined,
    plugin: undefined,
  });
}

describe('Graphite browser-access tracing headers', () => {
  const httpSeen: Captured[] = [];
  const httpsSeen: Captured[] = [];
  let httpPort = 0;
  let httpsPort = 0;
  let httpServer: http.Server;
  let httpsServer: https.Server;
  let previousBackend: ReturnType<typeof getBackendSrv>;
  let previousTls: string | undefined;
  let previousBackendMode: boolean | undefined;

  beforeAll(async () => {
    previousTls = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    previousBackend = getBackendSrv();
    previousBackendMode = config.featureToggles.graphiteBackendMode;

    const certDir = fs.mkdtempSync(path.join(os.tmpdir(), 'graphite-tracing-'));
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-keyout',
        path.join(certDir, 'key.pem'),
        '-out',
        path.join(certDir, 'cert.pem'),
        '-days',
        '1',
        '-nodes',
        '-subj',
        '/CN=127.0.0.1',
      ],
      { stdio: 'ignore' }
    );

    httpServer = http.createServer(collect(httpSeen));
    httpsServer = https.createServer(
      {
        key: fs.readFileSync(path.join(certDir, 'key.pem')),
        cert: fs.readFileSync(path.join(certDir, 'cert.pem')),
      },
      collect(httpsSeen)
    );
    httpPort = await listen(httpServer);
    httpsPort = await listen(httpsServer);

    // jsdom 20.0.2 reads this flag when its XHR performs the browser request.
    const resourceLoader = (window as unknown as { _resourceLoader?: { _strictSSL?: boolean } })._resourceLoader;
    if (resourceLoader) {
      resourceLoader._strictSSL = false;
    }

    setBackendSrv(
      new BackendSrv({
        fromFetch,
        appEvents: { publish: () => {}, emit: () => {} } as never,
        contextSrv: { user: { orgId: 1, isSignedIn: true } } as never,
        logout: () => undefined,
      })
    );
  });

  afterAll(async () => {
    setBackendSrv(previousBackend);
    config.featureToggles.graphiteBackendMode = previousBackendMode;
    if (previousTls === undefined) {
      delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    } else {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = previousTls;
    }
    await Promise.all([
      new Promise<void>((resolve) => httpServer.close(() => resolve())),
      new Promise<void>((resolve) => httpsServer.close(() => resolve())),
    ]);
  });

  beforeEach(() => {
    config.featureToggles.graphiteBackendMode = false;
    httpSeen.length = 0;
    httpsSeen.length = 0;
  });

  it.each([
    ['HTTP', 'http'],
    ['Http', 'http'],
    ['HTTPS', 'https'],
    ['Https', 'https'],
  ] as const)(
    'does not send dashboard or panel identifiers when browser access uses scheme %s',
    async (scheme, transport) => {
      const port = transport === 'https' ? httpsPort : httpPort;
      const seen = transport === 'https' ? httpsSeen : httpSeen;
      const ds = datasource(`${scheme}://127.0.0.1:${port}`);

      await lastValueFrom(ds.query(panelQuery()));

      expectNoDashboardHeaders(seen, '/render', METRIC);
    }
  );

  it('does not send dashboard or panel identifiers when the browser-access URL has a path prefix and an uppercase scheme', async () => {
    const ds = datasource(`HTTPS://127.0.0.1:${httpsPort}/graphite`);

    await lastValueFrom(ds.query(panelQuery()));

    expectNoDashboardHeaders(httpsSeen, '/graphite/render', METRIC);
  });

  it('does not send the hardcoded panel id when testDatasource runs against an uppercase HTTPS URL', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const ds = datasource(`HTTPS://127.0.0.1:${httpsPort}`);

    try {
      await ds.testDatasource();
    } finally {
      warn.mockRestore();
    }

    expectNoDashboardHeaders(httpsSeen, '/render', 'constantLine(100)');
  });

  it.each(['http', 'https'] as const)(
    'does not send dashboard or panel identifiers for lowercase %s browser access',
    async (scheme) => {
      const port = scheme === 'https' ? httpsPort : httpPort;
      const seen = scheme === 'https' ? httpsSeen : httpSeen;
      const ds = datasource(`${scheme}://127.0.0.1:${port}`);

      await lastValueFrom(ds.query(panelQuery()));

      expectNoDashboardHeaders(seen, '/render', METRIC);
    }
  );

  it('sends dashboard and panel identifiers only on the Grafana datasource proxy path', async () => {
    const calls: Array<{ url: string; headers: Headers }> = [];
    const original = globalThis.fetch;
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      calls.push({ url, headers: new Headers(init?.headers) });
      return new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } });
    };

    try {
      const ds = datasource('/api/datasources/proxy/uid/graphite-uid');
      await lastValueFrom(ds.query(panelQuery()));
    } finally {
      globalThis.fetch = original;
    }

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('api/datasources/proxy/uid/graphite-uid/render');
    expect(calls[0].headers.get('x-dashboard-id')).toBe(DASHBOARD_UID);
    expect(calls[0].headers.get('x-panel-id')).toBe(String(PANEL_ID));
    expect(calls[0].headers.get('x-panel-plugin-id')).toBe(PANEL_PLUGIN_ID);
  });
});
