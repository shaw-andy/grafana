import { lastValueFrom } from 'rxjs';
import { fromFetch } from 'rxjs/fetch';

import { dateTime, type DataQueryRequest } from '@grafana/data';
import { config, getBackendSrv, setBackendSrv, type TemplateSrv } from '@grafana/runtime';

import { fetchPromBuildInfo } from '../../features/alerting/unified/api/buildInfo';
import { AlertManagerDatasource } from '../../plugins/datasource/alertmanager/DataSource';
import { AlertManagerImplementation } from '../../plugins/datasource/alertmanager/types';
import { GraphiteDatasource } from '../../plugins/datasource/graphite/datasource';
import { type GraphiteQuery } from '../../plugins/datasource/graphite/types';
import { BackendSrv, type BackendSrvDependencies } from './backend_srv';

jest.mock('@fingerprintjs/fingerprintjs', () => ({
  __esModule: true,
  default: {
    load: () =>
      Promise.resolve({
        get: () =>
          Promise.resolve({
            visitorId: 'viewer-device',
            confidence: { score: 1, comment: '' },
            components: {},
            version: '3.4.2',
          }),
      }),
  },
}));

const ORG_ID = 42;
const DEVICE_ID = 'viewer-device';
const EXTERNAL_HOST = 'collector.example';

const VIEWER_HEADERS = [
  'x-grafana-org-id',
  'x-grafana-device-id',
  'x-dashboard-id',
  'x-panel-id',
  'x-panel-plugin-id',
  'x-ds-authorization',
] as const;

interface RecordedFetch {
  url: string;
  init?: RequestInit;
}

const recorded: RecordedFetch[] = [];
const originalFetch = global.fetch;
let backendSrv: BackendSrv;
let originalBackendSrv: ReturnType<typeof getBackendSrv>;
let originalGraphiteBackendMode: boolean | undefined;

const templateSrv = {
  replace: (value: string) => value,
} as TemplateSrv;

function headerValue(init: RequestInit | undefined, name: string): string | null {
  if (!init?.headers) {
    return null;
  }
  return new Headers(init.headers).get(name);
}

function requestOrigin(requestUrl: string): string {
  return new URL(requestUrl, window.location.href).origin;
}

function requestTarget(requestUrl: string): string {
  const parsed = new URL(requestUrl, window.location.href);
  return `${parsed.hostname}${parsed.pathname}`;
}

function assertNoViewerHeadersOnForeignOrigin() {
  const pageOrigin = new URL(window.location.href).origin;
    const foreign = recorded.filter((call) => requestOrigin(call.url) !== pageOrigin);
    expect(foreign.length).toBeGreaterThan(0);
    for (const call of foreign) {
      const leaked: Record<string, string> = {};
      for (const name of VIEWER_HEADERS) {
        const value = headerValue(call.init, name);
        if (value != null) {
          leaked[name] = value;
        }
      }
      expect({ url: call.url, origin: requestOrigin(call.url), leaked }).toEqual({
        url: call.url,
        origin: requestOrigin(call.url),
        leaked: {},
      });
    }
  }

async function settle(run: () => Promise<unknown>) {
  try {
    await run();
  } catch {
    // A refusal before the request is sent is a passing outcome when no foreign
    // request carried viewer headers. Callers still assert that a foreign request
    // was recorded, so a silent no-op does not pass.
  }
}

function graphiteDatasource(url: string, basicAuth?: string) {
  return new GraphiteDatasource(
    {
      url,
      name: 'graphite',
      basicAuth,
      jsonData: {},
    },
    templateSrv
  );
}

function panelQuery(): DataQueryRequest<GraphiteQuery> {
  return {
    app: 'graphite',
    interval: '10ms',
    intervalMs: 10,
    requestId: 'req-1',
    scopedVars: {},
    startTime: 0,
    timezone: 'browser',
    panelId: 3,
    dashboardUID: 'dash-uid',
    panelPluginId: 'timeseries',
    rangeRaw: { from: '2020-01-01T00:00:00.000Z', to: '2020-01-01T01:00:00.000Z' },
    range: {
      from: dateTime(new Date('2020-01-01T00:00:00.000Z')),
      to: dateTime(new Date('2020-01-01T01:00:00.000Z')),
      raw: { from: '2020-01-01T00:00:00.000Z', to: '2020-01-01T01:00:00.000Z' },
    },
    targets: [{ refId: 'A', target: 'constantLine(100)' }],
    maxDataPoints: 300,
  };
}

describe('viewer identity headers stay on the Grafana origin', () => {
  beforeAll(async () => {
    originalBackendSrv = getBackendSrv();
    originalGraphiteBackendMode = config.featureToggles.graphiteBackendMode;
    config.featureToggles.graphiteBackendMode = false;

    backendSrv = new BackendSrv({
      fromFetch,
      appEvents: { emit: jest.fn(), publish: jest.fn() },
      contextSrv: { user: { orgId: ORG_ID, isSignedIn: true } },
      logout: () => undefined,
    } as unknown as BackendSrvDependencies);
    setBackendSrv(backendSrv as unknown as ReturnType<typeof getBackendSrv>);

    const started = Date.now();
    while (backendSrv['deviceID'] !== DEVICE_ID) {
      if (Date.now() - started > 2000) {
        throw new Error('device id was not initialized from FingerprintJS visitorId');
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  });

  afterAll(() => {
    setBackendSrv(originalBackendSrv);
    config.featureToggles.graphiteBackendMode = originalGraphiteBackendMode;
    global.fetch = originalFetch;
  });

  beforeEach(() => {
    recorded.length = 0;
    global.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      recorded.push({ url, init });
      return new Response('[]', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;
  });

  it('still sends the org id and device id on a same-origin datasource proxy request', async () => {
    await lastValueFrom(
      backendSrv.fetch({
        method: 'POST',
        url: '/api/datasources/proxy/uid/graphite/render',
      })
    );

    expect(recorded).toHaveLength(1);
    expect(requestOrigin(recorded[0].url)).toBe(new URL(window.location.href).origin);
    expect(headerValue(recorded[0].init, 'x-grafana-org-id')).toBe(String(ORG_ID));
    expect(headerValue(recorded[0].init, 'x-grafana-device-id')).toBe(DEVICE_ID);
  });

  it.each([
    'HTTPS://collector.example/render',
    'HTTP://collector.example/render',
    'Https://collector.example/render',
    'hTTp://collector.example/render',
    ' HTTPS://collector.example/render',
  ])('fetch does not attach viewer headers to %j', async (url) => {
    await settle(() => lastValueFrom(backendSrv.fetch({ method: 'POST', url })));

    assertNoViewerHeadersOnForeignOrigin();
    expect(new URL(recorded[0].url, window.location.href).hostname).toBe(EXTERNAL_HOST);
  });

  it('does not attach viewer headers when the scheme is already lowercase https', async () => {
    await lastValueFrom(backendSrv.fetch({ method: 'POST', url: 'https://collector.example/render' }));

    assertNoViewerHeadersOnForeignOrigin();
    expect(headerValue(recorded[0].init, 'x-grafana-org-id')).toBeNull();
  });

  it('post and datasourceRequest use the same header rules', async () => {
    await settle(() => backendSrv.post('HTTPS://collector.example/render', 'target=constantLine(100)'));
    await settle(() => backendSrv.datasourceRequest({ method: 'GET', url: 'HTTP://collector.example/metrics/find' }));

    expect(recorded).toHaveLength(2);
    assertNoViewerHeadersOnForeignOrigin();
  });

  it.each([
    'HTTPS://collector.example',
    'HTTP://collector.example',
    'Https://collector.example',
    ' HTTPS://collector.example',
  ])('a graphite panel query does not send viewer headers to %j', async (baseUrl) => {
    const ds = graphiteDatasource(baseUrl);
    await settle(() => lastValueFrom(ds.query(panelQuery())));

    assertNoViewerHeadersOnForeignOrigin();
    expect(recorded.some((call) => call.url.includes('/render'))).toBe(true);
    expect(new URL(recorded.find((call) => call.url.includes('/render'))!.url, window.location.href).hostname).toBe(
      EXTERNAL_HOST
    );
  });

  it('a graphite proxy query still sends org, device, and tracing headers', async () => {
    const ds = graphiteDatasource('/api/datasources/proxy/uid/graphite');
    await lastValueFrom(ds.query(panelQuery()));

    expect(recorded).toHaveLength(1);
    expect(requestOrigin(recorded[0].url)).toBe(new URL(window.location.href).origin);
    expect(headerValue(recorded[0].init, 'x-grafana-org-id')).toBe(String(ORG_ID));
    expect(headerValue(recorded[0].init, 'x-grafana-device-id')).toBe(DEVICE_ID);
    expect(headerValue(recorded[0].init, 'x-dashboard-id')).toBe('dash-uid');
    expect(headerValue(recorded[0].init, 'x-panel-id')).toBe('3');
    expect(headerValue(recorded[0].init, 'x-panel-plugin-id')).toBe('timeseries');
  });

  it('metric find and events use the graphite request path', async () => {
    const ds = graphiteDatasource('HTTPS://collector.example');
    await settle(() => ds.metricFindQuery('servers.*'));
    await settle(() =>
      ds.events({
        range: panelQuery().range,
        tags: '',
      })
    );

    expect(recorded.map((call) => requestTarget(call.url)).sort()).toEqual(
      [`${EXTERNAL_HOST}/events/get_data`, `${EXTERNAL_HOST}/metrics/find`].sort()
    );
    assertNoViewerHeadersOnForeignOrigin();
  });

  it('does not rewrite datasource authorization onto a foreign graphite host', async () => {
    // Direct access copies the datasource credential onto the request and also sets
    // withCredentials, which logs a deprecation warning. The warning is not the leak.
    jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const ds = graphiteDatasource('HTTPS://collector.example', 'placeholder');
    await settle(() => lastValueFrom(ds.query(panelQuery())));

    assertNoViewerHeadersOnForeignOrigin();
    expect(headerValue(recorded[0].init, 'x-ds-authorization')).toBeNull();
  });

  it('alertmanager browser access does not send viewer headers', async () => {
    const ds = new AlertManagerDatasource({
      url: 'HTTPS://collector.example',
      jsonData: { implementation: AlertManagerImplementation.prometheus },
    } as ConstructorParameters<typeof AlertManagerDatasource>[0]);

    await settle(() => ds.testDatasource());

    expect(recorded.map((call) => requestTarget(call.url)).sort()).toEqual(
      [`${EXTERNAL_HOST}/alertmanager/api/v2/status`, `${EXTERNAL_HOST}/api/v1/status/buildinfo`].sort()
    );
    assertNoViewerHeadersOnForeignOrigin();
  });

  it('prometheus build-info discovery does not send viewer headers', async () => {
    await settle(() => fetchPromBuildInfo('HTTPS://collector.example'));

    expect(recorded.map((call) => requestTarget(call.url))).toEqual([`${EXTERNAL_HOST}/api/v1/status/buildinfo`]);
    assertNoViewerHeadersOnForeignOrigin();
  });
});
