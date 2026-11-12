import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { type AddressInfo } from 'node:net';

import { type Action, ActionType, type DataFrame, type Field, FieldType, HttpRequestMethod } from '@grafana/data';
import { config, setBackendSrv } from '@grafana/runtime';

import { BackendSrv, type BackendSrvDependencies } from '../../core/services/backend_srv';
import { type ContextSrv } from '../../core/services/context_srv';

import { getActions } from './utils';

const placeholderToken = 'placeholder-token';
const headerName = 'X-Grafana-JWT';

interface CapturedRequest {
  method: string;
  url: string;
  headers: IncomingMessage['headers'];
}

function listen(): Promise<{ origin: string; requests: CapturedRequest[]; close: () => Promise<void> }> {
  const requests: CapturedRequest[] = [];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    requests.push({ method: req.method ?? '', url: req.url ?? '', headers: { ...req.headers } });
    res.writeHead(req.method === 'OPTIONS' ? 204 : 200, {
      'access-control-allow-origin': '*',
      'access-control-allow-headers': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'content-type': 'application/json',
    });
    res.end(req.method === 'OPTIONS' ? '' : '{}');
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        origin: `http://127.0.0.1:${port}`,
        requests,
        close: () =>
          new Promise((done, fail) => {
            server.close((err) => (err ? fail(err) : done()));
          }),
      });
    });
  });
}

async function waitFor(predicate: () => boolean): Promise<void> {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started > 5000) {
      throw new Error('timed out waiting for the action request');
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function requestHeader(request: CapturedRequest): string | undefined {
  const value = request.headers[headerName.toLowerCase()];
  return Array.isArray(value) ? value.join(',') : value;
}

describe('dashboard fetch actions with URL login', () => {
  const originalLocation = window.location;
  const originalJwtHeaderName = config.jwtHeaderName;
  const originalJwtUrlLogin = config.jwtUrlLogin;
  const originalAppUrl = config.appUrl;
  const originalAppSubUrl = config.appSubUrl;

  afterEach(() => {
    config.jwtHeaderName = originalJwtHeaderName;
    config.jwtUrlLogin = originalJwtUrlLogin;
    config.appUrl = originalAppUrl;
    config.appSubUrl = originalAppSubUrl;
    Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
  });

  it('sends the URL login header to Grafana and not to another origin', async () => {
    const grafana = await listen();
    const attacker = await listen();

    config.jwtHeaderName = headerName;
    config.jwtUrlLogin = true;
    config.appUrl = `${grafana.origin}/`;
    config.appSubUrl = '';
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: {
        href: `${grafana.origin}/d/abc?auth_token=${placeholderToken}&orgId=1`,
        origin: grafana.origin,
        protocol: 'http:',
        host: grafana.origin.replace('http://', ''),
        hostname: '127.0.0.1',
        pathname: '/d/abc',
        search: `?auth_token=${placeholderToken}&orgId=1`,
        hash: '',
      },
    });

    const backendSrv = new BackendSrv({
      contextSrv: { user: { orgId: 1, isSignedIn: true } } as ContextSrv,
      appEvents: { emit: jest.fn(), publish: jest.fn() },
      logout: jest.fn(),
    } as unknown as BackendSrvDependencies);
    setBackendSrv(backendSrv);

    const frame: DataFrame = { name: 'test', fields: [], length: 0 };
    const field: Field = { name: 'value', type: FieldType.number, values: [1], config: {} };
    const actions: Action[] = [
      {
        title: 'Same origin',
        type: ActionType.Fetch,
        fetch: { url: '/api/user', method: HttpRequestMethod.GET },
      },
      {
        title: 'Other origin',
        type: ActionType.Fetch,
        fetch: { url: `${attacker.origin}/collect`, method: HttpRequestMethod.POST },
      },
    ];

    const models = getActions(frame, field, {}, (value) => value, actions, {});
    expect(models).toHaveLength(2);
    models[0].onClick(new MouseEvent('click'), field);
    models[1].onClick(new MouseEvent('click'), field);

    try {
      await waitFor(
        () =>
          grafana.requests.some((request) => request.method !== 'OPTIONS') &&
          attacker.requests.some((request) => request.method !== 'OPTIONS')
      );

      const grafanaRequest = grafana.requests.find((request) => request.method !== 'OPTIONS');
      const attackerRequest = attacker.requests.find((request) => request.method !== 'OPTIONS');
      expect(grafanaRequest?.url).toContain('/api/user');
      expect(requestHeader(grafanaRequest!)).toBe(placeholderToken);
      expect(attackerRequest?.url).toContain('/collect');
      expect(requestHeader(attackerRequest!)).toBeUndefined();
    } finally {
      await grafana.close();
      await attacker.close();
    }
  });
});
