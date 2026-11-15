import http from 'node:http';

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { LiveChannelScope } from '@grafana/data';
import { setBackendSrv } from '@grafana/runtime';
import type { CodeMirrorEditorProps } from '@grafana/ui/unstable';
import { BackendSrv, type BackendSrvDependencies } from 'app/core/services/backend_srv';
import { GrafanaLiveService } from 'app/features/live/live';

import { getPanelProps } from '../test-utils';

import { LivePanel } from './LivePanel';
import { LivePublish } from './LivePublish';
import { MessageDisplayMode, MessagePublishMode } from './types';

jest.mock('@grafana/ui/unstable', () => ({
  ...jest.requireActual('@grafana/ui/unstable'),
  CodeMirrorEditor: ({ value, onChange, 'aria-label': ariaLabel }: CodeMirrorEditorProps) => (
    <textarea aria-label={ariaLabel} value={value} onChange={(event) => onChange(event.currentTarget.value)} />
  ),
}));

const jsdomFetch = globalThis.fetch;
const liveHolder: { current?: GrafanaLiveService } = {};

jest.mock('@grafana/runtime', () => {
  const actual = jest.requireActual('@grafana/runtime');
  return {
    ...actual,
    getGrafanaLiveSrv: () => liveHolder.current,
  };
});

type RecordedRequest = {
  method: string;
  path: string;
  origin?: string;
  orgId?: string;
  contentType?: string;
  body: string;
  credentials?: RequestCredentials;
};

const attacks: Array<{ attack: string; stream: string; body: object }> = [
  { attack: 'disable a local user', stream: '../../admin/users/1/disable', body: {} },
  { attack: 'create a user', stream: '../../admin/users', body: { login: 'new-user', email: 'new-user@example.test' } },
  {
    attack: 'add an existing user to the organization',
    stream: '../../org/invites',
    body: { loginOrEmail: 'existing-user', role: 'Admin', sendEmail: false },
  },
  { attack: 'log out a user', stream: '../../admin/users/1/logout', body: {} },
  { attack: 'enable a user through encoded dot segments', stream: '%2e%2e/%2e%2e/admin/users/1/enable', body: {} },
  { attack: 'disable a user through backslash separators', stream: '..\\..\\admin\\users\\1\\disable', body: {} },
];

const pageBases = [
  { page: 'the server root', prefix: '' },
  { page: 'a subpath', prefix: '/grafana' },
];

describe('Influx publish request target', () => {
  let server: http.Server;
  let origin: string;
  let pageBase: string;
  let seen: RecordedRequest[];
  let pendingCredentials: RequestCredentials | undefined;
  const inflight: Array<Promise<unknown>> = [];

  beforeAll(async () => {
    seen = [];
    server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk) => chunks.push(chunk));
      req.on('end', () => {
        seen.push({
          method: req.method ?? '',
          path: req.url ?? '',
          origin: req.headers.origin,
          orgId: header(req.headers['x-grafana-org-id']),
          contentType: header(req.headers['content-type']),
          body: Buffer.concat(chunks).toString('utf8'),
          credentials: pendingCredentials,
        });
        const payload = Buffer.from('{}');
        res.writeHead(200, {
          'content-type': 'application/json',
          'content-length': String(payload.length),
        });
        res.end(payload);
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const address = server.address();
    if (address == null || typeof address === 'string') {
      throw new Error('test server did not bind to a port');
    }
    origin = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  });

  beforeEach(() => {
    seen = [];
    inflight.length = 0;
    pendingCredentials = undefined;
    pageBase = `${origin}/`;
    globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      const raw = requestInput(input);
      pendingCredentials = init?.credentials;
      const promise = nodeFetch(new URL(absoluteRequest(pageBase, raw)), init);
      inflight.push(promise.then(() => undefined, () => undefined));
      return promise;
    }) as typeof fetch;

    const backendSrv = new BackendSrv({
      appEvents: { publish: jest.fn(), emit: jest.fn() },
      contextSrv: { user: { orgId: 1, isSignedIn: true } },
      logout: jest.fn(),
    } as unknown as BackendSrvDependencies);
    setBackendSrv(backendSrv);
    liveHolder.current = new GrafanaLiveService({
      backendSrv,
      centrifugeSrv: {
        getStream: () => ({ subscribe: () => ({ unsubscribe() {} }) }),
      } as never,
    });
  });

  afterEach(() => {
    globalThis.fetch = jsdomFetch;
    liveHolder.current = undefined;
  });

  it.each(pageBases)(
    'posts a saved safe stream id to one /api/live/push segment when the page is served from $page',
    async ({ prefix }) => {
      pageBase = `${origin}${prefix}/`;
      const body = { measurement: 'cpu' };
      await publishInflux('api-stream', body);
      await settle();

      expect(seen).toEqual([
        expect.objectContaining({
          method: 'POST',
          path: `${prefix}/api/live/push/api-stream`,
          orgId: '1',
          credentials: 'same-origin',
          body: JSON.stringify(body),
        }),
      ]);
      expect(seen[0].contentType).toContain('application/json');
    }
  );

  it.each(attacks.flatMap((attack) => pageBases.map((page) => ({ ...attack, ...page }))))(
    'does not let a saved stream $attack when the page is served from $page',
    async ({ stream, body, prefix }) => {
      pageBase = `${origin}${prefix}/`;
      await publishInflux(stream, body);
      await settle();

      expect(seen.length).toBeLessThanOrEqual(1);
      for (const request of seen) {
        expect(request.method).toBe('POST');
        expect(request.credentials).toBe('same-origin');
        expect(request.orgId).toBe('1');
        expect(request.body).toBe(JSON.stringify(body));
        expect(request.path.split('?')[0]).toMatch(new RegExp(`^${prefix}/api/live/push/[^/]+$`));
      }
    }
  );

  it('checks the stream that is current when Publish is clicked', async () => {
    const user = userEvent.setup();
    const first = address('api-stream');
    const next = address('../../admin/users/1/disable');
    const { rerender } = render(
      <LivePublish height={200} mode={MessagePublishMode.Influx} body={{}} addr={first} onSave={jest.fn()} />
    );
    rerender(<LivePublish height={200} mode={MessagePublishMode.Influx} body={{}} addr={next} onSave={jest.fn()} />);

    await user.click(screen.getByRole('button', { name: 'Publish' }));
    await settle();

    for (const request of seen) {
      expect(request.path.split('?')[0]).toMatch(/^\/api\/live\/push\/[^/]+$/);
    }
  });

  it('keeps JSON publish on /api/live/publish when the saved stream contains dot segments', async () => {
    const user = userEvent.setup();
    const body = { hello: 'world' };
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    render(
      <LivePublish
        height={200}
        mode={MessagePublishMode.JSON}
        body={body}
        addr={address('../../admin/users/1/disable')}
        onSave={jest.fn()}
      />
    );

    await user.click(screen.getByRole('button', { name: 'Publish' }));
    await settle();
    await new Promise((resolve) => setTimeout(resolve, 0));
    log.mockRestore();

    expect(seen).toEqual([
      expect.objectContaining({
        method: 'POST',
        path: '/api/live/publish',
        credentials: 'same-origin',
        body: JSON.stringify({
          channel: 'stream/../../admin/users/1/disable/channel',
          data: body,
        }),
      }),
    ]);
  });

  it('publishes the saved panel message when a viewer clicks Publish on a display-none Influx panel', async () => {
    const user = userEvent.setup();
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    const body = { loginOrEmail: 'existing-user', role: 'Admin', sendEmail: false };
    render(
      <LivePanel
        {...getPanelProps({
          channel: address('../../org/invites'),
          display: MessageDisplayMode.None,
          publish: MessagePublishMode.Influx,
          message: body,
        })}
      />
    );

    await user.click(await screen.findByRole('button', { name: 'Publish' }));
    await settle();
    log.mockRestore();

    expect(seen.length).toBeLessThanOrEqual(1);
    for (const request of seen) {
      expect(request.body).toBe(JSON.stringify(body));
      expect(request.path.split('?')[0]).toMatch(/^\/api\/live\/push\/[^/]+$/);
    }
  });

  async function publishInflux(stream: string, body: object) {
    const user = userEvent.setup();
    render(
      <LivePublish
        height={200}
        mode={MessagePublishMode.Influx}
        body={body}
        addr={address(stream)}
        onSave={jest.fn()}
      />
    );
    await user.click(screen.getByRole('button', { name: 'Publish' }));
  }

  async function settle() {
    await Promise.all(inflight);
  }
});

function address(stream: string) {
  return { scope: LiveChannelScope.Stream, stream, path: 'channel' };
}

function requestInput(input: RequestInfo | URL): string {
  if (typeof input === 'string') {
    return input;
  }
  if (input instanceof URL) {
    return input.href;
  }
  return input.url;
}

function absoluteRequest(pageBase: string, raw: string): string {
  if (/^[a-zA-Z][a-zA-Z\d+.-]*:/.test(raw) || raw.startsWith('//')) {
    return raw;
  }
  return pageBase + raw.replace(/^\//, '');
}

function header(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

// jsdom's fetch refuses this cross-origin request before it is sent. Node's URL
// parser is the same one fetch uses to collapse dot segments, so the request
// below is sent to the path that parser produces.
function nodeFetch(target: URL, init?: RequestInit): Promise<Response> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method: init?.method,
        headers: headersToObject(init?.headers),
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const responseHeaders = new Headers();
          for (const [key, value] of Object.entries(res.headers)) {
            if (typeof value === 'string') {
              responseHeaders.set(key, value);
            }
          }
          resolve(new Response(Buffer.concat(chunks), { status: res.statusCode, headers: responseHeaders }));
        });
      }
    );
    req.on('error', reject);
    const body = init?.body;
    if (typeof body === 'string') {
      req.write(body);
    } else if (body instanceof Uint8Array) {
      req.write(body);
    }
    req.end();
  });
}

function headersToObject(headers?: HeadersInit): Record<string, string> {
  const out: Record<string, string> = {};
  if (headers == null) {
    return out;
  }
  if (headers instanceof Headers) {
    headers.forEach((value, key) => {
      out[key] = value;
    });
    return out;
  }
  if (Array.isArray(headers)) {
    for (const [key, value] of headers) {
      out[key] = value;
    }
    return out;
  }
  return { ...headers };
}

it('preserves an unsaved draft across rerenders', async () => {
  const user = userEvent.setup();
  const props = {
    height: 200,
    mode: MessagePublishMode.JSON,
    body: { saved: true },
    onSave: jest.fn(),
  };
  const { rerender } = render(<LivePublish {...props} />);
  const editor = screen.getByRole('textbox', { name: 'Message to publish' });

  await user.clear(editor);
  await user.paste('{"draft":true}');
  rerender(<LivePublish {...props} />);

  expect(editor).toHaveValue('{"draft":true}');
  expect(props.onSave).not.toHaveBeenCalled();
});
