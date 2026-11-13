import { fromFetch } from 'rxjs/fetch';
import { render, screen, within } from 'test/test-utils';

import { config, setBackendSrv, setTemplateSrv } from '@grafana/runtime';
import { TextDimensionMode } from '@grafana/schema';
import { appEvents } from 'app/core/app_events';
import { BackendSrv } from 'app/core/services/backend_srv';
import { contextSrv } from 'app/core/services/context_srv';
import { type CanvasElementOptions } from 'app/features/canvas/element';
import { buttonItem } from 'app/features/canvas/elements/button';
import { Align } from 'app/features/canvas/types';
import { type DimensionContext } from 'app/features/dimensions/context';
import { getTextDimensionFromData } from 'app/features/dimensions/utils';
import { TemplateSrv } from 'app/features/templating/template_srv';
import { type APIEditorConfig } from 'app/plugins/panel/canvas/editor/element/APIEditor';
import { HttpRequestMethod } from 'app/plugins/panel/canvas/panelcfg.gen';

const grafanaOrigin = 'http://grafana.example';

interface CapturedRequest {
  url: string;
  method: string;
  body: string | undefined;
  credentials: RequestCredentials | undefined;
  headers: Record<string, string>;
}

interface SavedCall {
  method: HttpRequestMethod;
  endpoint: string;
  body: string;
  queryName: string;
  queryValue: string;
  headerName: string;
  headerValue: string;
  expectedUrl: string;
  tamperedEndpoint: string;
  tamperedBody: string;
}

const savedCalls: SavedCall[] = [
  {
    method: HttpRequestMethod.POST,
    endpoint: '/api/datasources/proxy/uid/prom-uid/api/v1/write',
    body: '{"state":"paused"}',
    queryName: 'db',
    queryValue: 'metrics',
    headerName: 'X-Canvas-Intent',
    headerValue: 'write-sample',
    expectedUrl: 'http://grafana.example/api/datasources/proxy/uid/prom-uid/api/v1/write?db=metrics',
    tamperedEndpoint: '/api/datasources/proxy/uid/other-uid/api/v1/admin',
    tamperedBody: '{"state":"deleted"}',
  },
  {
    method: HttpRequestMethod.PUT,
    endpoint: '/api/annotations',
    body: '{"text":"ack"}',
    queryName: 'tag',
    queryValue: 'canvas',
    headerName: 'X-Canvas-Intent',
    headerValue: 'write-sample',
    expectedUrl: 'http://grafana.example/api/annotations?tag=canvas',
    tamperedEndpoint: '/api/admin/users',
    tamperedBody: '{"text":"other"}',
  },
];

function headersToRecord(headers: HeadersInit | undefined): Record<string, string> {
  const record: Record<string, string> = {};
  new Headers(headers).forEach((value, key) => {
    record[key] = value;
  });
  return record;
}

function dimensionContext(): DimensionContext {
  return {
    getText: (text) => getTextDimensionFromData(undefined, text),
  } as DimensionContext;
}

function renderSavedButton(saved: SavedCall) {
  const api: APIEditorConfig = {
    endpoint: saved.endpoint,
    method: saved.method,
    data: saved.body,
    contentType: 'application/json',
    queryParams: [[saved.queryName, saved.queryValue]],
    headerParams: [[saved.headerName, saved.headerValue]],
    successMessage: 'API call was successful',
  };
  const options: CanvasElementOptions = {
    name: 'Refresh button',
    type: buttonItem.id,
    config: {
      text: { mode: TextDimensionMode.Fixed, fixed: 'Refresh' },
      align: Align.Center,
      api,
    },
  };
  const prepared = buttonItem.prepareData!(dimensionContext(), options);
  const Display = buttonItem.display;

  const view = render(<Display config={options.config} data={prepared} />);

  return { ...view, prepared };
}

describe('canvas button saved API call', () => {
  const sent: CapturedRequest[] = [];
  let originalFetch: typeof globalThis.fetch;
  let originalAppUrl: string;
  let originalAppSubUrl: string;

  beforeEach(() => {
    sent.length = 0;
    originalFetch = globalThis.fetch;
    originalAppUrl = config.appUrl;
    originalAppSubUrl = config.appSubUrl;
    config.appUrl = `${grafanaOrigin}/`;
    config.appSubUrl = '';
    setTemplateSrv(new TemplateSrv());

    globalThis.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith(`${grafanaOrigin}/`)) {
        sent.push({
          url,
          method: init?.method ?? 'GET',
          body: typeof init?.body === 'string' ? init.body : undefined,
          credentials: init?.credentials,
          headers: headersToRecord(init?.headers),
        });
      }
      return new Response('{}', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;

    setBackendSrv(
      new BackendSrv({
        fromFetch,
        appEvents,
        contextSrv,
        logout: jest.fn(),
      })
    );
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    config.appUrl = originalAppUrl;
    config.appSubUrl = originalAppSubUrl;
  });

  it.each(savedCalls)(
    'keeps a $method labeled Refresh from running until the viewer confirms that method, URL, and body',
    async (saved) => {
      const { user, prepared } = renderSavedButton(saved);

      expect(prepared?.text).toBe('Refresh');
      const refresh = screen.getByRole('button', { name: 'Refresh' });
      expect(refresh).toBeInTheDocument();
      expect(screen.queryByText(saved.expectedUrl)).not.toBeInTheDocument();
      expect(screen.queryByText(saved.body)).not.toBeInTheDocument();

      await user.click(refresh);

      expect(sent).toEqual([]);

      const confirmation = screen.getByRole('dialog');
      expect(confirmation).toHaveTextContent(saved.method);
      expect(confirmation).toHaveTextContent(saved.expectedUrl);
      expect(confirmation).toHaveTextContent(saved.body);

      prepared!.api!.endpoint = saved.tamperedEndpoint;
      prepared!.api!.data = saved.tamperedBody;

      expect(confirmation).toHaveTextContent(saved.expectedUrl);
      expect(confirmation).toHaveTextContent(saved.body);
      expect(confirmation).not.toHaveTextContent(saved.tamperedEndpoint);
      expect(confirmation).not.toHaveTextContent(saved.tamperedBody);

      await user.click(within(confirmation).getByRole('button', { name: 'Confirm' }));

      expect(sent).toEqual([
        expect.objectContaining({
          url: saved.expectedUrl,
          method: saved.method,
          body: saved.body,
          credentials: 'same-origin',
          headers: expect.objectContaining({
            'x-grafana-action': '1',
            'x-canvas-intent': saved.headerValue,
          }),
        }),
      ]);
    }
  );

  it('leaves the saved POST unsent when the viewer cancels the confirmation', async () => {
    const saved = savedCalls[0];
    const { user } = renderSavedButton(saved);

    await user.click(screen.getByRole('button', { name: 'Refresh' }));

    expect(sent).toEqual([]);
    const confirmation = screen.getByRole('dialog');
    expect(confirmation).toHaveTextContent(saved.method);
    expect(confirmation).toHaveTextContent(saved.expectedUrl);
    expect(confirmation).toHaveTextContent(saved.body);

    await user.click(within(confirmation).getByRole('button', { name: 'Cancel' }));

    expect(screen.getByRole('button', { name: 'Refresh' })).toBeInTheDocument();
    expect(sent).toEqual([]);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});
