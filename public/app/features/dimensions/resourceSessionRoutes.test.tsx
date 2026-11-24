import { spawn } from 'child_process';
import { existsSync } from 'fs';
import http from 'http';
import type { AddressInfo } from 'net';
import { render, screen } from 'test/test-utils';

import { createDataFrame, LoadingState, type PanelData } from '@grafana/data';
import { ConnectionDirection, ResourceDimensionMode } from '@grafana/schema';
import { cloudItem } from 'app/features/canvas/elements/cloud';
import { ellipseItem } from 'app/features/canvas/elements/ellipse';
import { iconItem } from 'app/features/canvas/elements/icon';
import { parallelogramItem } from 'app/features/canvas/elements/parallelogram';
import { rectangleItem } from 'app/features/canvas/elements/rectangle';
import { triangleItem } from 'app/features/canvas/elements/triangle';
import { type DimensionContext } from 'app/features/dimensions/context';
import { URLPickerTab } from 'app/features/dimensions/editors/URLPickerTab';
import { getPublicOrAbsoluteUrl } from 'app/features/dimensions/resource';
import { MediaType } from 'app/features/dimensions/types';
import { getResourceDimensionFromData } from 'app/features/dimensions/utils';
import { applyStyles } from 'app/plugins/panel/canvas/utils';
import { MarkersLegend } from 'app/plugins/panel/geomap/components/MarkersLegend';
import { getMarkerMaker, getWebGLStyle } from 'app/plugins/panel/geomap/style/markers';
import { type StyleConfigState } from 'app/plugins/panel/geomap/style/types';

/**
 * These tests fail while a saved panel resource can make the viewer's browser
 * send a credentialed GET to a session route. They pass once that load no
 * longer resolves to logout or the organization switch page.
 */

const SESSION_COOKIE = 'grafana_session=placeholder-session-value';
const BROWSER_BUILD_PATH = 'public/build/';

type LoadKind = 'css-background' | 'svg-image' | 'geomap-fetch' | 'inline-svg-fetch' | 'img';

interface Load {
  kind: LoadKind;
  value: string;
}

interface RecordedRequest {
  method: string;
  path: string;
  cookie: string;
}

function chromeBinary(): string {
  const candidates = [process.env.CHROME_BIN, '/usr/bin/google-chrome', '/usr/bin/chromium'].filter(
    (value): value is string => Boolean(value)
  );
  const found = candidates.find((candidate) => existsSync(candidate));
  if (!found) {
    throw new Error('A Chrome binary is required to resolve resource URLs the way the viewer browser does');
  }
  return found;
}

function isSessionRoute(pathname: string): boolean {
  return pathname === '/logout' || pathname === '/grafana/logout' || /\/profile\/switch-org\/[^/]+$/.test(pathname);
}

function resourceContext(): DimensionContext {
  const empty = <T,>(value: T) => ({
    value: () => value,
    get: () => value,
    fixed: value,
    isAssumed: false,
  });
  return {
    getColor: () => empty('#000000'),
    getScale: () => empty(1),
    getScalar: () => empty(1),
    getText: () => empty(''),
    getDirection: () => empty(ConnectionDirection.Forward),
    getResource: (resource) => getResourceDimensionFromData(undefined, resource),
    getPanelData: () => undefined,
  };
}

function fixedImage(path: string) {
  return { mode: ResourceDimensionMode.Fixed, fixed: path };
}

function cssUrl(path: string): string {
  return `url("${path}")`;
}

function push(loads: Load[], load: Load | undefined) {
  if (load && load.value) {
    loads.push(load);
  }
}

interface Page {
  baseHref: string;
  cookiePath: string;
  loads: Load[];
  recorded: RecordedRequest[];
}

let page: Page | undefined;
let server: http.Server;

function handleRequest(req: http.IncomingMessage, res: http.ServerResponse) {
  const host = req.headers.host ?? '127.0.0.1';
  const url = new URL(req.url ?? '/', `http://${host}`);
  const current = page;
  if (!current) {
    res.writeHead(404);
    res.end();
    return;
  }

  current.recorded.push({
    method: req.method ?? 'GET',
    path: url.pathname,
    cookie: req.headers.cookie ?? '',
  });

  if (url.pathname !== '/d/uid/slug') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok');
    return;
  }

  const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<base href="${current.baseHref}" />
</head>
<body>
<script type="application/json" id="loads">${JSON.stringify(current.loads).replace(/</g, '\\u003c')}</script>
<script>
const loads = JSON.parse(document.getElementById('loads').textContent);
for (const load of loads) {
  if (load.kind === 'css-background') {
    const div = document.createElement('div');
    div.style.backgroundImage = load.value;
    document.body.appendChild(div);
  } else if (load.kind === 'svg-image') {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    const image = document.createElementNS('http://www.w3.org/2000/svg', 'image');
    image.setAttribute('href', load.value);
    svg.appendChild(image);
    document.body.appendChild(svg);
  } else if (load.kind === 'geomap-fetch') {
    fetch(load.value, { method: 'GET' }).catch(function () {});
  } else if (load.kind === 'inline-svg-fetch') {
    const controller = new AbortController();
    fetch(load.value, { signal: controller.signal }).catch(function () {});
  } else if (load.kind === 'img') {
    const img = document.createElement('img');
    img.src = load.value;
    document.body.appendChild(img);
  }
}
</script>
</body>
</html>`;
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'set-cookie': `${SESSION_COOKIE}; Path=${current.cookiePath}; HttpOnly; SameSite=Lax`,
  });
  res.end(html);
}

async function visit(baseHref: string, cookiePath: string, loads: Load[]): Promise<RecordedRequest[]> {
  page = { baseHref, cookiePath, loads, recorded: [] };
  const port = (server.address() as AddressInfo).port;
  await new Promise<void>((resolve, reject) => {
    const chrome = spawn(
      chromeBinary(),
      [
        '--headless=new',
        '--disable-gpu',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--timeout=8000',
        '--dump-dom',
        `http://127.0.0.1:${port}/d/uid/slug`,
      ],
      { stdio: 'ignore' }
    );
    const timer = setTimeout(() => chrome.kill('SIGKILL'), 15000);
    chrome.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    chrome.on('exit', () => {
      clearTimeout(timer);
      resolve();
    });
  });
  const recorded = page.recorded.filter((request) => request.path !== '/d/uid/slug' && request.path !== '/favicon.ico');
  page = undefined;
  return recorded;
}

describe('panel resource loads and session routes', () => {
  beforeAll((done) => {
    server = http.createServer(handleRequest);
    server.listen(0, '127.0.0.1', done);
  });

  afterAll((done) => {
    server.close(done);
  });

  it('does not send the viewer session cookie to logout or switch-org', async () => {
    window.__grafana_build_path__ = BROWSER_BUILD_PATH;
    const { ElementState } = await import('app/features/canvas/runtime/element');
    const context = resourceContext();
    const loads: Load[] = [];
    const fetched: string[] = [];
    const fetchImpl = global.fetch;
    global.fetch = jest.fn(async (input: RequestInfo | URL) => {
      fetched.push(String(input));
      return new Response('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"></svg>', {
        status: 200,
        headers: { 'content-type': 'image/svg+xml' },
      });
    }) as typeof fetch;

    const rectangle = new ElementState(rectangleItem, {
      type: rectangleItem.id,
      name: 'rectangle',
      background: { image: fixedImage('../../logout') },
    });
    rectangle.div = document.createElement('div');
    rectangle.updateData(context);
    applyStyles(rectangle.dataStyle, rectangle.div);
    push(loads, { kind: 'css-background', value: String(rectangle.dataStyle.backgroundImage ?? '') });

    const switchOrg = new ElementState(rectangleItem, {
      type: rectangleItem.id,
      name: 'switch-org',
      background: { image: fixedImage('../../profile/switch-org/2') },
    });
    switchOrg.div = document.createElement('div');
    switchOrg.updateData(context);
    push(loads, { kind: 'css-background', value: String(switchOrg.dataStyle.backgroundImage ?? '') });

    for (const path of ['..\\..\\logout', '%2e%2e/%2e%2e/logout', '..%2f..%2flogout']) {
      const element = new ElementState(rectangleItem, {
        type: rectangleItem.id,
        name: path,
        background: { image: fixedImage(path) },
      });
      element.div = document.createElement('div');
      element.updateData(context);
      push(loads, { kind: 'css-background', value: String(element.dataStyle.backgroundImage ?? '') });
    }

    const benign = new ElementState(rectangleItem, {
      type: rectangleItem.id,
      name: 'benign',
      background: { image: fixedImage('img/icons/unicons/question-circle.svg') },
    });
    benign.div = document.createElement('div');
    benign.updateData(context);
    push(loads, { kind: 'css-background', value: String(benign.dataStyle.backgroundImage ?? '') });

    for (const item of [ellipseItem, cloudItem, parallelogramItem, triangleItem]) {
      const data = item.prepareData?.(context, {
        type: item.id,
        name: item.id,
        background: { image: fixedImage('../../logout') },
      });
      if (data?.backgroundImage) {
        push(loads, { kind: 'svg-image', value: data.backgroundImage });
      }
    }

    const icon = iconItem.prepareData?.(context, {
      type: iconItem.id,
      name: 'icon',
      config: { path: fixedImage('../../logout') },
    });
    if (icon?.path) {
      push(loads, { kind: 'inline-svg-fetch', value: icon.path });
    }

    const fieldFrame = createDataFrame({
      fields: [{ name: 'icon', values: ['../../profile/switch-org/3'] }],
    });
    const fieldData = { series: [fieldFrame], state: LoadingState.Done } as PanelData;
    const fieldValue = getResourceDimensionFromData(fieldData, {
      mode: ResourceDimensionMode.Field,
      field: 'icon',
      fixed: '',
    }).value();
    if (fieldValue) {
      push(loads, { kind: 'css-background', value: cssUrl(fieldValue) });
    }

    const mappingFrame = createDataFrame({
      fields: [{ name: 'icon', values: ['../../logout'] }],
    });
    const mappingValue = getResourceDimensionFromData(
      { series: [mappingFrame], state: LoadingState.Done } as PanelData,
      { mode: ResourceDimensionMode.Mapping, field: 'icon', fixed: '' }
    ).value();
    if (mappingValue) {
      push(loads, { kind: 'css-background', value: cssUrl(mappingValue) });
    }

    const previousBuildPath = window.__grafana_build_path__;
    // @ts-expect-error exercising the fallback used when the bundler has not set the global
    delete window.__grafana_build_path__;
    const fallback = getPublicOrAbsoluteUrl('../../logout');
    window.__grafana_build_path__ = previousBuildPath;
    if (fallback) {
      push(loads, { kind: 'css-background', value: cssUrl(fallback) });
    }

    await getWebGLStyle('../../logout#.svg');
    await getWebGLStyle('../../profile/switch-org/4#.svg');
    await getMarkerMaker('..\\..\\logout.svg');
    for (const url of fetched) {
      push(loads, { kind: 'geomap-fetch', value: url });
    }
    global.fetch = fetchImpl;

    render(<URLPickerTab newValue="../../logout" setNewValue={jest.fn()} mediaType={MediaType.Image} />);
    push(loads, { kind: 'img', value: screen.getByRole('img').getAttribute('src') ?? '' });

    const legendFetches: string[] = [];
    global.fetch = jest.fn(async (input: RequestInfo | URL) => {
      legendFetches.push(String(input));
      return new Response('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"></svg>', {
        status: 200,
        headers: { 'content-type': 'image/svg+xml' },
      });
    }) as typeof fetch;
    const legendConfig = {
      config: {
        symbol: fixedImage('../../logout'),
        color: { fixed: 'red' },
      },
      base: { color: '#ff0000', opacity: 1 },
      maker: () => {
        throw new Error('legend rendering does not build the marker');
      },
    } as StyleConfigState;
    render(<MarkersLegend layerName="markers" styleConfig={legendConfig} />);
    await screen.findByTitle('Symbol');
    global.fetch = fetchImpl;
    for (const url of legendFetches) {
      push(loads, { kind: 'inline-svg-fetch', value: url });
    }

    const port = (server.address() as AddressInfo).port;
    const absolute = getPublicOrAbsoluteUrl(`http://127.0.0.1:${port}/logout`);
    if (absolute) {
      push(loads, { kind: 'css-background', value: cssUrl(absolute) });
    }
    const external = getPublicOrAbsoluteUrl('https://example.com/icon.svg');
    if (external) {
      push(loads, { kind: 'img', value: external });
    }

    const rootRequests = await visit('/', '/', loads);
    const subpathRequests = await visit('/grafana/', '/grafana', [
      { kind: 'css-background', value: String(rectangle.dataStyle.backgroundImage ?? '') },
    ]);

    const sessionRoutes = [...rootRequests, ...subpathRequests]
      .filter((request) => request.method === 'GET' && isSessionRoute(request.path))
      .map((request) => ({ path: request.path, cookie: request.cookie }));
    const benignIcon = rootRequests.find(
      (request) => request.path === `/${BROWSER_BUILD_PATH}img/icons/unicons/question-circle.svg`
    );

    expect({
      sessionRoutes,
      benignIconRequestedWithSessionCookie: benignIcon?.cookie.includes('grafana_session=') ?? false,
    }).toEqual({
      sessionRoutes: [],
      benignIconRequestedWithSessionCookie: true,
    });
  }, 90000);
});
