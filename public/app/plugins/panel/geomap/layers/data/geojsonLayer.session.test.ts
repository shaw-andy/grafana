/**
 * @jest-environment-options {"url": "http://127.0.0.1:38471/d/abc/dashboard", "resources": "usable", "customExportConditions": ["@grafana-app/source", "browser"]}
 *
 * OpenLayers loads a vector URL with XMLHttpRequest. withCredentials stays false,
 * and a same-origin XHR still includes the document cookie. These tests fail
 * while a saved layer URL can issue that GET outside /public/maps/.
 */
import http from 'node:http';
import path from 'node:path';
import { type Map as OpenLayersMap } from 'ol';
import TileState from 'ol/TileState';
import VectorImage from 'ol/layer/VectorImage';
import { get as getProjection, type Projection } from 'ol/proj';
import XYZ from 'ol/source/XYZ';
import { initTemplateSrv } from 'test/helpers/initTemplateSrv';

import { createTheme, EventBusSrv, type MapLayerOptions } from '@grafana/data';
import { setTemplateSrv } from '@grafana/runtime';
import { ResourceDimensionMode } from '@grafana/schema';

// ol-mapbox-style does not load under jest. MapLibre still calls fetch on the saved URL
// before apply(), and that fetch is the real one.
jest.mock('ol-mapbox-style', () => ({
  apply: jest.fn().mockResolvedValue(undefined),
}));

import { defaultStyleConfig } from '../../style/types';
import { xyzTiles, type XYZConfig } from '../basemaps/generic';
import { maplibreLayers, type MaplibreConfig } from '../basemaps/maplibre';
import { ensureInstanceOf } from '../test-utils';

import { dynamicGeoJSONLayer, type DynamicGeoJSONMapperConfig } from './geojsonDynamic';
import { geojsonLayer, type GeoJSONMapperConfig } from './geojsonLayer';

const ORIGIN = 'http://127.0.0.1:38471';
const SESSION_COOKIE = 'grafana_session=placeholder-session';
const SHIPPED_MAP = '/public/maps/countries.geojson';

type Hit = { method: string; path: string; cookie: string };

const hits: Hit[] = [];
let server: http.Server;

const circleStyle = {
  ...defaultStyleConfig,
  symbol: { mode: ResourceDimensionMode.Fixed, fixed: 'circle' },
};

function normalizedPathname(requestPath: string): string {
  const pathname = requestPath.split('?')[0] ?? requestPath;
  let decoded = pathname;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    decoded = pathname;
  }
  const normalized = path.posix.normalize(decoded);
  return normalized.startsWith('/') ? normalized : `/${normalized}`;
}

function outsideMapHits(seen: Hit[]): Hit[] {
  return seen.filter((hit) => hit.method === 'GET' && !normalizedPathname(hit.path).startsWith('/public/maps/'));
}

async function waitForRequests(): Promise<Hit[]> {
  const start = hits.length;
  const startedAt = Date.now();
  let lastCount = -1;
  let lastChange = Date.now();
  while (Date.now() - startedAt < 800) {
    if (hits.length !== lastCount) {
      lastCount = hits.length;
      lastChange = Date.now();
    } else if (hits.length > start && Date.now() - lastChange >= 50) {
      return hits.slice(start);
    }
    await new Promise((resolve) => setTimeout(resolve, 15));
  }
  return hits.slice(start);
}

function webMercator(): Projection {
  const projection = getProjection('EPSG:3857');
  if (!projection) {
    throw new Error('EPSG:3857 is unavailable');
  }
  return projection;
}

function loadFeatures(layer: VectorImage) {
  const source = layer.getSource();
  if (!source) {
    throw new Error('vector layer has no source');
  }
  const projection = webMercator();
  // CanvasVectorLayerRenderer.prepareFrame calls this when the map draws the layer.
  source.loadFeatures(projection.getExtent(), 1000, projection);
}

async function createGeoJSON(src: string): Promise<VectorImage> {
  const options: MapLayerOptions<GeoJSONMapperConfig> = {
    type: 'geojson',
    name: 'GeoJSON',
    config: { rules: [], style: circleStyle, src },
  };
  const handler = await geojsonLayer.create({} as OpenLayersMap, options, new EventBusSrv(), createTheme());
  return ensureInstanceOf(handler.init(), VectorImage);
}

async function createDynamicGeoJSON(src: string): Promise<VectorImage> {
  const options: MapLayerOptions<DynamicGeoJSONMapperConfig> = {
    type: 'dynamic-geojson',
    name: 'Dynamic GeoJSON',
    config: { rules: [], style: circleStyle, dataStyle: {}, src },
  };
  const handler = await dynamicGeoJSONLayer.create({} as OpenLayersMap, options, new EventBusSrv(), createTheme());
  return ensureInstanceOf(handler.init(), VectorImage);
}

beforeAll((done) => {
  server = http.createServer((req, res) => {
    hits.push({
      method: req.method ?? '',
      path: req.url ?? '',
      cookie: req.headers.cookie ?? '',
    });
    res.writeHead(200, { 'Content-Type': 'application/geo+json' });
    res.end('{"type":"FeatureCollection","features":[]}');
  });
  server.listen(38471, '127.0.0.1', done);
});

afterAll((done) => {
  server.close(done);
});

beforeEach(() => {
  hits.length = 0;
  document.cookie = `${SESSION_COOKIE}; Path=/`;
  window.__grafana_public_path__ = `${ORIGIN}/public/`;
  window.__grafana_build_path__ = `${ORIGIN}/public/build/`;
  setTemplateSrv(initTemplateSrv('geomap-layer-session', []));
  expect(document.cookie).toContain(SESSION_COOKIE);
  expect(window.location.origin).toBe(ORIGIN);
});

describe('GeoJSON layer', () => {
  it('loads a shipped map from the public maps directory', async () => {
    const layer = await createGeoJSON('public/maps/countries.geojson');
    loadFeatures(layer);
    const seen = await waitForRequests();
    expect(seen.map((hit) => normalizedPathname(hit.path))).toContain(SHIPPED_MAP);
    expect(outsideMapHits(seen)).toEqual([]);
  });

  it.each([
    ['a parent segment under the public path', '../logout'],
    ['a public maps prefix followed by parent segments', 'public/maps/../../logout'],
    ['an absolute same-origin logout URL', `${ORIGIN}/logout`],
    ['an absolute URL whose path still contains parent segments', `${ORIGIN}/public/../logout`],
    ['an absolute same-origin org switch', `${ORIGIN}/profile/switch-org/2`],
    ['an encoded parent segment after the public prefix', 'public/%2e%2e/logout'],
  ])('does not request outside /public/maps/ for %s', async (_label, src) => {
    try {
      loadFeatures(await createGeoJSON(src));
    } catch {
      // A refusal before any request is a fix. A request that already left is not.
    }
    expect(outsideMapHits(await waitForRequests())).toEqual([]);
  });

  it('does not request outside /public/maps/ when a dashboard variable expands to a traversal', async () => {
    setTemplateSrv(
      initTemplateSrv('geomap-layer-session', [
        { type: 'query', name: 'src', current: { value: '../logout', text: '../logout' } },
      ])
    );
    try {
      loadFeatures(await createGeoJSON('$src'));
    } catch {
      // A refusal before any request is a fix. A request that already left is not.
    }
    expect(outsideMapHits(await waitForRequests())).toEqual([]);
  });
});

describe('dynamic GeoJSON layer', () => {
  it('loads a shipped map from the public maps directory', async () => {
    const layer = await createDynamicGeoJSON('public/maps/countries.geojson');
    loadFeatures(layer);
    const seen = await waitForRequests();
    expect(outsideMapHits(seen)).toEqual([]);
    expect(seen.map((hit) => normalizedPathname(hit.path))).toContain(SHIPPED_MAP);
  });

  it.each([
    ['an absolute path to logout', '/logout'],
    ['parent segments from the dashboard URL', '../../logout'],
    ['a protocol-relative logout URL', '//127.0.0.1:38471/logout'],
    ['an absolute same-origin logout URL', `${ORIGIN}/logout`],
    ['an absolute same-origin org switch', `${ORIGIN}/profile/switch-org/2`],
  ])('does not request outside /public/maps/ for %s', async (_label, src) => {
    try {
      loadFeatures(await createDynamicGeoJSON(src));
    } catch {
      // A refusal before any request is a fix. A request that already left is not.
    }
    expect(outsideMapHits(await waitForRequests())).toEqual([]);
  });
});

describe('XYZ tile layer', () => {
  it.each([
    ['an absolute same-origin logout URL', `${ORIGIN}/logout`],
    ['an absolute path to logout', '/logout'],
    ['parent segments from the dashboard URL', '../../logout'],
  ])('does not request outside /public/maps/ for %s', async (_label, url) => {
    const options: MapLayerOptions<XYZConfig> = {
      type: 'xyz',
      name: 'XYZ',
      config: { url, attribution: '' },
    };
    let src = '';
    try {
      const handler = await xyzTiles.create({} as OpenLayersMap, options, new EventBusSrv(), createTheme());
      const source = handler.init().getSource();
      if (!(source instanceof XYZ)) {
        throw new Error('expected an XYZ source');
      }
      const tile = source.getTile(0, 0, 0, 1, webMercator());
      if (tile.getState() === TileState.IDLE) {
        tile.load();
      }
      const image = 'getImage' in tile && typeof tile.getImage === 'function' ? tile.getImage() : undefined;
      src = image && typeof image === 'object' && 'src' in image ? String(image.src) : '';
    } catch {
      // A refusal before any request is a fix. A request that already left is not.
    }
    const resolved = src ? new URL(src, window.location.href) : undefined;
    const imageOnThisServer =
      resolved !== undefined &&
      resolved.origin === window.location.origin &&
      !normalizedPathname(resolved.pathname).startsWith('/public/maps/');
    // The tile loader assigns this URL to an image. jsdom does not fetch it.
    expect(imageOnThisServer ? resolved.href : '').toBe('');
    expect(outsideMapHits(await waitForRequests())).toEqual([]);
  });
});

describe('MapLibre layer', () => {
  it.each([
    ['an absolute path to logout', '/logout'],
    ['an absolute same-origin logout URL', `${ORIGIN}/logout`],
    ['parent segments from the dashboard URL', '../../logout'],
  ])('does not request outside /public/maps/ for %s', async (_label, url) => {
    const options: MapLayerOptions<Partial<MaplibreConfig>> = {
      type: 'maplibre',
      name: 'MapLibre',
      config: { url },
    };
    try {
      const handler = await maplibreLayers[0].create({} as OpenLayersMap, options, new EventBusSrv(), createTheme());
      handler.init();
    } catch {
      // A refusal before any request is a fix. A request that already left is not.
    }
    expect(outsideMapHits(await waitForRequests())).toEqual([]);
  });
});
