import type OpenLayersMap from 'ol/Map';
import ImageTile from 'ol/ImageTile';
import type BaseLayer from 'ol/layer/Base';
import { get as getProjection } from 'ol/proj';
import type VectorSource from 'ol/source/Vector';
import XYZ from 'ol/source/XYZ';

import { createTheme, EventBusSrv, type EventBus, type GrafanaTheme2, type MapLayerOptions } from '@grafana/data';

import { dynamicGeoJSONLayer, type DynamicGeoJSONMapperConfig } from '../data/geojsonDynamic';
import { geojsonLayer, type GeoJSONMapperConfig } from '../data/geojsonLayer';
import { getTileSource } from '../test-utils';

import { esriLayers, type ESRIXYZConfig } from './esri';
import { xyzTiles, type XYZConfig, type UnresolvedXYZConfig } from './generic';
import { maplibreLayers, type MaplibreConfig } from './maplibre';

const applyMock = jest.fn().mockResolvedValue(undefined);
jest.mock('ol-mapbox-style', () => ({
  apply: (...args: unknown[]) => applyMock(...args),
}));

const replaceMock = jest.fn((value: string) => value);
jest.mock('@grafana/runtime', () => ({
  ...jest.requireActual('@grafana/runtime'),
  getTemplateSrv: () => ({
    replace: replaceMock,
  }),
}));

const [esriXYZ] = esriLayers;
const [maplibreLayer] = maplibreLayers;

const map = {} as OpenLayersMap;
const eventBus = {} as EventBus;
const theme = { isDark: false } as GrafanaTheme2;

const EXTERNAL_TILES = 'https://tiles.example.com/{z}/{x}/{y}.png';

function pageOrigin(): string {
  return window.location.origin;
}

function resolvesToThisServer(raw: string): boolean {
  if (!raw || raw === 'about:blank') {
    return false;
  }
  try {
    return new URL(raw, window.location.href).origin === pageOrigin();
  } catch {
    return false;
  }
}

function attackTemplates(): string[] {
  const origin = pageOrigin();
  const host = window.location.host;
  return [
    '/logout',
    '/profile/switch-org/2',
    '/profile/switch-org/{z}',
    `${origin}/logout`,
    `${origin}/profile/switch-org/2`,
    `//${host}/logout`,
    `//${host}/profile/switch-org/2`,
  ];
}

function withImageSrc(run: () => void): string[] {
  const assigned: string[] = [];
  const proto = HTMLImageElement.prototype;
  const previous = Object.getOwnPropertyDescriptor(proto, 'src');
  Object.defineProperty(proto, 'src', {
    configurable: true,
    enumerable: true,
    get() {
      return '';
    },
    set(value: string) {
      assigned.push(String(value));
    },
  });
  try {
    run();
  } finally {
    if (previous) {
      Object.defineProperty(proto, 'src', previous);
    }
  }
  return assigned;
}

function tileImageRequests(source: XYZ): string[] {
  return withImageSrc(() => {
    const projection = source.getProjection() ?? getProjection('EPSG:3857');
    if (!projection) {
      throw new Error('missing projection');
    }
    // z=2 so a template of /profile/switch-org/{z} is the organization id from the attack.
    const tile = source.getTile(2, 0, 0, 1, projection);
    if (!(tile instanceof ImageTile)) {
      throw new Error('expected an image tile');
    }
    try {
      tile.load();
    } catch {
      // A refusal after the image src is assigned still counts as a request.
    }
  });
}

function requestsFromLayer(layer: BaseLayer): string[] {
  let source: XYZ;
  try {
    source = getTileSource(layer, XYZ);
  } catch {
    return [];
  }
  return tileImageRequests(source);
}

async function xyzTileRequests(url: string): Promise<string[]> {
  const options: MapLayerOptions<XYZConfig> = {
    name: 'xyz',
    type: 'xyz',
    config: { url, attribution: '' },
  };
  let layer: BaseLayer;
  try {
    const handler = await xyzTiles.create(map, options, eventBus, theme);
    layer = handler.init();
  } catch {
    return [];
  }
  return requestsFromLayer(layer);
}

async function esriCustomTileRequests(url: string): Promise<string[]> {
  const options: MapLayerOptions<UnresolvedXYZConfig<ESRIXYZConfig>> = {
    name: 'esri',
    type: 'esri-xyz',
    config: { server: 'custom', url, attribution: '' },
  };
  let layer: BaseLayer;
  try {
    const handler = await esriXYZ.create(map, options, eventBus, theme);
    layer = handler.init();
  } catch {
    return [];
  }
  return requestsFromLayer(layer);
}

function withXHR(run: () => void): string[] {
  const opened: string[] = [];
  const proto = XMLHttpRequest.prototype;
  const originalOpen = proto.open;
  const originalSend = proto.send;
  proto.open = function open(method: string, url: string | URL, async?: boolean, username?: string | null, password?: string | null) {
    opened.push(String(url));
    return originalOpen.call(this, method, url, async ?? true, username, password);
  };
  proto.send = function send() {
    // The URL was chosen by the loader. Do not perform the request.
  };
  try {
    run();
  } finally {
    proto.open = originalOpen;
    proto.send = originalSend;
  }
  return opened;
}

function vectorRequests(source: VectorSource): string[] {
  const projection = getProjection('EPSG:3857');
  if (!projection) {
    throw new Error('missing projection');
  }
  return withXHR(() => {
    source.loadFeatures([0, 0, 1, 1], 1, projection);
  });
}

async function geojsonRequests(src: string): Promise<string[]> {
  const options: MapLayerOptions<GeoJSONMapperConfig> = {
    type: 'geojson',
    name: 'GeoJSON',
    config: { src, rules: [], style: { symbol: { fixed: '', mode: 'fixed' } } },
  };
  try {
    const handler = await geojsonLayer.create(map, options, new EventBusSrv(), createTheme());
    const layer = handler.init() as { getSource: () => VectorSource | null };
    const source = layer.getSource();
    if (!source) {
      return [];
    }
    return vectorRequests(source);
  } catch {
    return [];
  }
}

async function dynamicGeojsonRequests(src: string): Promise<string[]> {
  const options: MapLayerOptions<DynamicGeoJSONMapperConfig> = {
    type: 'dynamic-geojson',
    name: 'Dynamic GeoJSON',
    config: { src, rules: [], style: { symbol: { fixed: '', mode: 'fixed' } }, dataStyle: {} },
  };
  try {
    const handler = await dynamicGeoJSONLayer.create(map, options, new EventBusSrv(), createTheme());
    const layer = handler.init() as { getSource: () => VectorSource | null };
    const source = layer.getSource();
    if (!source) {
      return [];
    }
    return vectorRequests(source);
  } catch {
    return [];
  }
}

async function maplibreRequests(url: string): Promise<string[]> {
  const requested: string[] = [];
  const original = global.fetch;
  global.fetch = ((input: RequestInfo | URL) => {
    requested.push(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    return Promise.resolve(new Response('', { status: 404, statusText: 'not found' }));
  }) as typeof fetch;
  try {
    const options: MapLayerOptions<Partial<MaplibreConfig>> = {
      name: 'maplibre',
      type: 'maplibre',
      config: { url },
    };
    const handler = await maplibreLayer.create(map, options, eventBus, theme);
    handler.init();
    await Promise.resolve();
    return requested;
  } catch {
    return requested;
  } finally {
    global.fetch = original;
  }
}

describe('geomap saved URLs are not loaded with the viewer session', () => {
  beforeEach(() => {
    replaceMock.mockReset();
    replaceMock.mockImplementation((value: string) => value);
    applyMock.mockClear();
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    window.__grafana_public_path__ = `${pageOrigin()}/public/`;
  });

  it('still requests an external https XYZ tile', async () => {
    const urls = await xyzTileRequests(EXTERNAL_TILES);
    expect(urls).toContain('https://tiles.example.com/2/0/0.png');
  });

  it.each(attackTemplates())('XYZ tile layer does not request %s', async (template) => {
    const urls = await xyzTileRequests(template);
    expect(urls.filter(resolvesToThisServer)).toEqual([]);
  });

  it.each(attackTemplates())('ArcGIS custom MapServer does not request %s', async (template) => {
    const urls = await esriCustomTileRequests(template);
    expect(urls.filter(resolvesToThisServer)).toEqual([]);
  });

  it('uses the XYZ url from the same template replacement that is validated', async () => {
    let reads = 0;
    replaceMock.mockImplementation((value: string) => {
      if (value !== '$basemap') {
        return value;
      }
      reads += 1;
      return reads === 1 ? EXTERNAL_TILES : `${pageOrigin()}/logout`;
    });

    const urls = await xyzTileRequests('$basemap');
    expect(urls.filter(resolvesToThisServer)).toEqual([]);
  });

  it('uses the ArcGIS custom url from the same template replacement that is validated', async () => {
    let reads = 0;
    replaceMock.mockImplementation((value: string) => {
      if (value !== '$basemap') {
        return value;
      }
      reads += 1;
      return reads === 1 ? EXTERNAL_TILES : `${pageOrigin()}/profile/switch-org/2`;
    });

    const urls = await esriCustomTileRequests('$basemap');
    expect(urls.filter(resolvesToThisServer)).toEqual([]);
  });

  it.each([`${pageOrigin()}/logout`, `${pageOrigin()}/profile/switch-org/2`])(
    'MapLibre does not fetch %s',
    async (url) => {
      const urls = await maplibreRequests(url);
      expect(urls.filter(resolvesToThisServer)).toEqual([]);
    }
  );

  it.each([`${pageOrigin()}/logout`, `${pageOrigin()}/profile/switch-org/2`, '/logout'])(
    'GeoJSON does not load %s',
    async (src) => {
      const urls = await geojsonRequests(src);
      expect(urls.filter(resolvesToThisServer)).toEqual([]);
    }
  );

  it.each(['/logout', '/profile/switch-org/2', `${pageOrigin()}/logout`])(
    'dynamic GeoJSON does not load %s',
    async (src) => {
      const urls = await dynamicGeojsonRequests(src);
      expect(urls.filter(resolvesToThisServer)).toEqual([]);
    }
  );

  it('uses the dynamic GeoJSON src from the same config read that is validated', async () => {
    let reads = 0;
    const config = {
      rules: [],
      style: { symbol: { fixed: '', mode: 'fixed' as const } },
      dataStyle: {},
    };
    Object.defineProperty(config, 'src', {
      enumerable: true,
      get() {
        reads += 1;
        return reads === 1 ? 'https://tiles.example.com/borders.geojson' : `${pageOrigin()}/logout`;
      },
    });

    const options: MapLayerOptions<DynamicGeoJSONMapperConfig> = {
      type: 'dynamic-geojson',
      name: 'Dynamic GeoJSON',
      config: config as DynamicGeoJSONMapperConfig,
    };
    let urls: string[] = [];
    try {
      const handler = await dynamicGeoJSONLayer.create(map, options, new EventBusSrv(), createTheme());
      const layer = handler.init() as { getSource: () => VectorSource | null };
      const source = layer.getSource();
      urls = source ? vectorRequests(source) : [];
    } catch {
      urls = [];
    }
    expect(urls.filter(resolvesToThisServer)).toEqual([]);
  });
});
